"""ZAP scan router — trigger OWASP ZAP scans on assets and retrieve results."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import get_db
from netlanventory.core.config import get_settings
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve
from netlanventory.models.zap_report import ZapReport
from netlanventory.schemas.zap import ZapAlertOut, ZapReportDetail, ZapReportOut, ZapScanRequest

router = APIRouter(prefix="/assets/{asset_id}/zap", tags=["zap"])
logger = get_logger(__name__)

DbDep = Annotated[AsyncSession, Depends(get_db)]

# Matches CVE-YYYY-NNNNN (4+ digit suffix)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# Matches "<name>/<version>" or "<name> <version>" in evidence strings
_COMPONENT_RE = re.compile(r"([A-Za-z][A-Za-z0-9_\-\.]+)[/\s](\d[\d\.]+)", re.IGNORECASE)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("", response_model=ZapReportOut, status_code=status.HTTP_202_ACCEPTED)
async def start_zap_scan(
    asset_id: uuid.UUID,
    payload: ZapScanRequest,
    background_tasks: BackgroundTasks,
    db: DbDep,
) -> ZapReport:
    """Trigger a ZAP scan for an asset. The scan runs in the background."""
    asset = await _get_asset_or_404(asset_id, db)

    report = ZapReport(
        asset_id=asset.id,
        status="pending",
        target_url=payload.target_url,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(
        _run_zap_scan,
        report_id=report.id,
        asset_id=asset.id,
        target_url=payload.target_url,
        spider=payload.spider,
    )
    logger.info("ZAP scan queued", report_id=str(report.id), target=payload.target_url)
    return report


@router.get("", response_model=list[ZapReportOut])
async def list_zap_reports(asset_id: uuid.UUID, db: DbDep) -> list[ZapReport]:
    """List all ZAP reports for an asset, newest first."""
    await _get_asset_or_404(asset_id, db)
    result = await db.execute(
        select(ZapReport)
        .where(ZapReport.asset_id == asset_id)
        .order_by(ZapReport.created_at.desc())
    )
    return list(result.scalars().all())


@router.get("/{report_id}", response_model=ZapReportDetail)
async def get_zap_report(
    asset_id: uuid.UUID, report_id: uuid.UUID, db: DbDep
) -> ZapReportDetail:
    """Get a specific ZAP report with full alert list."""
    await _get_asset_or_404(asset_id, db)
    result = await db.execute(
        select(ZapReport).where(
            ZapReport.id == report_id,
            ZapReport.asset_id == asset_id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="ZAP report not found")

    alerts = _parse_alerts_from_report(report.report or {})
    return ZapReportDetail(
        id=report.id,
        status=report.status,
        target_url=report.target_url,
        risk_summary=report.risk_summary,
        alerts_count=len(alerts),
        error_msg=report.error_msg,
        created_at=report.created_at,
        updated_at=report.updated_at,
        alerts=alerts,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_asset_or_404(asset_id: uuid.UUID, db: AsyncSession) -> Asset:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


def _parse_alerts_from_report(report: dict[str, Any]) -> list[ZapAlertOut]:
    """Convert raw ZAP alerts JSON into ZapAlertOut objects."""
    raw_alerts: list[dict] = report.get("alerts", [])
    out: list[ZapAlertOut] = []
    for a in raw_alerts:
        ref = a.get("reference", "") or ""
        evidence = a.get("evidence", "") or ""
        alert_name = a.get("alert", "") or ""

        cve_ids = list({cve.upper() for cve in _CVE_RE.findall(ref)})

        # Try to extract component + version from evidence, then alert name
        pkg_name: str | None = None
        pkg_version: str | None = None
        for text in (evidence, alert_name):
            m = _COMPONENT_RE.search(text)
            if m:
                pkg_name = m.group(1)
                pkg_version = m.group(2)
                break

        out.append(ZapAlertOut(
            alert=alert_name,
            risk=a.get("risk", "Informational"),
            confidence=a.get("confidence", "Low"),
            description=a.get("description") or None,
            solution=a.get("solution") or None,
            reference=ref or None,
            evidence=evidence or None,
            cwe_id=str(a.get("cweid", "")) or None,
            cve_ids=cve_ids,
            package_name=pkg_name,
            package_version=pkg_version,
            url=a.get("url") or None,
        ))
    return out


# ── Background task ───────────────────────────────────────────────────────────

async def _run_zap_scan(
    report_id: uuid.UUID,
    asset_id: uuid.UUID,
    target_url: str,
    spider: bool,
) -> None:
    """Execute a full ZAP spider + passive scan and persist results."""
    from netlanventory.core.database import get_session_factory

    settings = get_settings()
    factory = get_session_factory()

    async with factory() as session:
        # Mark as running
        report = await _fetch_report(session, report_id)
        if not report:
            return
        report.status = "running"
        await session.commit()

        try:
            async with httpx.AsyncClient(
                base_url=settings.zap_api_url, timeout=30.0
            ) as zap:
                # 1. Fresh session
                await zap.get("/JSON/core/action/newSession/", params={"apikey": ""})

                # 2. Spider
                if spider:
                    resp = await zap.get(
                        "/JSON/spider/action/scan/",
                        params={"url": target_url, "apikey": ""},
                    )
                    spider_id = resp.json().get("scan", "0")
                    await _poll_spider(zap, spider_id)

                # 3. Passive scan
                await _poll_passive_scan(zap)

                # 4. Fetch alerts
                resp = await zap.get(
                    "/JSON/core/view/alerts/",
                    params={"baseurl": target_url, "start": "0", "count": "1000"},
                )
                raw_alerts: list[dict] = resp.json().get("alerts", [])

            # 5. Persist CVEs
            report = await _fetch_report(session, report_id)
            if not report:
                return
            await _persist_cves(session, asset_id, raw_alerts)

            # 6. Build risk summary
            risk_summary = _build_risk_summary(raw_alerts)

            # 7. Update report
            report.status = "completed"
            report.report = {"alerts": raw_alerts}
            report.risk_summary = risk_summary
            await session.commit()
            logger.info(
                "ZAP scan completed",
                report_id=str(report_id),
                alerts=len(raw_alerts),
            )

        except httpx.ConnectError as exc:
            await _fail_report(session, report_id, f"ZAP unreachable: {exc}")
        except Exception as exc:
            logger.error("ZAP scan failed", report_id=str(report_id), error=str(exc), exc_info=True)
            await _fail_report(session, report_id, str(exc))


async def _fetch_report(session: AsyncSession, report_id: uuid.UUID) -> ZapReport | None:
    result = await session.execute(select(ZapReport).where(ZapReport.id == report_id))
    return result.scalar_one_or_none()


async def _fail_report(session: AsyncSession, report_id: uuid.UUID, msg: str) -> None:
    report = await _fetch_report(session, report_id)
    if report:
        report.status = "failed"
        report.error_msg = msg
        await session.commit()


async def _poll_spider(zap: httpx.AsyncClient, spider_id: str, max_wait: int = 120) -> None:
    import asyncio
    for _ in range(max_wait // 3):
        await asyncio.sleep(3)
        resp = await zap.get(
            "/JSON/spider/view/status/", params={"scanId": spider_id}
        )
        pct = int(resp.json().get("status", 0))
        if pct >= 100:
            return
    logger.warning("Spider did not finish within timeout", spider_id=spider_id)


async def _poll_passive_scan(zap: httpx.AsyncClient, max_wait: int = 60) -> None:
    import asyncio
    for _ in range(max_wait // 3):
        await asyncio.sleep(3)
        resp = await zap.get("/JSON/pscan/view/recordsToScan/")
        remaining = int(resp.json().get("recordsToScan", 0))
        if remaining == 0:
            return


def _build_risk_summary(alerts: list[dict]) -> dict[str, int]:
    summary = {"high": 0, "medium": 0, "low": 0, "informational": 0}
    for a in alerts:
        risk = (a.get("risk") or "").lower()
        if risk in summary:
            summary[risk] += 1
    return summary


async def _persist_cves(
    session: AsyncSession, asset_id: uuid.UUID, alerts: list[dict]
) -> None:
    """Upsert Cve rows and create AssetCve links for each ZAP alert with CVE refs."""
    for alert in alerts:
        ref = (alert.get("reference") or "") + (alert.get("description") or "")
        cve_ids = list({cve.upper() for cve in _CVE_RE.findall(ref)})
        if not cve_ids:
            continue

        # Extract component info once per alert
        pkg_name: str | None = None
        pkg_version: str | None = None
        for text in (alert.get("evidence", "") or "", alert.get("alert", "") or ""):
            m = _COMPONENT_RE.search(text)
            if m:
                pkg_name = m.group(1)
                pkg_version = m.group(2)
                break

        severity = _risk_to_severity(alert.get("risk", ""))

        for cve_id_str in cve_ids:
            # Upsert Cve
            cve_result = await session.execute(
                select(Cve).where(Cve.cve_id == cve_id_str)
            )
            cve = cve_result.scalar_one_or_none()
            if not cve:
                cve = Cve(
                    cve_id=cve_id_str,
                    severity=severity,
                    description=alert.get("description"),
                )
                session.add(cve)
                await session.flush()

            # Skip if AssetCve already exists for this asset+cve
            existing = await session.execute(
                select(AssetCve).where(
                    AssetCve.asset_id == asset_id,
                    AssetCve.cve_id == cve.id,
                )
            )
            if existing.scalar_one_or_none():
                continue

            link = AssetCve(
                asset_id=asset_id,
                cve_id=cve.id,
                source="zap",
                package_name=pkg_name,
                package_version=pkg_version,
            )
            session.add(link)

    await session.commit()


def _risk_to_severity(risk: str) -> str:
    return {
        "High": "HIGH",
        "Medium": "MEDIUM",
        "Low": "LOW",
        "Informational": "INFO",
    }.get(risk, "UNKNOWN")
