"""Background auto-scan scheduler.

Runs as an asyncio task in the app lifespan. Every 60 seconds it checks
all assets where ZAP, SSH, or Trivy auto-scan is enabled and triggers
scans when the configured interval has elapsed since the last scan.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import case, func, select
from sqlalchemy.orm import selectinload

import httpx

from netlanventory.api.routers.epss import _download_epss_map
from netlanventory.api.routers.scans import _run_scan
from netlanventory.core.config import get_settings
from netlanventory.core.database import get_session_factory
from netlanventory.core.logging import get_logger
from netlanventory.models.scan import Scan

logger = get_logger(__name__)

# Web service ports that ZAP should scan
_WEB_PORTS_HTTP = {80, 8080, 8000, 3000, 8888}
_WEB_PORTS_HTTPS = {443, 8443, 4443}
_WEB_PORTS_ALL = _WEB_PORTS_HTTP | _WEB_PORTS_HTTPS

_CHECK_INTERVAL_SECONDS = 60  # how often the scheduler wakes up to check


_THREAT_FEED_INTERVAL_SECONDS = 6 * 3600  # 6 hours
_last_threat_feed_refresh: datetime | None = None

_last_epss_refresh: datetime | None = None
_last_kev_sync: datetime | None = None
_last_sla_compute: datetime | None = None
_last_default_scan: datetime | None = None
_last_ssh_profile_test: datetime | None = None
_last_ioc_correlation: datetime | None = None
_last_attack_paths_refresh: datetime | None = None
_last_scan_priorities_recompute: datetime | None = None
_last_ssvc_recompute: datetime | None = None
_last_famine_guard: datetime | None = None


async def scheduler_loop() -> None:
    """Infinite loop: wake every 60 s and trigger all automated tasks."""
    logger.info(
        "Auto-scan scheduler started "
        "(ZAP + SSH + Trivy + scheduled scans + threat feeds + EPSS + KEV + SLA "
        "+ default scan + SSH profile test + IOC correlation + new assets)"
    )
    tasks = [
        ("ZAP auto-scan", _check_and_trigger_auto_scans),
        ("SSH auto-scan", _check_and_trigger_ssh_auto_scans),
        ("Trivy auto-scan", _check_and_trigger_trivy_auto_scans),
        ("New-assets check", _check_new_assets),
        ("Threat feeds refresh", _maybe_refresh_threat_feeds),
        ("IOC auto-correlation", _maybe_auto_correlate_iocs),
        ("Scheduled reports", _check_scheduled_reports),
        ("Scheduled scans (recurring)", _check_scheduled_scans),
        ("Scheduled scans (table)", _check_scheduled_scans_table),
        ("Default network scan", _maybe_run_default_scan),
        ("SSH profile test", _maybe_test_ssh_profiles),
        ("EPSS enrichment", _maybe_enrich_epss),
        ("KEV sync", _maybe_sync_kev),
        ("SLA compute", _maybe_compute_sla),
        ("KPI snapshot", _take_daily_kpi_snapshot),
        # Innovation roadmap hooks
        ("Attack paths refresh", _maybe_refresh_attack_paths),
        # SSVC must run before the priority recompute so the dominant SSVC
        # term reads freshly-stored decisions.
        ("SSVC recompute", _maybe_recompute_ssvc),
        ("Scan priorities recompute", _maybe_recompute_scan_priorities),
        ("Smart queue drain", _drain_priority_queue),
    ]
    while True:
        await asyncio.sleep(_CHECK_INTERVAL_SECONDS)
        for task_name, task_fn in tasks:
            try:
                await task_fn()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception(f"{task_name} error — will retry next cycle")


async def _check_and_trigger_auto_scans() -> None:
    """Check all assets and trigger ZAP scans where due."""
    from netlanventory.models.asset import Asset
    from netlanventory.models.asset_dns import AssetDns
    from netlanventory.models.global_settings import GlobalSettings
    from netlanventory.models.port import Port
    from netlanventory.models.zap_report import ZapReport
    from netlanventory.api.routers.zap import _run_zap_scan

    factory = get_session_factory()

    async with factory() as session:
        # 1. Load global settings (singleton id=1)
        gs_result = await session.execute(
            select(GlobalSettings).where(GlobalSettings.id == 1)
        )
        gs = gs_result.scalar_one_or_none()
        global_enabled = gs.zap_auto_scan_enabled if gs else False
        global_interval = gs.zap_scan_interval_minutes if gs else 60

        # 2. Load all active assets with their ports and DNS entries
        assets_result = await session.execute(
            select(Asset)
            .where(Asset.is_active.is_(True))
            .options(
                selectinload(Asset.ports),
                selectinload(Asset.dns_entries),
            )
        )
        assets = assets_result.scalars().all()

        now = datetime.now(timezone.utc)

        for asset in assets:
            # Resolve effective enabled/interval for this asset
            asset_enabled = asset.zap_auto_scan_enabled
            if asset_enabled is None:
                effective_enabled = global_enabled
            else:
                effective_enabled = asset_enabled

            if not effective_enabled:
                continue

            asset_interval = asset.zap_scan_interval_minutes
            effective_interval_minutes = asset_interval if asset_interval is not None else global_interval

            # Check if it's time to scan
            last = asset.zap_last_auto_scan_at
            if last is not None:
                # Ensure last is timezone-aware for comparison
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                elapsed_minutes = (now - last).total_seconds() / 60
                if elapsed_minutes < effective_interval_minutes:
                    continue

            # Find open web ports
            open_ports = [p for p in (asset.ports or []) if p.state == "open"]
            web_ports = [p for p in open_ports if p.port_number in _WEB_PORTS_ALL]
            if not web_ports:
                continue

            # Build target list: IP + all DNS names, on each web port
            targets: list[str] = []
            hosts: list[str] = []

            if asset.ip:
                hosts.append(asset.ip)
            for dns in (asset.dns_entries or []):
                if dns.fqdn:
                    hosts.append(dns.fqdn)

            if not hosts:
                continue

            for port in web_ports:
                scheme = "https" if port.port_number in _WEB_PORTS_HTTPS else "http"
                for host in hosts:
                    if (scheme == "http" and port.port_number == 80) or \
                       (scheme == "https" and port.port_number == 443):
                        targets.append(f"{scheme}://{host}")
                    else:
                        targets.append(f"{scheme}://{host}:{port.port_number}")

            if not targets:
                continue

            # Update last-scan timestamp before launching tasks so we don't
            # accidentally double-trigger if a scan is slow
            asset.zap_last_auto_scan_at = now
            await session.flush()

            logger.info(
                "Auto-scan triggered",
                asset_id=str(asset.id),
                ip=asset.ip,
                targets=targets,
            )

            # Create a ZapReport and launch a background task for each target
            for target_url in targets:
                report = ZapReport(
                    asset_id=asset.id,
                    status="pending",
                    target_url=target_url,
                )
                session.add(report)
                await session.flush()
                await session.refresh(report)

                # Fire-and-forget — _run_zap_scan manages its own session
                asyncio.create_task(
                    _run_zap_scan(
                        report_id=report.id,
                        asset_id=asset.id,
                        target_url=target_url,
                        spider=True,
                    ),
                    name=f"zap-auto-{asset.id}-{report.id}",
                )

        await session.commit()


async def _check_and_trigger_ssh_auto_scans() -> None:
    """Check all assets and trigger SSH CVE scans where due."""
    from netlanventory.models.asset import Asset
    from netlanventory.models.ssh_scan_report import SshScanReport
    from netlanventory.api.routers.ssh_scan import _run_ssh_scan

    if get_settings().smart_scheduler_queue_enabled:
        return  # smart priority queue owns ssh_scan dispatch (see _drain_priority_queue)

    factory = get_session_factory()

    async with factory() as session:
        assets_result = await session.execute(
            select(Asset)
            .where(Asset.is_active.is_(True))
            .where(Asset.ssh_auto_scan_enabled.is_(True))
            .options(selectinload(Asset.ssh_profile))
        )
        assets = assets_result.scalars().all()

        now = datetime.now(timezone.utc)

        for asset in assets:
            # Must have SSH credentials to scan
            if not asset.has_ssh_credentials:
                continue

            if not asset.ip:
                continue

            interval_minutes = asset.ssh_scan_interval_minutes or 60

            last = asset.ssh_last_auto_scan_at
            if last is not None:
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                elapsed_minutes = (now - last).total_seconds() / 60
                if elapsed_minutes < interval_minutes:
                    continue

            # Mark before launching to avoid double-trigger
            asset.ssh_last_auto_scan_at = now
            await session.flush()

            report = SshScanReport(asset_id=asset.id, status="pending")
            session.add(report)
            await session.flush()
            await session.refresh(report)

            logger.info(
                "SSH auto-scan triggered",
                asset_id=str(asset.id),
                ip=asset.ip,
            )

            asyncio.create_task(
                _run_ssh_scan(report_id=report.id, asset_id=asset.id),
                name=f"ssh-auto-{asset.id}-{report.id}",
            )

        await session.commit()


async def _check_and_trigger_trivy_auto_scans() -> None:
    """Check all assets and trigger Trivy Docker scans where due."""
    import shutil
    from netlanventory.models.asset import Asset
    from netlanventory.models.trivy_docker_report import TrivyDockerReport
    from netlanventory.api.routers.trivy_docker_scan import _run_trivy_docker_scan, TRIVY_BINARY

    if not shutil.which(TRIVY_BINARY):
        return  # Trivy not installed, skip silently

    if get_settings().smart_scheduler_queue_enabled:
        return  # smart priority queue owns trivy_docker dispatch (see _drain_priority_queue)

    factory = get_session_factory()

    async with factory() as session:
        assets_result = await session.execute(
            select(Asset)
            .where(Asset.is_active.is_(True))
            .where(Asset.trivy_auto_scan_enabled.is_(True))
            .options(selectinload(Asset.ssh_profile))
        )
        assets = assets_result.scalars().all()

        now = datetime.now(timezone.utc)

        for asset in assets:
            if not asset.has_ssh_credentials:
                continue

            if not asset.ip:
                continue

            interval_minutes = asset.trivy_scan_interval_minutes or 60

            last = asset.trivy_last_auto_scan_at
            if last is not None:
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                elapsed_minutes = (now - last).total_seconds() / 60
                if elapsed_minutes < interval_minutes:
                    continue

            # Mark before launching to avoid double-trigger
            asset.trivy_last_auto_scan_at = now
            await session.flush()

            report = TrivyDockerReport(asset_id=asset.id, status="pending")
            session.add(report)
            await session.flush()
            await session.refresh(report)

            logger.info(
                "Trivy auto-scan triggered",
                asset_id=str(asset.id),
                ip=asset.ip,
            )

            asyncio.create_task(
                _run_trivy_docker_scan(report_id=report.id, asset_id=asset.id),
                name=f"trivy-auto-{asset.id}-{report.id}",
            )

        await session.commit()


async def _check_new_assets() -> None:
    """Notify about high/critical assets discovered in the last 5 minutes."""
    from datetime import timedelta
    from netlanventory.core.notifications import notify_new_critical_asset
    from netlanventory.models.asset import Asset

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
    factory = get_session_factory()

    async with factory() as session:
        result = await session.execute(
            select(Asset).where(
                Asset.created_at >= cutoff,
                Asset.criticality.in_(["high", "critical"]),
                Asset.is_active.is_(True),
            )
        )
        new_critical = result.scalars().all()
        for asset in new_critical:
            await notify_new_critical_asset(asset)


async def _maybe_refresh_threat_feeds() -> None:
    """Refresh threat intelligence feeds every 6 hours."""
    global _last_threat_feed_refresh

    now = datetime.now(timezone.utc)
    if _last_threat_feed_refresh is not None:
        elapsed = (now - _last_threat_feed_refresh).total_seconds()
        if elapsed < _THREAT_FEED_INTERVAL_SECONDS:
            return

    from netlanventory.core.threat_feeds import refresh_abusech_feed, refresh_otx_feed

    _last_threat_feed_refresh = now
    settings = get_settings()

    if settings.otx_api_key:
        try:
            count = await refresh_otx_feed(settings.otx_api_key)
            logger.info("OTX feed refreshed", count=count)
        except Exception:  # noqa: BLE001
            logger.exception("OTX feed refresh failed")

    try:
        count = await refresh_abusech_feed()
        logger.info("Abuse.ch feed refreshed", count=count)
    except Exception:  # noqa: BLE001
        logger.exception("Abuse.ch feed refresh failed")


async def _check_scheduled_reports() -> None:
    """Send overdue scheduled reports."""
    from datetime import timedelta
    from netlanventory.core.email_sender import send_report_email
    from netlanventory.models.scheduled_report import ScheduledReport

    now = datetime.now(timezone.utc)
    factory = get_session_factory()

    async with factory() as session:
        result = await session.execute(
            select(ScheduledReport).where(
                ScheduledReport.enabled.is_(True),
                ScheduledReport.next_run_at <= now,
            )
        )
        due_reports = result.scalars().all()

        interval_map = {
            "daily": timedelta(days=1),
            "weekly": timedelta(weeks=1),
            "monthly": timedelta(days=30),
        }

        for report in due_reports:
            try:
                subject = f"[NetLanVentory] {report.name} — {report.report_type} report"
                html_body = f"<h1>NetLanVentory Report: {report.name}</h1><p>Type: {report.report_type}</p>"

                await send_report_email(
                    recipients=report.recipients,
                    subject=subject,
                    html_body=html_body,
                    pdf_attachment=None,
                )

                report.last_sent_at = now
                report.next_run_at = now + interval_map.get(report.schedule, timedelta(days=1))
                logger.info("Scheduled report sent", name=report.name, recipients=report.recipients)
            except Exception:  # noqa: BLE001
                logger.exception("Failed to send scheduled report", name=report.name)

        await session.commit()


async def _check_scheduled_scans() -> None:
    """Trigger recurring scans when their interval has elapsed.

    Re-runs the SAME scan in place (resets status, clears old results)
    instead of creating a new scan row. The scan list stays clean.
    """
    from netlanventory.models.scan_result import ScanResult

    factory = get_session_factory()
    now = datetime.now(timezone.utc)

    async with factory() as session:
        result = await session.execute(
            select(Scan).where(
                Scan.recurring.is_(True),
                Scan.recurring_interval_hours.isnot(None),
                # Don't re-trigger a scan that's already running
                Scan.status.notin_(["pending", "running"]),
            )
        )
        recurring_scans = result.scalars().all()

        for scan in recurring_scans:
            interval = scan.recurring_interval_hours or 24

            last = scan.recurring_last_triggered_at or scan.finished_at or scan.created_at
            if last is not None:
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                elapsed_hours = (now - last).total_seconds() / 3600
                if elapsed_hours < interval:
                    continue

            modules = scan.modules_run or []
            if not modules:
                continue

            # Clear previous results
            old_results = await session.execute(
                select(ScanResult).where(ScanResult.scan_id == scan.id)
            )
            for r in old_results.scalars().all():
                await session.delete(r)

            # Reset scan state in place
            scan.status = "pending"
            scan.started_at = None
            scan.finished_at = None
            scan.summary = None
            scan.error_msg = None
            scan.partial_results = {}
            scan.recurring_last_triggered_at = now
            scan.recurring_run_count = (scan.recurring_run_count or 0) + 1
            await session.flush()

            logger.info(
                "Recurring scan triggered (in-place)",
                scan_id=str(scan.id),
                target=scan.target,
                modules=modules,
                run_count=scan.recurring_run_count,
            )

            asyncio.create_task(
                _run_scan(scan.id, scan.target, modules, {}),
                name=f"recurring-{scan.id}",
            )

        await session.commit()


async def _take_daily_kpi_snapshot() -> None:
    """Create a daily KPI snapshot if one does not already exist for today."""
    from netlanventory.models.asset import Asset
    from netlanventory.models.asset_cve import AssetCve
    from netlanventory.models.cve import Cve
    from netlanventory.models.kpi_snapshot import KpiSnapshot

    factory = get_session_factory()
    today = date.today()
    now = datetime.now(timezone.utc)

    async with factory() as session:
        # Check if snapshot already exists for today
        existing = (
            await session.execute(
                select(KpiSnapshot).where(KpiSnapshot.date == today)
            )
        ).scalar_one_or_none()
        if existing is not None:
            return

        # ── Asset metrics ────────────────────────────────────────────
        total_assets = (
            await session.execute(select(func.count()).select_from(Asset))
        ).scalar_one()

        active_assets = (
            await session.execute(
                select(func.count()).select_from(Asset).where(Asset.is_active.is_(True))
            )
        ).scalar_one()

        # ── CVE metrics ──────────────────────────────────────────────
        total_cves = (
            await session.execute(select(func.count()).select_from(AssetCve))
        ).scalar_one()

        # Critical and High CVE counts (by Cve severity)
        sev_rows = (
            await session.execute(
                select(Cve.severity, func.count(AssetCve.id).label("cnt"))
                .join(AssetCve, AssetCve.cve_id == Cve.id)
                .group_by(Cve.severity)
            )
        ).all()
        sev_map = {r.severity or "Unknown": r.cnt for r in sev_rows}
        critical_cves = sev_map.get("Critical", 0)
        high_cves = sev_map.get("High", 0)

        open_cves = (
            await session.execute(
                select(func.count())
                .select_from(AssetCve)
                .where(AssetCve.remediation_status != "resolved")
            )
        ).scalar_one()

        resolved_cves = (
            await session.execute(
                select(func.count())
                .select_from(AssetCve)
                .where(AssetCve.remediation_status == "resolved")
            )
        ).scalar_one()

        # ── MTTR (last 90 days) ──────────────────────────────────────
        cutoff_90d = now - timedelta(days=90)
        mttr_result = (
            await session.execute(
                select(
                    func.avg(
                        func.extract("epoch", AssetCve.remediation_resolved_at)
                        - func.extract("epoch", AssetCve.discovered_at)
                    )
                    / 3600.0
                )
                .where(
                    AssetCve.remediation_status == "resolved",
                    AssetCve.remediation_resolved_at.isnot(None),
                    AssetCve.remediation_resolved_at >= cutoff_90d,
                )
            )
        ).scalar_one_or_none()
        mttr_hours: float | None = round(mttr_result, 2) if mttr_result is not None else None

        # ── SLA breach count ─────────────────────────────────────────
        sla_breach_count = (
            await session.execute(
                select(func.count())
                .select_from(AssetCve)
                .where(AssetCve.sla_breached.is_(True))
            )
        ).scalar_one()

        # ── Risk score average ───────────────────────────────────────
        risk_score_avg_result = (
            await session.execute(
                select(func.avg(Asset.risk_score)).where(Asset.risk_score.isnot(None))
            )
        ).scalar_one_or_none()
        risk_score_avg: float | None = (
            round(risk_score_avg_result, 2) if risk_score_avg_result is not None else None
        )

        # ── Scan coverage ────────────────────────────────────────────
        cutoff_scan = now - timedelta(days=7)
        assets_recently_scanned = (
            await session.execute(
                select(func.count())
                .select_from(Asset)
                .where(
                    Asset.is_active.is_(True),
                    Asset.last_seen >= cutoff_scan,
                )
            )
        ).scalar_one()
        denom = max(active_assets, 1)
        scan_coverage_pct = round(assets_recently_scanned / denom * 100, 1)

        # ── Insert snapshot ──────────────────────────────────────────
        snapshot = KpiSnapshot(
            date=today,
            total_assets=total_assets,
            active_assets=active_assets,
            total_cves=total_cves,
            critical_cves=critical_cves,
            high_cves=high_cves,
            open_cves=open_cves,
            resolved_cves=resolved_cves,
            mttr_hours=mttr_hours,
            sla_breach_count=sla_breach_count,
            risk_score_avg=risk_score_avg,
            scan_coverage_pct=scan_coverage_pct,
        )
        session.add(snapshot)
        await session.commit()
        logger.info("Daily KPI snapshot recorded", date=str(today))


# ── EPSS daily enrichment ───────────────────────────────────────────────────

_EPSS_INTERVAL_SECONDS = 24 * 3600  # once per day


async def _maybe_enrich_epss() -> None:
    """Enrich CVEs with EPSS scores once per day."""
    global _last_epss_refresh

    now = datetime.now(timezone.utc)
    if _last_epss_refresh is not None:
        if (now - _last_epss_refresh).total_seconds() < _EPSS_INTERVAL_SECONDS:
            return

    from netlanventory.models.cve import Cve

    _last_epss_refresh = now

    epss_map = await _download_epss_map()
    if not epss_map:
        logger.warning("EPSS auto-enrichment: download failed")
        return

    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(select(Cve))
        cves = result.scalars().all()

        updated = 0
        for cve in cves:
            entry = epss_map.get(cve.cve_id)
            if entry is None:
                continue
            cve.epss_score = entry[0]
            cve.epss_percentile = entry[1]
            cve.epss_updated_at = now
            updated += 1

        await session.commit()
        logger.info("EPSS auto-enrichment complete", updated=updated)


# ── KEV daily sync ──────────────────────────────────────────────────────────

_KEV_INTERVAL_SECONDS = 24 * 3600  # once per day
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def _maybe_sync_kev() -> None:
    """Sync CISA KEV catalog once per day."""
    global _last_kev_sync

    now = datetime.now(timezone.utc)
    if _last_kev_sync is not None:
        if (now - _last_kev_sync).total_seconds() < _KEV_INTERVAL_SECONDS:
            return

    from netlanventory.models.cve import Cve

    _last_kev_sync = now

    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            resp = await client.get(_KEV_URL)
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        logger.exception("KEV auto-sync: download failed")
        return

    vulnerabilities = data.get("vulnerabilities", [])
    kev_map: dict[str, dict] = {}
    for v in vulnerabilities:
        cve_id = v.get("cveID", "")
        if cve_id:
            kev_map[cve_id] = {
                "date_added": v.get("dateAdded"),
                "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known",
            }

    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(select(Cve))
        cves = result.scalars().all()

        matched = 0
        for cve in cves:
            entry = kev_map.get(cve.cve_id)
            if entry:
                matched += 1
                from datetime import date as _date
                date_str = entry["date_added"]
                kev_date = None
                if date_str:
                    try:
                        kev_date = _date.fromisoformat(date_str)
                    except ValueError:
                        pass
                cve.kev_date_added = kev_date
                cve.kev_ransomware_use = entry["ransomware"]
                cve.exploit_maturity = "weaponized"
                cve.threat_intel_updated_at = now
            else:
                if cve.kev_date_added is not None:
                    cve.kev_date_added = None
                    cve.kev_ransomware_use = False

        await session.commit()
        logger.info("KEV auto-sync complete", matched=matched, total_kev=len(kev_map))


# ── SLA deadline computation (daily) ────────────────────────────────────────

_SLA_INTERVAL_SECONDS = 6 * 3600  # every 6 hours


async def _maybe_compute_sla() -> None:
    """Recompute SLA deadlines and flag breaches periodically."""
    global _last_sla_compute

    now = datetime.now(timezone.utc)
    if _last_sla_compute is not None:
        if (now - _last_sla_compute).total_seconds() < _SLA_INTERVAL_SECONDS:
            return

    from netlanventory.models.asset import Asset
    from netlanventory.models.asset_cve import AssetCve
    from netlanventory.models.cve import Cve
    from netlanventory.models.sla_config import SlaConfig
    from netlanventory.core.notifications import notify_sla_breach
    from netlanventory.core.sla_policy import effective_sla_deadline
    from sqlalchemy.orm import selectinload

    _last_sla_compute = now

    _DEFAULT_SLA_DAYS = {"Critical": 3, "High": 7, "Medium": 30, "Low": 90}

    factory = get_session_factory()
    async with factory() as session:
        # Load SLA config
        config_result = await session.execute(select(SlaConfig))
        sla_config = dict(_DEFAULT_SLA_DAYS)
        for row in config_result.scalars().all():
            sla_config[row.severity] = row.days

        # Load all CVE links with their CVE data
        result = await session.execute(
            select(AssetCve).options(selectinload(AssetCve.cve))
        )
        links = result.scalars().all()

        today = date.today()
        updated = 0
        new_breaches = 0

        for link in links:
            cve = link.cve
            if not cve:
                continue
            severity = (cve.severity or "Medium").capitalize()
            days = sla_config.get(severity, 30)

            deadline = effective_sla_deadline(
                discovered_at=link.discovered_at,
                severity_days=days,
                ssvc_decision=link.ssvc_decision,
                ssvc_decided_at=link.ssvc_evaluated_at,
            )
            link.sla_deadline = deadline

            was_breached = link.sla_breached
            if deadline < today and link.ack_status != "accepted":
                link.sla_breached = True
                if not was_breached:
                    new_breaches += 1
            else:
                link.sla_breached = False
            updated += 1

        await session.commit()

        # Notify new SLA breaches
        if new_breaches > 0:
            breach_result = await session.execute(
                select(AssetCve, Asset)
                .join(Asset, AssetCve.asset_id == Asset.id)
                .where(AssetCve.sla_breached.is_(True))
                .limit(20)
            )
            for link, asset in breach_result.all():
                try:
                    await notify_sla_breach(asset, link)
                except Exception:
                    logger.exception("SLA breach notification failed")

        logger.info("SLA auto-compute complete", updated=updated, new_breaches=new_breaches)


# ── ScheduledScan table check ──────────────────────────────────────────────


async def _check_scheduled_scans_table() -> None:
    """Check the ScheduledScan table for due scans and launch them."""
    from netlanventory.models.scheduled_scan import ScheduledScan

    factory = get_session_factory()
    now = datetime.now(timezone.utc)

    async with factory() as session:
        result = await session.execute(
            select(ScheduledScan).where(ScheduledScan.enabled.is_(True))
        )
        scheduled_scans = result.scalars().all()

        for scheduled in scheduled_scans:
            last = scheduled.last_run_at
            if last is not None:
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                elapsed_hours = (now - last).total_seconds() / 3600
                if elapsed_hours < scheduled.interval_hours:
                    continue

            modules = [m.strip() for m in scheduled.modules.split(",") if m.strip()]
            if not modules:
                continue

            # Create a Scan record
            scan = Scan(
                target=scheduled.target,
                status="pending",
                modules_run=modules,
            )
            session.add(scan)
            await session.flush()
            await session.refresh(scan)

            # Update tracking
            scheduled.last_run_at = now
            scheduled.last_scan_id = str(scan.id)
            scheduled.last_status = "pending"
            scheduled.run_count = (scheduled.run_count or 0) + 1
            await session.flush()

            logger.info(
                "ScheduledScan triggered",
                scheduled_scan_id=str(scheduled.id),
                scan_id=str(scan.id),
                target=scheduled.target,
                modules=modules,
            )

            asyncio.create_task(
                _run_scan(scan.id, scheduled.target, modules, {}),
                name=f"scheduled-table-{scheduled.id}-{scan.id}",
            )

        await session.commit()


# ── Default daily network scan ──────────────────────────────────────────────


async def _maybe_run_default_scan() -> None:
    """Run a default network scan on all active assets at the configured interval."""
    global _last_default_scan

    settings = get_settings()

    if not settings.default_scan_enabled:
        return

    now = datetime.now(timezone.utc)
    interval_seconds = settings.default_scan_interval_hours * 3600
    if _last_default_scan is not None:
        if (now - _last_default_scan).total_seconds() < interval_seconds:
            return

    from netlanventory.models.asset import Asset

    _last_default_scan = now

    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(Asset.ip)
            .where(Asset.is_active.is_(True), Asset.ip.isnot(None))
        )
        ips = [row[0] for row in result.all() if row[0]]

    if not ips:
        return

    modules = [m.strip() for m in settings.default_scan_modules.split(",") if m.strip()]
    if not modules:
        return

    # Group IPs into /24-like batches to avoid one scan per host
    # Deduplicate and create one scan per unique /24 subnet
    subnets: dict[str, list[str]] = {}
    for ip in ips:
        parts = ip.rsplit(".", 1)
        if len(parts) == 2:
            prefix = parts[0] + ".0/24"
            subnets.setdefault(prefix, []).append(ip)
        else:
            subnets.setdefault(ip, []).append(ip)

    factory = get_session_factory()
    async with factory() as session:
        for target, _hosts in subnets.items():
            scan = Scan(
                target=target,
                status="pending",
                modules_run=modules,
            )
            session.add(scan)
            await session.flush()
            await session.refresh(scan)

            logger.info(
                "Default scan triggered",
                scan_id=str(scan.id),
                target=target,
                modules=modules,
                host_count=len(_hosts),
            )

            asyncio.create_task(
                _run_scan(scan.id, target, modules, {}),
                name=f"default-scan-{scan.id}",
            )

        await session.commit()

    logger.info("Default daily scan launched", subnets=len(subnets), total_hosts=len(ips))


# ── SSH profile auto-test ───────────────────────────────────────────────────


async def _maybe_test_ssh_profiles() -> None:
    """Test all SSH profiles against their assigned assets periodically."""
    global _last_ssh_profile_test

    settings = get_settings()

    if not settings.ssh_profile_test_enabled:
        return

    now = datetime.now(timezone.utc)
    interval_seconds = settings.ssh_profile_test_interval_hours * 3600
    if _last_ssh_profile_test is not None:
        if (now - _last_ssh_profile_test).total_seconds() < interval_seconds:
            return

    import asyncssh
    from netlanventory.core.notifications import notify_ssh_profile_failed
    from netlanventory.models.asset import Asset
    from netlanventory.models.ssh_profile import SshProfile
    from sqlalchemy.orm import selectinload

    _last_ssh_profile_test = now

    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(SshProfile).options(selectinload(SshProfile.assets))
        )
        profiles = result.scalars().all()

        tested = 0
        failed = 0

        for profile in profiles:
            # Test on the first active asset with an IP that uses this profile
            test_assets = [
                a for a in (profile.assets or [])
                if a.is_active and a.ip
            ]
            if not test_assets:
                continue

            asset = test_assets[0]
            port = profile.ssh_port or 22

            try:
                async with asyncssh.connect(
                    asset.ip,
                    port=port,
                    username=profile.ssh_user,
                    known_hosts=None,
                    connect_timeout=10,
                ) as conn:
                    # Simple connectivity test — run a harmless command
                    result = await conn.run("echo ok", timeout=5)
                    if result.exit_status != 0:
                        raise RuntimeError(f"exit code {result.exit_status}")
                tested += 1
                logger.debug("SSH profile test OK", profile=profile.name, host=asset.ip)
            except Exception as exc:
                failed += 1
                logger.warning(
                    "SSH profile test failed",
                    profile=profile.name,
                    host=asset.ip,
                    error=str(exc),
                )
                try:
                    await notify_ssh_profile_failed(profile.name, asset.ip, str(exc))
                except Exception:
                    logger.exception("SSH profile failure notification error")

        logger.info("SSH profile auto-test complete", tested=tested, failed=failed)


# ── IOC auto-correlation after threat feed refresh ──────────────────────────


async def _maybe_auto_correlate_iocs() -> None:
    """Run IOC correlation automatically after each threat feed refresh."""
    global _last_ioc_correlation

    # Only correlate when feeds were just refreshed (within the last cycle)
    if _last_threat_feed_refresh is None:
        return

    now = datetime.now(timezone.utc)
    # Run correlation shortly after a feed refresh (within 2 minutes)
    feed_age = (now - _last_threat_feed_refresh).total_seconds()
    if feed_age > 120:
        # Not a recent feed refresh — skip
        if _last_ioc_correlation is not None and _last_ioc_correlation >= _last_threat_feed_refresh:
            return

    if _last_ioc_correlation is not None:
        if _last_ioc_correlation >= _last_threat_feed_refresh:
            return  # Already correlated for this feed refresh

    from netlanventory.core.notifications import notify_ioc_match
    from netlanventory.models.asset import Asset
    from netlanventory.models.asset_dns import AssetDns
    from netlanventory.models.threat_ioc import ThreatIoc
    from sqlalchemy.orm import selectinload

    _last_ioc_correlation = now

    factory = get_session_factory()
    async with factory() as session:
        # Load active assets
        assets_result = await session.execute(
            select(Asset).options(selectinload(Asset.dns_entries)).where(Asset.is_active.is_(True))
        )
        assets = list(assets_result.scalars().all())

        ip_to_assets: dict[str, list] = {}
        domain_to_assets: dict[str, list] = {}
        for asset in assets:
            if asset.ip:
                ip_to_assets.setdefault(asset.ip, []).append(asset)
            for dns in (asset.dns_entries or []):
                if dns.fqdn:
                    domain_to_assets.setdefault(dns.fqdn.lower(), []).append(asset)

        # Load IOCs (ip + domain only for auto-correlation)
        iocs_result = await session.execute(
            select(ThreatIoc).where(ThreatIoc.ioc_type.in_(["ip", "domain"]))
        )
        iocs = list(iocs_result.scalars().all())

        matches = 0
        for ioc in iocs:
            matched_assets = []
            if ioc.ioc_type == "ip" and ioc.indicator in ip_to_assets:
                matched_assets = [(a, "ip") for a in ip_to_assets[ioc.indicator]]
            elif ioc.ioc_type == "domain":
                indicator_lower = ioc.indicator.lower()
                if indicator_lower in domain_to_assets:
                    matched_assets = [(a, "domain") for a in domain_to_assets[indicator_lower]]

            for asset, match_type in matched_assets:
                matches += 1
                if ioc.severity in ("critical", "high"):
                    try:
                        await notify_ioc_match(
                            asset=asset,
                            ioc_indicator=ioc.indicator,
                            ioc_type=ioc.ioc_type,
                            ioc_severity=ioc.severity,
                            ioc_source=ioc.source,
                            match_type=match_type,
                        )
                    except Exception:
                        logger.exception("IOC auto-correlation notification failed")

        logger.info("IOC auto-correlation complete", matches=matches)


# ── Innovation roadmap hooks (#1, #5) ────────────────────────────────────────


_ATTACK_PATHS_INTERVAL_HOURS = 24
_SCAN_PRIORITIES_INTERVAL_HOURS = 1
_SSVC_INTERVAL_HOURS = 1


async def _maybe_refresh_attack_paths() -> None:
    """Recompute the attack-path graph once a day (innovation #1)."""
    global _last_attack_paths_refresh

    now = datetime.now(timezone.utc)
    if _last_attack_paths_refresh is not None:
        if (now - _last_attack_paths_refresh).total_seconds() < _ATTACK_PATHS_INTERVAL_HOURS * 3600:
            return

    from netlanventory.core.attack_paths import refresh_attack_paths

    factory = get_session_factory()
    async with factory() as session:
        try:
            count = await refresh_attack_paths(session)
            logger.info("attack_paths_scheduler_refresh_done", count=count)
            _last_attack_paths_refresh = now
        except Exception:
            logger.exception("attack_paths_scheduler_refresh_failed")


async def _maybe_recompute_ssvc() -> None:
    """Recompute & persist the SSVC decision per (cve, asset) hourly (#6).

    SSVC is the primary patch-prioritisation signal. Runs after the KEV/EPSS
    syncs (which feed Exploitation/Automatable) and before the scan-priority
    recompute (which reads the stored decisions as its dominant term).
    """
    global _last_ssvc_recompute

    now = datetime.now(timezone.utc)
    if _last_ssvc_recompute is not None:
        if (now - _last_ssvc_recompute).total_seconds() < _SSVC_INTERVAL_HOURS * 3600:
            return

    from netlanventory.core.ssvc_eval import recompute_for_asset as ssvc_recompute
    from netlanventory.models.asset import Asset

    factory = get_session_factory()
    async with factory() as session:
        try:
            asset_ids = (
                await session.execute(
                    select(Asset.id).where(Asset.is_active.is_(True))
                )
            ).scalars().all()

            act = attend = 0
            for asset_id in asset_ids:
                try:
                    summary = await ssvc_recompute(session, asset_id)
                    act += summary.get("act", 0)
                    attend += summary.get("attend", 0)
                except Exception:
                    logger.exception("ssvc_recompute_failed", asset_id=str(asset_id))
            await session.commit()
            logger.info(
                "ssvc_recomputed", assets=len(asset_ids), act=act, attend=attend
            )
            _last_ssvc_recompute = now
        except Exception:
            logger.exception("ssvc_recompute_loop_failed")


async def _maybe_recompute_scan_priorities() -> None:
    """Recompute priorities for every active asset hourly (innovation #5).

    Cheap: one query per asset (a few rows each). Splits the work across
    cycles by skipping if the engine is younger than the interval.
    """
    global _last_scan_priorities_recompute

    now = datetime.now(timezone.utc)
    if _last_scan_priorities_recompute is not None:
        if (now - _last_scan_priorities_recompute).total_seconds() < _SCAN_PRIORITIES_INTERVAL_HOURS * 3600:
            return

    from netlanventory.core.scan_priority import recompute_for_asset
    from netlanventory.models.asset import Asset

    # Modules tracked by the priority queue. Keep small and stable.
    tracked_modules = ["ssh_scan", "trivy_docker", "nuclei", "headers_audit"]

    factory = get_session_factory()
    async with factory() as session:
        try:
            asset_ids = (
                await session.execute(
                    select(Asset.id).where(Asset.is_active.is_(True))
                )
            ).scalars().all()

            for asset_id in asset_ids:
                try:
                    await recompute_for_asset(session, asset_id, tracked_modules)
                except Exception:
                    logger.exception(
                        "scan_priority_recompute_failed", asset_id=str(asset_id)
                    )
            await session.commit()
            logger.info(
                "scan_priorities_recomputed",
                assets=len(asset_ids),
                modules=len(tracked_modules),
            )
            _last_scan_priorities_recompute = now
        except Exception:
            logger.exception("scan_priorities_recompute_loop_failed")


# ── Smart priority queue drain (innovation #5, gated) ────────────────────────

_FAMINE_GUARD_INTERVAL_HOURS = 1
_DRAIN_BUDGET = 20  # max scans launched per cycle


async def _drain_priority_queue() -> None:
    """Pop the most urgent (asset, module) rows and launch their scans.

    Active only when `smart_scheduler_queue_enabled` is set — otherwise this is
    a no-op and the fixed-interval loops drive scanning as before. On each
    cycle it:

      1. runs the famine guard (`force_stale_into_queue`) at most hourly,
      2. pops up to `_DRAIN_BUDGET` due rows (highest score first),
      3. dispatches each via `scan_dispatch.dispatch_module`,
      4. `mark_scanned` on launch, or `defer` when the asset is ineligible.
    """
    global _last_famine_guard

    if not get_settings().smart_scheduler_queue_enabled:
        return

    from sqlalchemy.orm import selectinload

    from netlanventory.core import scan_priority
    from netlanventory.core.scan_dispatch import dispatch_module
    from netlanventory.models.asset import Asset

    factory = get_session_factory()
    now = datetime.now(timezone.utc)

    async with factory() as session:
        # 1. Famine guard (hourly): promote rows starved past max_age_hours.
        if (
            _last_famine_guard is None
            or (now - _last_famine_guard).total_seconds()
            >= _FAMINE_GUARD_INTERVAL_HOURS * 3600
        ):
            try:
                bumped = await scan_priority.force_stale_into_queue(session)
                if bumped:
                    logger.info("smart_queue_famine_guard", promoted=bumped)
                _last_famine_guard = now
            except Exception:
                logger.exception("smart_queue_famine_guard_failed")

        # 2. Pop the due rows.
        due = await scan_priority.pop_due_priorities(session, budget=_DRAIN_BUDGET)
        if not due:
            await session.commit()
            return

        # 3. Load the assets referenced (with ports + DNS for web/nuclei targets).
        asset_ids = {row.asset_id for row in due}
        assets = (
            await session.execute(
                select(Asset)
                .where(Asset.id.in_(asset_ids), Asset.is_active.is_(True))
                .options(selectinload(Asset.ports), selectinload(Asset.dns_entries))
            )
        ).scalars().all()
        asset_by_id = {a.id: a for a in assets}

        launched = 0
        deferred = 0
        for row in due:
            asset = asset_by_id.get(row.asset_id)
            if asset is None:
                # Asset gone or inactive — defer so we stop popping it.
                await scan_priority.defer(session, row.asset_id, row.module)
                deferred += 1
                continue
            try:
                ok = await dispatch_module(session, asset, row.module)
            except Exception:
                logger.exception(
                    "smart_queue_dispatch_failed",
                    asset_id=str(row.asset_id),
                    module=row.module,
                )
                await scan_priority.defer(session, row.asset_id, row.module)
                deferred += 1
                continue

            if ok:
                await scan_priority.mark_scanned(session, row.asset_id, row.module)
                launched += 1
            else:
                await scan_priority.defer(session, row.asset_id, row.module)
                deferred += 1

        await session.commit()
        if launched or deferred:
            logger.info(
                "smart_queue_drained",
                popped=len(due),
                launched=launched,
                deferred=deferred,
            )
