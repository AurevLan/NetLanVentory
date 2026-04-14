"""Threat intelligence feed ingestion.

Supports:
- AlienVault OTX (Open Threat Exchange) — requires API key
- abuse.ch URLhaus — public CSV feed, no key required

IOCs are upserted into the threat_iocs table.
"""

from __future__ import annotations

import asyncio
import csv
import io
from datetime import datetime, timezone

import httpx

from netlanventory.core.logging import get_logger

logger = get_logger(__name__)

_OTX_API_BASE = "https://otx.alienvault.com/api/v1"
_ABUSECH_URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"


async def refresh_otx_feed(api_key: str, max_pulses: int = 50) -> int:
    """Fetch recent OTX pulses and upsert their IOCs.

    Returns the number of IOCs upserted.
    """
    from netlanventory.core.database import get_session_factory
    from netlanventory.models.threat_ioc import ThreatIoc

    headers = {"X-OTX-API-KEY": api_key}
    upserted = 0

    try:
        async with httpx.AsyncClient(timeout=30, headers=headers) as client:
            resp = await client.get(
                f"{_OTX_API_BASE}/pulses/subscribed",
                params={"limit": max_pulses, "modified_since": ""},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("OTX feed fetch failed", error=str(exc))
        return 0

    factory = get_session_factory()
    now = datetime.now(timezone.utc)

    for pulse in data.get("results", []):
        pulse_name = pulse.get("name", "")
        for ind in pulse.get("indicators", []):
            ioc_type = _map_otx_type(ind.get("type", ""))
            if not ioc_type:
                continue
            indicator = ind.get("indicator", "").strip()
            if not indicator:
                continue

            try:
                async with factory() as session:
                    from sqlalchemy import select
                    existing = (
                        await session.execute(
                            select(ThreatIoc).where(
                                ThreatIoc.indicator == indicator,
                                ThreatIoc.ioc_type == ioc_type,
                            )
                        )
                    ).scalar_one_or_none()

                    if existing:
                        existing.last_seen = now
                        existing.source = "otx"
                    else:
                        ioc = ThreatIoc(
                            indicator=indicator,
                            ioc_type=ioc_type,
                            source="otx",
                            severity=_otx_severity(ind.get("type", "")),
                            description=pulse_name[:500],
                            first_seen=now,
                            last_seen=now,
                        )
                        session.add(ioc)
                        upserted += 1
                    await session.commit()
            except Exception as exc:  # noqa: BLE001
                logger.debug("OTX IOC upsert error", error=str(exc))

    logger.info("OTX feed refreshed", upserted=upserted)
    return upserted


async def refresh_abusech_feed() -> int:
    """Fetch abuse.ch URLhaus feed and upsert URL IOCs.

    Returns the number of IOCs upserted.
    """
    from netlanventory.core.database import get_session_factory
    from netlanventory.models.threat_ioc import ThreatIoc
    from sqlalchemy import select

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get(_ABUSECH_URLHAUS_CSV)
            resp.raise_for_status()
            content = resp.text
    except Exception as exc:  # noqa: BLE001
        logger.warning("URLhaus feed fetch failed", error=str(exc))
        return 0

    now = datetime.now(timezone.utc)
    upserted = 0
    factory = get_session_factory()

    # URLhaus CSV has comment lines starting with '#'
    lines = [l for l in content.splitlines() if not l.startswith("#")]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))

    for row in reader:
        url = (row.get("url") or "").strip()
        if not url:
            continue

        try:
            async with factory() as session:
                existing = (
                    await session.execute(
                        select(ThreatIoc).where(
                            ThreatIoc.indicator == url[:500],
                            ThreatIoc.ioc_type == "url",
                        )
                    )
                ).scalar_one_or_none()

                if existing:
                    existing.last_seen = now
                else:
                    ioc = ThreatIoc(
                        indicator=url[:500],
                        ioc_type="url",
                        source="abusech_urlhaus",
                        severity="medium",
                        description=(row.get("threat") or "")[:200],
                        first_seen=now,
                        last_seen=now,
                    )
                    session.add(ioc)
                    upserted += 1
                await session.commit()
        except Exception as exc:  # noqa: BLE001
            logger.debug("URLhaus IOC upsert error", error=str(exc))

    logger.info("abuse.ch URLhaus feed refreshed", upserted=upserted)
    return upserted


async def check_asset_against_iocs(asset_ip: str) -> list[dict]:
    """Return IOCs matching the given asset IP address."""
    from netlanventory.core.database import get_session_factory
    from netlanventory.models.threat_ioc import ThreatIoc
    from sqlalchemy import select

    if not asset_ip:
        return []

    factory = get_session_factory()
    try:
        async with factory() as session:
            result = await session.execute(
                select(ThreatIoc).where(
                    ThreatIoc.indicator == asset_ip,
                    ThreatIoc.ioc_type == "ip",
                )
            )
            iocs = result.scalars().all()
            return [
                {
                    "id": str(ioc.id),
                    "indicator": ioc.indicator,
                    "ioc_type": ioc.ioc_type,
                    "source": ioc.source,
                    "severity": ioc.severity,
                    "description": ioc.description,
                    "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                    "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
                }
                for ioc in iocs
            ]
    except Exception as exc:  # noqa: BLE001
        logger.warning("IOC check failed", ip=asset_ip, error=str(exc))
        return []


def _map_otx_type(otx_type: str) -> str | None:
    """Map OTX indicator type to our normalized ioc_type."""
    mapping = {
        "IPv4": "ip",
        "IPv6": "ip",
        "domain": "domain",
        "hostname": "domain",
        "URL": "url",
        "FileHash-MD5": "hash_md5",
        "FileHash-SHA1": "hash_sha1",
        "FileHash-SHA256": "hash_sha256",
    }
    return mapping.get(otx_type)


def _otx_severity(otx_type: str) -> str:
    """Derive severity from OTX indicator type."""
    if otx_type in ("FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"):
        return "high"
    if otx_type in ("IPv4", "IPv6"):
        return "high"
    return "medium"


async def correlate_urls_against_iocs(urls: list[str]) -> list[dict]:
    """Match a list of URLs against stored IOC URLs.

    Returns list of matches: [{"url": ..., "ioc_id": ..., "source": ..., "severity": ..., "description": ...}]
    """
    if not urls:
        return []

    from netlanventory.core.database import get_session_factory
    from netlanventory.models.threat_ioc import ThreatIoc
    from sqlalchemy import select

    # Normalize and deduplicate URLs
    normalized = list({u.strip().rstrip("/").lower() for u in urls if u.strip()})
    if not normalized:
        return []

    matches = []
    factory = get_session_factory()

    try:
        async with factory() as session:
            # Batch query — check against IOC URL indicators
            # Use substring matching: if IOC URL is contained in found URL or vice versa
            result = await session.execute(
                select(ThreatIoc).where(
                    ThreatIoc.ioc_type == "url",
                    ThreatIoc.indicator.in_(normalized[:500]),  # cap to avoid huge IN clause
                )
            )
            exact_matches = result.scalars().all()

            for ioc in exact_matches:
                matches.append({
                    "url": ioc.indicator,
                    "ioc_id": str(ioc.id),
                    "source": ioc.source,
                    "severity": ioc.severity,
                    "description": ioc.description,
                })

            # Also check if any IOC URL domains match found URL domains
            # Extract domains from both IOC URLs and found URLs
            if not exact_matches:
                import re
                domain_pattern = re.compile(r"https?://([^/:]+)")
                found_domains = set()
                for u in normalized[:200]:
                    m = domain_pattern.match(u)
                    if m:
                        found_domains.add(m.group(1).lower())

                if found_domains:
                    # Check domain IOCs
                    domain_result = await session.execute(
                        select(ThreatIoc).where(
                            ThreatIoc.ioc_type == "domain",
                            ThreatIoc.indicator.in_(list(found_domains)),
                        )
                    )
                    domain_iocs = domain_result.scalars().all()
                    for ioc in domain_iocs:
                        matching_urls = [u for u in normalized if ioc.indicator in u]
                        for url in matching_urls[:3]:
                            matches.append({
                                "url": url,
                                "ioc_id": str(ioc.id),
                                "source": ioc.source,
                                "severity": ioc.severity,
                                "description": f"Domain {ioc.indicator} matched: {ioc.description or ''}",
                            })
    except Exception as exc:
        logger.warning("URL IOC correlation failed", error=str(exc))

    return matches
