"""CVE enrichment — fetch CVSS / severity / description from OSV then NVD.

Called after a scan persists new CVEs. Enriches rows in the `cves` table that
are missing data so that repeated encounters of the same CVE across assets reuse
the cached row without any extra API call.

Rate limits
-----------
OSV individual endpoint (/v1/vulns/{id}) — no official limit; we use 0.05 s
NVD REST API without key     — 5 req / 30 s  → sleep 6 s between calls
NVD REST API with key        — 50 req / 30 s → sleep 0.6 s between calls
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Sequence

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.core.logging import get_logger
from netlanventory.models.cve import Cve

logger = get_logger(__name__)

_OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{cve_id}"
_NVD_CVE_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_SEVERITY_TEXT: dict[str, str] = {
    "critical":    "Critical",
    "high":        "High",
    "medium":      "Medium",
    "low":         "Low",
    "negligible":  "Low",
    "unimportant": "Low",
}

# Enrich at most this many CVEs per scan call to keep background tasks short.
_MAX_PER_CALL = 60


def _canonical_cve_id(cve_id: str) -> str | None:
    """Return the standard CVE-YYYY-NNNNN form of a possibly non-standard ID.

    - ``CVE-2016-2781``          → ``CVE-2016-2781``       (already canonical)
    - ``UBUNTU-CVE-2016-2781``   → ``CVE-2016-2781``
    - ``USN-7743-1``             → ``None``  (no canonical CVE, query OSV directly)
    - ``GHSA-xxxx-xxxx-xxxx``    → ``None``  (GitHub SA, query OSV directly)
    """
    upper = cve_id.upper()
    if upper.startswith("CVE-"):
        return cve_id
    if upper.startswith("UBUNTU-CVE-"):
        return cve_id[len("UBUNTU-"):]   # "CVE-2016-2781"
    return None


def _osv_lookup_id(cve_id: str) -> str:
    """Return the ID to use for the OSV individual endpoint.

    For UBUNTU-CVE IDs, prefer looking up the canonical CVE so we get richer data.
    For everything else, use the ID as-is.
    """
    canonical = _canonical_cve_id(cve_id)
    return canonical if canonical else cve_id


async def enrich_cves(
    session: AsyncSession,
    cve_ids: Sequence[str],
    nvd_api_key: str = "",
) -> None:
    """Enrich CVE rows that still have missing data after a scan.

    Handles all ID formats:
    - ``CVE-YYYY-NNNNN``        → OSV individual lookup + NVD fallback
    - ``UBUNTU-CVE-YYYY-NNNNN`` → lookup canonical CVE on OSV, NVD skipped
    - ``USN-XXXX-X``            → OSV direct lookup (OSV indexes USN entries)
    - ``GHSA-XXXX-XXXX-XXXX``   → OSV direct lookup
    """
    if not cve_ids:
        return

    # Find rows that actually need enrichment (any format)
    result = await session.execute(
        select(Cve).where(
            Cve.cve_id.in_(list(cve_ids)),
            (Cve.cvss_score.is_(None))
            | (Cve.severity.is_(None))
            | (Cve.severity == "Unknown"),
        )
    )
    to_enrich = list(result.scalars().all())[:_MAX_PER_CALL]

    if not to_enrich:
        return

    logger.info(
        "Enriching CVEs",
        count=len(to_enrich),
        source="osv" if not nvd_api_key else "osv+nvd",
    )

    nvd_sleep = 0.6 if nvd_api_key else 6.0
    nvd_headers = {"apiKey": nvd_api_key} if nvd_api_key else {}

    async with httpx.AsyncClient(timeout=15) as client:
        for cve in to_enrich:
            osv_id = _osv_lookup_id(cve.cve_id)

            # ── OSV individual lookup ─────────────────────────────────────────
            try:
                resp = await client.get(_OSV_VULN_URL.format(cve_id=osv_id))
                if resp.status_code == 200:
                    _apply_osv(cve, resp.json())
                elif resp.status_code == 404 and osv_id != cve.cve_id:
                    # Canonical CVE not found on OSV — try original ID
                    resp2 = await client.get(_OSV_VULN_URL.format(cve_id=cve.cve_id))
                    if resp2.status_code == 200:
                        _apply_osv(cve, resp2.json())
            except Exception as exc:
                logger.debug("OSV lookup failed", cve_id=cve.cve_id, error=str(exc))

            await asyncio.sleep(0.05)

            # ── NVD fallback — only for canonical CVE-YYYY-NNNNN IDs ─────────
            canonical = _canonical_cve_id(cve.cve_id)
            if canonical and cve.cvss_score is None:
                try:
                    resp = await client.get(
                        _NVD_CVE_URL,
                        params={"cveId": canonical},
                        headers=nvd_headers,
                    )
                    if resp.status_code == 200:
                        vulns = resp.json().get("vulnerabilities", [])
                        if vulns:
                            _apply_nvd(cve, vulns[0]["cve"])
                    await asyncio.sleep(nvd_sleep)
                except Exception as exc:
                    logger.debug("NVD lookup failed", cve_id=canonical, error=str(exc))

    await session.flush()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _apply_osv(cve: Cve, data: dict) -> None:
    """Write OSV individual vuln data into the Cve ORM object."""
    # Severity — prefer text labels, skip CVSS vectors
    if not cve.severity or cve.severity == "Unknown":
        for entry in (data.get("severity") or []):
            label = entry.get("score", "").lower()
            if label in _SEVERITY_TEXT:
                cve.severity = _SEVERITY_TEXT[label]
                break

    # Description (OSV uses "details" for the full text)
    if not cve.description:
        cve.description = data.get("details") or data.get("summary") or ""

    # Published date
    if not cve.published_at and data.get("published"):
        cve.published_at = _parse_dt(data["published"])


def _apply_nvd(cve: Cve, nvd_cve: dict) -> None:
    """Write NVD CVE data into the Cve ORM object."""
    metrics = nvd_cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if not entries:
            continue
        try:
            score = float(entries[0]["cvssData"]["baseScore"])
            cve.cvss_score = score
            if not cve.severity or cve.severity == "Unknown":
                if score >= 9.0:
                    cve.severity = "Critical"
                elif score >= 7.0:
                    cve.severity = "High"
                elif score >= 4.0:
                    cve.severity = "Medium"
                else:
                    cve.severity = "Low"
        except (KeyError, TypeError, ValueError):
            pass
        break

    if not cve.description:
        for desc in nvd_cve.get("descriptions", []):
            if desc.get("lang") == "en":
                cve.description = desc.get("value", "")
                break

    if not cve.published_at and nvd_cve.get("published"):
        cve.published_at = _parse_dt(nvd_cve["published"])


def _parse_dt(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None
