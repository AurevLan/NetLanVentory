"""MITRE ATT&CK enrichment — map CVEs to ATT&CK techniques.

Downloads the MITRE ATT&CK Enterprise STIX bundle and builds an index
of CVE → list of techniques. Results are stored in cves.mitre_techniques
as a JSONB array of {technique_id, technique_name, tactic} dicts.

The STIX bundle is cached locally to avoid repeated downloads.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.core.logging import get_logger
from netlanventory.models.cve import Cve

logger = get_logger(__name__)

_MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
_CACHE_PATH = Path("/tmp/mitre_enterprise_attack.json")  # noqa: S108
_CACHE_MAX_AGE_HOURS = 24

# CVE-YYYY-NNNNN pattern
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# Tactic short-name → display name
_TACTIC_NAMES: dict[str, str] = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command & Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
}


async def _load_stix_bundle() -> dict | None:
    """Load the MITRE ATT&CK STIX bundle, using local cache when fresh."""
    if _CACHE_PATH.exists():
        age_hours = (datetime.now().timestamp() - _CACHE_PATH.stat().st_mtime) / 3600
        if age_hours < _CACHE_MAX_AGE_HOURS:
            try:
                return json.loads(_CACHE_PATH.read_text())
            except Exception:
                pass

    logger.info("Downloading MITRE ATT&CK STIX bundle")
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get(_MITRE_STIX_URL)
            resp.raise_for_status()
            bundle = resp.json()
            _CACHE_PATH.write_text(json.dumps(bundle))
            logger.info("MITRE ATT&CK STIX bundle cached", path=str(_CACHE_PATH))
            return bundle
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to download MITRE ATT&CK bundle", error=str(exc))
        return None


def _build_cve_index(bundle: dict) -> dict[str, list[dict]]:
    """Build a mapping of CVE ID → list of ATT&CK technique dicts."""
    index: dict[str, list[dict]] = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        technique_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                break
        if not technique_id:
            continue

        technique_name = obj.get("name", "")
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                short = phase.get("phase_name", "")
                tactics.append(_TACTIC_NAMES.get(short, short.replace("-", " ").title()))

        # Find CVEs referenced in external_references
        for ref in obj.get("external_references", []):
            cve_matches = _CVE_RE.findall(ref.get("external_id", "") + ref.get("url", ""))
            for cve_id in cve_matches:
                cve_upper = cve_id.upper()
                if cve_upper not in index:
                    index[cve_upper] = []
                index[cve_upper].append({
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "tactics": tactics,
                })

    logger.info("MITRE ATT&CK index built", techniques=len(index))
    return index


async def enrich_mitre(cve_ids: list[str], db: AsyncSession) -> None:
    """Look up CVEs in the MITRE ATT&CK index and update the DB rows."""
    if not cve_ids:
        return

    bundle = await _load_stix_bundle()
    if not bundle:
        return

    index = _build_cve_index(bundle)
    if not index:
        return

    result = await db.execute(select(Cve).where(Cve.cve_id.in_(cve_ids)))
    cves = result.scalars().all()

    updated = 0
    now = datetime.now(timezone.utc)
    for cve in cves:
        techniques = index.get(cve.cve_id.upper(), [])
        if techniques:
            cve.mitre_techniques = techniques
            cve.mitre_updated_at = now
            updated += 1

    if updated:
        await db.flush()
        logger.info("MITRE ATT&CK techniques enriched", updated=updated)


async def refresh_mitre_for_all_cves(db: AsyncSession) -> int:
    """Refresh MITRE ATT&CK techniques for all CVEs in the database."""
    result = await db.execute(select(Cve.cve_id))
    cve_ids = [row[0] for row in result.all()]
    await enrich_mitre(cve_ids, db)
    return len(cve_ids)
