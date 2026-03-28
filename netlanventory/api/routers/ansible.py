"""Ansible playbook generation router."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve

try:
    import yaml as _yaml
    _yaml_available = True
except ImportError:
    _yaml_available = False

logger = get_logger(__name__)
router = APIRouter(prefix="/ansible", tags=["ansible"])

DbDep = Annotated[AsyncSession, Depends(get_db)]

_PKG_MANAGERS = {
    "ubuntu": "apt",
    "debian": "apt",
    "fedora": "dnf",
    "centos": "yum",
    "rhel": "yum",
    "rocky": "dnf",
    "almalinux": "dnf",
    "suse": "zypper",
    "opensuse": "zypper",
}


def _detect_pkg_manager(os_name: str | None, os_family: str | None) -> str:
    text = ((os_name or "") + " " + (os_family or "")).lower()
    for key, mgr in _PKG_MANAGERS.items():
        if key in text:
            return mgr
    return "apt"  # default


def _cve_to_task(cve_id: str, pkg_manager: str) -> dict:
    """Build an Ansible task dict for patching a CVE."""
    task: dict = {"name": f"Apply security patch for {cve_id}"}
    if pkg_manager == "apt":
        task["ansible.builtin.apt"] = {
            "update_cache": True,
            "upgrade": "safe",
            "state": "latest",
        }
    elif pkg_manager in ("yum", "dnf"):
        task[f"ansible.builtin.{pkg_manager}"] = {
            "name": "*",
            "state": "latest",
            "security": True,
        }
    elif pkg_manager == "zypper":
        task["community.general.zypper"] = {
            "name": "*",
            "state": "latest",
            "type": "patch",
        }
    else:
        task["ansible.builtin.command"] = {
            "cmd": "echo 'Unsupported package manager — patch manually'",
            "_raw_params": "",
        }
    return task


async def _build_playbook(assets_cves: list[tuple[Asset, list[str]]], min_cvss: float) -> str:
    """Generate a YAML playbook string for the given assets and their CVE IDs."""
    if not _yaml_available:
        raise HTTPException(status_code=501, detail="pyyaml not installed")

    plays = []
    for asset, cve_ids in assets_cves:
        if not cve_ids:
            continue

        host = asset.hostname or asset.ip or str(asset.id)[:8]
        pkg_manager = _detect_pkg_manager(asset.os_name, asset.os_family)

        tasks = [
            {
                "name": "Gather facts",
                "ansible.builtin.gather_facts": {},
            }
        ]
        for cve_id in cve_ids:
            tasks.append(_cve_to_task(cve_id, pkg_manager))

        tasks.append({
            "name": "Verify no pending security updates",
            "ansible.builtin.command": {
                "_raw_params": "echo 'Patch applied for: " + ", ".join(cve_ids) + "'",
            },
            "register": "patch_result",
            "changed_when": False,
        })

        plays.append({
            "name": f"Security patches for {host}",
            "hosts": host,
            "become": True,
            "gather_facts": True,
            "vars": {
                "asset_id": str(asset.id),
                "cve_list": cve_ids,
            },
            "tasks": tasks,
        })

    if not plays:
        plays = [{"name": "No patches required", "hosts": "all", "tasks": []}]

    return _yaml.dump(plays, default_flow_style=False, allow_unicode=True, sort_keys=False)


@router.get("/playbook/{asset_id}")
async def generate_playbook(
    asset_id: str,
    db: DbDep,
    min_cvss: float = Query(0.0, ge=0.0, le=10.0, description="Minimum CVSS score"),
) -> Response:
    """Generate an Ansible playbook for a single asset."""
    try:
        aid = uuid.UUID(asset_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid asset_id")

    asset = (await db.execute(select(Asset).where(Asset.id == aid))).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    cve_q = (
        select(Cve.cve_id, Cve.cvss_score)
        .join(AssetCve, AssetCve.cve_id == Cve.id)
        .where(AssetCve.asset_id == aid, AssetCve.ack_status == "none")
    )
    if min_cvss > 0:
        cve_q = cve_q.where(Cve.cvss_score >= min_cvss)

    cve_rows = (await db.execute(cve_q)).all()
    cve_ids = [r.cve_id for r in cve_rows if r.cve_id]

    playbook_yaml = await _build_playbook([(asset, cve_ids)], min_cvss)
    filename = f"patch_{asset.hostname or asset.ip or asset_id[:8]}.yml"

    return Response(
        content=playbook_yaml,
        media_type="text/yaml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


class BulkPlaybookRequest(BaseModel):
    asset_ids: list[str]
    min_cvss: float = 0.0


@router.post("/playbook/bulk")
async def generate_bulk_playbook(body: BulkPlaybookRequest, db: DbDep) -> Response:
    """Generate a multi-host Ansible playbook for several assets."""
    if not body.asset_ids:
        raise HTTPException(status_code=400, detail="asset_ids must not be empty")

    assets_cves: list[tuple[Asset, list[str]]] = []

    for asset_id_str in body.asset_ids[:50]:  # cap at 50 hosts
        try:
            aid = uuid.UUID(asset_id_str)
        except ValueError:
            continue

        asset = (await db.execute(select(Asset).where(Asset.id == aid))).scalar_one_or_none()
        if not asset:
            continue

        cve_q = (
            select(Cve.cve_id, Cve.cvss_score)
            .join(AssetCve, AssetCve.cve_id == Cve.id)
            .where(AssetCve.asset_id == aid, AssetCve.ack_status == "none")
        )
        if body.min_cvss > 0:
            cve_q = cve_q.where(Cve.cvss_score >= body.min_cvss)

        cve_rows = (await db.execute(cve_q)).all()
        cve_ids = [r.cve_id for r in cve_rows if r.cve_id]
        assets_cves.append((asset, cve_ids))

    playbook_yaml = await _build_playbook(assets_cves, body.min_cvss)

    return Response(
        content=playbook_yaml,
        media_type="text/yaml",
        headers={"Content-Disposition": 'attachment; filename="bulk_patch.yml"'},
    )
