"""Ticket integration router — Jira and ServiceNow."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db
from netlanventory.core.logging import get_logger
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve
from netlanventory.models.ticket_config import TicketConfig

try:
    import httpx as _httpx
    _httpx_available = True
except ImportError:
    _httpx_available = False

logger = get_logger(__name__)
router = APIRouter(prefix="/tickets", tags=["tickets"])

DbDep = Annotated[AsyncSession, Depends(get_db)]


class TicketConfigCreate(BaseModel):
    name: str
    type: str  # jira | servicenow
    base_url: str
    api_token: str
    project_key: str | None = None
    username: str | None = None


class TicketConfigResponse(BaseModel):
    id: str
    name: str
    type: str
    base_url: str
    project_key: str | None
    username: str | None
    enabled: bool


class CreateTicketRequest(BaseModel):
    config_id: str
    asset_cve_id: str
    summary: str | None = None
    description: str | None = None
    priority: str = "Medium"


class CreateTicketResponse(BaseModel):
    ticket_id: str
    ticket_url: str
    asset_cve_id: str


def _encrypt_token(token: str) -> str:
    """Encrypt API token using application Fernet key."""
    from netlanventory.core.crypto import encrypt
    return encrypt(token)


def _decrypt_token(enc: str) -> str:
    """Decrypt API token."""
    from netlanventory.core.crypto import decrypt
    return decrypt(enc)


@router.get("/configs", response_model=list[TicketConfigResponse])
async def list_configs(db: DbDep) -> list[TicketConfigResponse]:
    rows = (await db.execute(select(TicketConfig).order_by(TicketConfig.name))).scalars().all()
    return [
        TicketConfigResponse(
            id=str(r.id),
            name=r.name,
            type=r.type,
            base_url=r.base_url,
            project_key=r.project_key,
            username=r.username,
            enabled=r.enabled,
        )
        for r in rows
    ]


@router.post("/configs", response_model=TicketConfigResponse, status_code=201)
async def create_config(body: TicketConfigCreate, db: DbDep) -> TicketConfigResponse:
    if body.type not in ("jira", "servicenow"):
        raise HTTPException(status_code=400, detail="type must be 'jira' or 'servicenow'")

    config = TicketConfig(
        name=body.name,
        type=body.type,
        base_url=body.base_url.rstrip("/"),
        api_token_enc=_encrypt_token(body.api_token),
        project_key=body.project_key,
        username=body.username,
        enabled=True,
    )
    db.add(config)
    await db.commit()
    await db.refresh(config)

    return TicketConfigResponse(
        id=str(config.id),
        name=config.name,
        type=config.type,
        base_url=config.base_url,
        project_key=config.project_key,
        username=config.username,
        enabled=config.enabled,
    )


@router.delete("/configs/{config_id}", status_code=204)
async def delete_config(config_id: str, db: DbDep) -> None:
    try:
        cid = uuid.UUID(config_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid config_id")

    config = (await db.execute(select(TicketConfig).where(TicketConfig.id == cid))).scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=404, detail="Config not found")

    await db.delete(config)
    await db.commit()


@router.post("/create", response_model=CreateTicketResponse, status_code=201)
async def create_ticket(body: CreateTicketRequest, db: DbDep) -> CreateTicketResponse:
    """Create a ticket in Jira or ServiceNow for a CVE finding."""
    if not _httpx_available:
        raise HTTPException(status_code=501, detail="httpx not installed")

    try:
        cid = uuid.UUID(body.config_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid config_id")

    config = (await db.execute(select(TicketConfig).where(TicketConfig.id == cid))).scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=404, detail="Ticket config not found")

    try:
        acve_id = uuid.UUID(body.asset_cve_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid asset_cve_id")

    asset_cve = (await db.execute(
        select(AssetCve).join(Cve, AssetCve.cve_id == Cve.id).where(AssetCve.id == acve_id)
    )).scalar_one_or_none()
    if not asset_cve:
        raise HTTPException(status_code=404, detail="AssetCve not found")

    cve = (await db.execute(select(Cve).where(Cve.id == asset_cve.cve_id))).scalar_one_or_none()

    summary = body.summary or f"Security vulnerability: {cve.cve_id if cve else 'Unknown CVE'}"
    description = body.description or (
        f"CVE: {cve.cve_id if cve else 'N/A'}\n"
        f"Severity: {cve.severity if cve else 'N/A'}\n"
        f"CVSS: {cve.cvss_score if cve else 'N/A'}\n"
        f"Description: {cve.description[:500] if cve and cve.description else 'N/A'}\n\n"
        "Please remediate as soon as possible."
    )

    api_token = _decrypt_token(config.api_token_enc)
    ticket_id, ticket_url = await _create_ticket_external(config, api_token, summary, description, body.priority)

    # Persist ticket reference
    asset_cve.ticket_id = ticket_id
    asset_cve.ticket_url = ticket_url
    await db.commit()

    return CreateTicketResponse(
        ticket_id=ticket_id,
        ticket_url=ticket_url,
        asset_cve_id=body.asset_cve_id,
    )


async def _create_ticket_external(config: TicketConfig, api_token: str, summary: str, description: str, priority: str) -> tuple[str, str]:
    """Call external API to create a ticket. Returns (ticket_id, ticket_url)."""
    if config.type == "jira":
        return await _create_jira_ticket(config, api_token, summary, description, priority)
    elif config.type == "servicenow":
        return await _create_servicenow_ticket(config, api_token, summary, description, priority)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown ticket type: {config.type}")


async def _create_jira_ticket(config: TicketConfig, api_token: str, summary: str, description: str, priority: str) -> tuple[str, str]:
    import base64
    auth = base64.b64encode(f"{config.username}:{api_token}".encode()).decode()

    payload = {
        "fields": {
            "project": {"key": config.project_key or "SEC"},
            "summary": summary,
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{"type": "paragraph", "content": [{"type": "text", "text": description}]}],
            },
            "issuetype": {"name": "Bug"},
            "priority": {"name": priority},
        }
    }

    async with _httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{config.base_url}/rest/api/3/issue",
            json=payload,
            headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
        )
        if resp.status_code not in (200, 201):
            raise HTTPException(status_code=502, detail=f"Jira API error: {resp.status_code} {resp.text[:200]}")

        data = resp.json()
        ticket_id = data["key"]
        ticket_url = f"{config.base_url}/browse/{ticket_id}"
        return ticket_id, ticket_url


async def _create_servicenow_ticket(config: TicketConfig, api_token: str, summary: str, description: str, priority: str) -> tuple[str, str]:
    priority_map = {"Critical": "1", "High": "2", "Medium": "3", "Low": "4"}
    sn_priority = priority_map.get(priority, "3")

    payload = {
        "short_description": summary,
        "description": description,
        "priority": sn_priority,
        "category": "Security",
    }

    async with _httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{config.base_url}/api/now/table/incident",
            json=payload,
            headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json", "Accept": "application/json"},
        )
        if resp.status_code not in (200, 201):
            raise HTTPException(status_code=502, detail=f"ServiceNow API error: {resp.status_code} {resp.text[:200]}")

        data = resp.json().get("result", {})
        ticket_id = data.get("number", data.get("sys_id", "UNKNOWN"))
        ticket_url = f"{config.base_url}/nav_to.do?uri=incident.do?sys_id={data.get('sys_id', '')}"
        return ticket_id, ticket_url
