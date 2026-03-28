"""Notification config router — manage webhook alerting configurations."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db, require_admin
from netlanventory.core.logging import get_logger
from netlanventory.models.notification_config import NotificationConfig

logger = get_logger(__name__)

router = APIRouter(prefix="/admin/notifications", tags=["notifications"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
AdminDep = Annotated[object, Depends(require_admin)]

_ALLOWED_EVENTS = {
    "cve_critical",
    "sla_breach",
    "port_change",
    "asset_offline",
    "scan_done",
}


# ── Pydantic schemas ──────────────────────────────────────────────────────────


class NotificationConfigOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    type: str
    url: str | None
    enabled: bool
    events: list | None
    created_at: datetime
    updated_at: datetime


class NotificationConfigCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    type: str = Field(default="webhook", pattern="^(webhook|email)$")
    url: str | None = None
    enabled: bool = True
    events: list[str] = Field(default_factory=list)
    secret: str | None = None

    def validate_events(self) -> None:
        unknown = set(self.events) - _ALLOWED_EVENTS
        if unknown:
            raise ValueError(f"Unknown events: {unknown}. Allowed: {_ALLOWED_EVENTS}")


class NotificationConfigUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    type: str | None = Field(default=None, pattern="^(webhook|email)$")
    url: str | None = None
    enabled: bool | None = None
    events: list[str] | None = None
    secret: str | None = None


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("", response_model=list[NotificationConfigOut])
async def list_notification_configs(db: DbDep, _admin: AdminDep) -> list[NotificationConfig]:
    """List all notification configurations."""
    result = await db.execute(
        select(NotificationConfig).order_by(NotificationConfig.name)
    )
    return list(result.scalars().all())


@router.post("", response_model=NotificationConfigOut, status_code=status.HTTP_201_CREATED)
async def create_notification_config(
    body: NotificationConfigCreate,
    db: DbDep,
    _admin: AdminDep,
) -> NotificationConfig:
    """Create a new notification configuration."""
    unknown_events = set(body.events) - _ALLOWED_EVENTS
    if unknown_events:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown events: {sorted(unknown_events)}. Allowed: {sorted(_ALLOWED_EVENTS)}",
        )

    config = NotificationConfig(
        name=body.name,
        type=body.type,
        url=body.url,
        enabled=body.enabled,
        events=body.events,
        secret=body.secret,
    )
    db.add(config)
    await db.flush()
    await db.commit()
    await db.refresh(config)
    return config


@router.put("/{config_id}", response_model=NotificationConfigOut)
async def update_notification_config(
    config_id: uuid.UUID,
    body: NotificationConfigUpdate,
    db: DbDep,
    _admin: AdminDep,
) -> NotificationConfig:
    """Update an existing notification configuration."""
    config = (
        await db.execute(
            select(NotificationConfig).where(NotificationConfig.id == config_id)
        )
    ).scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Config not found")

    if body.events is not None:
        unknown_events = set(body.events) - _ALLOWED_EVENTS
        if unknown_events:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unknown events: {sorted(unknown_events)}",
            )
        config.events = body.events
    if body.name is not None:
        config.name = body.name
    if body.type is not None:
        config.type = body.type
    if body.url is not None:
        config.url = body.url
    if body.enabled is not None:
        config.enabled = body.enabled
    if body.secret is not None:
        config.secret = body.secret

    await db.commit()
    await db.refresh(config)
    return config


@router.delete("/{config_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_notification_config(
    config_id: uuid.UUID,
    db: DbDep,
    _admin: AdminDep,
) -> None:
    """Delete a notification configuration."""
    config = (
        await db.execute(
            select(NotificationConfig).where(NotificationConfig.id == config_id)
        )
    ).scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Config not found")
    await db.delete(config)
    await db.commit()


@router.post("/{config_id}/test", status_code=status.HTTP_200_OK)
async def test_notification_config(
    config_id: uuid.UUID,
    db: DbDep,
    _admin: AdminDep,
) -> dict:
    """Send a test webhook payload to a notification config."""
    import hashlib
    import hmac
    import json
    from datetime import timezone

    config = (
        await db.execute(
            select(NotificationConfig).where(NotificationConfig.id == config_id)
        )
    ).scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Config not found")
    if not config.url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="No URL configured"
        )

    payload = {
        "event": "test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": "This is a test notification from NetLanVentory",
        "config_id": str(config.id),
        "config_name": config.name,
    }
    body_bytes = json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "X-NLV-Event": "test",
    }
    if config.secret:
        sig = hmac.new(config.secret.encode(), body_bytes, hashlib.sha256).hexdigest()
        headers["X-NLV-Signature"] = f"sha256={sig}"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(config.url, content=body_bytes, headers=headers)
        logger.info("Test webhook sent", config_id=str(config_id), status_code=resp.status_code)
        return {"status": "sent", "http_status": resp.status_code, "url": config.url}
    except Exception as exc:  # noqa: BLE001
        logger.warning("Test webhook failed", config_id=str(config_id), error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Webhook delivery failed: {exc}",
        )
