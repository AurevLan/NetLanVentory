"""AI-Triage API (innovation #3) — feature-flagged.

Two endpoints:
  - GET /triage/{cve_id}/asset/{asset_id} — returns cached or fresh recommendation
  - POST /triage/{cve_id}/asset/{asset_id}/refresh — admin: force refresh

When `AI_TRIAGE_ENABLED=False` (default), the GET returns 503 to make the
disabled state explicit. Admins can still inspect the existing cache via
the model directly through `/admin` if needed.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_current_active_user, get_db, require_admin
from netlanventory.core.ai_triage import (
    PROMPT_VERSION,
    build_inputs_from_db,
    get_or_create_recommendation,
)
from netlanventory.core.logging import get_logger
from netlanventory.models.triage_recommendation import TriageRecommendation, TriageUrgency

logger = get_logger(__name__)

router = APIRouter(prefix="/triage", tags=["triage"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]
AdminDep = Annotated[object, Depends(require_admin)]


def _enabled() -> bool:
    return os.environ.get("AI_TRIAGE_ENABLED", "false").lower() in ("1", "true", "yes")


class TriageOut(BaseModel):
    cve_id: str
    asset_id: uuid.UUID
    urgency: TriageUrgency
    one_liner: str
    top_factors: list[str]
    model_id: str
    prompt_version: str
    cached_until: datetime
    tokens_in: int | None = None
    tokens_out: int | None = None


def _to_out(rec: TriageRecommendation) -> TriageOut:
    return TriageOut(
        cve_id=rec.cve_id,
        asset_id=rec.asset_id,
        urgency=rec.urgency,
        one_liner=rec.one_liner,
        top_factors=list(rec.top_factors or []),
        model_id=rec.model_id,
        prompt_version=rec.prompt_version,
        cached_until=rec.cached_until,
        tokens_in=rec.tokens_in,
        tokens_out=rec.tokens_out,
    )


@router.get("/{cve_id}/asset/{asset_id}", response_model=TriageOut)
async def get_recommendation(
    cve_id: str, asset_id: uuid.UUID, db: DbDep, _user: UserDep,
) -> TriageOut:
    if not _enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI triage disabled. Set AI_TRIAGE_ENABLED=true to enable.",
        )
    inputs = await build_inputs_from_db(db, asset_id, cve_id)
    if inputs is None:
        raise HTTPException(status_code=404, detail="Asset or CVE not found")
    rec = await get_or_create_recommendation(db, inputs)
    if rec is None:
        raise HTTPException(
            status_code=502,
            detail="LLM provider unavailable or daily token budget exceeded",
        )
    await db.commit()
    return _to_out(rec)


@router.post("/{cve_id}/asset/{asset_id}/refresh", response_model=TriageOut)
async def refresh_recommendation(
    cve_id: str, asset_id: uuid.UUID, db: DbDep, _admin: AdminDep,
) -> TriageOut:
    """Admin-only: force a fresh LLM call (bypasses TTL but still cached after)."""
    if not _enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI triage disabled. Set AI_TRIAGE_ENABLED=true to enable.",
        )
    inputs = await build_inputs_from_db(db, asset_id, cve_id)
    if inputs is None:
        raise HTTPException(status_code=404, detail="Asset or CVE not found")
    # Force expiry to trigger recompute
    from sqlalchemy import select
    existing = (
        await db.execute(
            select(TriageRecommendation).where(
                TriageRecommendation.cve_id == cve_id,
                TriageRecommendation.asset_id == asset_id,
                TriageRecommendation.prompt_version == PROMPT_VERSION,
            )
        )
    ).scalar_one_or_none()
    if existing:
        existing.input_hash = "stale"  # forces miss on next compute
    rec = await get_or_create_recommendation(db, inputs)
    if rec is None:
        raise HTTPException(status_code=502, detail="LLM call failed")
    await db.commit()
    return _to_out(rec)
