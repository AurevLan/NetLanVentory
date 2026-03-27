"""Saved filters router — persist and retrieve view filter presets."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_current_active_user, get_db
from netlanventory.core.logging import get_logger
from netlanventory.models.saved_filter import SavedFilter

logger = get_logger(__name__)
router = APIRouter(prefix="/saved-filters", tags=["saved-filters"])

DbDep = Annotated[AsyncSession, Depends(get_db)]


class SavedFilterCreate(BaseModel):
    name: str
    view: str  # assets | cves | topology | timeline
    filters: dict


class SavedFilterResponse(BaseModel):
    id: str
    name: str
    view: str
    filters: dict
    created_at: str | None


@router.get("", response_model=list[SavedFilterResponse])
async def list_saved_filters(
    db: DbDep,
    current_user: Annotated[object, Depends(get_current_active_user)],
    view: str | None = Query(None, description="Filter by view name"),
) -> list[SavedFilterResponse]:
    """List saved filters for the current user."""
    user_id = str(current_user.id)
    q = select(SavedFilter).where(SavedFilter.user_id == str(user_id)).order_by(SavedFilter.created_at.desc())
    if view:
        q = q.where(SavedFilter.view == view)

    rows = (await db.execute(q)).scalars().all()
    return [
        SavedFilterResponse(
            id=str(r.id),
            name=r.name,
            view=r.view,
            filters=r.filters or {},
            created_at=r.created_at.isoformat() if r.created_at else None,
        )
        for r in rows
    ]


@router.post("", response_model=SavedFilterResponse, status_code=201)
async def create_saved_filter(
    body: SavedFilterCreate,
    db: DbDep,
    current_user: Annotated[object, Depends(get_current_active_user)],
) -> SavedFilterResponse:
    """Save a filter preset."""
    user_id = str(current_user.id)

    sf = SavedFilter(
        user_id=user_id,
        name=body.name,
        view=body.view,
        filters=body.filters,
    )
    db.add(sf)
    await db.commit()
    await db.refresh(sf)

    return SavedFilterResponse(
        id=str(sf.id),
        name=sf.name,
        view=sf.view,
        filters=sf.filters or {},
        created_at=sf.created_at.isoformat() if sf.created_at else None,
    )


@router.delete("/{filter_id}", status_code=204)
async def delete_saved_filter(
    filter_id: str,
    db: DbDep,
    current_user: Annotated[object, Depends(get_current_active_user)],
) -> None:
    """Delete a saved filter."""
    try:
        fid = uuid.UUID(filter_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid filter_id")

    user_id = str(current_user.id)
    sf = (await db.execute(
        select(SavedFilter).where(SavedFilter.id == fid, SavedFilter.user_id == user_id)
    )).scalar_one_or_none()

    if not sf:
        raise HTTPException(status_code=404, detail="Filter not found")

    await db.delete(sf)
    await db.commit()
