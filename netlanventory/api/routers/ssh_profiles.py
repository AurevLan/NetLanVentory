"""Admin router — SSH credential profiles (admin only)."""

from __future__ import annotations

import time
import uuid
from typing import Annotated

import asyncssh
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db, require_admin
from netlanventory.core.crypto import decrypt, encrypt
from netlanventory.core.logging import get_logger
from netlanventory.models.ssh_profile import SshProfile
from netlanventory.schemas.ssh_profile import SshProfileCreate, SshProfileOut, SshProfileUpdate

router = APIRouter(prefix="/admin/ssh-profiles", tags=["admin"])
logger = get_logger(__name__)

DbDep = Annotated[AsyncSession, Depends(get_db)]


# ── List ──────────────────────────────────────────────────────────────────────

@router.get("", response_model=list[SshProfileOut],
            dependencies=[Depends(require_admin)])
async def list_ssh_profiles(db: DbDep) -> list[SshProfileOut]:
    """Return all SSH credential profiles."""
    result = await db.execute(select(SshProfile).order_by(SshProfile.name))
    profiles = result.scalars().all()
    return [SshProfileOut.from_orm_safe(p) for p in profiles]


# ── Create ────────────────────────────────────────────────────────────────────

@router.post("", response_model=SshProfileOut, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_admin)])
async def create_ssh_profile(payload: SshProfileCreate, db: DbDep) -> SshProfileOut:
    """Create a new SSH credential profile."""
    profile = SshProfile(
        name=payload.name,
        ssh_user=payload.ssh_user,
        ssh_port=payload.ssh_port,
    )
    if payload.ssh_password:
        profile.ssh_password_enc = encrypt(payload.ssh_password)
    if payload.ssh_private_key:
        profile.ssh_private_key_enc = encrypt(payload.ssh_private_key)

    db.add(profile)
    try:
        await db.flush()
        await db.refresh(profile)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An SSH profile named {payload.name!r} already exists.",
        )

    logger.info("SSH profile created", profile_id=str(profile.id), name=profile.name)
    return SshProfileOut.from_orm_safe(profile)


# ── Get one ───────────────────────────────────────────────────────────────────

@router.get("/{profile_id}", response_model=SshProfileOut,
            dependencies=[Depends(require_admin)])
async def get_ssh_profile(profile_id: uuid.UUID, db: DbDep) -> SshProfileOut:
    """Return a single SSH credential profile."""
    profile = await _get_or_404(profile_id, db)
    return SshProfileOut.from_orm_safe(profile)


# ── Update ────────────────────────────────────────────────────────────────────

@router.patch("/{profile_id}", response_model=SshProfileOut,
              dependencies=[Depends(require_admin)])
async def update_ssh_profile(
    profile_id: uuid.UUID, payload: SshProfileUpdate, db: DbDep
) -> SshProfileOut:
    """Update an SSH credential profile. Omitted fields are left unchanged."""
    profile = await _get_or_404(profile_id, db)

    if payload.name is not None:
        profile.name = payload.name
    if payload.ssh_user is not None:
        if not payload.ssh_user:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="ssh_user cannot be empty.",
            )
        profile.ssh_user = payload.ssh_user
    if payload.ssh_port is not None:
        profile.ssh_port = payload.ssh_port

    # Credential handling: None = keep; "" = clear; non-empty = overwrite
    if payload.ssh_password is not None:
        profile.ssh_password_enc = encrypt(payload.ssh_password) if payload.ssh_password else None
    if payload.ssh_private_key is not None:
        profile.ssh_private_key_enc = (
            encrypt(payload.ssh_private_key) if payload.ssh_private_key else None
        )

    try:
        await db.flush()
        await db.refresh(profile)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An SSH profile named {payload.name!r} already exists.",
        )

    logger.info("SSH profile updated", profile_id=str(profile.id), name=profile.name)
    return SshProfileOut.from_orm_safe(profile)


# ── Delete ────────────────────────────────────────────────────────────────────

@router.delete("/{profile_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(require_admin)])
async def delete_ssh_profile(profile_id: uuid.UUID, db: DbDep) -> None:
    """Delete an SSH credential profile. Assets that used it will have their
    ssh_profile_id set to NULL (ON DELETE SET NULL)."""
    profile = await _get_or_404(profile_id, db)
    await db.delete(profile)
    await db.flush()
    logger.info("SSH profile deleted", profile_id=str(profile_id))


# ── Helper ────────────────────────────────────────────────────────────────────

async def _get_or_404(profile_id: uuid.UUID, db: AsyncSession) -> SshProfile:
    result = await db.execute(select(SshProfile).where(SshProfile.id == profile_id))
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="SSH profile not found"
        )
    return profile


# ── Test credentials ──────────────────────────────────────────────────────────

class SshTestRequest(BaseModel):
    host: str


class SshTestResult(BaseModel):
    success: bool
    latency_ms: int | None = None
    error: str | None = None


@router.post("/{profile_id}/test", response_model=SshTestResult,
             dependencies=[Depends(require_admin)])
async def test_ssh_profile(
    profile_id: uuid.UUID,
    payload: SshTestRequest,
    db: DbDep,
) -> SshTestResult:
    """Attempt to connect to a host using the SSH profile credentials (5s timeout)."""
    profile = await _get_or_404(profile_id, db)

    password = decrypt(profile.ssh_password_enc) if profile.ssh_password_enc else None
    private_key_str = decrypt(profile.ssh_private_key_enc) if profile.ssh_private_key_enc else None

    connect_kwargs: dict = {
        "host": payload.host,
        "port": profile.ssh_port or 22,
        "username": profile.ssh_user,
        "known_hosts": None,
        "connect_timeout": 5,
    }
    if password:
        connect_kwargs["password"] = password
    if private_key_str:
        try:
            connect_kwargs["client_keys"] = [asyncssh.import_private_key(private_key_str)]
        except Exception:
            pass

    t0 = time.monotonic()
    try:
        async with asyncssh.connect(**connect_kwargs):
            latency_ms = int((time.monotonic() - t0) * 1000)
            return SshTestResult(success=True, latency_ms=latency_ms)
    except Exception as exc:
        latency_ms = int((time.monotonic() - t0) * 1000)
        return SshTestResult(success=False, latency_ms=latency_ms, error=str(exc))
