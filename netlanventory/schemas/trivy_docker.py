"""Schemas for TrivyDockerReport."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class TrivyDockerReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    status: str
    containers_found: int
    images_scanned: int
    cves_found: int
    error_msg: str | None
    created_at: datetime
    updated_at: datetime
