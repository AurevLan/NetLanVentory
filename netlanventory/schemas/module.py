"""Schemas for Module metadata."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from netlanventory.modules.base import ModuleCategory


class ModuleOut(BaseModel):
    name: str
    display_name: str
    version: str
    category: ModuleCategory
    description: str
    author: str
    requires_root: bool
    options_schema: dict[str, Any]


class ModuleList(BaseModel):
    total: int
    items: list[ModuleOut]
