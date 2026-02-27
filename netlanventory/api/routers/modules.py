"""Modules API router — list available scanning modules."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from netlanventory.api.dependencies import get_module_registry
from netlanventory.core.registry import ModuleRegistry
from netlanventory.schemas.module import ModuleList, ModuleOut

router = APIRouter(prefix="/modules", tags=["modules"])

RegistryDep = Annotated[ModuleRegistry, Depends(get_module_registry)]


@router.get("", response_model=ModuleList)
async def list_modules(registry: RegistryDep) -> ModuleList:
    modules = registry.all()
    items = [
        ModuleOut(
            name=cls.metadata.name,
            display_name=cls.metadata.display_name,
            version=cls.metadata.version,
            category=cls.metadata.category,
            description=cls.metadata.description,
            author=cls.metadata.author,
            requires_root=cls.metadata.requires_root,
            options_schema=cls.metadata.options_schema,
        )
        for cls in modules.values()
    ]
    return ModuleList(total=len(items), items=items)


@router.get("/{name}", response_model=ModuleOut)
async def get_module(name: str, registry: RegistryDep) -> ModuleOut:
    cls = registry.get(name)
    if not cls:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Module {name!r} not found. Available: {registry.names()}",
        )
    return ModuleOut(
        name=cls.metadata.name,
        display_name=cls.metadata.display_name,
        version=cls.metadata.version,
        category=cls.metadata.category,
        description=cls.metadata.description,
        author=cls.metadata.author,
        requires_root=cls.metadata.requires_root,
        options_schema=cls.metadata.options_schema,
    )
