"""Tests for the module registry and base module contract."""

import pytest

from netlanventory.core.registry import ModuleRegistry
from netlanventory.modules.base import BaseModule, ModuleCategory, ModuleMetadata


def test_registry_discovers_modules():
    reg = ModuleRegistry()
    reg.discover()
    names = reg.names()

    assert "arp_sweep" in names
    assert "port_scanner" in names
    assert "service_detector" in names
    assert "os_fingerprint" in names


def test_registry_get_returns_class():
    reg = ModuleRegistry()
    reg.discover()
    cls = reg.get("arp_sweep")
    assert cls is not None
    assert issubclass(cls, BaseModule)


def test_registry_get_unknown_returns_none():
    reg = ModuleRegistry()
    reg.discover()
    assert reg.get("does_not_exist") is None


def test_module_metadata_fields():
    reg = ModuleRegistry()
    reg.discover()
    for name, cls in reg.all().items():
        meta = cls.metadata
        assert isinstance(meta.name, str) and meta.name
        assert isinstance(meta.display_name, str)
        assert isinstance(meta.category, ModuleCategory)
        assert isinstance(meta.requires_root, bool)
        assert isinstance(meta.options_schema, dict)


def test_concrete_module_without_metadata_raises():
    with pytest.raises(TypeError, match="metadata"):
        class BadModule(BaseModule):
            async def run(self, session, options):
                return {}
