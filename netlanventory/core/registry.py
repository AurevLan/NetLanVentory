"""Module registry — auto-discovers and registers all BaseModule subclasses."""

import importlib
import importlib.util
import pkgutil
from pathlib import Path
from typing import TYPE_CHECKING

from netlanventory.core.logging import get_logger

if TYPE_CHECKING:
    from netlanventory.modules.base import BaseModule

logger = get_logger(__name__)


class ModuleRegistry:
    """Singleton registry holding all discovered modules.

    Usage:
        registry = ModuleRegistry()
        registry.discover()
        module_cls = registry.get("arp_sweep")
    """

    def __init__(self) -> None:
        self._modules: dict[str, type["BaseModule"]] = {}
        self._discovered = False

    def discover(self, package: str = "netlanventory.modules") -> None:
        """Scan the modules package and register all concrete BaseModule subclasses."""
        from netlanventory.modules.base import BaseModule  # avoid circular import

        modules_path = Path(__file__).parent.parent / "modules"

        for module_info in pkgutil.iter_modules([str(modules_path)]):
            if module_info.name == "base":
                continue  # skip the abstract base

            full_name = f"{package}.{module_info.name}"
            try:
                mod = importlib.import_module(full_name)
            except Exception as exc:
                logger.warning("Failed to import module file", name=full_name, error=str(exc))
                continue

            for attr_name in dir(mod):
                obj = getattr(mod, attr_name)
                if (
                    isinstance(obj, type)
                    and issubclass(obj, BaseModule)
                    and obj is not BaseModule
                    and not getattr(obj, "__abstractmethods__", None)
                ):
                    slug = obj.metadata.name
                    if slug in self._modules:
                        logger.warning(
                            "Duplicate module name — skipping",
                            name=slug,
                            existing=self._modules[slug].__name__,
                            new=obj.__name__,
                        )
                        continue
                    self._modules[slug] = obj
                    logger.debug("Registered module", name=slug, cls=obj.__name__)

        self._discovered = True
        logger.info("Module discovery complete", count=len(self._modules))

    def get(self, name: str) -> type["BaseModule"] | None:
        return self._modules.get(name)

    def all(self) -> dict[str, type["BaseModule"]]:
        return dict(self._modules)

    def names(self) -> list[str]:
        return list(self._modules.keys())

    @property
    def is_discovered(self) -> bool:
        return self._discovered


# Global singleton
_registry: ModuleRegistry | None = None


def get_registry() -> ModuleRegistry:
    global _registry
    if _registry is None:
        _registry = ModuleRegistry()
        _registry.discover()
    return _registry
