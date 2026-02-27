"""Base module contract — all scanning modules must implement this interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar

from sqlalchemy.ext.asyncio import AsyncSession


class ModuleCategory(str, Enum):
    DISCOVERY = "discovery"
    PORT_SCAN = "port_scan"
    SERVICE = "service"
    OS_DETECT = "os_detect"
    CREDENTIALS = "credentials"
    SSH = "ssh"
    REST_API = "rest_api"
    WEB_SCAN = "web_scan"


@dataclass
class ModuleMetadata:
    name: str               # Unique slug (e.g. "arp_sweep")
    display_name: str       # Human-readable name
    version: str
    category: ModuleCategory
    description: str
    author: str
    requires_root: bool = False
    options_schema: dict[str, Any] = field(default_factory=dict)
    """JSON Schema describing accepted options for this module."""


class BaseModule(ABC):
    """Abstract base class for all NetLanVentory scanning modules.

    Subclass this, set the ``metadata`` class variable, and implement ``run``.
    The registry will auto-discover any concrete subclass found in
    ``netlanventory/modules/*.py``.
    """

    metadata: ClassVar[ModuleMetadata]

    @abstractmethod
    async def run(
        self,
        session: AsyncSession,
        options: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute the module.

        Args:
            session: Active async database session.
            options: User-supplied options validated against ``metadata.options_schema``.

        Returns:
            A dict with at least these keys::

                {
                    "module": str,        # metadata.name
                    "status": str,        # "success" | "error" | "partial"
                    "assets_found": int,
                    "details": {...},     # Module-specific payload
                }
        """
        ...

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Concrete subclasses must declare metadata
        if not getattr(cls, "__abstractmethods__", None):
            if not hasattr(cls, "metadata"):
                raise TypeError(
                    f"Module {cls.__name__} must define a 'metadata' class variable."
                )
