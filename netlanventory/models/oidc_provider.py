"""OidcProvider — OIDC connector configuration stored in the database.

Only one provider row is expected (upserted on save).
The client_secret is stored in plaintext; encrypt at rest if needed.
"""

from __future__ import annotations

from sqlalchemy import Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from netlanventory.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class OidcProvider(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "oidc_providers"

    # Display name shown on the login button
    name: Mapped[str] = mapped_column(String(100), nullable=False, default="SSO")

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # OIDC discovery base URL (e.g. https://accounts.google.com)
    issuer_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Stored plaintext — encrypt at rest for production hardening
    client_secret: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Space-separated scopes (e.g. "openid email profile")
    scopes: Mapped[str] = mapped_column(
        String(255), nullable=False, default="openid email profile"
    )

    # Automatically create a local user record on first OIDC login
    auto_create_users: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Role assigned to auto-created users ("user" | "admin")
    default_role: Mapped[str] = mapped_column(String(20), nullable=False, default="user")

    def __repr__(self) -> str:
        return f"<OidcProvider name={self.name!r} enabled={self.enabled}>"
