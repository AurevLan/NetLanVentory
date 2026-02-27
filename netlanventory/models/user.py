"""User model — local accounts and OIDC-federated identities."""

from __future__ import annotations

from sqlalchemy import Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from netlanventory.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # None for OIDC-only accounts
    hashed_password: Mapped[str | None] = mapped_column(Text, nullable=True)

    # "admin" | "user"
    role: Mapped[str] = mapped_column(String(20), nullable=False, server_default="user")

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # ── OIDC future fields ───────────────────────────────────────────────────
    # "local" | "oidc"
    auth_provider: Mapped[str] = mapped_column(String(20), nullable=False, default="local")
    # Subject claim from the OIDC ID token (unique per provider)
    provider_sub: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<User {self.email!r} role={self.role!r} provider={self.auth_provider!r}>"
