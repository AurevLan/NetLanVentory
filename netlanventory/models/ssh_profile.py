"""SshProfile — reusable SSH credential profile stored encrypted."""

from __future__ import annotations

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class SshProfile(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "ssh_profiles"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    ssh_user: Mapped[str] = mapped_column(String(100), nullable=False)
    ssh_port: Mapped[int | None] = mapped_column(nullable=True)
    # Encrypted credentials — never returned in plain text via API
    ssh_password_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    ssh_private_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Back-reference — assets that use this profile
    assets: Mapped[list["Asset"]] = relationship(  # noqa: F821
        "Asset", back_populates="ssh_profile"
    )

    def __repr__(self) -> str:
        return f"<SshProfile name={self.name!r} user={self.ssh_user!r}>"
