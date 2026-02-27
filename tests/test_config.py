"""Tests for core/config.py."""

from netlanventory.core.config import Settings


def test_default_settings():
    s = Settings()
    assert s.app_port == 8000
    assert s.app_host == "0.0.0.0"
    assert s.log_level == "INFO"
    assert "netlanventory" in s.database_url


def test_sync_db_url():
    s = Settings()
    assert "+asyncpg" not in s.sync_database_url
    assert "postgresql" in s.sync_database_url
