"""Tests for admin-restricted API endpoints.

Covers: user management, admin settings, audit logs, SSH profiles,
quota usage, sessions, notifications, compliance, EPSS/KEV stats,
reports, tickets, scheduled reports, and threat intel.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


# ── Users CRUD (admin only) ─────────────────────────────────────────────────


async def test_users_list(client):
    """GET /api/v1/users returns 200 for admin."""
    r = await client.get("/api/v1/users")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, dict)
    assert "items" in body
    assert "total" in body


async def test_users_create(client):
    """POST /api/v1/users with valid payload returns 201."""
    payload = {
        "email": "new@test.com",
        "username": "newuser",
        "password": "Test1234!@#$",
        "role": "user",
    }
    r = await client.post("/api/v1/users", json=payload)
    assert r.status_code == 201
    body = r.json()
    assert body["email"] == "new@test.com"
    assert body["username"] == "newuser"
    assert body["role"] == "user"


async def test_users_create_missing_fields(client):
    """POST /api/v1/users without email returns 422."""
    payload = {
        "username": "nomail",
        "password": "Test1234!@#$",
        "role": "user",
    }
    r = await client.post("/api/v1/users", json=payload)
    assert r.status_code == 422


async def test_users_regular_user_forbidden(user_client):
    """GET /api/v1/users with a regular user client returns 403."""
    r = await user_client.get("/api/v1/users")
    assert r.status_code == 403


# ── Admin Settings ───────────────────────────────────────────────────────────


async def test_admin_auth_settings(client):
    """GET /api/v1/admin/auth-settings returns 200."""
    r = await client.get("/api/v1/admin/auth-settings")
    assert r.status_code == 200


async def test_admin_zap_settings_get(client):
    """GET /api/v1/admin/zap-settings returns 200."""
    r = await client.get("/api/v1/admin/zap-settings")
    assert r.status_code == 200


async def test_admin_zap_settings_update(client):
    """PUT /api/v1/admin/zap-settings returns 200."""
    r = await client.put("/api/v1/admin/zap-settings", json={})
    assert r.status_code == 200


async def test_admin_oidc_get(client):
    """GET /api/v1/admin/oidc returns 200."""
    r = await client.get("/api/v1/admin/oidc")
    assert r.status_code == 200


# ── Audit Logs ───────────────────────────────────────────────────────────────


async def test_admin_audit_logs(client):
    """GET /api/v1/admin/audit-logs returns 200."""
    r = await client.get("/api/v1/admin/audit-logs")
    assert r.status_code == 200


# ── SSH Profiles (admin only) ───────────────────────────────────────────────


async def test_ssh_profiles_list_empty(client):
    """GET /api/v1/admin/ssh-profiles returns 200 and empty list initially."""
    r = await client.get("/api/v1/admin/ssh-profiles")
    assert r.status_code == 200
    assert r.json() == []


async def test_ssh_profiles_create(client):
    """POST /api/v1/admin/ssh-profiles returns 201."""
    payload = {
        "name": "test-profile",
        "ssh_user": "root",
        "ssh_password": "s3cret_P@ssw0rd",
    }
    r = await client.post("/api/v1/admin/ssh-profiles", json=payload)
    assert r.status_code == 201
    body = r.json()
    assert body["name"] == "test-profile"


# ── Quota ────────────────────────────────────────────────────────────────────


async def test_quota_usage(client):
    """GET /api/v1/admin/quota-usage returns 200."""
    r = await client.get("/api/v1/admin/quota-usage")
    assert r.status_code == 200


# ── Sessions ─────────────────────────────────────────────────────────────────


async def test_sessions_list(client):
    """GET /api/v1/users/me/sessions returns 200."""
    r = await client.get("/api/v1/users/me/sessions")
    assert r.status_code == 200


# ── Notifications ────────────────────────────────────────────────────────────


async def test_notifications_list_empty(client):
    """GET /api/v1/admin/notifications returns 200."""
    r = await client.get("/api/v1/admin/notifications")
    assert r.status_code == 200


# ── Compliance ───────────────────────────────────────────────────────────────


async def test_compliance_frameworks(client):
    """GET /api/v1/compliance/frameworks returns 200."""
    r = await client.get("/api/v1/compliance/frameworks")
    assert r.status_code == 200


async def test_compliance_reports_list(client):
    """GET /api/v1/compliance/reports returns 200."""
    r = await client.get("/api/v1/compliance/reports")
    assert r.status_code == 200


# ── EPSS & KEV (admin) ──────────────────────────────────────────────────────


async def test_epss_stats(client):
    """GET /api/v1/admin/epss/stats returns 200."""
    r = await client.get("/api/v1/admin/epss/stats")
    assert r.status_code == 200


async def test_kev_stats(client):
    """GET /api/v1/admin/kev/stats returns 200."""
    r = await client.get("/api/v1/admin/kev/stats")
    assert r.status_code == 200


# ── Reports ──────────────────────────────────────────────────────────────────


async def test_executive_report(client):
    """GET /api/v1/reports/executive returns 200."""
    r = await client.get("/api/v1/reports/executive")
    assert r.status_code == 200


async def test_executive_report_data(client):
    """GET /api/v1/reports/executive/data returns 200."""
    r = await client.get("/api/v1/reports/executive/data")
    assert r.status_code == 200


# ── Tickets ──────────────────────────────────────────────────────────────────


async def test_tickets_configs_list(client):
    """GET /api/v1/tickets/configs returns 200."""
    r = await client.get("/api/v1/tickets/configs")
    assert r.status_code == 200


# ── Scheduled Reports ───────────────────────────────────────────────────────


async def test_scheduled_reports_list(client):
    """GET /api/v1/scheduled-reports returns 200."""
    r = await client.get("/api/v1/scheduled-reports")
    assert r.status_code == 200


# ── Threat Intel ─────────────────────────────────────────────────────────────


async def test_threat_intel_iocs(client):
    """GET /api/v1/threat-intel/iocs returns 200."""
    r = await client.get("/api/v1/threat-intel/iocs")
    assert r.status_code == 200
