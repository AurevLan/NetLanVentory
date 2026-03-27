"""Tests for the CIS Benchmark mapper."""

import pytest

from netlanventory.core.cis_mapper import map_hardening_to_cis


def test_empty_findings():
    """Empty input should return a valid but low score."""
    result = map_hardening_to_cis({}, None)
    assert "score" in result
    assert "level" in result
    assert "findings" in result
    assert isinstance(result["findings"], list)
    assert result["level"] in ("L1", "L2")


def test_good_ssh_config():
    """Secure SSH settings should yield passing controls."""
    findings = {
        "ssh_config": {
            "PermitRootLogin": "no",
            "PasswordAuthentication": "no",
            "X11Forwarding": "no",
            "MaxAuthTries": "4",
            "Protocol": "2",
        }
    }
    result = map_hardening_to_cis(findings, lynis_index=85)
    assert result["score"] > 0

    # Check that SSH controls are present in findings
    ssh_controls = [f for f in result["findings"] if "SSH" in f.get("title", "").upper() or "ssh" in f.get("control_id", "")]
    assert len(ssh_controls) > 0


def test_bad_ssh_config():
    """Insecure SSH settings should yield failing controls."""
    findings = {
        "ssh_config": {
            "PermitRootLogin": "yes",
            "PasswordAuthentication": "yes",
            "X11Forwarding": "yes",
        }
    }
    result = map_hardening_to_cis(findings, lynis_index=30)
    fail_count = sum(1 for f in result["findings"] if f.get("status") == "fail")
    assert fail_count > 0


def test_password_policy():
    """Password policy checks should affect the result."""
    findings = {
        "password_policy": {
            "PASS_MAX_DAYS": "90",
            "PASS_MIN_DAYS": "7",
            "PASS_WARN_AGE": "7",
            "PASS_MIN_LEN": "14",
        }
    }
    result = map_hardening_to_cis(findings, lynis_index=None)
    pw_controls = [f for f in result["findings"] if "password" in f.get("title", "").lower() or "pass" in f.get("control_id", "").lower()]
    assert len(pw_controls) > 0


def test_world_writable_files():
    """World-writable files check."""
    findings = {
        "cis_checks": {
            "world_writable_files": ["/tmp/badfile", "/var/insecure"],
        },
    }
    result = map_hardening_to_cis(findings, lynis_index=None)
    ww_controls = [f for f in result["findings"] if "writable" in f.get("title", "").lower()]
    assert len(ww_controls) > 0
    assert any(f.get("status") == "fail" for f in ww_controls)


def test_suid_binaries():
    """SUID binary check."""
    findings = {
        "suid_binaries": ["/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/unknown_suid"],
    }
    result = map_hardening_to_cis(findings, lynis_index=None)
    # Should have a finding about SUID
    suid_controls = [f for f in result["findings"] if "suid" in f.get("title", "").lower()]
    assert len(suid_controls) > 0


def test_lynis_index_affects_score():
    """Higher lynis index should yield a higher score."""
    result_low = map_hardening_to_cis({}, lynis_index=20)
    result_high = map_hardening_to_cis({}, lynis_index=90)
    assert result_high["score"] >= result_low["score"]
