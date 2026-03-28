"""Unit tests for parsing helpers in the new internal audit routers.

Tests the pure functions (no DB, no SSH) used to parse command output
and analyze risk findings.
"""

from __future__ import annotations

import os

# Set environment variables BEFORE importing application modules so the
# Settings validator accepts the non-default secrets without raising.
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-unit-tests")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-for-tests")
os.environ.setdefault("ADMIN_PASSWORD", "Test1234!@#$")
os.environ.setdefault("APP_DEBUG", "true")

import pytest

from netlanventory.api.routers.privesc_audit import (
    _parse_passwd,
    _parse_sudoers,
    _parse_capabilities,
    _analyze_risks,
)
from netlanventory.api.routers.firewall_audit import (
    _parse_iptables_policies,
    _parse_iptables_rules,
    _parse_ufw_rules,
    _parse_ss,
    _analyze_firewall_risks,
)
from netlanventory.api.routers.rootkit_audit import (
    _parse_chkrootkit,
    _parse_rkhunter,
)
from netlanventory.api.routers.auth_log_audit import (
    _parse_last,
    _is_private_ip,
)


# ── Privesc Parsers ──────────────────────────────────────────────────────────


class TestParsePasswd:
    def test_basic_entry(self):
        raw = "root:x:0:0:root:/root:/bin/bash"
        users = _parse_passwd(raw)
        assert len(users) == 1
        assert users[0]["name"] == "root"
        assert users[0]["uid"] == 0
        assert users[0]["shell"] == "/bin/bash"

    def test_multiple_users(self):
        raw = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin"
        users = _parse_passwd(raw)
        assert len(users) == 2
        assert users[1]["name"] == "nobody"
        assert users[1]["shell"] == "/usr/sbin/nologin"

    def test_empty_input(self):
        assert _parse_passwd("") == []

    def test_malformed_line_skipped(self):
        raw = "short:entry"
        assert _parse_passwd(raw) == []


class TestParseSudoers:
    def test_nopasswd_flagged(self):
        main = "admin ALL=(ALL) NOPASSWD: ALL"
        rules = _parse_sudoers(main, "")
        assert len(rules) == 1
        assert rules[0]["risky"] is True

    def test_comments_ignored(self):
        main = "# This is a comment\nDefaults env_reset"
        rules = _parse_sudoers(main, "")
        assert len(rules) == 0

    def test_denied_handled(self):
        rules = _parse_sudoers("DENIED", "")
        assert len(rules) == 0

    def test_drop_in_merged(self):
        main = "user1 ALL=(ALL) ALL"
        drop = "user2 ALL=(ALL) NOPASSWD: /usr/bin/systemctl"
        rules = _parse_sudoers(main, drop)
        assert len(rules) == 2

    def test_normal_rule_not_risky(self):
        main = "deploy ALL=(www-data) /usr/bin/systemctl restart app"
        rules = _parse_sudoers(main, "")
        assert len(rules) == 1
        assert rules[0]["risky"] is False


class TestParseCapabilities:
    def test_basic_capability(self):
        raw = "/usr/bin/ping cap_net_raw=ep"
        caps = _parse_capabilities(raw)
        assert len(caps) == 1
        assert caps[0]["path"] == "/usr/bin/ping"
        assert "cap_net_raw" in caps[0]["caps"]

    def test_empty(self):
        assert _parse_capabilities("") == []

    def test_multiple(self):
        raw = "/usr/bin/ping cap_net_raw=ep\n/usr/sbin/tcpdump cap_net_raw,cap_net_admin=eip"
        caps = _parse_capabilities(raw)
        assert len(caps) == 2


class TestAnalyzeRisks:
    def test_uid0_non_root_flagged(self):
        risks = _analyze_risks([], [], [], [], [], [], [], "denied", [], ["root", "toor"])
        critical = [r for r in risks if r["severity"] == "critical"]
        assert any("toor" in r["finding"] for r in critical)

    def test_empty_password_flagged(self):
        risks = _analyze_risks([], [], [], [], [], [], [], "denied", ["testuser"], [])
        critical = [r for r in risks if r["severity"] == "critical"]
        assert any("testuser" in r["finding"] for r in critical)

    def test_shadow_readable_flagged(self):
        risks = _analyze_risks([], [], [], [], [], [], [], "readable", [], [])
        assert any("shadow" in r["finding"].lower() for r in risks)

    def test_suid_python_flagged(self):
        risks = _analyze_risks([], [], ["/usr/bin/python3"], [], [], [], [], "denied", [], [])
        assert any("python" in r["finding"].lower() for r in risks)

    def test_suid_normal_binary_ok(self):
        risks = _analyze_risks([], [], ["/usr/bin/passwd"], [], [], [], [], "denied", [], [])
        # passwd is not in GTFOBins SUID set
        assert not any("passwd" in r["finding"] for r in risks)

    def test_dangerous_cap_flagged(self):
        caps = [{"path": "/usr/bin/evil", "caps": "cap_setuid=ep"}]
        risks = _analyze_risks([], [], [], [], caps, [], [], "denied", [], [])
        assert any("cap_setuid" in r["finding"] for r in risks)

    def test_nopasswd_sudo_flagged(self):
        sudoers = [{"rule": "admin ALL=(ALL) NOPASSWD: ALL", "risky": True}]
        risks = _analyze_risks([], sudoers, [], [], [], [], [], "denied", [], [])
        critical = [r for r in risks if r["severity"] == "critical"]
        assert any("NOPASSWD" in r["finding"] for r in critical)

    def test_clean_system_no_risks(self):
        risks = _analyze_risks([], [], ["/usr/bin/sudo"], [], [], [], [], "denied", [], ["root"])
        assert len(risks) == 0


# ── Firewall Parsers ─────────────────────────────────────────────────────────


class TestParseIptablesPolicies:
    def test_basic_policies(self):
        raw = "Chain INPUT (policy ACCEPT)\nChain FORWARD (policy DROP)\nChain OUTPUT (policy ACCEPT)"
        policies = _parse_iptables_policies(raw)
        assert policies["INPUT"] == "ACCEPT"
        assert policies["FORWARD"] == "DROP"
        assert policies["OUTPUT"] == "ACCEPT"

    def test_empty(self):
        assert _parse_iptables_policies("") == {}


class TestParseUfwRules:
    def test_basic_rules(self):
        raw = "Status: active\nLogging: on (low)\nDefault: deny (incoming)\n--\n22/tcp ALLOW Anywhere\n80/tcp ALLOW Anywhere"
        rules = _parse_ufw_rules(raw)
        assert len(rules) == 2
        assert "22/tcp" in rules[0]

    def test_empty_when_inactive(self):
        raw = "Status: inactive"
        rules = _parse_ufw_rules(raw)
        assert rules == []


class TestParseSs:
    def test_basic_service(self):
        raw = "LISTEN 0      128    0.0.0.0:22   0.0.0.0:*   users:((\"sshd\",pid=1234))"
        services = _parse_ss(raw)
        assert len(services) == 1
        assert services[0]["port"] == "22"
        assert services[0]["bind"] == "0.0.0.0"

    def test_empty(self):
        assert _parse_ss("") == []


class TestAnalyzeFirewallRisks:
    def test_no_firewall_critical(self):
        risks = _analyze_firewall_risks("none", False, {}, [], [], [], "")
        assert any(r["severity"] == "critical" for r in risks)
        assert any("no active firewall" in r["finding"].lower() for r in risks)

    def test_default_input_accept_critical(self):
        risks = _analyze_firewall_risks("iptables", True, {"INPUT": "ACCEPT"}, [], [], [], "")
        assert any("INPUT policy is ACCEPT" in r["finding"] for r in risks)

    def test_forward_accept_flagged(self):
        risks = _analyze_firewall_risks("iptables", True, {"INPUT": "DROP", "FORWARD": "ACCEPT"}, [], [], [], "")
        assert any("FORWARD" in r["finding"] for r in risks)

    def test_clean_firewall_no_critical(self):
        risks = _analyze_firewall_risks("iptables", True, {"INPUT": "DROP", "FORWARD": "DROP", "OUTPUT": "ACCEPT"}, [], [], [], "")
        assert not any(r["severity"] == "critical" for r in risks)


# ── Rootkit Parsers ──────────────────────────────────────────────────────────


class TestParseChkrootkit:
    def test_infected(self):
        raw = "Checking `bindshell'... INFECTED\nChecking `amd'... not infected"
        result = _parse_chkrootkit(raw)
        assert len(result["infected"]) == 1
        assert result["not_infected_count"] == 1

    def test_clean(self):
        raw = "Checking `amd'... not infected\nChecking `biff'... not found"
        result = _parse_chkrootkit(raw)
        assert len(result["infected"]) == 0

    def test_empty(self):
        result = _parse_chkrootkit("")
        assert result["infected"] == []
        assert result["suspects"] == []


class TestParseRkhunter:
    def test_warnings(self):
        raw = "Warning: The command '/usr/bin/lwp-request' has been replaced\n[ Warning ] /usr/bin/wget"
        result = _parse_rkhunter(raw)
        assert len(result["warnings"]) == 2

    def test_clean(self):
        result = _parse_rkhunter("System checks summary\nAll checks passed")
        assert result["warnings"] == []
        assert result["infected"] == []


# ── Auth Log Parsers ─────────────────────────────────────────────────────────


class TestParseLast:
    def test_basic_entries(self):
        raw = "admin    pts/0    192.168.1.10   Thu Mar 28 09:00\nroot     tty1                    Thu Mar 28 08:00"
        entries = _parse_last(raw)
        assert len(entries) == 2
        assert entries[0]["user"] == "admin"
        assert entries[0]["source"] == "192.168.1.10"

    def test_wtmp_line_skipped(self):
        raw = "wtmp begins Thu Mar 1 00:00:00 2026"
        entries = _parse_last(raw)
        assert len(entries) == 0

    def test_reboot_skipped(self):
        raw = "reboot   system boot  5.15.0-91-generic Thu Mar 28 00:00"
        entries = _parse_last(raw)
        assert len(entries) == 0

    def test_empty(self):
        assert _parse_last("") == []

    def test_max_50_entries(self):
        lines = [f"user{i}    pts/0    10.0.0.{i % 256}   Thu Mar 28" for i in range(100)]
        entries = _parse_last("\n".join(lines))
        assert len(entries) == 50


class TestIsPrivateIp:
    def test_private_10(self):
        assert _is_private_ip("10.0.0.1") is True

    def test_private_172(self):
        assert _is_private_ip("172.16.0.1") is True

    def test_private_192(self):
        assert _is_private_ip("192.168.1.1") is True

    def test_loopback(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_public(self):
        assert _is_private_ip("8.8.8.8") is False

    def test_public_172_outside_range(self):
        assert _is_private_ip("172.32.0.1") is False

    def test_invalid(self):
        assert _is_private_ip("not-an-ip") is False
