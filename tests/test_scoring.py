"""Unit tests for the Lynis .dat parser and hardening risk indicators.

The priority-matrix composite score / tier tests that used to live here were
retired in v0.16: tiers are now the unified SSVC verdict, covered by
tests/test_prioritization.py.
"""

from __future__ import annotations

from netlanventory.api.routers.hardening import (
    _parse_lynis_dat,
    _parse_lynis_finding,
    _parse_lynis_compliance,
    _compute_risk_indicators,
)


# ── _parse_lynis_finding ──────────────────────────────────────────────────────

class TestParseLynisFinding:
    def test_full_finding(self):
        raw = "SSH-7408|PermitRootLogin is enabled|Set PermitRootLogin to no|https://cisofy.com/lynis/controls/SSH-7408/"
        result = _parse_lynis_finding(raw)
        assert result["test_id"] == "SSH-7408"
        assert "PermitRootLogin" in result["description"]
        assert "no" in result["solution"]
        assert result["url"].startswith("https://")

    def test_partial_finding_no_url(self):
        raw = "SSH-7408|Some issue|Some fix"
        result = _parse_lynis_finding(raw)
        assert result["test_id"] == "SSH-7408"
        assert result["url"] == ""

    def test_empty_finding(self):
        # No pipe separator → test_id is the full string; description falls back to raw
        raw = "BARE_ID"
        result = _parse_lynis_finding(raw)
        assert result["test_id"] == "BARE_ID"
        assert result["description"] == raw  # fallback: full string as description

    def test_strips_whitespace(self):
        raw = " TEST-001 | desc with spaces | fix | url "
        result = _parse_lynis_finding(raw)
        assert result["test_id"] == "TEST-001"
        assert result["description"] == "desc with spaces"


# ── _parse_lynis_compliance ───────────────────────────────────────────────────

class TestParseLynisCompliance:
    def test_iso27001(self):
        raw = ["iso27001|partial", "pci_dss|none"]
        result = _parse_lynis_compliance(raw)
        assert result["iso27001"] == "partial"
        assert result["pci_dss"] == "none"

    def test_empty(self):
        assert _parse_lynis_compliance([]) == {}

    def test_ignores_malformed_lines(self):
        raw = ["good|ok", "badline", "another|value"]
        result = _parse_lynis_compliance(raw)
        assert "good" in result
        assert "another" in result
        assert len(result) == 2


# ── _parse_lynis_dat ──────────────────────────────────────────────────────────

SAMPLE_DAT = """\
# Lynis report
hardening_index=72
lynis_version=3.0.9
os=Linux
os_version=22.04
os_full_name=Ubuntu 22.04.3 LTS
linux_kernel_version=5.15.0
warning[]=SSH-7408|PermitRootLogin enabled|Disable root login|https://example.com/SSH-7408/
warning[]=AUTH-9286|No password complexity policy|Set up PAM|
suggestion[]=BOOT-5122|Set a password for GRUB|Use grub-mkpasswd-pbkdf2|
test_performed[]=SSH-7408
test_performed[]=AUTH-9286
test_category[]=authentication
test_category[]=networking
compliance[]=iso27001|partial
uid_0_accounts[]=root
uid_0_accounts[]=backdoor
network_interface[]=eth0
network_listen_port[]=22
network_listen_port[]=80
"""


class TestParseLynisDat:
    def setup_method(self):
        self.result = _parse_lynis_dat(SAMPLE_DAT)

    def test_available_flag(self):
        assert self.result["available"] is True

    def test_hardening_index(self):
        assert self.result["hardening_index"] == 72

    def test_lynis_version(self):
        assert self.result["lynis_version"] == "3.0.9"

    def test_os_info(self):
        assert self.result["os"]["name"] == "Linux"
        assert self.result["os"]["version"] == "22.04"
        assert "Ubuntu" in self.result["os"]["full"]

    def test_warnings_count(self):
        assert len(self.result["warnings"]) == 2

    def test_warnings_structured(self):
        w = self.result["warnings"][0]
        assert w["test_id"] == "SSH-7408"
        assert "PermitRootLogin" in w["description"]

    def test_suggestions_count(self):
        assert len(self.result["suggestions"]) == 1

    def test_tests_performed(self):
        assert "SSH-7408" in self.result["tests_performed"]

    def test_categories(self):
        assert "authentication" in self.result["categories"]
        assert "networking" in self.result["categories"]

    def test_compliance(self):
        assert self.result["compliance"]["iso27001"] == "partial"

    def test_uid0_excludes_root(self):
        # root is filtered out; only extra accounts returned
        assert "backdoor" in self.result["users_with_uid0"]
        assert "root" not in self.result["users_with_uid0"]

    def test_network_listening_count(self):
        assert self.result["network"]["listening_services"] == 2

    def test_summary_counts(self):
        s = self.result["summary"]
        assert s["warnings_count"] == 2
        assert s["suggestions_count"] == 1

    def test_empty_dat(self):
        result = _parse_lynis_dat("")
        assert result["available"] is True
        assert result["hardening_index"] is None
        assert result["warnings"] == []

    def test_comments_ignored(self):
        dat = "# This is a comment\nhardening_index=50\n"
        result = _parse_lynis_dat(dat)
        assert result["hardening_index"] == 50


# ── _compute_risk_indicators ──────────────────────────────────────────────────

class TestComputeRiskIndicators:
    def test_no_issues_clean(self):
        ssh_cfg = {"PermitRootLogin": "no", "PasswordAuthentication": "no"}
        login_defs = {"PASS_MAX_DAYS": "60"}
        indicators = _compute_risk_indicators({}, ssh_cfg, login_defs)
        assert indicators == []

    def test_permit_root_login_flagged(self):
        ssh_cfg = {"PermitRootLogin": "yes"}
        indicators = _compute_risk_indicators({}, ssh_cfg, {})
        ids = [i["id"] for i in indicators]
        assert "SSH-001" in ids

    def test_password_auth_flagged(self):
        ssh_cfg = {"PasswordAuthentication": "yes"}
        indicators = _compute_risk_indicators({}, ssh_cfg, {})
        ids = [i["id"] for i in indicators]
        assert "SSH-002" in ids

    def test_empty_passwords_critical(self):
        ssh_cfg = {"PermitEmptyPasswords": "yes"}
        indicators = _compute_risk_indicators({}, ssh_cfg, {})
        critical = [i for i in indicators if i["severity"] == "critical"]
        assert any(i["id"] == "SSH-003" for i in critical)

    def test_pass_max_days_too_long(self):
        login_defs = {"PASS_MAX_DAYS": "365"}
        indicators = _compute_risk_indicators({}, {}, login_defs)
        ids = [i["id"] for i in indicators]
        assert "PWD-001" in ids

    def test_pass_max_days_ok(self):
        login_defs = {"PASS_MAX_DAYS": "90"}
        indicators = _compute_risk_indicators({}, {}, login_defs)
        assert not any(i["id"] == "PWD-001" for i in indicators)

    def test_world_writable_files_flagged(self):
        cis = {"world_writable_files": ["/tmp/foo", "/var/bar"]}
        indicators = _compute_risk_indicators(cis, {}, {})
        ids = [i["id"] for i in indicators]
        assert "FS-001" in ids

    def test_many_suid_flagged(self):
        cis = {"suid_binaries": [f"/usr/bin/bin{i}" for i in range(25)]}
        indicators = _compute_risk_indicators(cis, {}, {})
        ids = [i["id"] for i in indicators]
        assert "FS-002" in ids

    def test_few_suid_ok(self):
        cis = {"suid_binaries": ["/usr/bin/sudo", "/usr/bin/ping"]}
        indicators = _compute_risk_indicators(cis, {}, {})
        assert not any(i["id"] == "FS-002" for i in indicators)
