"""CIS Benchmark mapper — map hardening report findings to CIS controls.

Maps the results from HardeningReport (Lynis + CIS checks via SSH) to
CIS Benchmark for Linux v3.0 controls, producing a score and findings list.

The mapping is heuristic: SSH config, password policy, suid binaries, and
world-writable files are mapped to specific CIS control IDs.
"""

from __future__ import annotations

from typing import Any


# CIS Benchmark Linux v3.0 controls that we can evaluate
_CIS_CONTROLS: list[dict[str, Any]] = [
    # Section 1 — Filesystem
    {
        "id": "1.1.2.1",
        "title": "Ensure /tmp is a separate partition",
        "section": "Initial Setup",
        "level": "L1",
        "check_key": None,
        "weight": 2,
    },
    # Section 5 — Access, Authentication and Authorization
    {
        "id": "5.2.5",
        "title": "Ensure SSH root login is disabled",
        "section": "Access Control",
        "level": "L1",
        "check_key": "ssh_root_login",
        "weight": 5,
    },
    {
        "id": "5.2.11",
        "title": "Ensure SSH PasswordAuthentication is disabled",
        "section": "Access Control",
        "level": "L2",
        "check_key": "ssh_password_auth",
        "weight": 4,
    },
    {
        "id": "5.2.4",
        "title": "Ensure SSH Protocol is set to 2",
        "section": "Access Control",
        "level": "L1",
        "check_key": "ssh_protocol",
        "weight": 5,
    },
    {
        "id": "5.4.1.1",
        "title": "Ensure password expiration is 365 days or less",
        "section": "Password Policy",
        "level": "L1",
        "check_key": "pass_max_days",
        "weight": 3,
    },
    {
        "id": "5.4.1.2",
        "title": "Ensure minimum days between password changes",
        "section": "Password Policy",
        "level": "L1",
        "check_key": "pass_min_days",
        "weight": 2,
    },
    # Section 6 — System Maintenance
    {
        "id": "6.1.10",
        "title": "Ensure no world-writable files exist",
        "section": "System Maintenance",
        "level": "L1",
        "check_key": "world_writable",
        "weight": 4,
    },
    {
        "id": "6.1.13",
        "title": "Ensure SUID and SGID files are reviewed",
        "section": "System Maintenance",
        "level": "L1",
        "check_key": "suid_binaries",
        "weight": 3,
    },
    # Section 4 — Logging and Auditing
    {
        "id": "4.1.1.1",
        "title": "Ensure cron daemon is enabled",
        "section": "Logging & Auditing",
        "level": "L1",
        "check_key": "cron_running",
        "weight": 2,
    },
]


def map_hardening_to_cis(findings: dict | None, lynis_index: int | None = None) -> dict:
    """Map HardeningReport findings to CIS Benchmark controls.

    Returns a dict with:
    - score (int 0-100): percentage of passing controls (weighted)
    - level (str): "L1" or "L2" based on which controls are evaluated
    - findings (list): [{control_id, title, section, level, status, severity, detail}]
    """
    if not findings:
        return {"score": 0, "level": "L1", "findings": []}

    cis_checks = findings.get("cis_checks", {})
    ssh_config = cis_checks.get("ssh_config", {})
    password_policy = cis_checks.get("password_policy", {})
    world_writable = cis_checks.get("world_writable_files", [])
    suid_binaries = cis_checks.get("suid_binaries", [])
    cron_entries = cis_checks.get("cron_entries", "")

    result_findings = []
    total_weight = 0
    passed_weight = 0

    for ctrl in _CIS_CONTROLS:
        check_key = ctrl["check_key"]
        weight = ctrl["weight"]
        status = "unknown"
        detail = ""

        if check_key == "ssh_root_login":
            val = str(ssh_config.get("PermitRootLogin", "")).lower()
            if val in ("no", "prohibit-password", "forced-commands-only"):
                status = "pass"
            elif val in ("yes", ""):
                status = "fail"
                detail = f"PermitRootLogin={val or 'not set'}"

        elif check_key == "ssh_password_auth":
            val = str(ssh_config.get("PasswordAuthentication", "")).lower()
            if val == "no":
                status = "pass"
            elif val in ("yes", ""):
                status = "fail"
                detail = f"PasswordAuthentication={val or 'not set (defaults to yes)'}"

        elif check_key == "ssh_protocol":
            val = str(ssh_config.get("Protocol", "2"))
            status = "pass" if val == "2" else "fail"
            detail = f"Protocol={val}"

        elif check_key == "pass_max_days":
            val = password_policy.get("PASS_MAX_DAYS", "")
            try:
                days = int(val)
                status = "pass" if days <= 365 else "fail"
                detail = f"PASS_MAX_DAYS={days}"
            except (ValueError, TypeError):
                status = "unknown"

        elif check_key == "pass_min_days":
            val = password_policy.get("PASS_MIN_DAYS", "")
            try:
                days = int(val)
                status = "pass" if days >= 1 else "fail"
                detail = f"PASS_MIN_DAYS={days}"
            except (ValueError, TypeError):
                status = "unknown"

        elif check_key == "world_writable":
            if isinstance(world_writable, list):
                if len(world_writable) == 0:
                    status = "pass"
                else:
                    status = "fail"
                    detail = f"{len(world_writable)} world-writable file(s) found"

        elif check_key == "suid_binaries":
            if isinstance(suid_binaries, list):
                # SUID binaries exist by design — flag if more than expected
                expected_count = 20  # typical Linux has ~15-25
                status = "pass" if len(suid_binaries) <= expected_count else "fail"
                detail = f"{len(suid_binaries)} SUID binaries found"

        elif check_key == "cron_running":
            status = "pass" if cron_entries else "unknown"

        else:
            status = "unknown"

        severity = "high" if weight >= 5 else "medium" if weight >= 3 else "low"

        result_findings.append({
            "control_id": ctrl["id"],
            "title": ctrl["title"],
            "section": ctrl["section"],
            "level": ctrl["level"],
            "status": status,
            "severity": severity,
            "detail": detail,
        })

        if status != "unknown":
            total_weight += weight
            if status == "pass":
                passed_weight += weight

    # Incorporate Lynis index into the score if available
    if lynis_index is not None and total_weight > 0:
        cis_score = int((passed_weight / total_weight) * 60 + lynis_index * 0.4)
    elif total_weight > 0:
        cis_score = int((passed_weight / total_weight) * 100)
    else:
        cis_score = 0

    cis_score = max(0, min(100, cis_score))

    return {
        "score": cis_score,
        "level": "L2",  # We evaluate some L2 controls
        "findings": result_findings,
    }
