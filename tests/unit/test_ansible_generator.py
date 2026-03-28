"""Tests for the Ansible playbook generation logic."""

import pytest

from netlanventory.api.routers.ansible import _cve_to_task, _detect_pkg_manager


def test_detect_apt_from_ubuntu():
    assert _detect_pkg_manager("Ubuntu 22.04 LTS", None) == "apt"


def test_detect_apt_from_debian():
    assert _detect_pkg_manager("Debian GNU/Linux 12", "Linux") == "apt"


def test_detect_dnf_from_rocky():
    assert _detect_pkg_manager("Rocky Linux 9", None) == "dnf"


def test_detect_yum_from_centos():
    assert _detect_pkg_manager("CentOS 7", None) == "yum"


def test_detect_zypper_from_suse():
    assert _detect_pkg_manager("openSUSE Leap 15", None) == "zypper"


def test_detect_default_apt():
    """Unknown OS defaults to apt."""
    assert _detect_pkg_manager(None, None) == "apt"
    assert _detect_pkg_manager("Unknown OS", "Unknown") == "apt"


def test_cve_to_task_apt():
    task = _cve_to_task("CVE-2024-1234", "apt")
    assert task["name"] == "Apply security patch for CVE-2024-1234"
    assert "ansible.builtin.apt" in task
    assert task["ansible.builtin.apt"]["upgrade"] == "safe"


def test_cve_to_task_dnf():
    task = _cve_to_task("CVE-2024-5678", "dnf")
    assert "ansible.builtin.dnf" in task
    assert task["ansible.builtin.dnf"]["security"] is True


def test_cve_to_task_yum():
    task = _cve_to_task("CVE-2024-0001", "yum")
    assert "ansible.builtin.yum" in task
    assert task["ansible.builtin.yum"]["state"] == "latest"


def test_cve_to_task_zypper():
    task = _cve_to_task("CVE-2024-0002", "zypper")
    assert "community.general.zypper" in task
