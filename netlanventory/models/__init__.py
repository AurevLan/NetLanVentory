"""SQLAlchemy ORM models."""

from netlanventory.models.asset import Asset
from netlanventory.models.asset_baseline import AssetBaseline
from netlanventory.models.asset_tag import AssetTag
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.asset_dns import AssetDns
from netlanventory.models.audit_log import AuditLog
from netlanventory.models.base import Base
from netlanventory.models.compliance_report import ComplianceReport
from netlanventory.models.cve import Cve
from netlanventory.models.global_settings import GlobalSettings
from netlanventory.models.kpi_snapshot import KpiSnapshot
from netlanventory.models.notification_config import NotificationConfig
from netlanventory.models.oidc_provider import OidcProvider
from netlanventory.models.port import Port
from netlanventory.models.saved_filter import SavedFilter
from netlanventory.models.scan import Scan
from netlanventory.models.scan_history import ScanHistory
from netlanventory.models.scan_quota import ScanQuotaLog
from netlanventory.models.scan_result import ScanResult
from netlanventory.models.scheduled_report import ScheduledReport
from netlanventory.models.scheduled_scan import ScheduledScan
from netlanventory.models.nuclei_report import NucleiReport
from netlanventory.models.sla_config import SlaConfig
from netlanventory.models.ssh_profile import SshProfile
from netlanventory.models.ssl_scan_report import SslScanReport
from netlanventory.models.testssl_report import TestsslReport
from netlanventory.models.ssh_audit_report import SshAuditReport
from netlanventory.models.default_creds_report import DefaultCredsReport
from netlanventory.models.full_audit_job import FullAuditJob
from netlanventory.models.threat_ioc import ThreatIoc
from netlanventory.models.ticket_config import TicketConfig
from netlanventory.models.trivy_docker_report import TrivyDockerReport
from netlanventory.models.ssh_scan_report import SshScanReport
from netlanventory.models.user import User
from netlanventory.models.user_session import UserSession
from netlanventory.models.zap_report import ZapReport
from netlanventory.models.hardening_report import HardeningReport
from netlanventory.models.headers_audit_report import HeadersAuditReport
from netlanventory.models.msf_validation_report import MsfValidationReport
from netlanventory.models.privesc_report import PrivescReport
from netlanventory.models.firewall_report import FirewallReport
from netlanventory.models.rootkit_report import RootkitReport
from netlanventory.models.docker_bench_report import DockerBenchReport
from netlanventory.models.auth_log_report import AuthLogReport
from netlanventory.models.dangling_cname_report import DanglingCnameReport
from netlanventory.models.dns_email_report import DnsEmailReport
from netlanventory.models.js_secrets_report import JsSecretsReport
from netlanventory.models.tech_fingerprint_report import TechFingerprintReport

__all__ = [
    "Base", "Asset", "AssetBaseline", "AssetCve", "AssetDns", "AssetTag", "AuditLog",
    "AuthLogReport", "ComplianceReport", "Cve",
    "DanglingCnameReport", "DefaultCredsReport", "DnsEmailReport",
    "DockerBenchReport", "FirewallReport", "FullAuditJob",
    "GlobalSettings", "HardeningReport", "HeadersAuditReport",
    "JsSecretsReport", "KpiSnapshot", "MsfValidationReport",
    "NotificationConfig", "NucleiReport", "OidcProvider",
    "Port", "PrivescReport", "RootkitReport",
    "SavedFilter", "Scan", "ScanHistory", "ScanQuotaLog", "ScanResult",
    "ScheduledReport", "ScheduledScan", "SlaConfig",
    "SshAuditReport", "SshProfile", "SshScanReport",
    "SslScanReport", "TechFingerprintReport", "TestsslReport", "ThreatIoc", "TicketConfig",
    "TrivyDockerReport", "User", "UserSession", "ZapReport",
]
