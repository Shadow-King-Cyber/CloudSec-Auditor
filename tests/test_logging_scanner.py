"""Tests para el escáner de logging."""

from cloud_sec_auditor.scanners.logging_scanner import LoggingScanner


def test_cloudtrail_disabled():
    scanner = LoggingScanner()
    finding = scanner.check_cloudtrail({"enabled": False, "multi_region": False, "cloudwatch_alerts": False})
    assert finding.is_enabled is False
    assert finding.severity == "Critico"


def test_cloudtrail_no_multiregion():
    scanner = LoggingScanner()
    finding = scanner.check_cloudtrail({"enabled": True, "multi_region": False, "cloudwatch_alerts": False})
    assert finding.is_multiregion is False
    assert finding.severity == "Alto"


def test_cloudtrail_ok():
    scanner = LoggingScanner()
    finding = scanner.check_cloudtrail({"enabled": True, "multi_region": True, "cloudwatch_alerts": True})
    assert finding.severity == "OK"


def test_activity_log_disabled():
    scanner = LoggingScanner()
    finding = scanner.check_activity_log({"enabled": False, "retention_days": 0, "alerts": False})
    assert finding.severity == "Alto"


def test_activity_log_short_retention():
    scanner = LoggingScanner()
    finding = scanner.check_activity_log({"enabled": True, "retention_days": 30, "alerts": False})
    assert finding.severity == "Medio"


def test_audit_log_disabled():
    scanner = LoggingScanner()
    finding = scanner.check_audit_log({"enabled": False, "exported_to_cloud_storage": False, "alerts": False})
    assert finding.severity == "Alto"
