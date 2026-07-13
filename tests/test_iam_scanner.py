"""Tests para el escáner de IAM."""

from cloud_sec_auditor.scanners.iam_scanner import IAMScanner


def test_check_root_no_mfa():
    scanner = IAMScanner()
    finding = scanner.check_root_mfa({"arn": "root", "mfa_enabled": False})
    assert finding is not None
    assert finding.severity == "Critico"


def test_check_root_mfa():
    scanner = IAMScanner()
    finding = scanner.check_root_mfa({"arn": "root", "mfa_enabled": True})
    assert finding is None


def test_check_user_no_mfa():
    scanner = IAMScanner()
    finding = scanner.check_user_mfa({"name": "test", "mfa_enabled": False})
    assert finding is not None
    assert finding.severity == "Alto"


def test_check_user_mfa():
    scanner = IAMScanner()
    finding = scanner.check_user_mfa({"name": "test", "mfa_enabled": True})
    assert finding is None


def test_check_excessive_permissions():
    scanner = IAMScanner()
    finding = scanner.check_excessive_permissions({"name": "admin", "policies": ["*"]})
    assert finding is not None
    assert finding.severity == "Critico"


def test_audit_user():
    scanner = IAMScanner()
    user = {"name": "test", "mfa_enabled": False, "policies": ["*"], "access_keys": ["k1", "k2"]}
    findings = scanner.audit_user(user)
    assert len(findings) >= 2
