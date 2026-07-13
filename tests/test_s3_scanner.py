"""Tests para el escáner de S3."""

from cloud_sec_auditor.scanners.s3_scanner import S3Scanner


def test_scan_public_bucket():
    scanner = S3Scanner("aws")
    finding = scanner.scan_bucket({"name": "test", "acl": "public-read", "logging_enabled": False})
    assert finding.is_public is True
    assert finding.severity == "Critico"


def test_scan_private_bucket():
    scanner = S3Scanner("aws")
    finding = scanner.scan_bucket({"name": "test", "acl": "private", "logging_enabled": True})
    assert finding.is_public is False
    assert finding.severity == "OK"


def test_scan_no_logging():
    scanner = S3Scanner("aws")
    finding = scanner.scan_bucket({"name": "test", "acl": "private", "logging_enabled": False})
    assert finding.has_logging is False
    assert finding.severity == "Medio"


def test_scan_buckets():
    scanner = S3Scanner("aws")
    buckets = [
        {"name": "b1", "acl": "public-read", "logging_enabled": False},
        {"name": "b2", "acl": "private", "logging_enabled": True},
    ]
    findings = scanner.scan_buckets(buckets)
    assert len(findings) == 2


def test_get_critical():
    scanner = S3Scanner("aws")
    buckets = [
        {"name": "b1", "acl": "public-read", "logging_enabled": False},
        {"name": "b2", "acl": "private", "logging_enabled": True},
    ]
    findings = scanner.scan_buckets(buckets)
    critical = scanner.get_critical_findings(findings)
    assert len(critical) == 1
