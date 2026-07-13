"""Tests para el escáner de RDS."""

from cloud_sec_auditor.scanners.rds_scanner import RDSScanner


def test_scan_public_db():
    scanner = RDSScanner()
    finding = scanner.scan_database({"name": "prod", "publicly_accessible": True, "encrypted": True, "backup_enabled": True})
    assert finding.is_public is True
    assert finding.severity == "Critico"


def test_scan_unencrypted_db():
    scanner = RDSScanner()
    finding = scanner.scan_database({"name": "dev", "publicly_accessible": False, "encrypted": False, "backup_enabled": True})
    assert finding.has_encryption is False
    assert finding.severity == "Alto"


def test_scan_no_backup():
    scanner = RDSScanner()
    finding = scanner.scan_database({"name": "dev", "publicly_accessible": False, "encrypted": True, "backup_enabled": False})
    assert finding.has_backup is False
    assert finding.severity == "Medio"


def test_scan_good_db():
    scanner = RDSScanner()
    finding = scanner.scan_database({"name": "prod", "publicly_accessible": False, "encrypted": True, "backup_enabled": True})
    assert finding.severity == "OK"


def test_scan_databases():
    scanner = RDSScanner()
    databases = [
        {"name": "db1", "publicly_accessible": True, "encrypted": True, "backup_enabled": True},
        {"name": "db2", "publicly_accessible": False, "encrypted": True, "backup_enabled": True},
    ]
    findings = scanner.scan_databases(databases)
    assert len(findings) == 2
