"""Tests para el escáner de Security Groups."""

from cloud_sec_auditor.scanners.sg_scanner import SGScanner


def test_scan_open_rule():
    scanner = SGScanner()
    finding = scanner.scan_rule({"port": 22, "source": "0.0.0.0/0", "protocol": "tcp"})
    assert finding.is_risky is True
    assert finding.severity == "Critico"


def test_scan_restricted_rule():
    scanner = SGScanner()
    finding = scanner.scan_rule({"port": 443, "source": "10.0.0.0/8", "protocol": "tcp"})
    assert finding.is_open is False
    assert finding.severity == "OK"


def test_scan_rules():
    scanner = SGScanner()
    rules = [
        {"port": 22, "source": "0.0.0.0/0", "protocol": "tcp"},
        {"port": 80, "source": "0.0.0.0/0", "protocol": "tcp"},
    ]
    findings = scanner.scan_rules(rules, "web")
    assert len(findings) == 2


def test_get_critical():
    scanner = SGScanner()
    rules = [
        {"port": 22, "source": "0.0.0.0/0", "protocol": "tcp"},
        {"port": 443, "source": "10.0.0.0/8", "protocol": "tcp"},
    ]
    findings = scanner.scan_rules(rules)
    critical = scanner.get_critical_findings(findings)
    assert len(critical) == 1
