"""Tests para el analizador de riesgos."""

from cloud_sec_auditor.analysis.risk_analyzer import RiskAnalyzer
from cloud_sec_auditor.scanners.s3_scanner import S3Finding


def test_consolidate():
    analyzer = RiskAnalyzer()
    findings = [
        S3Finding("b1", "aws", True, False, [], "Critico", "test"),
        S3Finding("b2", "aws", False, True, [], "OK", "ok"),
    ]
    summary = analyzer.consolidate(findings)
    assert summary["Critico"] == 1


def test_prioritize():
    analyzer = RiskAnalyzer()
    findings = [
        S3Finding("b1", "aws", False, True, [], "Medio", "test"),
        S3Finding("b2", "aws", True, False, [], "Critico", "test"),
    ]
    ordered = analyzer.prioritize(findings)
    assert ordered[0].severity == "Critico"


def test_get_risk_items():
    analyzer = RiskAnalyzer()
    findings = [
        S3Finding("b1", "aws", True, False, [], "Critico", "test"),
        S3Finding("b2", "aws", True, False, [], "Critico", "test"),
    ]
    items = analyzer.get_risk_items(findings)
    assert len(items) == 1
    assert items[0].count == 2
