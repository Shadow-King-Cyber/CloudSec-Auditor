"""Tests para el constructor de reportes."""

from cloud_sec_auditor.reporting.report_builder import ReportBuilder, ReportData


def test_build_summary_empty():
    builder = ReportBuilder()
    result = builder.build_summary([])
    assert result["total"] == 0


def test_build_summary_with_entries():
    builder = ReportBuilder()
    entries = [
        {"scan_type": "s3", "severity": "Critico"},
        {"scan_type": "sg", "severity": "Alto"},
    ]
    result = builder.build_summary(entries)
    assert result["total"] == 2
    assert "s3" in result["scan_types"]


def test_build_report():
    builder = ReportBuilder()
    data = ReportData(
        provider="aws",
        total_findings=2,
        severity_summary={"Critico": 1, "Alto": 1},
        cis_mapping={"S3.1": "test"},
        entries=[],
    )
    report = builder.build_report(data)
    assert report["tool"] == "CloudSec-Auditor"
    assert report["provider"] == "aws"
    assert report["summary"]["total_findings"] == 2
