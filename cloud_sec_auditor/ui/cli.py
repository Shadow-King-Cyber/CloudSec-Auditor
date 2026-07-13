"""CLI principal para CloudSec-Auditor."""

import click

from ..core.audit_logger import AuditLogger
from ..scanners.s3_scanner import S3Scanner
from ..scanners.sg_scanner import SGScanner
from ..scanners.iam_scanner import IAMScanner
from ..scanners.rds_scanner import RDSScanner
from ..scanners.logging_scanner import LoggingScanner
from ..analysis.risk_analyzer import RiskAnalyzer
from ..scoring.cloud_scoring import CloudScoring
from ..reporting.report_builder import ReportBuilder, ReportData
from ..reporting.json_exporter import JsonExporter
from ..reporting.html_exporter import HtmlExporter


@click.group()
@click.version_option(version="1.0.0", prog_name="cloudsec-auditor")
def main() -> None:
    """CloudSec-Auditor — Auditor de seguridad cloud para investigación autorizada."""
    pass


@main.command()
@click.option("--provider", type=click.Choice(["aws", "azure", "gcp"]), default="aws", help="Proveedor cloud")
def full_scan(provider: str) -> None:
    """Ejecuta un escaneo completo de seguridad cloud."""
    click.echo(f"=== Escaneo completo: {provider.upper()} ===")
    logger = AuditLogger()
    logger.log_scan(provider, "full_scan", 0)
    click.echo("Escaneo registrado. Use los scans individuales para detalles.")


@main.command()
def s3_scan() -> None:
    """Escanea buckets S3 buscando configuración insegura."""
    scanner = S3Scanner("aws")
    buckets = [
        {"name": "mi-bucket-publico", "acl": "public-read", "logging_enabled": False},
        {"name": "mi-bucket-privado", "acl": "private", "logging_enabled": True},
    ]
    findings = scanner.scan_buckets(buckets)
    click.echo("=== Escaneo S3 ===")
    for f in findings:
        status = "[!]" if f.severity != "OK" else "[OK]"
        click.echo(f"  {status} {f.bucket_name}: {f.recommendation}")


@main.command()
def sg_scan() -> None:
    """Escanea Security Groups buscando reglas abiertas."""
    scanner = SGScanner()
    rules = [
        {"port": 22, "source": "0.0.0.0/0", "protocol": "tcp"},
        {"port": 443, "source": "10.0.0.0/8", "protocol": "tcp"},
    ]
    findings = scanner.scan_rules(rules, "web-sg")
    click.echo("=== Escaneo Security Groups ===")
    for f in findings:
        status = "[!]" if f.severity != "OK" else "[OK]"
        click.echo(f"  {status} {f.port}/{f.protocol} ({f.source}): {f.recommendation}")


@main.command()
def iam_scan() -> None:
    """Escanea IAM buscando usuarios inseguros."""
    scanner = IAMScanner()
    users = [
        {"name": "admin", "mfa_enabled": True, "policies": ["read-only"], "access_keys": ["key1"]},
        {"name": "dev-user", "mfa_enabled": False, "policies": ["*"], "access_keys": ["k1", "k2"]},
    ]
    click.echo("=== Escaneo IAM ===")
    for user in users:
        findings = scanner.audit_user(user)
        if findings:
            for f in findings:
                click.echo(f"  [!] {user['name']}: {f.recommendation}")
        else:
            click.echo(f"  [OK] {user['name']}: Sin problemas")


@main.command()
def rds_scan() -> None:
    """Escanea bases de datos RDS."""
    scanner = RDSScanner()
    databases = [
        {"name": "prod-db", "publicly_accessible": True, "encrypted": True, "backup_enabled": True},
        {"name": "dev-db", "publicly_accessible": False, "encrypted": False, "backup_enabled": False},
    ]
    findings = scanner.scan_databases(databases)
    click.echo("=== Escaneo RDS ===")
    for f in findings:
        status = "[!]" if f.severity != "OK" else "[OK]"
        click.echo(f"  {status} {f.db_name}: {f.recommendation}")


@main.command()
@click.option("--provider", type=click.Choice(["aws", "azure", "gcp"]), default="aws")
def logging_scan(provider: str) -> None:
    """Escanea configuración de logging."""
    scanner = LoggingScanner()
    click.echo(f"=== Escaneo Logging ({provider.upper()}) ===")
    if provider == "aws":
        finding = scanner.check_cloudtrail({"enabled": True, "multi_region": False, "cloudwatch_alerts": False})
    elif provider == "azure":
        finding = scanner.check_activity_log({"enabled": True, "retention_days": 30, "alerts": False})
    else:
        finding = scanner.check_audit_log({"enabled": True, "exported_to_cloud_storage": False, "alerts": False})
    status = "[!]" if finding.severity != "OK" else "[OK]"
    click.echo(f"  {status} {finding.service}: {finding.recommendation}")


@main.command()
def mapping() -> None:
    """Muestra el mapping CIS Benchmark."""
    scoring = CloudScoring()
    mapping_data = scoring.get_cis_mapping()
    click.echo("=== CIS Benchmarks ===\n")
    for k, v in mapping_data.items():
        click.echo(f"  {k}: {v}")


@main.command()
def report() -> None:
    """Genera un reporte HTML + JSON."""
    logger = AuditLogger()
    entries = logger.read_all()
    builder = ReportBuilder()
    summary = builder.build_summary(entries)

    scoring = CloudScoring()
    score_result = scoring.calculate_score(summary.get("severity_summary", {}))

    data = ReportData(
        provider="aws",
        total_findings=summary.get("total", 0),
        severity_summary=summary.get("severity_summary", {}),
        cis_mapping=scoring.get_cis_mapping(),
        entries=entries,
    )
    report_data = builder.build_report(data)

    json_exp = JsonExporter()
    json_path = json_exp.export(report_data)
    click.echo(f"Reporte JSON: {json_path}")

    html_exp = HtmlExporter()
    html_path = html_exp.export(report_data)
    click.echo(f"Reporte HTML: {html_path}")
    click.echo(f"\nScore: {score_result.score}/100 (Grade: {score_result.grade})")


if __name__ == "__main__":
    main()
