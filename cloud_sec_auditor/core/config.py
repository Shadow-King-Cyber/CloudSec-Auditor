"""Configuración global del auditor cloud."""

from pathlib import Path


class Config:
    """Configuración centralizada."""

    BASE_DIR = Path(__file__).resolve().parent.parent
    SCOPE_FILE = BASE_DIR / "scope.json"
    AUDIT_LOG = BASE_DIR / "audit_log.jsonl"
    REPORTS_DIR = BASE_DIR / "reports"

    SUPPORTED_PROVIDERS = ["aws", "azure", "gcp"]

    S3_RISKY_PERMISSIONS = ["public-read", "public-read-write", "authenticated-read"]

    SG_OPEN_PORTS = {
        "22": "SSH expuesto públicamente",
        "3389": "RDP expuesto públicamente",
        "3306": "MySQL expuesto públicamente",
        "5432": "PostgreSQL expuesto públicamente",
        "27017": "MongoDB expuesto públicamente",
        "6379": "Redis expuesto públicamente",
        "9200": "Elasticsearch expuesto públicamente",
    }

    CIS_BENCHMARKS = {
        "S3.1": "CIS AWS 2.1.1 — S3 Bucket no debe tener acceso público",
        "S3.2": "CIS AWS 2.1.2 — S3 Bucket Logging habilitado",
        "SG.1": "CIS AWS 5.2 — Security Groups no deben permitir 0.0.0.0/0 en puertos sensibles",
        "IAM.1": "CIS AWS 1.4 — IAM Root no debe tener MFA deshabilitado",
        "IAM.2": "CIS AWS 1.5 — Usuarios IAM deben tener MFA habilitado",
        "RDS.1": "CIS AWS 2.3.1 — RDS no debe ser accesible públicamente",
        "CT.1": "CIS AWS 3.1 — CloudTrail debe estar habilitado",
    }

    OWASP_CLOUD_TOP10 = {
        "IAM Misconfig": "C1:2021 — Insecure Identity and Access Management",
        "Insecure Interfaces": "C2:2021 — Insecure Interfaces and APIs",
        "Misconfiguration": "C3:2021 — Misconfiguration and Change Control",
        "Lack of Visibility": "C4:2021 — Lack of Cloud Security Visibility",
        "Account Hijacking": "C5:2021 — Account Hijacking",
        "Insecure Data": "C6:2021 — Insecure Data Encryption",
        "SSRF": "C7:2021 — System Vulnerabilities Exploited via SSRF",
    }
