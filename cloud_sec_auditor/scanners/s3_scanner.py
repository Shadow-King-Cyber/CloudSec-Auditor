"""Escáner de S3 Buckets (AWS) / Blob Storage (Azure) / Buckets (GCP)."""

from __future__ import annotations

from dataclasses import dataclass

from ..core.config import Config


@dataclass
class S3Finding:
    """Resultado de auditoría de un bucket."""
    bucket_name: str
    provider: str
    is_public: bool
    has_logging: bool
    risky_permissions: list[str]
    severity: str
    recommendation: str


class S3Scanner:
    """Audita configuración de buckets en entornos cloud."""

    def __init__(self, provider: str = "aws") -> None:
        self.provider = provider.lower()
        self.config = Config()

    def scan_bucket(self, bucket: dict) -> S3Finding:
        name = bucket.get("name", "unknown")
        acl = bucket.get("acl", "private")
        logging = bucket.get("logging_enabled", False)
        public = acl in self.config.S3_RISKY_PERMISSIONS
        risky = [acl] if acl in self.config.S3_RISKY_PERMISSIONS else []

        if public:
            severity = "Critico"
            recommendation = f"Bucket '{name}' tiene ACL pública ({acl}). Cambiar a private."
        elif not logging:
            severity = "Medio"
            recommendation = f"Bucket '{name}' no tiene logging habilitado."
        else:
            severity = "OK"
            recommendation = "Configuración correcta."

        return S3Finding(
            bucket_name=name,
            provider=self.provider,
            is_public=public,
            has_logging=logging,
            risky_permissions=risky,
            severity=severity,
            recommendation=recommendation,
        )

    def scan_buckets(self, buckets: list[dict]) -> list[S3Finding]:
        return [self.scan_bucket(b) for b in buckets]

    def get_critical_findings(self, findings: list[S3Finding]) -> list[S3Finding]:
        return [f for f in findings if f.severity == "Critico"]
