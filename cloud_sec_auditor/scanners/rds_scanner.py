"""Escáner de RDS / Cloud SQL."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RDSFinding:
    """Resultado de auditoría de base de datos."""
    db_name: str
    is_public: bool
    has_encryption: bool
    has_backup: bool
    severity: str
    recommendation: str


class RDSScanner:
    """Audita configuración de bases de datos cloud (RDS, Cloud SQL)."""

    def scan_database(self, db: dict) -> RDSFinding:
        name = db.get("name", "unknown")
        is_public = db.get("publicly_accessible", False)
        encrypted = db.get("encrypted", False)
        backup = db.get("backup_enabled", False)

        if is_public:
            severity = "Critico"
            recommendation = f"Base de datos '{name}' es accesible públicamente — restringir a VPC"
        elif not encrypted:
            severity = "Alto"
            recommendation = f"Base de datos '{name}' no tiene cifrado habilitado"
        elif not backup:
            severity = "Medio"
            recommendation = f"Base de datos '{name}' no tiene backups habilitados"
        else:
            severity = "OK"
            recommendation = "Configuración correcta"

        return RDSFinding(
            db_name=name,
            is_public=is_public,
            has_encryption=encrypted,
            has_backup=backup,
            severity=severity,
            recommendation=recommendation,
        )

    def scan_databases(self, databases: list[dict]) -> list[RDSFinding]:
        return [self.scan_database(db) for db in databases]

    def get_critical_findings(self, findings: list[RDSFinding]) -> list[RDSFinding]:
        return [f for f in findings if f.severity == "Critico"]
