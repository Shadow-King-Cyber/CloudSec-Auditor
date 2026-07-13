"""Escáner de logging — CloudTrail / Activity Log / Audit Log."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class LoggingFinding:
    """Resultado de auditoría de logging."""
    service: str
    is_enabled: bool
    is_multiregion: bool
    has_alerts: bool
    severity: str
    recommendation: str


class LoggingScanner:
    """Audita configuración de logging en servicios cloud."""

    def check_cloudtrail(self, config: dict) -> LoggingFinding:
        enabled = config.get("enabled", False)
        multiregion = config.get("multi_region", False)
        alerts = config.get("cloudwatch_alerts", False)

        if not enabled:
            severity = "Critico"
            recommendation = "CloudTrail no está habilitado — habilitar inmediatamente"
        elif not multiregion:
            severity = "Alto"
            recommendation = "CloudTrail no tiene multi-region habilitado"
        elif not alerts:
            severity = "Medio"
            recommendation = "CloudTrail no tiene alertas de CloudWatch configuradas"
        else:
            severity = "OK"
            recommendation = "Logging configurado correctamente"

        return LoggingFinding(
            service="CloudTrail",
            is_enabled=enabled,
            is_multiregion=multiregion,
            has_alerts=alerts,
            severity=severity,
            recommendation=recommendation,
        )

    def check_activity_log(self, config: dict) -> LoggingFinding:
        enabled = config.get("enabled", False)
        retention = config.get("retention_days", 0)

        if not enabled:
            severity = "Alto"
            recommendation = "Azure Activity Log no está habilitado"
        elif retention < 90:
            severity = "Medio"
            recommendation = f"Retention de Activity Log es {retention} días — mínimo recomendado: 90"
        else:
            severity = "OK"
            recommendation = "Activity Log configurado correctamente"

        return LoggingFinding(
            service="Activity Log",
            is_enabled=enabled,
            is_multiregion=False,
            has_alerts=config.get("alerts", False),
            severity=severity,
            recommendation=recommendation,
        )

    def check_audit_log(self, config: dict) -> LoggingFinding:
        enabled = config.get("enabled", False)
        export = config.get("exported_to_cloud_storage", False)

        if not enabled:
            severity = "Alto"
            recommendation = "GCP Audit Log no está habilitado"
        elif not export:
            severity = "Medio"
            recommendation = "Audit Log no está exportado a Cloud Storage"
        else:
            severity = "OK"
            recommendation = "Audit Log configurado correctamente"

        return LoggingFinding(
            service="Audit Log",
            is_enabled=enabled,
            is_multiregion=False,
            has_alerts=config.get("alerts", False),
            severity=severity,
            recommendation=recommendation,
        )
