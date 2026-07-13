"""Constructor de reportes de auditoría cloud."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ReportData:
    """Datos para generar un reporte cloud."""
    provider: str
    total_findings: int
    severity_summary: dict[str, int]
    cis_mapping: dict[str, str]
    entries: list[dict[str, Any]] = field(default_factory=list)


class ReportBuilder:
    """Construye reportes consolidados de auditoría cloud."""

    def build_summary(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        if not entries:
            return {"total": 0, "severity_summary": {}, "scan_types": []}

        scan_types = list({e.get("scan_type", "") for e in entries if e.get("scan_type")})
        severity: dict[str, int] = {"Critico": 0, "Alto": 0, "Medio": 0, "Bajo": 0}
        for e in entries:
            sev = e.get("severity", "OK")
            if sev in severity:
                severity[sev] += 1

        return {
            "total": len(entries),
            "severity_summary": severity,
            "scan_types": scan_types,
        }

    def build_report(self, data: ReportData) -> dict[str, Any]:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": "CloudSec-Auditor",
            "version": "1.0.0",
            "provider": data.provider,
            "summary": {
                "total_findings": data.total_findings,
                "severity_summary": data.severity_summary,
            },
            "cis_mapping": data.cis_mapping,
            "entries": data.entries,
        }
