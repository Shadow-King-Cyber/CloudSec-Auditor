"""Analizador consolidado de riesgos cloud."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RiskItem:
    """Riesgo consolidado."""
    category: str
    severity: str
    count: int
    description: str


class RiskAnalyzer:
    """Consolida y prioriza riesgos encontrados por los scanners."""

    SEVERITY_ORDER = {"Critico": 4, "Alto": 3, "Medio": 2, "Bajo": 1, "OK": 0}

    def consolidate(self, findings: list[Any]) -> dict[str, int]:
        summary: dict[str, int] = {}
        for f in findings:
            sev = getattr(f, "severity", "OK")
            if sev != "OK":
                summary[sev] = summary.get(sev, 0) + 1
        return summary

    def prioritize(self, findings: list[Any]) -> list[Any]:
        return sorted(
            findings,
            key=lambda f: self.SEVERITY_ORDER.get(getattr(f, "severity", "OK"), 0),
            reverse=True,
        )

    def get_risk_items(self, findings: list[Any]) -> list[RiskItem]:
        categories: dict[str, dict[str, int]] = {}
        for f in findings:
            sev = getattr(f, "severity", "OK")
            if sev == "OK":
                continue
            cat = type(f).__name__
            if cat not in categories:
                categories[cat] = {}
            categories[cat][sev] = categories[cat].get(sev, 0) + 1

        items = []
        for cat, counts in categories.items():
            for sev, count in counts.items():
                items.append(RiskItem(
                    category=cat,
                    severity=sev,
                    count=count,
                    description=f"{count} finding(s) de severidad {sev} en {cat}",
                ))
        return items
