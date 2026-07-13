"""Escáner de Security Groups / NSGs."""

from __future__ import annotations

from dataclasses import dataclass

from ..core.config import Config


@dataclass
class SGFinding:
    """Resultado de auditoría de un Security Group."""
    group_name: str
    protocol: str
    port: str
    source: str
    is_open: bool
    is_risky: bool
    severity: str
    recommendation: str


class SGScanner:
    """Audita reglas de Security Groups en entornos cloud."""

    def __init__(self) -> None:
        self.config = Config()

    def scan_rule(self, rule: dict, group_name: str = "default") -> SGFinding:
        source = rule.get("source", "0.0.0.0/0")
        port = str(rule.get("port", ""))
        protocol = rule.get("protocol", "tcp")
        is_open = source in ["0.0.0.0/0", "::/0"]
        is_risky = is_open and port in self.config.SG_OPEN_PORTS

        if is_risky:
            severity = "Critico"
            recommendation = self.config.SG_OPEN_PORTS[port]
        elif is_open:
            severity = "Medio"
            recommendation = f"Puerto {port} abierto a 0.0.0.0/0 — restringir a IPs específicas"
        else:
            severity = "OK"
            recommendation = "Regla correcta"

        return SGFinding(
            group_name=group_name,
            protocol=protocol,
            port=port,
            source=source,
            is_open=is_open,
            is_risky=is_risky,
            severity=severity,
            recommendation=recommendation,
        )

    def scan_rules(self, rules: list[dict], group_name: str = "default") -> list[SGFinding]:
        return [self.scan_rule(r, group_name) for r in rules]

    def get_critical_findings(self, findings: list[SGFinding]) -> list[SGFinding]:
        return [f for f in findings if f.severity == "Critico"]
