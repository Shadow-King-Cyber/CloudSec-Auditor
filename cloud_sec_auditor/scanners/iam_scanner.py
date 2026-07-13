"""Escáner de IAM — usuarios, roles, políticas."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class IAMFinding:
    """Resultado de auditoría IAM."""
    resource_type: str
    resource_name: str
    issue: str
    severity: str
    recommendation: str


class IAMScanner:
    """Audita configuración de IAM en entornos cloud."""

    def check_root_mfa(self, root_account: dict) -> IAMFinding | None:
        if not root_account.get("mfa_enabled", False):
            return IAMFinding(
                resource_type="root",
                resource_name=root_account.get("arn", "unknown"),
                issue="Root account sin MFA",
                severity="Critico",
                recommendation="Habilitar MFA en la cuenta root inmediatamente",
            )
        return None

    def check_user_mfa(self, user: dict) -> IAMFinding | None:
        if not user.get("mfa_enabled", False):
            return IAMFinding(
                resource_type="user",
                resource_name=user.get("name", "unknown"),
                issue="Usuario sin MFA",
                severity="Alto",
                recommendation=f"Habilitar MFA para el usuario {user.get('name', 'desconocido')}",
            )
        return None

    def check_excessive_permissions(self, user: dict) -> IAMFinding | None:
        policies = user.get("policies", [])
        if "*" in policies:
            return IAMFinding(
                resource_type="user",
                resource_name=user.get("name", "unknown"),
                issue="Política admin excesiva",
                severity="Critico",
                recommendation=f"Usuario {user.get('name')} tiene permisos de administrador — aplicar least privilege",
            )
        return None

    def check_access_keys(self, user: dict) -> IAMFinding | None:
        keys = user.get("access_keys", [])
        if len(keys) > 1:
            return IAMFinding(
                resource_type="user",
                resource_name=user.get("name", "unknown"),
                issue="Múltiples access keys",
                severity="Medio",
                recommendation="Rotar y eliminar access keys excesivas",
            )
        return None

    def audit_user(self, user: dict) -> list[IAMFinding]:
        findings = []
        mfa = self.check_user_mfa(user)
        if mfa:
            findings.append(mfa)
        perms = self.check_excessive_permissions(user)
        if perms:
            findings.append(perms)
        keys = self.check_access_keys(user)
        if keys:
            findings.append(keys)
        return findings
