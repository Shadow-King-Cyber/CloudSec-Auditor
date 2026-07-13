"""Gestión de scope para auditoría de cloud."""

import json
from pathlib import Path
from typing import Any


class ScopeManager:
    """Gestiona el alcance autorizado del auditor cloud."""

    def __init__(self, scope_path: str | Path = "scope.json") -> None:
        self._scope_path = Path(scope_path)
        self._scope = self._load_scope()

    def _load_scope(self) -> dict[str, Any]:
        if self._scope_path.exists():
            return json.loads(self._scope_path.read_text(encoding="utf-8"))
        return {"authorized": False, "accounts": [], "purpose": "", "operator": ""}

    def save(self) -> None:
        self._scope_path.write_text(
            json.dumps(self._scope, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def is_authorized(self) -> bool:
        return self._scope.get("authorized", False)

    def get_accounts(self) -> list[str]:
        return self._scope.get("accounts", [])

    def set_authorized(self, authorized: bool) -> None:
        self._scope["authorized"] = authorized

    def set_accounts(self, accounts: list[str]) -> None:
        self._scope["accounts"] = accounts

    def require_authorization(self) -> None:
        if not self.is_authorized():
            raise PermissionError(
                "Auditoría no autorizada. Configure scope.json con authorized: true"
            )
