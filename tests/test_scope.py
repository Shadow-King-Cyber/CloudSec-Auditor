"""Tests para el gestor de scope."""

import tempfile
from pathlib import Path
from cloud_sec_auditor.core.scope import ScopeManager


def test_default_scope():
    with tempfile.TemporaryDirectory() as tmp:
        scope = ScopeManager(Path(tmp) / "scope.json")
        assert not scope.is_authorized()


def test_set_authorized():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "scope.json"
        scope = ScopeManager(path)
        scope.set_authorized(True)
        scope.save()
        scope2 = ScopeManager(path)
        assert scope2.is_authorized()


def test_set_accounts():
    with tempfile.TemporaryDirectory() as tmp:
        scope = ScopeManager(Path(tmp) / "scope.json")
        scope.set_accounts(["123456789012"])
        assert scope.get_accounts() == ["123456789012"]


def test_require_authorization_raises():
    with tempfile.TemporaryDirectory() as tmp:
        scope = ScopeManager(Path(tmp) / "scope.json")
        try:
            scope.require_authorization()
            assert False
        except PermissionError:
            pass


def test_require_authorization_ok():
    with tempfile.TemporaryDirectory() as tmp:
        scope = ScopeManager(Path(tmp) / "scope.json")
        scope.set_authorized(True)
        scope.require_authorization()
