"""Módulo core — Scope, auditoría, configuración."""

from .scope import ScopeManager
from .audit_logger import AuditLogger
from .config import Config

__all__ = ["ScopeManager", "AuditLogger", "Config"]
