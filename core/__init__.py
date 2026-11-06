"""Núcleo desacoplado de ZecSec.

Las exportaciones son perezosas para evitar ciclos de importación entre
``core`` y ``adapters``: los adaptadores usan ``core.validation`` y el
orquestador usa los adaptadores.
"""

from __future__ import annotations

import importlib
from typing import Any

__all__ = [
    "AuditCommand",
    "AuditConfig",
    "AuditOrchestrator",
    "AuditPhase",
    "AuditResult",
    "VPNManager",
]

_ORCHESTRATOR_EXPORTS = {
    "AuditCommand",
    "AuditConfig",
    "AuditOrchestrator",
    "AuditPhase",
    "AuditResult",
}


def __getattr__(name: str) -> Any:
    if name in _ORCHESTRATOR_EXPORTS:
        module = importlib.import_module(".orchestrator", __name__)
        return getattr(module, name)

    if name == "VPNManager":
        module = importlib.import_module(".vpn_manager", __name__)
        return getattr(module, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)
