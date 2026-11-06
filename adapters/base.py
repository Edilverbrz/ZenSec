"""Infraestructura común de los adaptadores de ZecSec.

Un adaptador describe los comandos de una herramienta como listas de
argumentos, nunca como cadenas de shell. La ejecución real queda centralizada
en el orquestador, que recibe el helper ``run_command`` por inyección.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core.validation import normalize_ports, parse_target


@dataclass(frozen=True)
class AdapterCommand:
    """Comando generado por un adaptador, listo para el orquestador."""

    command: tuple[str, ...]
    description: str
    output_file: Optional[str] = None

    def __post_init__(self) -> None:
        if isinstance(self.command, str):
            raise TypeError(
                "command debe ser una secuencia de argumentos, no una cadena."
            )

        normalized = tuple(str(part) for part in self.command)
        if not normalized or any(not part for part in normalized):
            raise ValueError(
                "command debe contener al menos un argumento no vacío."
            )
        if not self.description:
            raise ValueError("description no puede estar vacía.")

        object.__setattr__(self, "command", normalized)


class BaseAdapter:
    """Base para los wrappers de herramientas de auditoría."""

    tool: str = ""

    def __init__(self, target: str, ports: str = "") -> None:
        self.address = parse_target(target)
        self.target = self.address.compressed
        self.ports = normalize_ports(ports)

    @property
    def host(self) -> str:
        """Dirección lista para URLs, con corchetes si es IPv6."""
        if self.address.version == 6:
            return f"[{self.target}]"
        return self.target

    @property
    def http_url(self) -> str:
        return f"http://{self.host}"

    @property
    def https_url(self) -> str:
        return f"https://{self.host}"

    def commands(self) -> tuple[AdapterCommand, ...]:
        """Devuelve todos los comandos del adaptador en orden de matriz."""
        raise NotImplementedError

    def _require_ports(self) -> str:
        if not self.ports:
            raise ValueError(
                f"{self.tool}: se requiere un listado de puertos para "
                "este comando."
            )
        return self.ports
