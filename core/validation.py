"""Validaciones compartidas de objetivos y puertos.

Centraliza el parseo de direcciones IP y la normalización de puertos para
que ``AuditConfig`` y los adaptadores apliquen exactamente las mismas reglas.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

_PORT_PATTERN = re.compile(r"\d+(?:-\d+)?")


def parse_target(target: str) -> IPAddress:
    """Convierte una cadena en una dirección IPv4 o IPv6 validada."""
    cleaned = target.strip()
    try:
        return ipaddress.ip_address(cleaned)
    except ValueError as error:
        raise ValueError(
            f"Dirección IP no válida: {cleaned!r}"
        ) from error


def normalize_ports(ports: str) -> str:
    """Valida y normaliza un listado de puertos.

    Acepta formatos como ``80,443`` o ``1-1024``. Elimina espacios y rechaza
    valores fuera del rango 1-65535, rangos invertidos y sintaxis inválida.
    """
    cleaned = ports.replace(" ", "")
    if not cleaned:
        return ""

    for part in cleaned.split(","):
        if not _PORT_PATTERN.fullmatch(part):
            raise ValueError(
                "El listado de puertos debe usar el formato "
                "'80,443' o '1-1024'."
            )

        bounds = [int(value) for value in part.split("-", maxsplit=1)]
        if any(value < 1 or value > 65535 for value in bounds):
            raise ValueError(
                f"Puerto fuera de rango en {part!r}: "
                "debe estar entre 1 y 65535."
            )
        if len(bounds) == 2 and bounds[0] > bounds[1]:
            raise ValueError(
                f"Rango de puertos inválido en {part!r}: "
                "el inicio no puede ser mayor que el fin."
            )

    return cleaned
