"""Adaptador de Nuclei para los comandos 17 y 18 de la matriz."""

from __future__ import annotations

from .base import AdapterCommand, BaseAdapter


class NucleiAdapter(BaseAdapter):
    """Construye los escaneos rápidos de vulnerabilidades y paneles."""

    tool = "nuclei"

    def critical_high(self) -> AdapterCommand:
        return AdapterCommand(
            (
                "nuclei",
                "-u",
                self.target,
                "-severity",
                "critical,high",
                "-o",
                "nuclei.txt",
            ),
            "[17/21] Nuclei - Vulnerabilidades críticas/altas",
        )

    def panels(self) -> AdapterCommand:
        return AdapterCommand(
            (
                "nuclei",
                "-u",
                self.target,
                "-tags",
                "panel,login,default-login",
                "-o",
                "nucleitags.txt",
            ),
            "[18/21] Nuclei - Paneles y credenciales por defecto",
        )

    def commands(self) -> tuple[AdapterCommand, ...]:
        return (self.critical_high(), self.panels())
