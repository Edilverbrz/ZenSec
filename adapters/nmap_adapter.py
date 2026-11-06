"""Adaptador de Nmap para los comandos 3, 4 y 5 de la matriz."""

from __future__ import annotations

from .base import AdapterCommand, BaseAdapter


class NmapAdapter(BaseAdapter):
    """Construye los comandos de descubrimiento y análisis de red."""

    tool = "nmap"

    def vulnerability_scan(self) -> AdapterCommand:
        return AdapterCommand(
            (
                "nmap",
                "-sV",
                "--script",
                "Vuln",
                "-p-",
                "-T4",
                "-oN",
                "nmap_vuln.txt",
                self.target,
            ),
            "[3/21] Nmap - Escaneo completo de puertos y vulnerabilidades",
        )

    def service_inventory(self) -> AdapterCommand:
        return AdapterCommand(
            ("nmap", "-sV", "-oN", "puertostodos.txt", self.target),
            "[4/21] Nmap - Inventario de puertos y servicios",
        )

    def specific_ports(self) -> AdapterCommand:
        ports = self._require_ports()
        return AdapterCommand(
            (
                "nmap",
                "-p",
                ports,
                "-oN",
                "puertosespecificos.txt",
                self.target,
            ),
            "[5/21] Nmap - Puertos específicos",
        )

    def commands(self) -> tuple[AdapterCommand, ...]:
        specs = [self.vulnerability_scan(), self.service_inventory()]
        if self.ports:
            specs.append(self.specific_ports())
        return tuple(specs)
