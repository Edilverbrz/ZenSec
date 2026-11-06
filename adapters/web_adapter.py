"""Adaptador de Dirb, Nikto y Curl (comandos 6-9 y 16 de la matriz)."""

from __future__ import annotations

from .base import AdapterCommand, BaseAdapter


class WebAdapter(BaseAdapter):
    """Construye los comandos de descubrimiento y auditoría web."""

    tool = "web"

    def dirb_http(self) -> AdapterCommand:
        return AdapterCommand(
            ("dirb", self.http_url, "-o", "dirb.txt"),
            "[6/21] Dirb - Directorios HTTP",
        )

    def dirb_https(self) -> AdapterCommand:
        return AdapterCommand(
            ("dirb", self.https_url, "-o", "dirbs.txt"),
            "[7/21] Dirb - Directorios HTTPS",
        )

    def nikto_base(self) -> AdapterCommand:
        return AdapterCommand(
            ("nikto", "-h", self.target, "-o", "nikto.txt"),
            "[8/21] Nikto - Vulnerabilidades web HTTP",
        )

    def nikto_ports(self) -> AdapterCommand:
        ports = self._require_ports()
        return AdapterCommand(
            (
                "nikto",
                "-h",
                self.target,
                "-p",
                ports,
                "-o",
                "niktopuertos.txt",
            ),
            "[9/21] Nikto - Puertos web específicos",
        )

    def curl_headers(self) -> AdapterCommand:
        return AdapterCommand(
            ("curl", "-Iv", self.target, "-o", "curl.txt"),
            "[16/21] Curl - Cabeceras y certificados",
        )

    def discovery_commands(self) -> tuple[AdapterCommand, ...]:
        """Comandos 6-9: Dirb y Nikto, sin incluir Curl."""
        specs = [self.dirb_http(), self.dirb_https(), self.nikto_base()]
        if self.ports:
            specs.append(self.nikto_ports())
        return tuple(specs)

    def commands(self) -> tuple[AdapterCommand, ...]:
        """Comandos 6-9 y 16 en el orden de la matriz."""
        return self.discovery_commands() + (self.curl_headers(),)
