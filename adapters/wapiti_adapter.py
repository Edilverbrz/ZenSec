"""Adaptador de Wapiti para los comandos 19-21 de la matriz."""

from __future__ import annotations

from .base import AdapterCommand, BaseAdapter


class WapitiAdapter(BaseAdapter):
    """Construye las auditorías de aplicaciones web."""

    tool = "wapiti"

    def default_scan(self) -> AdapterCommand:
        return AdapterCommand(
            ("wapiti", "-u", self.target, "-o", "wapiti.txt"),
            "[19/21] Wapiti - Auditoría web por defecto",
        )

    def https_scan(self) -> AdapterCommand:
        return AdapterCommand(
            ("wapiti", "-u", self.https_url, "-o", "wapitihttps.txt"),
            "[20/21] Wapiti - Auditoría HTTPS",
        )

    def http_scan(self) -> AdapterCommand:
        return AdapterCommand(
            ("wapiti", "-u", self.http_url, "-o", "wapitihttp.txt"),
            "[21/21] Wapiti - Auditoría HTTP",
        )

    def commands(self) -> tuple[AdapterCommand, ...]:
        return (self.default_scan(), self.https_scan(), self.http_scan())
