"""Adaptador de SQLMap para los comandos 10-15 de la matriz."""

from __future__ import annotations

from .base import AdapterCommand, BaseAdapter


class SQLMapAdapter(BaseAdapter):
    """Construye las pruebas automatizadas de inyección SQL."""

    tool = "sqlmap"

    def http_basic(self) -> AdapterCommand:
        return AdapterCommand(
            ("sqlmap", "-u", self.http_url, "--batch"),
            "[10/21] SQLMap - HTTP básico",
            "sqlmap.txt",
        )

    def https_basic(self) -> AdapterCommand:
        return AdapterCommand(
            ("sqlmap", "-u", self.https_url, "--batch"),
            "[11/21] SQLMap - HTTPS básico",
            "sqlmaps.txt",
        )

    def http_crawl(self) -> AdapterCommand:
        return AdapterCommand(
            (
                "sqlmap",
                "-u",
                self.http_url,
                "--crawl=2",
                "--forms",
                "--batch",
                "--dbms=postgresql",
                "--level=3",
                "--risk=2",
            ),
            "[12/21] SQLMap - Crawl HTTP (formularios)",
            "sql_crawl2.txt",
        )

    def https_crawl(self) -> AdapterCommand:
        return AdapterCommand(
            (
                "sqlmap",
                "-u",
                self.https_url,
                "--crawl=2",
                "--forms",
                "--batch",
                "--dbms=postgresql",
                "--level=3",
                "--risk=2",
            ),
            "[13/21] SQLMap - Crawl HTTPS (formularios)",
            "sql_crawl2s.txt",
        )

    def http_alternative(self) -> AdapterCommand:
        return AdapterCommand(
            ("sqlmap", "-u", self.http_url, "--batch"),
            "[14/21] SQLMap - HTTP alternativo",
            "sqlmapurl.txt",
        )

    def https_alternative(self) -> AdapterCommand:
        return AdapterCommand(
            ("sqlmap", "-u", self.https_url, "--batch"),
            "[15/21] SQLMap - HTTPS alternativo",
            "sqlmapurls.txt",
        )

    def commands(self) -> tuple[AdapterCommand, ...]:
        return (
            self.http_basic(),
            self.https_basic(),
            self.http_crawl(),
            self.https_crawl(),
            self.http_alternative(),
            self.https_alternative(),
        )
