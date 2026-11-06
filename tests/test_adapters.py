"""Pruebas de los adaptadores y de su integración con el orquestador."""

import unittest

from adapters import (
    AdapterCommand,
    NmapAdapter,
    NucleiAdapter,
    SQLMapAdapter,
    WapitiAdapter,
    WebAdapter,
)
from core.orchestrator import AuditConfig, AuditOrchestrator
from core.validation import normalize_ports, parse_target


class AdapterCommandTests(unittest.TestCase):
    def test_normalizes_command_to_tuple(self):
        spec = AdapterCommand(["nmap", "-sV"], "[4/21] Nmap")

        self.assertEqual(spec.command, ("nmap", "-sV"))
        self.assertIsNone(spec.output_file)

    def test_rejects_invalid_commands(self):
        for invalid in ((), ("",), ("nmap", "")):
            with self.subTest(command=invalid):
                with self.assertRaises(ValueError):
                    AdapterCommand(invalid, "desc")

    def test_rejects_shell_string(self):
        with self.assertRaises(TypeError):
            AdapterCommand("nmap -sV", "desc")

    def test_rejects_empty_description(self):
        with self.assertRaises(ValueError):
            AdapterCommand(("nmap",), "")


class ValidationTests(unittest.TestCase):
    def test_parse_target(self):
        self.assertEqual(parse_target(" 10.0.0.5 ").compressed, "10.0.0.5")
        self.assertEqual(parse_target("::1").compressed, "::1")

    def test_normalize_ports(self):
        self.assertEqual(normalize_ports("80, 443"), "80,443")
        self.assertEqual(normalize_ports("1-1024"), "1-1024")
        self.assertEqual(normalize_ports(""), "")

    def test_rejects_invalid_targets(self):
        for invalid in ("10.0.0.999", "localhost", ""):
            with self.subTest(target=invalid):
                with self.assertRaises(ValueError):
                    parse_target(invalid)

    def test_rejects_invalid_ports(self):
        for invalid in ("0", "65536", "443-80", "80,,443", "abc"):
            with self.subTest(ports=invalid):
                with self.assertRaises(ValueError):
                    normalize_ports(invalid)


class AdapterWithPortsTests(unittest.TestCase):
    target = "192.168.1.10"
    ports = "80,443"

    def test_nmap_commands(self):
        commands = NmapAdapter(self.target, self.ports).commands()

        self.assertEqual(len(commands), 3)
        self.assertEqual(
            commands[0].command,
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
        )
        self.assertEqual(
            commands[1].command,
            ("nmap", "-sV", "-oN", "puertostodos.txt", self.target),
        )
        self.assertEqual(
            commands[2].command,
            (
                "nmap",
                "-p",
                self.ports,
                "-oN",
                "puertosespecificos.txt",
                self.target,
            ),
        )

    def test_web_commands(self):
        adapter = WebAdapter(self.target, self.ports)

        self.assertEqual(len(adapter.discovery_commands()), 4)
        self.assertEqual(len(adapter.commands()), 5)
        self.assertEqual(
            adapter.discovery_commands()[0].command,
            ("dirb", "http://192.168.1.10", "-o", "dirb.txt"),
        )
        self.assertEqual(
            adapter.discovery_commands()[3].command,
            (
                "nikto",
                "-h",
                self.target,
                "-p",
                self.ports,
                "-o",
                "niktopuertos.txt",
            ),
        )
        self.assertEqual(
            adapter.commands()[-1].command,
            ("curl", "-Iv", self.target, "-o", "curl.txt"),
        )

    def test_sqlmap_commands(self):
        commands = SQLMapAdapter(self.target, self.ports).commands()

        self.assertEqual(len(commands), 6)
        self.assertEqual(
            [spec.output_file for spec in commands],
            [
                "sqlmap.txt",
                "sqlmaps.txt",
                "sql_crawl2.txt",
                "sql_crawl2s.txt",
                "sqlmapurl.txt",
                "sqlmapurls.txt",
            ],
        )
        self.assertEqual(
            commands[0].command,
            ("sqlmap", "-u", "http://192.168.1.10", "--batch"),
        )
        self.assertEqual(
            commands[2].command,
            (
                "sqlmap",
                "-u",
                "http://192.168.1.10",
                "--crawl=2",
                "--forms",
                "--batch",
                "--dbms=postgresql",
                "--level=3",
                "--risk=2",
            ),
        )

    def test_nuclei_commands(self):
        commands = NucleiAdapter(self.target, self.ports).commands()

        self.assertEqual(len(commands), 2)
        self.assertEqual(
            commands[0].command,
            (
                "nuclei",
                "-u",
                self.target,
                "-severity",
                "critical,high",
                "-o",
                "nuclei.txt",
            ),
        )
        self.assertEqual(
            commands[1].command,
            (
                "nuclei",
                "-u",
                self.target,
                "-tags",
                "panel,login,default-login",
                "-o",
                "nucleitags.txt",
            ),
        )

    def test_wapiti_commands(self):
        commands = WapitiAdapter(self.target, self.ports).commands()

        self.assertEqual(len(commands), 3)
        self.assertEqual(
            commands[0].command,
            ("wapiti", "-u", self.target, "-o", "wapiti.txt"),
        )
        self.assertEqual(
            commands[1].command,
            (
                "wapiti",
                "-u",
                "https://192.168.1.10",
                "-o",
                "wapitihttps.txt",
            ),
        )
        self.assertEqual(
            commands[2].command,
            (
                "wapiti",
                "-u",
                "http://192.168.1.10",
                "-o",
                "wapitihttp.txt",
            ),
        )


class AdapterWithoutPortsTests(unittest.TestCase):
    target = "192.168.1.10"

    def test_nmap_omits_specific_ports(self):
        adapter = NmapAdapter(self.target)

        self.assertEqual(len(adapter.commands()), 2)
        with self.assertRaises(ValueError):
            adapter.specific_ports()

    def test_web_omits_nikto_ports(self):
        adapter = WebAdapter(self.target)

        self.assertEqual(len(adapter.discovery_commands()), 3)
        self.assertEqual(len(adapter.commands()), 4)
        with self.assertRaises(ValueError):
            adapter.nikto_ports()


class IPv6Tests(unittest.TestCase):
    def test_urls_use_brackets(self):
        adapter = WebAdapter("::1")

        self.assertEqual(adapter.target, "::1")
        self.assertEqual(adapter.host, "[::1]")
        self.assertEqual(adapter.http_url, "http://[::1]")
        self.assertEqual(adapter.https_url, "https://[::1]")
        self.assertEqual(
            adapter.dirb_http().command,
            ("dirb", "http://[::1]", "-o", "dirb.txt"),
        )


class OrchestratorIntegrationTests(unittest.TestCase):
    target = "192.168.1.10"
    ports = "80,443"

    def test_matrix_order_and_exact_commands(self):
        expected = [
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
            ("nmap", "-sV", "-oN", "puertostodos.txt", self.target),
            (
                "nmap",
                "-p",
                self.ports,
                "-oN",
                "puertosespecificos.txt",
                self.target,
            ),
            ("dirb", "http://192.168.1.10", "-o", "dirb.txt"),
            ("dirb", "https://192.168.1.10", "-o", "dirbs.txt"),
            ("nikto", "-h", self.target, "-o", "nikto.txt"),
            (
                "nikto",
                "-h",
                self.target,
                "-p",
                self.ports,
                "-o",
                "niktopuertos.txt",
            ),
            ("sqlmap", "-u", "http://192.168.1.10", "--batch"),
            ("sqlmap", "-u", "https://192.168.1.10", "--batch"),
            (
                "sqlmap",
                "-u",
                "http://192.168.1.10",
                "--crawl=2",
                "--forms",
                "--batch",
                "--dbms=postgresql",
                "--level=3",
                "--risk=2",
            ),
            (
                "sqlmap",
                "-u",
                "https://192.168.1.10",
                "--crawl=2",
                "--forms",
                "--batch",
                "--dbms=postgresql",
                "--level=3",
                "--risk=2",
            ),
            ("sqlmap", "-u", "http://192.168.1.10", "--batch"),
            ("sqlmap", "-u", "https://192.168.1.10", "--batch"),
            ("curl", "-Iv", self.target, "-o", "curl.txt"),
            (
                "nuclei",
                "-u",
                self.target,
                "-severity",
                "critical,high",
                "-o",
                "nuclei.txt",
            ),
            (
                "nuclei",
                "-u",
                self.target,
                "-tags",
                "panel,login,default-login",
                "-o",
                "nucleitags.txt",
            ),
            ("wapiti", "-u", self.target, "-o", "wapiti.txt"),
            (
                "wapiti",
                "-u",
                "https://192.168.1.10",
                "-o",
                "wapitihttps.txt",
            ),
            (
                "wapiti",
                "-u",
                "http://192.168.1.10",
                "-o",
                "wapitihttp.txt",
            ),
        ]

        orchestrator = AuditOrchestrator(lambda *args, **kwargs: 0)
        phases = orchestrator.build_phases(
            AuditConfig(target=self.target, ports=self.ports)
        )
        commands = [
            spec.command for phase in phases for spec in phase.commands
        ]

        self.assertEqual(commands, expected)

    def test_phase_names_and_counts(self):
        orchestrator = AuditOrchestrator(lambda *args, **kwargs: 0)
        phases = orchestrator.build_phases(
            AuditConfig(target=self.target, ports=self.ports)
        )

        self.assertEqual(
            [phase.name for phase in phases],
            ["Red", "Web", "Vulnerabilidades"],
        )
        self.assertEqual(
            [len(phase.commands) for phase in phases],
            [3, 4, 12],
        )
        labels = [
            spec.description.split("]", maxsplit=1)[0] + "]"
            for phase in phases
            for spec in phase.commands
        ]
        self.assertEqual(
            labels, [f"[{index}/21]" for index in range(3, 22)]
        )


if __name__ == "__main__":
    unittest.main()
