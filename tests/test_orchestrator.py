"""Pruebas del orquestador: configuración, fases, ejecución y VPN."""

import tempfile
import unittest
from pathlib import Path

from core.orchestrator import (
    AuditConfig,
    AuditOrchestrator,
    AuditResult,
)


class RecordingRunner:
    def __init__(self, codes=None):
        self.codes = list(codes or [])
        self.calls = []

    def __call__(self, command, description, cwd=None, output_file=None):
        self.calls.append(
            {
                "command": list(command),
                "description": description,
                "cwd": Path(cwd),
                "output_file": output_file,
            }
        )
        return self.codes.pop(0) if self.codes else 0


class FakeVPN:
    def __init__(
        self,
        connected=False,
        connect_ok=True,
        disconnect_error=None,
    ):
        self.is_connected = connected
        self.connect_ok = connect_ok
        self.disconnect_error = disconnect_error
        self.connect_calls = 0
        self.disconnect_calls = 0

    def connect(self, timeout=30.0):
        self.connect_calls += 1
        self.is_connected = self.connect_ok
        return self.connect_ok

    def disconnect(self, timeout=5.0):
        self.disconnect_calls += 1
        if self.disconnect_error:
            raise self.disconnect_error
        return True


class AuditConfigTests(unittest.TestCase):
    def test_rejects_invalid_ip(self):
        with self.assertRaises(ValueError):
            AuditConfig(target="10.0.0.999")

    def test_normalizes_ports(self):
        self.assertEqual(
            AuditConfig(target=" 10.0.0.5 ", ports="80, 443").ports,
            "80,443",
        )
        self.assertEqual(
            AuditConfig(target="10.0.0.5", ports="1-1024").ports,
            "1-1024",
        )
        self.assertEqual(AuditConfig(target="10.0.0.5").ports, "")

    def test_rejects_invalid_ports(self):
        for ports in (
            "0",
            "65536",
            "70000",
            "443-80",
            "80,,443",
            "abc",
            "80;443",
            "1-70000",
        ):
            with self.subTest(ports=ports):
                with self.assertRaises(ValueError):
                    AuditConfig(target="10.0.0.5", ports=ports)

    def test_folder_names(self):
        self.assertEqual(
            AuditConfig(target="10.0.0.5").folder_name,
            "recon_10_0_0_5",
        )
        self.assertEqual(
            AuditConfig(target="::1").folder_name,
            "recon___1",
        )


class PhaseTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def test_phase_names_and_counts_with_ports(self):
        config = AuditConfig(
            target="192.168.1.10",
            ports="80,443,8080",
            output_root=self.root,
        )
        phases = AuditOrchestrator(
            run_command=lambda *args, **kwargs: 0
        ).build_phases(config)

        self.assertEqual(
            [phase.name for phase in phases],
            ["Red", "Web", "Vulnerabilidades"],
        )
        self.assertEqual(
            [len(phase.commands) for phase in phases],
            [3, 4, 12],
        )
        labels = [
            "[" + command.description.split("]")[0].lstrip("[") + "]"
            for phase in phases
            for command in phase.commands
        ]
        self.assertEqual(
            labels, [f"[{index}/21]" for index in range(3, 22)]
        )

    def test_phase_counts_without_ports(self):
        config = AuditConfig(
            target="192.168.1.10",
            output_root=self.root,
        )
        phases = AuditOrchestrator(
            run_command=lambda *args, **kwargs: 0
        ).build_phases(config)

        self.assertEqual(
            [len(phase.commands) for phase in phases],
            [2, 3, 12],
        )
        self.assertEqual(
            sum(len(phase.commands) for phase in phases),
            17,
        )

    def test_prepare_output_directory(self):
        config = AuditConfig(
            target="192.168.1.10",
            output_root=self.root,
        )
        output_dir = AuditOrchestrator(
            run_command=lambda *args, **kwargs: 0
        ).prepare_output_directory(config)

        self.assertEqual(
            output_dir, self.root / "recon_192_168_1_10"
        )
        self.assertTrue(output_dir.is_dir())


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def test_run_with_mixed_results(self):
        messages = []
        runner = RecordingRunner([0] * 18 + [1])
        orchestrator = AuditOrchestrator(
            runner,
            log_callback=messages.append,
        )
        config = AuditConfig(
            target="10.20.30.40",
            ports="80,443",
            output_root=self.root,
        )

        result = orchestrator.run(config)

        self.assertIsInstance(result, AuditResult)
        self.assertTrue(result.completed)
        self.assertEqual(result.total_commands, 19)
        self.assertEqual(result.succeeded, 18)
        self.assertEqual(result.warned, 1)
        self.assertEqual(result.failed, 0)
        self.assertEqual(
            result.output_dir,
            self.root / "recon_10_20_30_40",
        )
        self.assertEqual(len(runner.calls), 19)

        for call in runner.calls:
            self.assertEqual(call["cwd"], result.output_dir)
            self.assertIsInstance(call["command"], list)

        sqlmap_calls = [
            call
            for call in runner.calls
            if call["command"][0] == "sqlmap"
        ]
        self.assertEqual(len(sqlmap_calls), 6)
        self.assertTrue(
            all(call["output_file"] for call in sqlmap_calls)
        )
        self.assertEqual(sqlmap_calls[0]["output_file"], "sqlmap.txt")
        self.assertEqual(sqlmap_calls[1]["output_file"], "sqlmaps.txt")

        nmap_commands = [
            call["command"]
            for call in runner.calls
            if call["command"][0] == "nmap"
        ]
        self.assertEqual(nmap_commands[0][-1], "10.20.30.40")
        self.assertEqual(
            nmap_commands[2][:3],
            ["nmap", "-p", "80,443"],
        )

        self.assertTrue(
            any("Fase 1/4: Inicialización" in m for m in messages)
        )
        self.assertTrue(
            any("Fase 2/4: Red" in m for m in messages)
        )
        self.assertTrue(
            any("Fase 3/4: Web" in m for m in messages)
        )
        self.assertTrue(
            any("Fase 4/4: Vulnerabilidades" in m for m in messages)
        )
        self.assertTrue(any("18 éxito(s)" in m for m in messages))

    def test_run_without_ports(self):
        runner = RecordingRunner()
        orchestrator = AuditOrchestrator(runner)

        result = orchestrator.run(
            AuditConfig(target="10.0.0.9", output_root=self.root)
        )

        self.assertEqual(result.total_commands, 17)
        self.assertEqual(result.succeeded, 17)
        self.assertTrue(result.completed)
        self.assertTrue(
            all(
                call["command"][0] not in {"nmap", "nikto"}
                or "-p" not in call["command"]
                for call in runner.calls
            )
        )

    def test_run_counts_warnings(self):
        messages = []
        runner = RecordingRunner([0, 2, 127, 3])
        orchestrator = AuditOrchestrator(
            runner,
            log_callback=messages.append,
        )

        result = orchestrator.run(
            AuditConfig(target="10.0.0.7", output_root=self.root)
        )

        self.assertEqual(result.total_commands, 17)
        self.assertEqual(result.succeeded, 14)
        self.assertEqual(result.warned, 3)
        self.assertEqual(result.failed, 0)
        self.assertTrue(result.completed)
        self.assertTrue(any("código 2" in m for m in messages))
        self.assertTrue(any("código 127" in m for m in messages))

    def test_runner_exception_is_counted_as_failure(self):
        class ExplodingRunner:
            def __call__(
                self,
                command,
                description,
                cwd=None,
                output_file=None,
            ):
                raise RuntimeError("fallo simulado")

        messages = []
        orchestrator = AuditOrchestrator(
            ExplodingRunner(),
            log_callback=messages.append,
        )

        result = orchestrator.run(
            AuditConfig(target="10.0.0.7", output_root=self.root)
        )

        self.assertTrue(result.completed)
        self.assertEqual(result.failed, 17)
        self.assertTrue(any("fallo simulado" in m for m in messages))


class VPNAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def test_failed_vpn_cancels_audit(self):
        vpn = FakeVPN(connect_ok=False)
        runner = RecordingRunner()
        messages = []
        orchestrator = AuditOrchestrator(
            runner,
            log_callback=messages.append,
            vpn_manager=vpn,
        )

        result = orchestrator.run(
            AuditConfig(
                target="10.0.0.8",
                use_vpn=True,
                output_root=self.root,
            )
        )

        self.assertFalse(result.completed)
        self.assertEqual(result.total_commands, 0)
        self.assertEqual(vpn.connect_calls, 1)
        self.assertEqual(vpn.disconnect_calls, 0)
        self.assertEqual(runner.calls, [])
        self.assertTrue((self.root / "recon_10_0_0_8").is_dir())
        self.assertTrue(
            any("Auditoría cancelada" in m for m in messages)
        )

    def test_started_vpn_is_disconnected(self):
        vpn = FakeVPN(connect_ok=True)
        orchestrator = AuditOrchestrator(
            RecordingRunner(),
            vpn_manager=vpn,
        )

        result = orchestrator.run(
            AuditConfig(
                target="10.0.0.8",
                use_vpn=True,
                output_root=self.root,
            )
        )

        self.assertTrue(result.completed)
        self.assertTrue(result.vpn_used)
        self.assertEqual(vpn.connect_calls, 1)
        self.assertEqual(vpn.disconnect_calls, 1)

    def test_preexisting_vpn_is_not_disconnected(self):
        vpn = FakeVPN(connected=True)
        orchestrator = AuditOrchestrator(
            RecordingRunner(),
            vpn_manager=vpn,
        )

        result = orchestrator.run(
            AuditConfig(
                target="10.0.0.8",
                use_vpn=True,
                output_root=self.root,
            )
        )

        self.assertTrue(result.completed)
        self.assertEqual(vpn.connect_calls, 0)
        self.assertEqual(vpn.disconnect_calls, 0)

    def test_disconnect_error_does_not_break_audit(self):
        vpn = FakeVPN(
            connect_ok=True,
            disconnect_error=OSError("sin permisos"),
        )
        messages = []
        orchestrator = AuditOrchestrator(
            RecordingRunner(),
            log_callback=messages.append,
            vpn_manager=vpn,
        )

        result = orchestrator.run(
            AuditConfig(
                target="10.0.0.8",
                use_vpn=True,
                output_root=self.root,
            )
        )

        self.assertTrue(result.completed)
        self.assertTrue(
            any("No se pudo cerrar la VPN" in m for m in messages)
        )


if __name__ == "__main__":
    unittest.main()
