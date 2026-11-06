"""Pruebas del gestor VPN con procesos simulados."""

import pathlib
import tempfile
import threading
import unittest
from unittest import mock

from core.vpn_manager import VPNManager


class BlockingStream:
    def __init__(self, output):
        self._lines = output.splitlines(keepends=True)
        self._closed = threading.Event()

    def readline(self):
        if self._lines:
            return self._lines.pop(0)
        self._closed.wait(timeout=5)
        return ""

    def close(self):
        self._closed.set()


class FakeProcess:
    def __init__(self, command, output, returncode=None):
        self.args = command
        self.pid = 4321
        self.stdout = BlockingStream(output)
        self._returncode = returncode
        self.terminated = False
        self.killed = False

    def poll(self):
        return self._returncode

    def wait(self, timeout=None):
        if self._returncode is None:
            self._returncode = 0
        return self._returncode

    def terminate(self):
        self.terminated = True
        self._returncode = 0
        self.stdout.close()

    def kill(self):
        self.killed = True
        self._returncode = -9
        self.stdout.close()


class VPNManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.config = pathlib.Path(self.temp_dir.name) / "vpn.conf"
        self.config.write_text(
            "host = vpn.example.com\n",
            encoding="utf-8",
        )
        self.messages = []

    def test_connect_verify_and_disconnect(self):
        created_processes = []

        def fake_popen(command, **kwargs):
            self.assertNotIn("shell", kwargs)
            process = FakeProcess(
                command,
                "INFO: Tunnel is up and running\n",
            )
            created_processes.append(process)
            return process

        manager = VPNManager(
            config_path=self.config,
            username="auditor",
            log_callback=self.messages.append,
        )

        with mock.patch(
            "core.vpn_manager.shutil.which",
            return_value="/usr/bin/openfortivpn",
        ):
            with mock.patch(
                "core.vpn_manager.subprocess.Popen",
                side_effect=fake_popen,
            ):
                self.assertTrue(manager.connect(timeout=2.0))
                self.assertTrue(manager.verify())
                self.assertTrue(manager.is_connected)
                self.assertEqual(manager.pid, 4321)
                self.assertTrue(manager.disconnect(timeout=2.0))
                self.assertFalse(manager.is_connected)

        self.assertTrue(created_processes)
        command = created_processes[0].args
        self.assertEqual(command[0], "/usr/bin/openfortivpn")
        self.assertEqual(
            command[1:3],
            ["-c", str(self.config.resolve())],
        )
        self.assertEqual(command[3:5], ["-u", "auditor"])
        self.assertTrue(
            any(
                "Túnel VPN establecido" in message
                for message in self.messages
            )
        )
        self.assertTrue(
            any(
                "Conexión VPN activa y verificada" in message
                for message in self.messages
            )
        )
        self.assertTrue(
            any(
                "Túnel VPN cerrado" in message
                for message in self.messages
            )
        )

    def test_connection_failure(self):
        process = FakeProcess(
            ["openfortivpn"],
            "ERROR: could not connect\n",
            returncode=1,
        )
        manager = VPNManager(
            config_path=self.config,
            log_callback=self.messages.append,
        )

        with mock.patch(
            "core.vpn_manager.shutil.which",
            return_value="/usr/bin/openfortivpn",
        ):
            with mock.patch(
                "core.vpn_manager.subprocess.Popen",
                return_value=process,
            ):
                self.assertFalse(manager.connect(timeout=0.5))

        self.assertTrue(
            any(
                "terminó antes de establecer" in message
                for message in self.messages
            )
        )

    def test_check_prerequisites(self):
        missing_config = (
            pathlib.Path(self.temp_dir.name) / "no-existe.conf"
        )
        manager = VPNManager(
            config_path=missing_config,
            log_callback=self.messages.append,
        )

        with mock.patch(
            "core.vpn_manager.shutil.which",
            return_value=None,
        ):
            self.assertFalse(manager.check_prerequisites())
        self.assertTrue(
            any(
                "No se encontró el binario" in message
                for message in self.messages
            )
        )

        with mock.patch(
            "core.vpn_manager.shutil.which",
            return_value="/usr/bin/openfortivpn",
        ):
            self.assertFalse(manager.check_prerequisites())
        self.assertTrue(
            any(
                "No existe el archivo" in message
                for message in self.messages
            )
        )


if __name__ == "__main__":
    unittest.main()
