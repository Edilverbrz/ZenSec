"""Gestión segura del túnel VPN mediante openfortivpn.

El módulo no depende de CustomTkinter ni de la GUI. Los eventos relevantes se
comunican mediante un callback de log, por lo que puede reutilizarse desde la
interfaz gráfica o desde un script de terminal.

Nota de privilegios: este módulo no ejecuta ``sudo`` ni almacena contraseñas.
El proceso hereda los privilegios del usuario que lanza ZecSec; si
``openfortivpn`` requiere root, la aplicación debe ejecutarse con los permisos
adecuados o configurar ``sudoers`` de forma restringida.
"""

from __future__ import annotations

import logging
import shlex
import shutil
import stat
import subprocess
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)

LogCallback = Callable[[str], None]


class VPNManager:
    """Encapsula el ciclo de vida del proceso openfortivpn."""

    CONNECTION_MARKER = "tunnel is up and running"

    def __init__(
        self,
        config_path: str | Path = "~/vpn.conf",
        username: Optional[str] = None,
        binary: str = "openfortivpn",
        log_callback: Optional[LogCallback] = None,
        max_recent_lines: int = 200,
    ) -> None:
        self.config_path = Path(config_path).expanduser().resolve()
        self.username = (
            username.strip() if username and username.strip() else None
        )
        self.binary = binary
        self._log_callback = log_callback
        self._process: Optional[subprocess.Popen[str]] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._connected = threading.Event()
        self._stop_requested = threading.Event()
        self._lock = threading.Lock()
        self._recent_output: deque[str] = deque(maxlen=max_recent_lines)

    def __enter__(self) -> "VPNManager":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.disconnect()

    @property
    def pid(self) -> Optional[int]:
        process = self._process
        if process is None or process.poll() is not None:
            return None
        return process.pid

    @property
    def is_running(self) -> bool:
        process = self._process
        return process is not None and process.poll() is None

    @property
    def is_connected(self) -> bool:
        return self.is_running and self._connected.is_set()

    @property
    def recent_output(self) -> tuple[str, ...]:
        """Últimas líneas recibidas de openfortivpn (útil para diagnóstico)."""
        return tuple(self._recent_output)

    def check_prerequisites(self) -> bool:
        """Valida el binario, el archivo de configuración y sus permisos."""
        if shutil.which(self.binary) is None:
            self._emit(
                f"[✘] No se encontró el binario '{self.binary}' en el PATH."
            )
            return False

        if not self.config_path.is_file():
            self._emit(
                "[✘] No existe el archivo de configuración VPN: "
                f"{self.config_path}"
            )
            return False

        self._warn_if_permissions_too_open()
        return True

    def verify(self) -> bool:
        """Comprueba que el proceso siga vivo y el túnel esté establecido."""
        process = self._process
        if process is None:
            self._emit("[⚠] No hay un proceso VPN en ejecución.")
            return False

        returncode = process.poll()
        if returncode is not None:
            self._emit(
                "[✘] openfortivpn no está en ejecución "
                f"(código de salida {returncode})."
            )
            return False

        if not self._connected.is_set():
            self._emit(
                "[⚠] openfortivpn está en ejecución, pero el túnel aún no "
                "ha sido verificado."
            )
            return False

        self._emit("[✔] Conexión VPN activa y verificada.")
        return True

    def connect(self, timeout: float = 30.0) -> bool:
        """Inicia openfortivpn y espera a que el túnel esté operativo.

        Debe invocarse desde un hilo secundario en aplicaciones con interfaz
        gráfica, ya que la espera es bloqueante.
        """
        with self._lock:
            if self.is_running:
                if self._connected.is_set():
                    self._emit("[+] La VPN ya está conectada.")
                    return True
                self._emit(
                    "[⚠] openfortivpn ya está en ejecución, pero la conexión "
                    "todavía no se ha verificado."
                )
                return False

            if not self.check_prerequisites():
                return False

            binary_path = shutil.which(self.binary)
            if binary_path is None:
                self._emit(
                    f"[✘] No se encontró el binario '{self.binary}' en el PATH."
                )
                return False

            command = self._build_command(binary_path)
            self._connected.clear()
            self._stop_requested.clear()
            self._recent_output.clear()

            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                )
            except OSError as error:
                self._emit(f"[✘] No se pudo iniciar openfortivpn: {error}")
                return False

            self._process = process
            self._reader_thread = threading.Thread(
                target=self._read_output,
                args=(process,),
                name="zecsec-vpn-reader",
                daemon=True,
            )
            self._reader_thread.start()

        self._emit(
            f"[+] openfortivpn iniciado con el PID {process.pid}: "
            f"{shlex.join(command)}"
        )

        if self._wait_for_connection(timeout):
            return True

        self.disconnect()
        return False

    def disconnect(self, timeout: float = 5.0) -> bool:
        """Solicita el cierre ordenado del proceso openfortivpn."""
        with self._lock:
            process = self._process
            reader = self._reader_thread

            if process is None:
                self._connected.clear()
                self._emit("[+] No hay una conexión VPN activa.")
                return True

            self._stop_requested.set()
            self._emit("[+] Cerrando túnel VPN...")

            if process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    self._emit(
                        "[⚠] openfortivpn no respondió al cierre ordenado; "
                        "se fuerza la terminación."
                    )
                    try:
                        process.kill()
                        process.wait(timeout=timeout)
                    except (OSError, subprocess.TimeoutExpired) as error:
                        self._emit(
                            f"[✘] No se pudo terminar openfortivpn: {error}"
                        )
                except OSError as error:
                    self._emit(f"[✘] Error al cerrar openfortivpn: {error}")

            if reader is not None and reader is not threading.current_thread():
                reader.join(timeout=timeout)
                if reader.is_alive():
                    self._emit(
                        "[⚠] El hilo lector de openfortivpn no finalizó a tiempo."
                    )

            returncode = process.poll()
            self._process = None
            self._reader_thread = None
            self._connected.clear()
            self._stop_requested.clear()

        if returncode is None:
            self._emit(
                "[⚠] El proceso VPN sigue activo tras el intento de cierre."
            )
            return False

        self._emit(f"[✔] Túnel VPN cerrado (código de salida {returncode}).")
        return True

    def _build_command(self, binary_path: str) -> list[str]:
        command = [binary_path, "-c", str(self.config_path)]
        if self.username is not None:
            command.extend(["-u", self.username])
        return command

    def _read_output(self, process: subprocess.Popen[str]) -> None:
        if process.stdout is None:
            return

        try:
            for line in iter(process.stdout.readline, ""):
                text = line.rstrip("\r\n")
                if not text:
                    continue

                self._recent_output.append(text)
                self._emit(f"    {text}")

                if self.CONNECTION_MARKER in text.lower():
                    self._connected.set()
        except (OSError, ValueError) as error:
            self._emit(
                f"[⚠] Error al leer la salida de openfortivpn: {error}"
            )
        finally:
            try:
                process.stdout.close()
            except OSError:
                pass

            returncode = process.poll()
            if returncode is None:
                returncode = process.wait()

            self._connected.clear()
            if not self._stop_requested.is_set():
                self._emit(
                    "[⚠] openfortivpn finalizó inesperadamente "
                    f"(código de salida {returncode})."
                )

    def _wait_for_connection(self, timeout: float) -> bool:
        deadline = time.monotonic() + max(timeout, 0.0)

        while time.monotonic() < deadline:
            if self._connected.is_set():
                self._emit("[✔] Túnel VPN establecido y verificado.")
                return True

            process = self._process
            if process is None:
                return False

            returncode = process.poll()
            if returncode is not None:
                self._emit(
                    "[✘] openfortivpn terminó antes de establecer el túnel "
                    f"(código de salida {returncode})."
                )
                return False

            time.sleep(0.2)

        self._emit(
            f"[⚠] Se agotó el tiempo de espera ({timeout:.0f}s) sin confirmar "
            "el túnel VPN."
        )
        return False

    def _warn_if_permissions_too_open(self) -> None:
        try:
            mode = self.config_path.stat().st_mode
        except OSError as error:
            self._emit(
                "[⚠] No se pudieron comprobar los permisos de "
                f"{self.config_path}: {error}"
            )
            return

        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            self._emit(
                "[⚠] El archivo VPN es accesible por grupo u otros usuarios. "
                f"Se recomienda ejecutar: chmod 600 {self.config_path}"
            )

    def _emit(self, message: str) -> None:
        if self._log_callback is None:
            logger.info(message)
            return

        try:
            self._log_callback(message)
        except Exception:
            logger.exception("Error al enviar un mensaje de log de VPN")
