"""Orquestador central de las auditorías de ZecSec.

El módulo organiza la ejecución por fases, crea el directorio aislado del
objetivo con ``pathlib.Path`` y delega la ejecución de cada comando en un
callable inyectado. De este modo reutiliza el helper ``run_command`` de la GUI
sin acoplar el núcleo a CustomTkinter.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Protocol, Sequence

from adapters.base import AdapterCommand
from adapters.nmap_adapter import NmapAdapter
from adapters.nuclei_adapter import NucleiAdapter
from adapters.sqlmap_adapter import SQLMapAdapter
from adapters.wapiti_adapter import WapitiAdapter
from adapters.web_adapter import WebAdapter

from .validation import IPAddress, normalize_ports, parse_target
from .vpn_manager import VPNManager

logger = logging.getLogger(__name__)

LogCallback = Callable[[str], None]


class CommandRunner(Protocol):
    """Contrato mínimo que debe cumplir el helper de ejecución."""

    def __call__(
        self,
        command: str | Sequence[str],
        description: str,
        cwd: Optional[Path] = None,
        output_file: Optional[str | Path] = None,
    ) -> int:
        ...


@dataclass
class AuditConfig:
    """Parámetros de entrada de una auditoría."""

    target: str
    ports: str = ""
    use_vpn: bool = False
    vpn_config_path: str | Path = "~/vpn.conf"
    vpn_username: Optional[str] = None
    vpn_timeout: float = 30.0
    output_root: str | Path = field(default_factory=Path.cwd)

    address: IPAddress = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.target = self.target.strip()
        self.address = parse_target(self.target)
        self.ports = normalize_ports(self.ports)
        self.vpn_config_path = Path(self.vpn_config_path).expanduser()
        self.vpn_username = (
            self.vpn_username.strip()
            if self.vpn_username and self.vpn_username.strip()
            else None
        )
        self.output_root = Path(self.output_root).expanduser().resolve()

        if self.vpn_timeout <= 0:
            raise ValueError("vpn_timeout debe ser mayor que cero.")

    @property
    def folder_name(self) -> str:
        return (
            f"recon_{self.address.compressed.replace('.', '_').replace(':', '_')}"
        )


@dataclass(frozen=True)
class AuditCommand:
    """Comando individual de la matriz con su archivo de salida opcional."""

    command: tuple[str, ...]
    description: str
    output_file: Optional[str] = None


@dataclass(frozen=True)
class AuditPhase:
    """Agrupación lógica de comandos dentro del flujo de auditoría."""

    name: str
    commands: tuple[AuditCommand, ...]


@dataclass(frozen=True)
class AuditResult:
    """Resumen del resultado de una ejecución del orquestador."""

    target: str
    output_dir: Optional[Path]
    total_commands: int
    succeeded: int
    warned: int
    failed: int
    vpn_used: bool
    completed: bool
    message: str


class AuditOrchestrator:
    """Coordina las fases de inicialización, red, web y vulnerabilidades."""

    _PHASE_TOTAL = 4

    def __init__(
        self,
        run_command: CommandRunner,
        log_callback: Optional[LogCallback] = None,
        vpn_manager: Optional[VPNManager] = None,
    ) -> None:
        if not callable(run_command):
            raise TypeError("run_command debe ser un callable ejecutable.")

        self._run_command = run_command
        self._log_callback = log_callback
        self._vpn_manager = vpn_manager

    def run(self, config: AuditConfig) -> AuditResult:
        """Ejecuta la auditoría completa de forma secuencial.

        La llamada es bloqueante. En una aplicación con GUI debe invocarse
        desde un hilo secundario para no congelar la ventana.
        """
        output_dir: Optional[Path] = None
        vpn_manager: Optional[VPNManager] = None
        vpn_started = False
        total = succeeded = warned = failed = 0

        try:
            self._log(f"[+] Fase 1/{self._PHASE_TOTAL}: Inicialización")
            try:
                output_dir = self.prepare_output_directory(config)
            except OSError as error:
                self._log(
                    f"[✘] No se pudo crear el directorio de salida: {error}"
                )
                return AuditResult(
                    target=config.target,
                    output_dir=None,
                    total_commands=0,
                    succeeded=0,
                    warned=0,
                    failed=0,
                    vpn_used=config.use_vpn,
                    completed=False,
                    message="No se pudo preparar el directorio de trabajo.",
                )

            self._log(f"[✔] Directorio de trabajo: {output_dir}")

            if config.use_vpn:
                vpn_manager = self._create_vpn_manager(config)
                if vpn_manager.is_connected:
                    self._log("[+] La VPN ya estaba conectada.")
                else:
                    self._log("[+] Estableciendo conexión VPN...")
                    if not vpn_manager.connect(timeout=config.vpn_timeout):
                        self._log(
                            "[✘] No se pudo establecer la VPN. "
                            "Auditoría cancelada."
                        )
                        return AuditResult(
                            target=config.target,
                            output_dir=output_dir,
                            total_commands=0,
                            succeeded=0,
                            warned=0,
                            failed=0,
                            vpn_used=True,
                            completed=False,
                            message="No se pudo establecer la conexión VPN.",
                        )
                    vpn_started = True
            else:
                self._log("[+] VPN desactivada; se usará la conexión actual.")

            phases = self.build_phases(config)
            total = sum(len(phase.commands) for phase in phases)

            if not config.ports:
                self._log(
                    "[⚠] Sin puertos específicos: se omiten los comandos "
                    "Nmap -p y Nikto -p."
                )

            for phase_number, phase in enumerate(phases, start=2):
                if not output_dir.is_dir():
                    self._log(
                        "[✘] Auditoría detenida: el directorio de trabajo "
                        f"ya no existe: {output_dir}"
                    )
                    return AuditResult(
                        target=config.target,
                        output_dir=output_dir,
                        total_commands=total,
                        succeeded=succeeded,
                        warned=warned,
                        failed=failed,
                        vpn_used=config.use_vpn,
                        completed=False,
                        message="El directorio de trabajo dejó de existir.",
                    )

                self._log(
                    f"[+] Fase {phase_number}/{self._PHASE_TOTAL}: {phase.name}"
                )
                for spec in phase.commands:
                    returncode = self._execute_command(spec, output_dir)
                    if returncode == 0:
                        succeeded += 1
                    elif returncode < 0:
                        failed += 1
                    else:
                        warned += 1
                        self._log(
                            f"[⚠] El comando terminó con código {returncode}; "
                            "se continúa con el siguiente."
                        )

            message = self._summary_message(
                total, succeeded, warned, failed
            )
            self._log(message)
            return AuditResult(
                target=config.target,
                output_dir=output_dir,
                total_commands=total,
                succeeded=succeeded,
                warned=warned,
                failed=failed,
                vpn_used=config.use_vpn,
                completed=True,
                message=message,
            )
        except Exception as error:
            self._log(f"[✘] Error inesperado en el orquestador: {error}")
            return AuditResult(
                target=config.target,
                output_dir=output_dir,
                total_commands=total,
                succeeded=succeeded,
                warned=warned,
                failed=failed,
                vpn_used=config.use_vpn,
                completed=False,
                message=f"Error inesperado: {error}",
            )
        finally:
            if vpn_started and vpn_manager is not None:
                self._log("[+] Cerrando la conexión VPN al finalizar...")
                try:
                    vpn_manager.disconnect()
                except Exception as error:
                    self._log(
                        f"[⚠] No se pudo cerrar la VPN correctamente: {error}"
                    )

    def prepare_output_directory(self, config: AuditConfig) -> Path:
        """Crea y devuelve el directorio aislado de la IP objetivo."""
        output_dir = config.output_root / config.folder_name
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    def build_phases(self, config: AuditConfig) -> tuple[AuditPhase, ...]:
        """Construye las fases 2-4 usando los adaptadores de cada herramienta."""
        target = config.address.compressed
        nmap = NmapAdapter(target, config.ports)
        web = WebAdapter(target, config.ports)
        sqlmap = SQLMapAdapter(target, config.ports)
        nuclei = NucleiAdapter(target, config.ports)
        wapiti = WapitiAdapter(target, config.ports)

        def as_audit(
            specs: tuple[AdapterCommand, ...],
        ) -> tuple[AuditCommand, ...]:
            return tuple(
                AuditCommand(
                    spec.command, spec.description, spec.output_file
                )
                for spec in specs
            )

        vulnerability_commands = (
            sqlmap.commands()
            + (web.curl_headers(),)
            + nuclei.commands()
            + wapiti.commands()
        )

        return (
            AuditPhase("Red", as_audit(nmap.commands())),
            AuditPhase("Web", as_audit(web.discovery_commands())),
            AuditPhase("Vulnerabilidades", as_audit(vulnerability_commands)),
        )

    def _execute_command(
        self, spec: AuditCommand, output_dir: Path
    ) -> int:
        # ``run_command`` ya registra la descripción y el comando ejecutado;
        # aquí solo se centraliza el manejo de errores del runner inyectado.
        try:
            return self._run_command(
                list(spec.command),
                spec.description,
                cwd=output_dir,
                output_file=spec.output_file,
            )
        except Exception as error:
            self._log(
                f"[✘] Error al ejecutar '{spec.description}': {error}"
            )
            return -1

    def _create_vpn_manager(self, config: AuditConfig) -> VPNManager:
        if self._vpn_manager is not None:
            return self._vpn_manager

        return VPNManager(
            config_path=config.vpn_config_path,
            username=config.vpn_username,
            log_callback=self._log,
        )

    def _summary_message(
        self,
        total: int,
        succeeded: int,
        warned: int,
        failed: int,
    ) -> str:
        if not warned and not failed:
            return (
                f"[✔] Auditoría finalizada: {succeeded}/{total} comandos "
                "completados correctamente."
            )

        return (
            f"[⚠] Auditoría finalizada con {succeeded} éxito(s), "
            f"{warned} advertencia(s) y {failed} error(es) de {total} "
            "comandos."
        )

    def _log(self, message: str) -> None:
        if self._log_callback is None:
            logger.info(message)
            return

        try:
            self._log_callback(message)
        except Exception:
            logger.exception(
                "Error al enviar un mensaje de log del orquestador"
            )
