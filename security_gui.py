import ipaddress
import queue
import shlex
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Optional
from tkinter import messagebox

import customtkinter as ctk


class SecurityAuditApp(ctk.CTk):
    _LOG_POLL_INTERVAL_MS = 100
    _MAX_LOG_MESSAGES_PER_POLL = 100
    _AUDIT_POLL_INTERVAL_MS = 250
    _REQUIRED_BINARIES = (
        "nmap",
        "dirb",
        "nikto",
        "sqlmap",
        "curl",
        "nuclei",
        "wapiti",
    )

    def __init__(self) -> None:
        super().__init__()

        self._log_queue: queue.Queue[str] = queue.Queue()
        self._audit_thread: Optional[threading.Thread] = None
        self.target_folder: Optional[Path] = None

        self.title("ZecSec - Auditoría de Seguridad")
        self.geometry("1000x640")
        self.minsize(820, 520)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._create_controls_panel()
        self._create_console_panel()
        self.after(self._LOG_POLL_INTERVAL_MS, self._drain_log_queue)

    def validate_dependencies(self) -> bool:
        missing = [
            binary
            for binary in self._REQUIRED_BINARIES
            if shutil.which(binary) is None
        ]
        if missing:
            missing_list = "\n".join(f"- {binary}" for binary in missing)
            messagebox.showerror(
                "Dependencias faltantes",
                "No se puede continuar. Instala los siguientes binarios "
                "y vuelve a intentarlo:\n\n"
                f"{missing_list}",
                parent=self,
            )
            self.log(f"[✘] Faltan dependencias: {', '.join(missing)}")
            return False

        self.log("[✔] Todas las dependencias requeridas están instaladas.")
        return True

    def create_target_directory(self) -> Optional[Path]:
        target = self.target_entry.get().strip()
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            messagebox.showerror(
                "IP no válida",
                "Introduce una dirección IPv4 o IPv6 válida.",
                parent=self,
            )
            self.log("[✘] No se creó el directorio: la IP no es válida.")
            return None

        try:
            directory_name = (
                f"recon_{address.compressed.replace('.', '_').replace(':', '_')}"
            )
            target_folder = Path.cwd() / directory_name
            target_folder.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            messagebox.showerror(
                "Error al crear el directorio",
                f"No se pudo crear el directorio de trabajo:\n{error}",
                parent=self,
            )
            self.log(f"[✘] No se pudo crear el directorio: {error}")
            return None

        self.target_folder = target_folder
        self.log(f"[✔] Directorio de trabajo: {target_folder}")
        return target_folder

    def prepare_target_directory(self) -> Optional[Path]:
        target_folder = self.create_target_directory()
        if target_folder is None:
            return None
        if not self.validate_dependencies():
            return None
        return target_folder

    def log(self, message: str) -> None:
        self._log_queue.put(message)

    def _drain_log_queue(self) -> None:
        messages = []
        for _ in range(self._MAX_LOG_MESSAGES_PER_POLL):
            try:
                messages.append(self._log_queue.get_nowait())
            except queue.Empty:
                break

        if messages:
            self.log_console.configure(state="normal")
            self.log_console.insert(
                "end", "".join(f"{message}\n" for message in messages)
            )
            self.log_console.see("end")
            self.log_console.configure(state="disabled")

        self.after(self._LOG_POLL_INTERVAL_MS, self._drain_log_queue)

    def run_command(
        self,
        command: str | list[str],
        description: str,
        cwd: Optional[Path] = None,
        output_file: Optional[str | Path] = None,
    ) -> int:
        """Ejecuta un comando y envía su salida a la consola en tiempo real.

        Debe invocarse desde un hilo secundario (threading.Thread): la lectura
        de los pipes es bloqueante y no debe ejecutarse en el hilo de Tkinter.

        Si se indica ``output_file``, la salida estándar también se guarda en
        ese archivo, relativo a ``cwd`` cuando no sea una ruta absoluta.
        """
        args = (
            shlex.split(command)
            if isinstance(command, str)
            else [str(part) for part in command]
        )
        if not args:
            self.log(f"[✘] {description}: el comando está vacío.")
            return 1

        workdir: Optional[Path] = None
        if cwd is not None:
            workdir = Path(cwd).expanduser().resolve()
            if not workdir.is_dir():
                self.log(
                    f"[✘] {description}: el directorio de trabajo no existe: "
                    f"{workdir}"
                )
                return 1

        output_path: Optional[Path] = None
        output_handle = None
        if output_file is not None:
            output_path = Path(output_file).expanduser()
            if not output_path.is_absolute() and workdir is not None:
                output_path = workdir / output_path
            try:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_handle = output_path.open(
                    "w", encoding="utf-8", errors="replace"
                )
            except OSError as error:
                self.log(
                    f"[✘] {description}: no se pudo abrir el archivo de salida "
                    f"'{output_path}': {error}"
                )
                return 1

        self.log(f"[+] {description}")
        self.log(f"    $ {shlex.join(args)}")
        if output_path is not None:
            self.log(f"    → Guardando salida en: {output_path.name}")

        try:
            process = subprocess.Popen(
                args,
                cwd=str(workdir) if workdir is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except FileNotFoundError:
            if output_handle is not None:
                output_handle.close()
            self.log(f"[✘] {description}: binario no encontrado: {args[0]}")
            return 127
        except OSError as error:
            if output_handle is not None:
                output_handle.close()
            self.log(f"[✘] {description}: no se pudo iniciar el proceso: {error}")
            return 1

        def stream_reader(stream, prefix: str, persist: bool = False) -> None:
            try:
                for line in iter(stream.readline, ""):
                    text = line.rstrip("\r\n")
                    if text:
                        self.log(f"{prefix}{text}")
                        if persist and output_handle is not None:
                            try:
                                output_handle.write(f"{text}\n")
                                output_handle.flush()
                            except OSError as error:
                                persist = False
                                self.log(
                                    f"[⚠] {description}: no se pudo escribir "
                                    f"en el archivo de salida: {error}"
                                )
            except (OSError, ValueError) as error:
                self.log(f"[⚠] {description}: error al leer la salida: {error}")
            finally:
                try:
                    stream.close()
                except OSError:
                    pass

        stdout_thread = threading.Thread(
            target=stream_reader,
            args=(process.stdout, "    ", output_handle is not None),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=stream_reader,
            args=(process.stderr, "    [stderr] "),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        stdout_thread.join()
        stderr_thread.join()

        if output_handle is not None:
            output_handle.close()

        returncode = process.wait()
        if returncode == 0:
            self.log(f"[✔] {description}: completado correctamente.")
        else:
            self.log(
                f"[⚠] {description}: finalizó con advertencias "
                f"(código de salida {returncode})."
            )
        return returncode

    @staticmethod
    def _format_target_url(scheme: str, target: str) -> str:
        host = f"[{target}]" if ":" in target else target
        return f"{scheme}://{host}"

    def _build_audit_plan(
        self, target: str, ports: str
    ) -> list[tuple[list[str], str, Optional[str]]]:
        """Construye la matriz de comandos 3-21 en orden de ejecución."""
        http_url = self._format_target_url("http", target)
        https_url = self._format_target_url("https", target)

        plan: list[tuple[list[str], str, Optional[str]]] = [
            (
                [
                    "nmap",
                    "-sV",
                    "--script",
                    "Vuln",
                    "-p-",
                    "-T4",
                    "-oN",
                    "nmap_vuln.txt",
                    target,
                ],
                "[3/21] Nmap - Escaneo completo de puertos y vulnerabilidades",
                None,
            ),
            (
                ["nmap", "-sV", "-oN", "puertostodos.txt", target],
                "[4/21] Nmap - Inventario de puertos y servicios",
                None,
            ),
        ]

        if ports:
            plan.append(
                (
                    [
                        "nmap",
                        "-p",
                        ports,
                        "-oN",
                        "puertosespecificos.txt",
                        target,
                    ],
                    "[5/21] Nmap - Puertos específicos",
                    None,
                )
            )

        plan.extend(
            [
                (
                    ["dirb", http_url, "-o", "dirb.txt"],
                    "[6/21] Dirb - Directorios HTTP",
                    None,
                ),
                (
                    ["dirb", https_url, "-o", "dirbs.txt"],
                    "[7/21] Dirb - Directorios HTTPS",
                    None,
                ),
                (
                    ["nikto", "-h", target, "-o", "nikto.txt"],
                    "[8/21] Nikto - Vulnerabilidades web HTTP",
                    None,
                ),
            ]
        )

        if ports:
            plan.append(
                (
                    [
                        "nikto",
                        "-h",
                        target,
                        "-p",
                        ports,
                        "-o",
                        "niktopuertos.txt",
                    ],
                    "[9/21] Nikto - Puertos web específicos",
                    None,
                )
            )

        plan.extend(
            [
                (
                    ["sqlmap", "-u", http_url, "--batch"],
                    "[10/21] SQLMap - HTTP básico",
                    "sqlmap.txt",
                ),
                (
                    ["sqlmap", "-u", https_url, "--batch"],
                    "[11/21] SQLMap - HTTPS básico",
                    "sqlmaps.txt",
                ),
                (
                    [
                        "sqlmap",
                        "-u",
                        http_url,
                        "--crawl=2",
                        "--forms",
                        "--batch",
                        "--dbms=postgresql",
                        "--level=3",
                        "--risk=2",
                    ],
                    "[12/21] SQLMap - Crawl HTTP (formularios)",
                    "sql_crawl2.txt",
                ),
                (
                    [
                        "sqlmap",
                        "-u",
                        https_url,
                        "--crawl=2",
                        "--forms",
                        "--batch",
                        "--dbms=postgresql",
                        "--level=3",
                        "--risk=2",
                    ],
                    "[13/21] SQLMap - Crawl HTTPS (formularios)",
                    "sql_crawl2s.txt",
                ),
                (
                    ["sqlmap", "-u", http_url, "--batch"],
                    "[14/21] SQLMap - HTTP alternativo",
                    "sqlmapurl.txt",
                ),
                (
                    ["sqlmap", "-u", https_url, "--batch"],
                    "[15/21] SQLMap - HTTPS alternativo",
                    "sqlmapurls.txt",
                ),
                (
                    ["curl", "-Iv", target, "-o", "curl.txt"],
                    "[16/21] Curl - Cabeceras y certificados",
                    None,
                ),
                (
                    [
                        "nuclei",
                        "-u",
                        target,
                        "-severity",
                        "critical,high",
                        "-o",
                        "nuclei.txt",
                    ],
                    "[17/21] Nuclei - Vulnerabilidades críticas/altas",
                    None,
                ),
                (
                    [
                        "nuclei",
                        "-u",
                        target,
                        "-tags",
                        "panel,login,default-login",
                        "-o",
                        "nucleitags.txt",
                    ],
                    "[18/21] Nuclei - Paneles y credenciales por defecto",
                    None,
                ),
                (
                    ["wapiti", "-u", target, "-o", "wapiti.txt"],
                    "[19/21] Wapiti - Auditoría web por defecto",
                    None,
                ),
                (
                    ["wapiti", "-u", https_url, "-o", "wapitihttps.txt"],
                    "[20/21] Wapiti - Auditoría HTTPS",
                    None,
                ),
                (
                    ["wapiti", "-u", http_url, "-o", "wapitihttp.txt"],
                    "[21/21] Wapiti - Auditoría HTTP",
                    None,
                ),
            ]
        )

        return plan

    def _run_audit(self, target_folder: Path, target: str, ports: str) -> None:
        """Ejecuta la matriz completa dentro del hilo de auditoría."""
        try:
            if not ports:
                self.log(
                    "[⚠] Sin puertos específicos: se omiten los comandos "
                    "5 (Nmap) y 9 (Nikto)."
                )

            plan = self._build_audit_plan(target, ports)
            total = len(plan)
            successes = 0
            warnings = 0

            self.log(
                f"[+] Iniciando auditoría de {target} en {target_folder} "
                f"({total} comandos programados)."
            )

            for position, (command, description, output_file) in enumerate(
                plan, start=1
            ):
                if not target_folder.is_dir():
                    self.log(
                        "[✘] Auditoría detenida: el directorio de trabajo "
                        f"ya no existe: {target_folder}"
                    )
                    return

                self.log(
                    f"[+] Progreso: {position}/{total} - {description}"
                )
                returncode = self.run_command(
                    command,
                    description,
                    cwd=target_folder,
                    output_file=output_file,
                )
                if returncode == 0:
                    successes += 1
                else:
                    warnings += 1
                    self.log(
                        f"[⚠] El comando terminó con código {returncode}; "
                        "se continúa con el siguiente."
                    )

            if warnings:
                self.log(
                    f"[⚠] Auditoría finalizada con {warnings} advertencia(s) "
                    f"y {successes} comando(s) exitoso(s) de {total}."
                )
            else:
                self.log(
                    f"[✔] Auditoría finalizada: {successes}/{total} comandos "
                    "completados correctamente."
                )
        except Exception as error:
            self.log(f"[✘] Error inesperado durante la auditoría: {error}")

    def start_audit(self) -> None:
        """Valida el objetivo y lanza la matriz en un hilo secundario."""
        if self._audit_thread is not None and self._audit_thread.is_alive():
            self.log("[⚠] Ya hay una auditoría en ejecución.")
            return

        target_folder = self.prepare_target_directory()
        if target_folder is None:
            return

        target = self.target_entry.get().strip()
        ports = self.ports_entry.get().strip()

        self._set_controls_enabled(False)
        self.log("[+] Lanzando auditoría en un hilo secundario...")
        self._audit_thread = threading.Thread(
            target=self._run_audit,
            args=(target_folder, target, ports),
            daemon=True,
        )
        self._audit_thread.start()
        self.after(self._AUDIT_POLL_INTERVAL_MS, self._monitor_audit)

    def _monitor_audit(self) -> None:
        """Reactiva los controles cuando el hilo de auditoría finaliza."""
        if self._audit_thread is not None and self._audit_thread.is_alive():
            self.after(self._AUDIT_POLL_INTERVAL_MS, self._monitor_audit)
            return

        self._audit_thread = None
        self._set_controls_enabled(True)

    def _set_controls_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for widget in (
            self.target_entry,
            self.ports_entry,
            self.vpn_enabled,
            self.vpn_config_entry,
            self.vpn_user_entry,
            self.start_button,
        ):
            widget.configure(state=state)

    def _create_controls_panel(self) -> None:
        controls = ctk.CTkFrame(self, width=280, corner_radius=0)
        controls.grid(row=0, column=0, sticky="nsew")
        controls.grid_columnconfigure(0, weight=1)
        controls.grid_propagate(False)

        ctk.CTkLabel(
            controls,
            text="ZecSec",
            font=ctk.CTkFont(size=26, weight="bold"),
        ).grid(row=0, column=0, padx=24, pady=(28, 4), sticky="w")
        ctk.CTkLabel(
            controls,
            text="Auditoría autorizada",
            text_color="gray",
        ).grid(row=1, column=0, padx=24, pady=(0, 24), sticky="w")

        ctk.CTkLabel(controls, text="IP objetivo").grid(
            row=2, column=0, padx=24, pady=(4, 6), sticky="w"
        )
        self.target_entry = ctk.CTkEntry(
            controls, placeholder_text="Ej. 192.168.1.50"
        )
        self.target_entry.grid(row=3, column=0, padx=24, pady=(0, 16), sticky="ew")

        ctk.CTkLabel(controls, text="Puertos opcionales").grid(
            row=4, column=0, padx=24, pady=(0, 6), sticky="w"
        )
        self.ports_entry = ctk.CTkEntry(
            controls, placeholder_text="Ej. 80,443,8080"
        )
        self.ports_entry.grid(row=5, column=0, padx=24, pady=(0, 20), sticky="ew")

        ctk.CTkLabel(
            controls,
            text="Configuración VPN",
            font=ctk.CTkFont(size=15, weight="bold"),
        ).grid(row=6, column=0, padx=24, pady=(4, 8), sticky="w")
        self.vpn_enabled = ctk.CTkCheckBox(
            controls, text="Usar conexión VPN"
        )
        self.vpn_enabled.grid(row=7, column=0, padx=24, pady=(0, 12), sticky="w")

        ctk.CTkLabel(controls, text="Archivo de configuración").grid(
            row=8, column=0, padx=24, pady=(0, 6), sticky="w"
        )
        self.vpn_config_entry = ctk.CTkEntry(
            controls, placeholder_text="~/vpn.conf"
        )
        self.vpn_config_entry.grid(
            row=9, column=0, padx=24, pady=(0, 12), sticky="ew"
        )

        ctk.CTkLabel(controls, text="Usuario VPN").grid(
            row=10, column=0, padx=24, pady=(0, 6), sticky="w"
        )
        self.vpn_user_entry = ctk.CTkEntry(
            controls, placeholder_text="Nombre de usuario"
        )
        self.vpn_user_entry.grid(
            row=11, column=0, padx=24, pady=(0, 20), sticky="ew"
        )

        self.start_button = ctk.CTkButton(
            controls,
            text="Iniciar Auditoría",
            command=self.start_audit,
        )
        self.start_button.grid(
            row=12, column=0, padx=24, pady=(4, 24), sticky="ew"
        )

    def _create_console_panel(self) -> None:
        console = ctk.CTkFrame(self, fg_color="transparent")
        console.grid(row=0, column=1, padx=24, pady=24, sticky="nsew")
        console.grid_columnconfigure(0, weight=1)
        console.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            console,
            text="Consola de actividad",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).grid(row=0, column=0, pady=(0, 12), sticky="w")

        self.log_console = ctk.CTkTextbox(
            console,
            wrap="word",
            state="disabled",
            font=ctk.CTkFont(family="monospace", size=13),
        )
        self.log_console.grid(row=1, column=0, sticky="nsew")


def main() -> None:
    app = SecurityAuditApp()
    app.mainloop()


if __name__ == "__main__":
    main()
