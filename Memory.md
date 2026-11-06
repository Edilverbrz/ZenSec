# 🧠 Project Memory: Ubuntu Security Audit Tool

## 📌 Estado Actual del Proyecto
- **Fecha de Inicio:** Noviembre 2026.
- **Última actualización:** 2026-11-06.
- **Estado:** Fase 2 (modularización) completada. `core/` contiene el orquestador, el gestor VPN y las validaciones compartidas; `adapters/` contiene los wrappers de Nmap, Web, SQLMap, Nuclei y Wapiti. El orquestador consume los adaptadores y mantiene el orden de la matriz 3-21.
- **Hitos Pendientes:** Integrar `core/orchestrator.py` y los adaptadores en `security_gui.py`, y comenzar la Fase 3 (despliegue y automatización).

## 🏛️ Decisiones Arquitectónicas Clave (Decisions Log)
- **2026-11-06 — Ejecución controlada con `run_command`:** Se implementó en `security_gui.py` un helper basado en `subprocess.Popen` que acepta comandos como cadena o lista, valida el directorio de trabajo con `pathlib.Path` y captura `stdout`/`stderr` línea por línea mediante hilos lectores. Cada línea se envía a la cola de la UI con `self.log()` y el `returncode` se reporta como éxito (`[✔]`) o advertencia (`[⚠]`).
- **2026-11-06 — Sin `shell=True`:** Por seguridad, los comandos se ejecutan como listas de argumentos. Las redirecciones de shell (`>`) se sustituyen por opciones nativas de cada herramienta o por el volcado opcional de `run_command` a un archivo de salida.
- **2026-11-06 — Secuencia de auditoría asíncrona:** Se conectó la matriz de comandos 3-21 mediante `_build_audit_plan`, `_run_audit`, `start_audit` y `_monitor_audit`. El flujo se ejecuta en un hilo secundario, usa el `cwd` aislado de la IP y deshabilita los controles de la UI hasta finalizar. La VPN persistente queda para `core/vpn_manager.py` en Fase 2.
- **2026-11-06 — Gestión modular de la VPN:** Se implementó `core/vpn_manager.py` con la clase `VPNManager`. Usa `pathlib.Path` para la configuración, `subprocess.Popen` sin `shell=True`, validación de binario/archivo/permisos, lectura de salida en hilo secundario y detección del mensaje de túnel activo. Expone `connect`, `verify`, `disconnect`, propiedades de estado y un callback de logs desacoplado de CustomTkinter.
- **2026-11-06 — Orquestador desacoplado:** Se implementó `core/orchestrator.py` con `AuditConfig`, `AuditCommand`, `AuditPhase`, `AuditResult` y `AuditOrchestrator`. El orquestador valida IP y puertos (1-65535), crea `recon_<IP>` con `pathlib.Path`, ejecuta las fases Inicialización, Red, Web y Vulnerabilidades en el orden de la matriz 3-21 y recibe el helper `run_command` como dependencia inyectada. La VPN es opcional: si el orquestador la inicia, la desconecta al finalizar; si falla, cancela la auditoría. No usa `shell=True` ni depende de la GUI.
- **2026-11-06 — Adaptadores como constructores de comandos:** Se implementaron `NmapAdapter`, `WebAdapter`, `SQLMapAdapter`, `NucleiAdapter` y `WapitiAdapter`. Cada uno expone métodos por prueba y un método `commands()` que devuelve `AdapterCommand` (tupla de argumentos, descripción y archivo de salida opcional). El orquestador consume estos adaptadores para construir las fases, eliminando la duplicación de la matriz. La validación de IP y puertos se centralizó en `core/validation.py` y `core/__init__.py` usa exportaciones perezosas para evitar ciclos de importación.

## 🧱 Estructura y Contratos Clave
- **Flujo de auditoría:** GUI/CLI → `AuditOrchestrator.run(AuditConfig)` → adaptadores → `AdapterCommand` → `run_command`.
- **`core/orchestrator.py`:** `AuditConfig` recibe `target`, `ports`, `use_vpn`, `vpn_config_path`, `vpn_username`, `vpn_timeout` y `output_root`. El directorio de salida es `output_root/recon_<IP>`; en IPv6 los `:` se sustituyen por `_`.
- **`AuditOrchestrator`:** se construye con `AuditOrchestrator(run_command, log_callback=None, vpn_manager=None)`. `run()` es bloqueante y debe llamarse desde un hilo secundario en la GUI.
- **`AdapterCommand`:** `command` es una tupla de argumentos, `description` es el texto de la matriz y `output_file` es opcional. Nunca se usa una cadena de shell.
- **Salidas:** Nmap, Dirb, Nikto, Curl, Nuclei y Wapiti escriben con sus opciones nativas (`-oN`/`-o`). SQLMap usa `output_file` de `run_command` para volcar su salida, ya que la matriz original usaba `>`.
- **Adaptadores:** `NmapAdapter` (3-5), `WebAdapter` (6-9 y 16), `SQLMapAdapter` (10-15), `NucleiAdapter` (17-18) y `WapitiAdapter` (19-21). `WebAdapter.discovery_commands()` devuelve 6-9 y `curl_headers()` devuelve 16.
- **`run_command`:** firma `(command, description, cwd=None, output_file=None) -> int`. Devuelve `0` en éxito, `127` si falta el binario, `1` ante errores de ejecución y el código real si el proceso termina con advertencias.
- **VPN:** si se solicita y falla, la auditoría se cancela. Si el orquestador inicia la VPN, la desconecta al finalizar; si ya estaba conectada, no la toca. Un fallo al desconectar solo genera una advertencia.

## 🧪 Contexto de Desarrollo y Pruebas
- El entorno de desarrollo actual es Windows, pero el objetivo final es Ubuntu / Linux Mint.
- Usar `.venv\Scripts\python.exe`. `customtkinter` **no** está instalado en el venv; para probar `security_gui.py` hay que simular ese módulo.
- `security_gui.py` todavía conserva su propio `_build_audit_plan` y `_run_audit`; aún no importa `core/` ni `adapters/`.
- Las pruebas están versionadas en `tests/`: `test_adapters.py`, `test_orchestrator.py` y `test_vpn_manager.py`. `tests/__init__.py` añade la raíz del proyecto al `sys.path`.
- Ejecutar la suite completa:
  `.venv\Scripts\python.exe -m unittest discover -s tests -t . -v`
  Actualmente son **36 tests** y cubren adaptadores, matriz 3-21, orquestador, IPv6, warnings/errores, VPN y el helper de ejecución simulado.
- Los tests usan `unittest` para no añadir dependencias. Son compatibles con `pytest`, pero `pytest` no está instalado en el venv.
- Verificación básica: `.venv\Scripts\python.exe -m py_compile core\*.py adapters\*.py tests\*.py`.
- `.gitignore` ignora `__pycache__/`, `.pytest_cache/`, `.venv/` y `recon_*/`.
- No se ha hecho commit. Según el último `git status`: `Memory.md` y `README.md` modificados; `.gitignore`, `core/`, `adapters/`, `tests/`, `security_gui.py` y `todo.md` sin seguimiento.

## 🚧 Próxima Sesión
1. Integrar `core/orchestrator.py` en `security_gui.py`: sustituir `_build_audit_plan`/`_run_audit` por el orquestador, pasar `self.run_command` y `self.log`, y mantener la ejecución en un hilo secundario.
2. Ejecutar la suite antes y después de la integración:
   `.venv\Scripts\python.exe -m unittest discover -s tests -t . -v`
3. Probar la GUI con `customtkinter` instalado en el entorno Ubuntu objetivo.
4. Comenzar la Fase 3: `install.sh`, validación `chmod 600 ~/vpn.conf` y `check_env.py`.

## 🗺️ Roadmap / Próximos Pasos
- [x] Implementar el script base de la GUI con CustomTkinter.
- [x] Integrar el sistema de hilos (`threading`) y validación de binarios.
- [x] Implementar el helper `run_command` con `subprocess.Popen`, `cwd` y logs en tiempo real.
- [x] Conectar la secuencia asíncrona de la matriz de auditoría (comandos 3-21).
- [x] Implementar la gestión de la VPN persistente en `core/vpn_manager.py`.
- [x] Crear los paquetes `core/` y `adapters/`.
- [x] Desarrollar `core/orchestrator.py`.
- [x] Implementar los adaptadores por herramienta.
- [ ] Integrar `core/orchestrator.py` en `security_gui.py`.