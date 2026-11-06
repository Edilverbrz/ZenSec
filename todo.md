# 📋 TODO: ZecSec (Ubuntu Security Audit Tool)

Este documento registra el progreso detallado de la implementación, las tareas pendientes y los micro-hitos del proyecto ZecSec.

## 🟢 Fase 1: MVP Base y Código Inicial (Completada)

> **Objetivo:** Construir la interfaz gráfica inicial `security_gui.py` y la lógica base de ejecución asíncrona.

* [x] Crear la estructura inicial de la interfaz de dos paneles con `CustomTkinter` en `security_gui.py`.
* [x] Implementar la consola de logs asíncrona en tiempo real usando `threading` y `queue.Queue`.
* [x] Integrar la comprobación y validación previa de dependencias con `shutil.which`.
* [x] Gestionar la creación de carpetas de salida aisladas por IP (`recon_IP/`) usando `pathlib.Path` y el parámetro `cwd` en subprocesos.
* [x] Implementar el método auxiliar `run_command` con `subprocess.Popen`, `cwd` mediante `pathlib.Path` y lectura asíncrona de `stdout`/`stderr` hacia la cola de la UI.
* [x] Conectar la secuencia de ejecución asíncrona para la matriz estandarizada de 21 comandos usando `run_command`.

## 🟢 Fase 2: Modularización de Arquitectura (Post-MVP Base) (Completada)

> **Objetivo:** Desacoplar la interfaz gráfica de la lógica de comandos para permitir una arquitectura limpia (`core/` y `adapters/`).

### 2.1 Módulos Core (Completada)
* [x] Crear el directorio `core/` y el inicializador `core/__init__.py`.
* [x] Desarrollar `core/orchestrator.py` para la gestión centralizada de fases y flujos de trabajo.
* [x] Desarrollar `core/vpn_manager.py` para encapsular la conexión y estado de `openfortivpn`.

### 2.2 Adaptadores por Herramienta (`adapters/`) (Completada)
* [x] Crear el directorio `adapters/` y el inicializador `adapters/__init__.py`.
* [x] Implementar `adapters/nmap_adapter.py` (Comandos 3, 4 y 5 de la Matriz).
* [x] Implementar `adapters/web_adapter.py` (Dirb, Nikto y Curl - Comandos 6-9, 16).
* [x] Implementar `adapters/sqlmap_adapter.py` (Comandos 10-15).
* [x] Implementar `adapters/nuclei_adapter.py` (Comandos 17 y 18).
* [x] Implementar `adapters/wapiti_adapter.py` (Comandos 19-21).

## 🔵 Fase 3: Despliegue y Automatización

* [ ] Crear el script Bash de instalación automatizada `install.sh` que verifique e instale:
  * Dependencias del sistema mediante `apt` (`nmap`, `dirb`, `nikto`, `sqlmap`, `curl`, `nuclei`, `wapiti`, `openfortivpn`, `python3-tk`).
  * Dependencias de Python mediante `pip` (`customtkinter`).
* [ ] Añadir validación de permisos de archivo (`chmod 600`) para las credenciales de VPN (`~/vpn.conf`).
* [ ] Generar un script de verificación previa del entorno (`check_env.py`).

## 🟣 Fase 4: Mejoras en la UI y Reportes

* [ ] Añadir un botón en `security_gui.py` para limpiar el contenido de la consola de texto.
* [ ] Implementar opción de cancelar o pausar el flujo de auditoría en marcha de forma limpia (`process.kill()`).
* [ ] Crear el módulo `reports/generator.py` para analizar los archivos `.txt` generados y resumir hallazgos.
* [ ] Exportar resúmenes ejecutivos del análisis en formato HTML / Markdown.

## 📌 Convenciones para Actualizar este Archivo

* Marcar como completada una tarea cambiando `- [ ]` por `- [x]`.
* Al iniciar una nueva sesión con Copilot, especificar la tarea exacta según la numeración (ej. *"Ayúdame a implementar el primer punto de la Fase 1 en `security_gui.py` siguiendo `Skill.md`"*).