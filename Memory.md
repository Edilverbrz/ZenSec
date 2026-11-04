# 🧠 Project Memory: Ubuntu Security Audit Tool

Este archivo almacena el estado actual del proyecto, decisiones históricas y la hoja de ruta activa. Actualizar este registro al finalizar cada hito importante.

## 📌 Estado Actual del Proyecto (MVP Fase 1)
- **Fecha de Inicio:** Octubre / Noviembre 2026.
- **Estado:** Código base de la GUI (`security_gui.py`) completado y validado con `CustomTkinter`.
- **Características Integradas:**
  - Interfaz de dos paneles (controles + consola en tiempo real).
  - Ejecución concurrente mediante hilos (`threading` + `queue.Queue`).
  - Escudos MVP: Validación de binarios con `shutil.which` y gestión de rutas absolutas con `pathlib`.
  - Matriz completa de 21 comandos de reconocimiento y auditoría.

## 🏛️ Decisiones Arquitectónicas Clave (Decisions Log)
1. **GUI Nativa sobre Web:** Se seleccionó `CustomTkinter` en lugar de Electron o web local para mantener la app ultraligera y nativa en Ubuntu / Linux Mint sin dependencias pesadas.
2. **Aislamiento de Procesos:** Se utiliza `subprocess.Popen` leyendo `stdout` línea por línea para alimentar la consola gráfica sin congelar la ventana principal.
3. **Estructura de Ficheros:** Cada objetivo crea una carpeta aislada del tipo `recon_IP/` para evitar colisiones de archivos de salida (`.txt`).

## 🗺️ Roadmap / Próximos Pasos (Post-MVP)
- [ ] Crear el script de instalación automatizada (`install.sh`).
- [ ] Desarrollar la arquitectura modular separando adaptadores (`core/` y `adapters/`).
- [ ] Implementar un generador de reportes consolidados en HTML / Markdown utilizando Jinja2.