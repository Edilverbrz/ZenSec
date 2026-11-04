# 🛠️ Project Skills: Ubuntu Security Audit Tool

Este archivo define las habilidades y patrones de código específicos que el agente debe dominar y replicar al desarrollar en este repositorio.

## Skill 1: Añadir una Nueva Herramienta / Comando
Cuando se solicite integrar una nueva herramienta de seguridad al flujo:
1. **Actualizar la Matriz:** Añadirla a la tabla en `AUDIT_TOOL_GUIDE.md` con su orden, comando y output exacto.
2. **Crear el Wrapper:** Implementar la llamada utilizando `subprocess.Popen` dentro de un hilo secundario.
3. **Validación de Binarios:** Asegurar que la herramienta sea chequeada mediante `shutil.which()` antes de iniciar la ejecución masiva.
4. **Directorio de Trabajo:** Pasar siempre el parámetro `cwd=str(target_folder)` utilizando `pathlib.Path` para evitar errores de ruta.

## Skill 2: Formato de Logs en la Interfaz (CustomTkinter)
Cualquier evento, error o inicio de comando debe registrarse mediante la cola de la interfaz para mantener la consistencia visual:
- Usar `self.log("[+] Mensaje...")` para procesos normales.
- Usar `[✔]` para completados exitosos.
- Usar `[✘]` o `[⚠]` para errores o alertas de código de salida distinto de cero.