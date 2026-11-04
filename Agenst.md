# 🤖 Agent Operating Guidelines: Ubuntu Security Audit Tool

Este documento establece las directrices operativas, restricciones y comportamientos esperados para cualquier agente de inteligencia artificial que desarrolle, modifique o mantenga código en este repositorio.

---

## 1. Comportamiento del Agente
* **Enfoque Pragmático y Ágil (MVP First):** Priorizar código limpio, funcional y directo que mantenga la estabilidad del Producto Mínimo Viable (MVP).
* **Respeto a la Arquitectura:** Toda nueva funcionalidad debe alinearse con la estructura modular establecida (`core/`, `adapters/`, `gui.py`) y aprovechar las utilidades nativas (`pathlib`, `shutil`, `threading`).
* **Claridad en los Logs:** Cualquier comando o proceso añadido debe reportar su estado detallado hacia la cola de la interfaz (`self.log()`) para que el usuario lo visualice en tiempo real sin bloquear la UI.

---

## 2. Lo que el Agente NO Debe Preguntar
Para optimizar el tiempo de desarrollo, el agente debe asumir como decisiones cerradas e imutables las siguientes directrices (a menos que el usuario indique explícitamente lo contrario):
* **No preguntar sobre el framework de UI:** La interfaz gráfica nativa es y seguirá siendo **CustomTkinter**. No proponer migraciones a frameworks web pesados (como React/Electron) para el MVP.
* **No cuestionar el sistema operativo objetivo:** El entorno nativo de ejecución es **Ubuntu / Linux Mint**. No adaptar rutas o dependencias para entornos ajenos a Linux sin un requerimiento expreso.
* **No alterar el orden de la Matriz de Comandos:** La secuencia del 1 al 21 definida en `Contex.md` está estandarizada para garantizar la integridad del informe. No modificar el flujo de ejecución de las herramientas de ciberseguridad por iniciativa propia.

---

## 3. Validaciones que el Agente Debe Realizar Antes de Continuar
Antes de generar código nuevo, refactorizar funciones o proponer parches, el agente debe validar mentalmente o mediante revisión de archivos lo siguiente:
* **Integridad de Dependencias del Sistema:** Confirmar que cualquier comando nuevo introducido esté respaldado por su respectiva validación mediante `shutil.which()` en el método de inicio.
* **Aislamiento de Hilos (Threading):** Asegurarse de que ninguna tarea de larga duración o llamada a `subprocess.Popen` se ejecute en el hilo principal de la interfaz gráfica (`tkinter`), evitando bloqueos de ventana.
* **Gestión de Rutas Absolutas:** Verificar que el manejo de directorios de salida (`recon_IP/`) se realice mediante `pathlib.Path` y se propague correctamente mediante el parámetro `cwd` en los subprocesos.

---

## 4. Reglas que el Agente NUNCA Debe Romper (Guardrails)
* **No eliminar los escudos de seguridad (MVP):** Jamás omitir las validaciones de binarios o el manejo de excepciones en `subprocess`. La herramienta debe fallar de manera limpia con advertencias en la UI y nunca colgarse de forma silenciosa.
* **No alterar el alcance de las credenciales VPN:** Respetar estrictamente la sintaxis de `openfortivpn` y la lectura de archivos de configuración locales (`~/vpn.conf`). No hardcodear contraseñas ni credenciales bajo ninguna circunstancia.
* **No promover prácticas de hacking deshonesto:** Todo el código y los flujos automatizados de la herramienta deben mantener el enfoque exclusivo de auditoría autorizada, pentesting ético y laboratorios controlados.