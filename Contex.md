# 🛡️ Guía Técnica y Arquitectura: Ubuntu Security Audit Tool

Herramienta de automatización de reconocimiento, escaneo de vulnerabilidades y auditoría de seguridad orientada a entornos **Ubuntu / Linux Mint**. Diseñada para orquestar comandos de red y web de forma modular, con una interfaz gráfica moderna de escritorio y escudos de validación robustos para el MVP.

---

## 📑 Índice
1. [Directrices del Proyecto](#1-directrices-del-proyecto)
2. [Mejores Prácticas de Ingeniería (MVP Ready)](#2-mejores-prácticas-de-ingeniería-mvp-ready)
3. [Reglas de Seguridad y No Romper (Guardrails)](#3-reglas-de-seguridad-y-no-romper-guardrails)
4. [Instrucciones de Uso](#4-instrucciones-de-uso)
5. [Arquitectura de Software (Clean & Modular)](#5-arquitectura-de-software-clean--modular)
6. [Mejores Tecnologías para el Proyecto](#6-mejores-tecnologías-para-el-proyecto)
7. [Matriz de Mapeo de Comandos y Resultados](#7-matriz-de-mapeo-de-comandos-y-resultados)
8. [Código Base de la Interfaz (CustomTkinter + Tips MVP)](#8-código-base-de-la-interfaz-customtkinter--tips-mvp)
9. [Tips y Recomendaciones para Agentes y Automatización](#9-tips-y-recomendaciones-para-agentes-y-automatización)

---

## 1. Directrices del Proyecto
* **Automatización Estándar:** Estandarizar la ejecución secuencial de herramientas de auditoría para evitar omisiones en fases de reconocimiento.
* **Trazabilidad de Resultados:** Cada ejecución debe aislarse en una carpeta específica para la IP analizada, evitando sobreescribir hallazgos anteriores.
* **Independencia de la Interfaz:** La lógica de ejecución de comandos debe estar desacoplada de la interfaz gráfica, permitiendo reutilizar el núcleo en scripts de terminal si es necesario.

---

## 2. Mejores Prácticas de Ingeniería (MVP Ready)
* **Validación Previa de Binarios (`shutil.which`):** Antes de iniciar cualquier hilo de escaneo, la herramienta verifica automáticamente que herramientas del sistema como `nmap`, `sqlmap`, `nuclei`, etc., se encuentren instaladas en el `PATH` de Ubuntu. Si falta alguna, arroja una advertencia limpia en lugar de fallar a mitad de proceso.
* **Manejo Seguro de Rutas (`pathlib` y `cwd`):** En lugar de modificar el directorio global de trabajo con `os.chdir`, se gestionan rutas absolutas mediante `pathlib.Path` y se pasa el contexto de ejecución (`cwd`) directamente a los procesos hijos, garantizando estabilidad si se lanzan múltiples análisis consecutivos.
* **Concurrencia Asíncrona (`threading`):** Las operaciones de larga duración se ejecutan en hilos secundarios utilizando una cola segura (`queue.Queue`) para alimentar la consola de la GUI en tiempo real sin congelar la ventana.

---

## 3. Reglas de Seguridad y No Romper (Guardrails)
> ⚠️ **Aviso legal importante:** Esta herramienta está diseñada estrictamente para auditorías autorizadas, laboratorios controlados y pentesting ético con consentimiento explícito.
* **Autorización Previa:** No ejecutar jamás escaneos agresivos (`-p-`, scripts de vulnerabilidades pesadas o fuzzing masivo) contra objetivos sin autorización por escrito.
* **Gestión Segura de VPN:** Asegurar que las credenciales y archivos de configuración (`vpn.conf`) tengan permisos restringidos en el sistema operativo (`chmod 600`).
* **Control de Ruido y Carga:** Evitar saturar redes de producción con parámetros masivos de `T4` o `sqlmap --risk=2` a menos que sea requerido y autorizado explícitamente.

---

## 4. Instrucciones de Uso

### Prerrequisitos en Ubuntu
Asegúrate de tener Python 3 y las librerías necesarias instaladas:
```bash
sudo apt update && sudo apt install nmap dirb nikto sqlmap curl nuclei wapiti openfortivpn -y
pip install customtkinter
Ejecución de la HerramientaClona o sitúate en el directorio del proyecto.Ejecuta la interfaz gráfica:Bashpython3 security_gui.py
Introduce la IP objetivo, opcionalmente los puertos específicos y configura tu ruta de VPN si es necesario.Presiona 🚀 Iniciar Auditoría y supervisa el progreso en tiempo real desde la consola integrada.5. Arquitectura de Software (Clean & Modular)Estructura recomendada para escalar el proyecto de forma profesional:Plaintextsecurity_tool/
│
├── core/
│   ├── __init__.py
│   ├── orchestrator.py      # Orquestador central de fases y comandos
│   └── vpn_manager.py       # Control de túneles VPN (openfortivpn)
│
├── adapters/                # Clases envoltorios (Wrappers) por herramienta
│   ├── __init__.py
│   ├── nmap_adapter.py
│   ├── sqlmap_adapter.py
│   └── nuclei_adapter.py
│
├── reports/
│   └── generator.py         # Compilador de informes ejecutivos (HTML/Markdown)
│
├── main.py                  # Punto de entrada CLI (Opcional)
└── security_gui.py          # Interfaz Nativa Ubuntu (CustomTkinter)

6. Mejores Tecnologías para el Proyecto
Lenguaje: Python 3 (versatilidad en manipulación de procesos y automatización).

Interfaz Gráfica: CustomTkinter (nativo, moderno, liviano, soporte de modo oscuro y adaptado perfectamente a Linux Mint/Ubuntu).

Control de Procesos: Módulo nativo subprocess para ejecución controlada de binarios del sistema.

Validación y Rutas: shutil (chequeo de dependencias) y pathlib (gestión limpia de directorios).

### 7. Matriz de Mapeo de Comandos y Resultados

| Orden | Fase / Herramienta | Comando Exacto / Sintaxis Base | Objetivo / Descripción del Proceso | Archivo de Salida (Output) |
| :---: | :--- | :--- | :--- | :--- |
| **1** | VPN (Openfortivpn) | `sudo openfortivpn -c ~/vpn.conf -u usuario` | Establecer el túnel VPN seguro con la red objetivo antes de iniciar los escaneos. | N/A (Logs de sistema en vivo) |
| **2** | Directorio de Trabajo | `mkdir carpeta && cd carpeta` | Crear y posicionarse en el directorio aislado de trabajo para almacenar todos los reportes de la IP. | N/A (Estructura de ficheros) |
| **3** | Nmap (Vuln Full) | `nmap -sV --script Vuln -p- -T4 -o nmap_vuln.txt direccion_ip` | Escaneo completo de los 65535 puertos con detección de versiones y scripts de vulnerabilidades. | `nmap_vuln.txt` |
| **4** | Nmap (Todos los Puertos) | `nmap -sV -oN puertostodos.txt direccion_ip` | Escaneo general de servicios y versiones para inventario principal. | `puertostodos.txt` |
| **5** | Nmap (Puertos Específicos) | `nmap -p listado_de_puertos -oN puertosespecificos.txt direccion_ip` | Auditoría detallada y focalizada sobre puertos concretos detectados previamente. | `puertosespecificos.txt` |
| **6** | Dirb (HTTP) | `dirb http://direccion_ip -o dirb.txt` | Fuerza bruta de directorios y archivos ocultos en protocolo HTTP. | `dirb.txt` |
| **7** | Dirb (HTTPS) | `dirb https://direccion_ip -o dirbs.txt` | Fuerza bruta de directorios y archivos ocultos en protocolo HTTPS seguro. | `dirbs.txt` |
| **8** | Nikto (HTTP Base) | `nikto -h direccion_ip -o nikto.txt` | Escaneo de vulnerabilidades genéricas, archivos peligrosos y malas configuraciones web. | `nikto.txt` |
| **9** | Nikto (Puertos Web) | `nikto -h direccion_ip -p listado_de_puertos -o niktopuertos.txt` | Escaneo de vulnerabilidades web enfocado en puertos específicos (ej. 8080, 8443). | `niktopuertos.txt` |
| **10** | SQLMap (HTTP Básico) | `sqlmap -u http://direccion_ip --batch > sqlmap.txt` | Detección automatizada de vulnerabilidades de inyección SQL en HTTP (modo no interactivo). | `sqlmap.txt` |
| **11** | SQLMap (HTTPS Básico) | `sqlmap -u https://direccion_ip --batch > sqlmaps.txt` | Detección automatizada de inyecciones SQL en HTTPS (modo no interactivo). | `sqlmaps.txt` |
| **12** | SQLMap (HTTP Crawl) | `sqlmap -u http://direccion_ip --crawl=2 --forms --batch --dbms=postgresql --level=3 --risk=2 > sql_crawl2.txt` | Rastreo web de formularios (profundidad 2), orientado a PostgreSQL con nivel y riesgo avanzado. | `sql_crawl2.txt` |
| **13** | SQLMap (HTTPS Crawl) | `sqlmap -u https://direccion_ip --crawl=2 --forms --batch --dbms=postgresql --level=3 --risk=2 > sql_crawl2s.txt` | Rastreo web de formularios seguros (profundidad 2), orientado a PostgreSQL con nivel y riesgo avanzado. | `sql_crawl2s.txt` |
| **14** | SQLMap (HTTP Alt/Url) | `sqlmap -u http://direccion_ip --batch > sqlmapurl.txt` | Ejecución complementaria de SQLMap orientada a parámetros de URL en HTTP. | `sqlmapurl.txt` |
| **15** | SQLMap (HTTPS Alt/Urls) | `sqlmap -u https://direccion_ip --batch > sqlmapurls.txt` | Ejecución complementaria de SQLMap orientada a parámetros de URL en HTTPS. | `sqlmapurls.txt` |
| **16** | Curl (Headers) | `curl -Iv direccion_ip -o curl.txt` | Inspección detallada de cabeceras HTTP, redirecciones y certificados SSL/TLS. | `curl.txt` |
| **17** | Nuclei (Críticos/Altos) | `nuclei -u direccion_ip -severity critical,high -o nuclei.txt` | Escaneo rápido de vulnerabilidades basadas en templates YAML filtradas por severidad alta y crítica. | `nuclei.txt` |
| **18** | Nuclei (Tags Panel/Login) | `nuclei -u direccion_ip -tags panel,login,default-login -o nucleitags.txt` | Búsqueda específica de paneles de autenticación, páginas de login y credenciales por defecto. | `nucleitags.txt` |
| **19** | Wapiti (Default/Gen) | `wapiti -u direccion_ip -o wapiti.txt` | Auditoría de aplicaciones web buscando vectores de ataque comunes (XSS, LFI, RCE). | `wapiti.txt` |
| **20** | Wapiti (HTTPS) | `wapiti -u https://direccion_ip -o wapitihttps.txt` | Escaneo completo de seguridad de aplicaciones web sobre protocolo HTTPS. | `wapitihttps.txt` |
| **21** | Wapiti (HTTP) | `wapiti -u http://direccion_ip -o wapitihttp.txt` | Escaneo completo de seguridad de aplicaciones web sobre protocolo HTTP. | `wapitihttp.txt` |

8. Código Base de la Interfaz (security_gui.py)

import shutil
import subprocess
import threading
import queue
import time
from pathlib import Path
import customtkinter as ctk
from tkinter import messagebox

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class SecurityAuditApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Ubuntu Security Audit Tool - Edi")
        self.geometry("1100x700")
        self.minsize(900, 600)

        self.log_queue = queue.Queue()

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Panel Izquierdo: Controles
        self.sidebar_frame = ctk.CTkFrame(self, width=320, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(12, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="🛡️ SecAudit Tool", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")

        self.lbl_ip = ctk.CTkLabel(self.sidebar_frame, text="Dirección IP Objetivo:", font=ctk.CTkFont(weight="bold"))
        self.lbl_ip.grid(row=1, column=0, padx=20, pady=(10, 0), sticky="w")
        self.entry_ip = ctk.CTkEntry(self.sidebar_frame, placeholder_text="ej. 192.168.1.50")
        self.entry_ip.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="ew")

        self.lbl_ports = ctk.CTkLabel(self.sidebar_frame, text="Puertos Específicos (opcional):", font=ctk.CTkFont(weight="bold"))
        self.lbl_ports.grid(row=3, column=0, padx=20, pady=(5, 0), sticky="w")
        self.entry_ports = ctk.CTkEntry(self.sidebar_frame, placeholder_text="ej. 80,443,8080")
        self.entry_ports.grid(row=4, column=0, padx=20, pady=(0, 10), sticky="ew")

        self.lbl_vpn_conf = ctk.CTkLabel(self.sidebar_frame, text="Ruta Config VPN:", font=ctk.CTkFont(weight="bold"))
        self.lbl_vpn_conf.grid(row=5, column=0, padx=20, pady=(5, 0), sticky="w")
        self.entry_vpn_conf = ctk.CTkEntry(self.sidebar_frame)
        self.entry_vpn_conf.insert(0, "~/vpn.conf")
        self.entry_vpn_conf.grid(row=6, column=0, padx=20, pady=(0, 10), sticky="ew")

        self.lbl_vpn_user = ctk.CTkLabel(self.sidebar_frame, text="Usuario VPN:", font=ctk.CTkFont(weight="bold"))
        self.lbl_vpn_user.grid(row=7, column=0, padx=20, pady=(5, 0), sticky="w")
        self.entry_vpn_user = ctk.CTkEntry(self.sidebar_frame)
        self.entry_vpn_user.grid(row=8, column=0, padx=20, pady=(0, 10), sticky="ew")

        self.check_vpn = ctk.CTkCheckBox(self.sidebar_frame, text="Conectar VPN antes de escanear")
        self.check_vpn.grid(row=9, column=0, padx=20, pady=10, sticky="w")

        self.btn_start = ctk.CTkButton(self.sidebar_frame, text="🚀 Iniciar Auditoría", fg_color="#2fa572", hover_color="#248f5e", command=self.start_audit_thread)
        self.btn_start.grid(row=10, column=0, padx=20, pady=20, sticky="ew")

        # Panel Derecho: Consola
        self.console_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.console_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.console_frame.grid_rowconfigure(0, weight=1)
        self.console_frame.grid_columnconfigure(0, weight=1)

        self.text_console = ctk.CTkTextbox(self.console_frame, font=ctk.CTkFont(family="Courier", size=12))
        self.text_console.grid(row=0, column=0, sticky="nsew")
        self.text_console.insert("0.0", "[*] Sistema listo. Introduce los datos y presiona 'Iniciar Auditoría'.\n")

        self.after(100, self.process_log_queue)

    def log(self, message):
        self.log_queue.put(message)

    def process_log_queue(self):
        while not self.log_queue.empty():
            msg = self.log_queue.get()
            self.text_console.insert("end", msg + "\n")
            self.text_console.see("end")
        self.after(100, self.process_log_queue)

    def start_audit_thread(self):
        ip = self.entry_ip.get().strip()
        if not ip:
            messagebox.showerror("Error", "¡Debes introducir una dirección IP objetivo!")
            return
        
        # Validación MVP: Chequeo de Binarios con shutil.which
        required_tools = ['nmap', 'dirb', 'nikto', 'sqlmap', 'curl', 'nuclei', 'wapiti']
        missing_tools = [tool for tool in required_tools if not shutil.which(tool)]
        if missing_tools:
            messagebox.showerror("Faltan Herramientas", f"Las siguientes dependencias no están instaladas en Ubuntu:\n{', '.join(missing_tools)}")
            return

        self.btn_start.configure(state="disabled", fg_color="gray")
        threading.Thread(target=self.run_audit_workflow, args=(ip,), daemon=True).start()

    def run_command(self, command, description, cwd=None):
        self.log(f"\n[+] Ejecutando: {description}...")
        self.log(f"    $ {command}")
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=cwd)
            for line in process.stdout:
                self.log(line.strip())
            process.wait()
            if process.returncode == 0:
                self.log(f"[✔] Completado: {description}")
            else:
                self.log(f"[⚠] Finalizado con código {process.returncode}: {description}")
        except Exception as e:
            self.log(f"[✘] Error crítico ejecutando {description}: {str(e)}")

    def run_audit_workflow(self, ip):
        # Manejo MVP de Directorios con pathlib
        base_dir = Path.cwd()
        target_folder = base_dir / f"recon_{ip.replace('.', '_')}"
        target_folder.mkdir(parents=True, exist_ok=True)
        self.log(f"[*] Directorio de trabajo establecido: {target_folder}")

        if self.check_vpn.get():
            vpn_conf = self.entry_vpn_conf.get().strip()
            vpn_user = self.entry_vpn_user.get().strip()
            subprocess.Popen(f"sudo openfortivpn -c {vpn_conf} -u {vpn_user}", shell=True)
            time.sleep(5)

        ports = self.entry_ports.get().strip()
        cwd_path = str(target_folder)

        # Secuencia de ejecución utilizando el directorio de trabajo seguro
        self.run_command(f"nmap -sV --script Vuln -p- -T4 -o nmap_vuln.txt {ip}", "Nmap Vulnerabilidades Completo", cwd=cwd_path)
        self.run_command(f"nmap -sV -oN puertostodos.txt {ip}", "Nmap Todos los Puertos", cwd=cwd_path)
        if ports:
            self.run_command(f"nmap -p {ports} -oN puertosespecificos.txt {ip}", "Nmap Puertos Específicos", cwd=cwd_path)

        self.run_command(f"dirb http://{ip} -o dirb.txt", "Dirb HTTP", cwd=cwd_path)
        self.run_command(f"dirb https://{ip} -o dirbs.txt", "Dirb HTTPS", cwd=cwd_path)

        self.run_command(f"nikto -h {ip} -o nikto.txt", "Nikto HTTP", cwd=cwd_path)
        if ports:
            self.run_command(f"nikto -h {ip} -p {ports} -o niktopuertos.txt", "Nikto Puertos", cwd=cwd_path)

        self.run_command(f"sqlmap -u http://{ip} --batch > sqlmap.txt", "SQLMap HTTP Básico", cwd=cwd_path)
        self.run_command(f"sqlmap -u https://{ip} --batch > sqlmaps.txt", "SQLMap HTTPS Básico", cwd=cwd_path)
        self.run_command(f"sqlmap -u http://{ip} --crawl=2 --forms --batch --dbms=postgresql --level=3 --risk=2 > sql_crawl2.txt", "SQLMap HTTP Crawl", cwd=cwd_path)
        self.run_command(f"sqlmap -u https://{ip} --crawl=2 --forms --batch --dbms=postgresql --level=3 --risk=2 > sql_crawl2s.txt", "SQLMap HTTPS Crawl", cwd=cwd_path)
        self.run_command(f"sqlmap -u http://{ip} --batch > sqlmapurl.tx", "SQLMap HTTP Alt/Url", cwd=cwd_path)
        self.run_command(f"sqlmap -u https://{ip} --batch > sqlmapurls.tx", "SQLMap HTTPS Alt/Urls", cwd=cwd_path)

        self.run_command(f"curl -Iv {ip} -o curl.txt", "Curl Headers", cwd=cwd_path)

        self.run_command(f"nuclei -u {ip} -severity critical,high -o nuclei.txt", "Nuclei Críticos/Altos", cwd=cwd_path)
        self.run_command(f"nuclei -u {ip} -tags panel,login,default-login -o nucleitags.txt", "Nuclei Panels/Logins", cwd=cwd_path)

        self.run_command(f"wapiti -u {ip} -o wapiti.txt", "Wapiti Default", cwd=cwd_path)
        self.run_command(f"wapiti -u https://{ip} -o wapitihttps.txt", "Wapiti HTTPS", cwd=cwd_path)
        self.run_command(f"wapiti -u http://{ip} -o wapitihttp.txt", "Wapiti HTTP", cwd=cwd_path)

        self.log(f"\n🎉 ¡Auditoría finalizada! Informes guardados en: {target_folder}/")
        self.btn_start.configure(state="normal", fg_color="#2fa572")
        messagebox.showinfo("Completado", f"La auditoría para {ip} ha finalizado.")

if __name__ == "__main__":
    app = SecurityAuditApp()
    app.mainloop()

9. Tips y Recomendaciones para Agentes y AutomatizaciónModularización de Wrappers: Si planeas expandir la herramienta en el futuro, puedes aislar cada comando en clases individuales dentro de la carpeta adapters/.Post-Procesamiento de Informes: Añadir próximamente un analizador de texto que lea los archivos .txt para mostrar un resumen ejecutivo directamente en la interfaz.