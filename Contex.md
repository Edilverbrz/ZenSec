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
8. [Tips y Recomendaciones para Agentes y Automatización](#9-tips-y-recomendaciones-para-agentes-y-automatización)

---

### 1. Directrices del Proyecto
* **Automatización Estándar:** Estandarizar la ejecución secuencial de herramientas de auditoría para evitar omisiones en fases de reconocimiento.
* **Trazabilidad de Resultados:** Cada ejecución debe aislarse en una carpeta específica para la IP analizada, evitando sobreescribir hallazgos anteriores.
* **Independencia de la Interfaz:** La lógica de ejecución de comandos debe estar desacoplada de la interfaz gráfica, permitiendo reutilizar el núcleo en scripts de terminal si es necesario.

---

### 2. Mejores Prácticas de Ingeniería (MVP Ready)
* **Validación Previa de Binarios (`shutil.which`):** Antes de iniciar cualquier hilo de escaneo, la herramienta verifica automáticamente que herramientas del sistema como `nmap`, `sqlmap`, `nuclei`, etc., se encuentren instaladas en el `PATH` de Ubuntu. Si falta alguna, arroja una advertencia limpia en lugar de fallar a mitad de proceso.
* **Manejo Seguro de Rutas (`pathlib` y `cwd`):** En lugar de modificar el directorio global de trabajo con `os.chdir`, se gestionan rutas absolutas mediante `pathlib.Path` y se pasa el contexto de ejecución (`cwd`) directamente a los procesos hijos, garantizando estabilidad si se lanzan múltiples análisis consecutivos.
* **Concurrencia Asíncrona (`threading`):** Las operaciones de larga duración se ejecutan en hilos secundarios utilizando una cola segura (`queue.Queue`) para alimentar la consola de la GUI en tiempo real sin congelar la ventana.

---

### 3. Reglas de Seguridad y No Romper (Guardrails)
> ⚠️ **Aviso legal importante:** Esta herramienta está diseñada estrictamente para auditorías autorizadas, laboratorios controlados y pentesting ético con consentimiento explícito.
* **Autorización Previa:** No ejecutar jamás escaneos agresivos (`-p-`, scripts de vulnerabilidades pesadas o fuzzing masivo) contra objetivos sin autorización por escrito.
* **Gestión Segura de VPN:** Asegurar que las credenciales y archivos de configuración (`vpn.conf`) tengan permisos restringidos en el sistema operativo (`chmod 600`).
* **Control de Ruido y Carga:** Evitar saturar redes de producción con parámetros masivos de `T4` o `sqlmap --risk=2` a menos que sea requerido y autorizado explícitamente.

---

### 4. Instrucciones de Uso

### Prerrequisitos en Ubuntu
Asegúrate de tener Python 3 y las librerías necesarias instaladas:
```bash
sudo apt update && sudo apt install nmap dirb nikto sqlmap curl nuclei wapiti openfortivpn -y
pip install customtkinter

Ejecución de la HerramientaClona o sitúate en el directorio del proyecto.Ejecuta la interfaz gráfica:Bashpython3 security_gui.py
Introduce la IP objetivo, opcionalmente los puertos específicos y configura tu ruta de VPN si es necesario.Presiona 🚀 Iniciar Auditoría y supervisa el progreso en tiempo real desde la consola integrada.

---

5. Arquitectura de Software (Clean & Modular)Estructura recomendada para escalar el proyecto de forma profesional:Plaintextsecurity_tool/
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


### 6. Mejores Tecnologías para el Proyecto

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

### 8. Tips y Recomendaciones para Agentes y AutomatizaciónModularización de Wrappers:

 Si planeas expandir la herramienta en el futuro, puedes aislar cada comando en clases individuales dentro de la carpeta adapters/.Post-Procesamiento de Informes: Añadir próximamente un analizador de texto que lea los archivos .txt para mostrar un resumen ejecutivo directamente en la interfaz.