🛡️ ZecSec

ZecSec es una aplicación de escritorio nativa para Ubuntu / Linux Mint diseñada para automatizar y estandarizar flujos de trabajo en reconocimiento, escaneo de vulnerabilidades y auditorías de seguridad. 

El desarrollador no se hace responsable del mal uso, daños o actividades ilegales que terceros puedan realizar con este software.

La herramienta orquesta la ejecución secuencial de comandos de red y web mediante una interfaz gráfica moderna, mostrando logs en tiempo real y organizando todos los reportes de resultados de forma aislada por objetivo.

🚀 Características Principales

Interfaz Nativa y Moderna: Diseñada con CustomTkinter, con modo oscuro automático e integración nativa en entornos Linux.

Consola en Tiempo Real (Multi-hilo): Ejecuta escaneos pesados sin congelar la ventana gráfica gracias a una arquitectura basada en threading y colas de procesos.

Orquestación Secuencial Completa: Flujo estandarizado que abarca desde la conexión VPN hasta análisis exhaustivos con Nmap, Dirb, Nikto, SQLMap, Curl, Nuclei y Wapiti.

Escudos de Validación (MVP Ready): Comprobación automática de dependencias e instalación previa de binarios en el sistema con shutil.which.

Aislamiento de Resultados: Generación automática de carpetas únicas por dirección IP utilizando rutas limpias y absolutas con pathlib.

🛠️ Tecnologías Utilizadas

Lenguaje Principal: Python 3

Interfaz Gráfica: CustomTkinter

Orquestación y Procesos: Módulos nativos subprocess, threading, queue, shutil y pathlib.

Herramientas de Auditoría: openfortivpn, nmap, dirb, nikto, sqlmap, curl, nuclei, wapiti.

📋 Requisitos Previos e Instalación

1. Clonar el repositorio

git clone https://github.com/tu-usuario/zecsec.git
cd zecsec


2. Instalar dependencias del sistema en Ubuntu

Asegúrate de contar con las herramientas de escaneo en el PATH de tu sistema:

sudo apt update && sudo apt install -y \
    nmap \
    dirb \
    nikto \
    sqlmap \
    curl \
    nuclei \
    wapiti \
    openfortivpn \
    python3-pip \
    python3-tk


3. Instalar dependencias de Python

pip install customtkinter


🎯 Instrucciones de Uso

Lanza la aplicación desde la terminal:

python3 security_gui.py


Introduce la Dirección IP Objetivo (ej. 192.168.1.50).

(Opcional) Especifica puertos personalizados o marca la casilla para establecer una conexión VPN automática con openfortivpn.

Haz clic en 🚀 Iniciar Auditoría.

Revisa la salida en tiempo real en el panel derecho de la consola. Al finalizar, los resultados se guardarán en una carpeta del tipo recon_192_168_1_50/.

📚 Documentación y Archivos del Proyecto

Contex.md: Guía técnica completa, matriz de 21 comandos y código fuente base.

Comandos.md: Guia de comandos a seguir para la herramientas.

Agents.md: Directrices operativas y límites para agentes de IA que colaboren en el desarrollo.

skill.md: Estándares de desarrollo y habilidades específicas para la extensión de código.

memory.md: Registro del estado del proyecto, decisiones históricas y roadmap.

⚠️ Descargo de Responsabilidad / Legal

Esta herramienta ha sido creada estrictamente con fines educativos, auditorías autorizadas, laboratorios controlados y pentesting ético. El uso de esta herramienta contra objetivos sin autorización previa por escrito es ilegal y responsabilidad exclusiva del usuario final.