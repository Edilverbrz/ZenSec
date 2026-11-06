"""Adaptadores de herramientas de auditoría de ZecSec.

Cada adaptador describe los comandos de su herramienta como listas de
argumentos; el orquestador se encarga de ejecutarlos mediante
``run_command``.
"""

from .base import AdapterCommand, BaseAdapter
from .nmap_adapter import NmapAdapter
from .nuclei_adapter import NucleiAdapter
from .sqlmap_adapter import SQLMapAdapter
from .wapiti_adapter import WapitiAdapter
from .web_adapter import WebAdapter

__all__ = [
    "AdapterCommand",
    "BaseAdapter",
    "NmapAdapter",
    "NucleiAdapter",
    "SQLMapAdapter",
    "WapitiAdapter",
    "WebAdapter",
]
