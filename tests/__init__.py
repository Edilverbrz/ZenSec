"""Suite de pruebas de ZecSec.

Añade la raíz del proyecto al ``sys.path`` para que los tests puedan
importar ``core`` y ``adapters`` sin rutas absolutas.
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
