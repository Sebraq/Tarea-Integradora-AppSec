"""
Cifrado de datos en reposo - DPI de estudiantes.

Se usa Fernet, de la biblioteca 'cryptography' (no se implementa un
algoritmo propio, como pide la tarea). Fernet combina:
- AES-128 en modo CBC para confidencialidad
- HMAC-SHA256 para integridad/autenticidad (detecta si el dato fue alterado)
- Un timestamp firmado (permite expirar tokens si se quisiera)

FIX-SECRETOS: la clave YA NO está escrita en el código. Se lee desde la
variable de entorno DPI_ENCRYPTION_KEY (ver .env / .env.example). Si
falta, la aplicación se niega a arrancar en vez de usar un valor por
defecto inseguro.
"""
import os
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

load_dotenv()  # carga .env si existe; en un servidor real esto vendría
                # de variables de entorno del sistema o de una bóveda (Vault)

_CLAVE_DPI = os.environ.get("DPI_ENCRYPTION_KEY")
if not _CLAVE_DPI:
    raise RuntimeError(
        "Falta la variable de entorno DPI_ENCRYPTION_KEY. "
        "Copia .env.example a .env y complétala, o expórtala en tu shell."
    )

_fernet = Fernet(_CLAVE_DPI.encode())


def cifrar_dpi(texto_plano: str) -> str:
    if texto_plano is None:
        return None
    return _fernet.encrypt(texto_plano.encode()).decode()


def descifrar_dpi(token: str) -> str:
    if token is None:
        return None
    try:
        return _fernet.decrypt(token.encode()).decode()
    except InvalidToken:
        return "(dato ilegible o alterado)"
