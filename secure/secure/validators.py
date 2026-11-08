"""
Validadores de entrada - Fase I.
IMPORTANTE: validar NO sustituye a parametrizar consultas ni a escapar
salida. Un dato con forma correcta (ej. O'Brien) puede seguir rompiendo
SQL/HTML/comandos si no se maneja con las técnicas adecuadas además de
validarlo. Aquí se validan solo FORMATO y RANGO.
"""
import re

RE_CORREO = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
RE_CARNET = re.compile(r"^\d{8}$")
RE_NOMBRE = re.compile(r"^[A-Za-zÀ-ÖØ-öø-ÿ' -]{1,60}$")
RE_BUSQUEDA = re.compile(r"^[A-Za-zÀ-ÖØ-öø-ÿ0-9 '\-]{0,50}$")
RE_REPORTE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


def validar_correo(v):
    return bool(RE_CORREO.match(v or ""))


def validar_carnet(v):
    return bool(RE_CARNET.match(v or ""))


def validar_nombre(v):
    return bool(v) and bool(RE_NOMBRE.match(v.strip()))


def validar_nota(v):
    try:
        n = float(v)
    except (TypeError, ValueError):
        return False, None
    if 0 <= n <= 100:
        return True, n
    return False, None


def validar_busqueda(v):
    return bool(RE_BUSQUEDA.match(v or ""))


def validar_nombre_reporte(v):
    return bool(RE_REPORTE.match(v or ""))


def validar_password(v):
    # Política mínima: al menos 8 caracteres. No es el foco de la tarea,
    # pero evita que Argon2 proteja contraseñas triviales como "123".
    return bool(v) and len(v) >= 8
