"""
Modulo de notificaciones (simulado) - envia un aviso cuando se crea
un estudiante nuevo. No hace una llamada real a internet.
"""
import os

API_KEY = os.environ.get("NOTIF_API_KEY")


def notificar_estudiante_creado(nombre):
    if not API_KEY:
        raise RuntimeError("Falta la variable de entorno NOTIF_API_KEY")
    print(f"[notificaciones] aviso creado para {nombre}")
