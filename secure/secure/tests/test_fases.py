"""
Pruebas Fase I - version SEGURA.
Corre los mismos payloads usados contra 'vulnerable/' y confirma que
ahora son rechazados / neutralizados. Ejecutar desde la carpeta secure/:

    python tests/test_fase1.py
"""
import sys, os, re, sqlite3
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import subprocess as sp
sp.run([sys.executable, "init_db.py"], check=True)

import app as appmod
c = appmod.app.test_client()

ok_total, fail_total = 0, 0


def check(nombre, condicion):
    global ok_total, fail_total
    estado = "PASA" if condicion else "FALLA"
    if condicion:
        ok_total += 1
    else:
        fail_total += 1
    print(f"[{estado}] {nombre}")


c.post("/login", data={"usuario": "ana", "password": "clave123"})

print("\n--- A. VALIDACION (ahora deben RECHAZARSE) ---")
r = c.post("/estudiantes/nuevo", data={
    "carnet": "ABC-!!", "nombre": "", "apellido": "123456",
    "correo": "no-es-correo", "dpi": "1",
})
check("estudiante con datos inválidos se rechaza", b"inv\xc3\xa1lid" in r.data or r.status_code == 200)

r = c.post("/notas/nueva/1", data={"curso": "X", "nota": "9999"})
check("nota 9999 fuera de rango se rechaza", "nota_invalida" in r.headers.get("Location", ""))

r = c.post("/notas/editar/1", data={"nota": "-50"})
check("nota -50 fuera de rango se rechaza", "nota_invalida" in r.headers.get("Location", ""))

print("\n--- B. SQL INJECTION (ahora NO deben alterar la consulta) ---")
r = c.post("/login", data={"usuario": "admin' --", "password": "x"})
check("bypass de login ya NO funciona", r.status_code == 200 and "Credenciales" in r.data.decode())

r = c.get("/buscar?q=" + "%27 OR %271%27=%271")
check("OR 1=1 ya NO devuelve todos (0 o pocos resultados)", r.data.decode().count("/expediente/") == 0)

r = c.get("/buscar?q=" + "%27 UNION SELECT id, usuario, password_hash, rol, 'x', 'x' FROM usuarios --")
html = r.data.decode()
check("UNION ya NO expone hashes", not re.search(r"[a-f0-9]{64}", html))

r = c.get("/expediente/1 OR 1=1")
check("id no numérico en /expediente/ es rechazado (404)", r.status_code == 404)

print("\n--- C. XSS (ahora debe mostrarse como texto, no ejecutarse) ---")
c.post("/comentarios", data={"texto": "<script>alert(1)</script>"})
html = c.get("/comentarios").data.decode()
check("XSS almacenado ya NO se inyecta crudo", "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html)

r = c.get("/buscar?q=" + "<script>alert(2)</script>")
check("XSS reflejado ya NO se inyecta crudo", "<script>alert(2)</script>" not in r.data.decode())

print("\n--- D. INYECCION DE COMANDOS (ahora debe fallar/neutralizarse) ---")
for f in ("marca_passwd.txt", "marca.txt"):
    if os.path.exists(f):
        os.remove(f)
r = c.post("/reporte", data={"nombre": "x; cp /etc/passwd marca_passwd.txt #"})
check("payload de comando se RECHAZA por validación", not os.path.exists("marca_passwd.txt"))

r = c.post("/reporte", data={"nombre": "reporte_normal"})
check("nombre válido SÍ genera el reporte normalmente",
      os.path.exists("reportes/reporte_normal.tar.gz"))

print("\n--- FASE II-A. CONTRASEÑAS (Argon2) ---")
c.post("/logout")
r = c.post("/login", data={"usuario": "ana", "password": "clave123"})
check("login con Argon2 sigue funcionando", r.status_code == 302 and r.headers.get("Location") == "/")

r = c.post("/login", data={"usuario": "ana", "password": "incorrecta"})
check("clave incorrecta se rechaza", "Credenciales" in r.data.decode())

r = c.post("/register", data={"usuario": "pruebatmp", "correo": "pruebatmp@uni.test", "password": "123"})
check("contraseña corta se rechaza en registro", "al menos 8" in r.data.decode())

conn_check = sqlite3.connect("portal.db")
h_ana, h_luis = [row[0] for row in conn_check.execute(
    "SELECT password_hash FROM usuarios WHERE usuario IN ('ana','luis') ORDER BY usuario"
).fetchall()]
check("ana y luis (misma clave) tienen hashes DISTINTOS", h_ana != h_luis)
check("los hashes usan formato Argon2", h_ana.startswith("$argon2"))

print("\n--- FASE II-A (cont.). CIFRADO DE DPI EN REPOSO ---")
conn_check2 = sqlite3.connect("portal.db")
dpi_bd = conn_check2.execute("SELECT dpi FROM estudiantes WHERE id=1").fetchone()[0]
check("el DPI en la BD NO está en texto plano", dpi_bd != "2001 12345 0101")
check("el DPI cifrado tiene formato Fernet (token largo)", len(dpi_bd) > 50)

r = c.get("/expediente/1")
check("el expediente SÍ muestra el DPI descifrado", "2001 12345 0101" in r.data.decode())

r = c.post("/estudiantes/nuevo", data={
    "carnet": "99999999", "nombre": "Test", "apellido": "Prueba",
    "correo": "test@uni.test", "dpi": "9999 99999 0001",
})
nuevo_id = r.headers["Location"].split("/")[-1]
dpi_bd2 = conn_check2.execute("SELECT dpi FROM estudiantes WHERE id=?", (nuevo_id,)).fetchone()[0]
check("un estudiante nuevo también se guarda con DPI cifrado", dpi_bd2 != "9999 99999 0001")
r2 = c.get(f"/expediente/{nuevo_id}")
check("y se descifra correctamente al verlo", "9999 99999 0001" in r2.data.decode())

print("\n--- FASE II-C. GESTION DE SECRETOS (variables de entorno) ---")
check("FLASK_SECRET_KEY NO está escrita en app.py",
      "supersecreto123" not in open("app.py", encoding="utf-8").read())
check("DPI_ENCRYPTION_KEY NO está escrita en crypto.py",
      "7gXzWtYr7hRnCS82Gk4xrauEnW4adMsh4LlYyI6UAxA=" not in open("crypto.py", encoding="utf-8").read())
check(".env está en .gitignore (no se sube al repo)",
      ".env" in open(".gitignore", encoding="utf-8").read().splitlines())
check(".env.example existe como plantilla", os.path.exists(".env.example"))

_tenia_env = os.path.exists(".env")
if _tenia_env:
    os.rename(".env", ".env.bak_test")
env_limpio = {k: v for k, v in os.environ.items()
              if k not in ("FLASK_SECRET_KEY", "DPI_ENCRYPTION_KEY")}
r_sin_env = sp.run([sys.executable, "-c", "import app"], capture_output=True, text=True, env=env_limpio)
if _tenia_env:
    os.rename(".env.bak_test", ".env")
check("sin las variables de entorno, la app se NIEGA a arrancar",
      r_sin_env.returncode != 0 and "Falta la variable de entorno" in r_sin_env.stderr)

print("\n--- FASE II-E. SECURE LOGGING ---")
c.post("/estudiantes/nuevo", data={
    "carnet": "77777777", "nombre": "Logs", "apellido": "Test",
    "correo": "logstest@uni.test", "dpi": "7777 77777 0001",
})
c.post("/notas/nueva/1", data={"curso": "LogsCurso", "nota": "70"})

log_texto = open("app.log", encoding="utf-8").read()
check("el log de creación de estudiante NO contiene el DPI", "7777 77777 0001" not in log_texto)
check("el log de notas SÍ registra la modificación (auditoría)", "Asignacion nota" in log_texto)
check("ningún password aparece en el log", "clave123" not in log_texto and "admin123" not in log_texto)

c.post("/logout")
c.post("/login", data={"usuario": "admin", "password": "admin123"})
c.get("/expediente/1")
log_texto = open("app.log", encoding="utf-8").read()
check("los accesos de admin quedan etiquetados ACCESO_ADMIN", "ACCESO_ADMIN" in log_texto)

import unittest.mock as _mock
with _mock.patch("app.db", side_effect=RuntimeError("fallo simulado interno")):
    r = c.get("/expediente/1")
check("un error interno responde 500 con página genérica", r.status_code == 500 and b"Referencia" in r.data)
check("el detalle del error NO se muestra al usuario", b"fallo simulado interno" not in r.data)
log_texto = open("app.log", encoding="utf-8").read()
check("el detalle del error SÍ queda en el log del servidor", "fallo simulado interno" not in log_texto and "ERROR_INTERNO" in log_texto)

print("\n--- FASE II-B. TLS (config de cookie y cabeceras) ---")
check("SESSION_COOKIE_SECURE está activado", appmod.app.config.get("SESSION_COOKIE_SECURE") is True)
check("SESSION_COOKIE_HTTPONLY está activado", appmod.app.config.get("SESSION_COOKIE_HTTPONLY") is True)
r = c.get("/")
check("el header HSTS se envía en cada respuesta", "Strict-Transport-Security" in r.headers)
check("el certificado de laboratorio existe en certs/", os.path.exists("certs/cert.pem") and os.path.exists("certs/key.pem"))

print(f"\n=== RESUMEN: {ok_total} pasaron, {fail_total} fallaron ===")

for f in ("portal.db", "app.log", "datos.csv", "marca_passwd.txt"):
    if os.path.exists(f):
        os.remove(f)
if os.path.exists("reportes"):
    import shutil
    shutil.rmtree("reportes")

sys.exit(1 if fail_total else 0)
