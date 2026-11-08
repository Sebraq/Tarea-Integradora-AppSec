# ============================================================
# PORTAL UNIVERSITARIO - VERSION SEGURA (en construcción por fases)
# Fase I aplicada: validación, SQLi, XSS, inyección de comandos.
# Fase II (contraseñas/cripto/secretos/TLS/logging) se agrega luego
# sobre este mismo archivo. Datos y credenciales 100% ficticios.
# ============================================================
import sqlite3, hashlib, os, logging, subprocess, secrets as pysecrets
from flask import Flask, request, render_template, redirect, session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from dotenv import load_dotenv

from validators import (
    validar_correo, validar_carnet, validar_nombre,
    validar_nota, validar_busqueda, validar_nombre_reporte,
    validar_password,
)
from crypto import cifrar_dpi, descifrar_dpi  # crypto.py ya carga su propio secreto

load_dotenv()

app = Flask(__name__)
ph = PasswordHasher()

# FIX-TLS: la cookie de sesión solo se envía por HTTPS (Secure), no se
# puede leer desde JavaScript (HttpOnly, ya era el default de Flask) y
# no se envía en navegación entre sitios (SameSite=Lax). Con esto, si la
# app llegara a caer a HTTP (por ejemplo, si falta el certificado), las
# sesiones existentes dejan de funcionar en vez de viajar sin cifrar.
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


@app.after_request
def agregar_cabeceras_seguridad(resp):
    # FIX-TLS: HSTS le dice al navegador que, para este sitio, recuerde
    # usar siempre HTTPS durante 1 año, incluso si alguien escribe
    # "http://" a mano o sigue un enlace viejo sin "s".
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp

# FIX-SECRETOS: ya no hay credenciales escritas en el código.
# - 'secret_key' ahora viene de FLASK_SECRET_KEY (variable de entorno / .env).
# - DB_PASSWORD y API_KEY (presentes en vulnerable/) se eliminaron: eran
#   credenciales hardcodeadas que ningún código llegaba a usar realmente.
#   Encontrar secretos "muertos" como esos es en sí un hallazgo de auditoría:
#   quedan en el código por descuido y siguen siendo una fuga si alguien
#   reutiliza esa clave en otro sistema.
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError(
        "Falta la variable de entorno FLASK_SECRET_KEY. "
        "Copia .env.example a .env y complétala, o expórtala en tu shell."
    )

logging.basicConfig(filename="app.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("portal")


def log_evento(mensaje):
    """
    FIX-LOGS: helper central de logging. Si el usuario en sesión es admin,
    antepone ACCESO_ADMIN para poder filtrar luego los accesos
    administrativos (requisito de la tarea). Nunca recibe contraseñas,
    DPI, ni otros datos sensibles: eso lo decide quien llama a esta función.
    """
    prefijo = "ACCESO_ADMIN " if session.get("rol") == "admin" else ""
    log.info(f"{prefijo}{mensaje} ip={request.remote_addr}")


def db():
    c = sqlite3.connect("portal.db")
    c.row_factory = sqlite3.Row
    return c


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form["usuario"].strip()
        correo = request.form["correo"].strip()
        p = request.form["password"]

        if not u or not validar_correo(correo):
            return render_template("register.html", error="Usuario y/o correo inválidos")
        if not validar_password(p):
            return render_template("register.html", error="La contraseña debe tener al menos 8 caracteres")

        # FIX-PASSWORDS: Argon2 en vez de SHA-256. ph.hash() genera una sal
        # aleatoria distinta cada vez, así que dos usuarios con la misma
        # contraseña NUNCA terminan con el mismo hash (ver prueba comparativa).
        h = ph.hash(p)
        try:
            c = db()
            c.execute("INSERT INTO usuarios(usuario,correo,password_hash,rol) VALUES(?,?,?,?)",
                      (u, correo, h, "docente"))
            c.commit()
        except sqlite3.IntegrityError:
            return render_template("register.html", error="Usuario ya existe")
        return redirect("/login")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["usuario"]
        p = request.form["password"]
        # FIX-SQLI: consulta parametrizada, solo busca por usuario (no por password_hash)
        row = db().execute(
            "SELECT * FROM usuarios WHERE usuario=?", (u,)
        ).fetchone()
        # FIX-PASSWORDS: ph.verify() recalcula el hash usando la sal guardada
        # dentro del propio hash y lo compara; nunca se compara hash==hash.
        if row:
            try:
                ph.verify(row["password_hash"], p)
            except (VerifyMismatchError, InvalidHash):
                row = None
        if row:
            session["usuario"] = row["usuario"]
            session["rol"] = row["rol"]
            log_evento(f"Login OK usuario={u}")             # FIX-LOGS: ya no se registra la contraseña
            return redirect("/")
        log.warning(f"Login FALLIDO usuario={u} ip={request.remote_addr}")  # FIX-LOGS: sin contraseña
        return render_template("login.html", error="Credenciales inválidas")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/expediente/<int:id>")
def expediente(id):
    # FIX-SQLI: <int:id> en la ruta ya rechaza cualquier valor no numérico (Flask responde 404)
    if "usuario" not in session:
        return redirect("/login")
    est = db().execute("SELECT * FROM estudiantes WHERE id = ?", (id,)).fetchone()
    notas = db().execute("SELECT * FROM notas WHERE estudiante_id = ?", (id,)).fetchall()
    log_evento(f"Consulta expediente id={id} usuario={session['usuario']}")  # FIX-LOGS: sin DPI en el log
    # FIX-CRIPTO: el DPI se descifra solo para mostrarlo; en la BD sigue cifrado.
    est_dict = dict(est) if est else None
    if est_dict:
        est_dict["dpi"] = descifrar_dpi(est_dict["dpi"])
    return render_template("expediente.html", est=est_dict, notas=notas)


@app.route("/estudiantes/nuevo", methods=["GET", "POST"])
def estudiante_nuevo():
    if "usuario" not in session:
        return redirect("/login")
    if request.method == "POST":
        f = request.form
        errores = []
        if not validar_carnet(f["carnet"]):
            errores.append("Carnet inválido (debe ser 8 dígitos)")
        if not validar_nombre(f["nombre"]):
            errores.append("Nombre inválido")
        if not validar_nombre(f["apellido"]):
            errores.append("Apellido inválido")
        if not validar_correo(f["correo"]):
            errores.append("Correo inválido")
        if errores:
            return render_template("estudiante_nuevo.html", errores=errores, valores=f)

        c = db()
        # FIX-CRIPTO: el DPI se cifra antes de guardarse, nunca en texto plano.
        cur = c.execute(
            "INSERT INTO estudiantes(carnet,nombre,apellido,correo,dpi) VALUES(?,?,?,?,?)",
            (f["carnet"], f["nombre"].strip(), f["apellido"].strip(), f["correo"].strip(),
             cifrar_dpi(f["dpi"])),
        )
        c.commit()
        # FIX-LOGS: se registra la modificación (quién, qué, cuándo) sin
        # incluir correo, DPI ni otros datos personales del estudiante.
        log_evento(f"Creacion estudiante id={cur.lastrowid} usuario={session['usuario']}")
        return redirect(f"/expediente/{cur.lastrowid}")
    return render_template("estudiante_nuevo.html", errores=None, valores={})


@app.route("/notas/nueva/<int:est_id>", methods=["POST"])
def nota_nueva(est_id):
    if "usuario" not in session:
        return redirect("/login")
    ok, nota = validar_nota(request.form.get("nota"))
    if not ok:
        return redirect(f"/expediente/{est_id}?error=nota_invalida")
    c = db()
    c.execute("INSERT INTO notas(estudiante_id,curso,nota) VALUES(?,?,?)",
              (est_id, request.form["curso"].strip()[:60], nota))
    c.commit()
    # FIX-LOGS: se registra la modificación con el valor nuevo (es una nota,
    # no un dato personal sensible); no se registra ni correo ni DPI.
    log_evento(f"Asignacion nota estudiante_id={est_id} valor={nota} usuario={session['usuario']}")
    return redirect(f"/expediente/{est_id}")


@app.route("/notas/editar/<int:nota_id>", methods=["POST"])
def nota_editar(nota_id):
    if "usuario" not in session:
        return redirect("/login")
    ok, nota = validar_nota(request.form.get("nota"))
    row = db().execute("SELECT estudiante_id FROM notas WHERE id=?", (nota_id,)).fetchone()
    if row is None:
        return redirect("/")
    est_id = row["estudiante_id"]
    if not ok:
        return redirect(f"/expediente/{est_id}?error=nota_invalida")
    c = db()
    c.execute("UPDATE notas SET nota=? WHERE id=?", (nota, nota_id))
    c.commit()
    log_evento(f"Modificacion nota id={nota_id} estudiante_id={est_id} valor_nuevo={nota} usuario={session['usuario']}")
    return redirect(f"/expediente/{est_id}")


@app.route("/buscar")
def buscar():
    if "usuario" not in session:
        return redirect("/login")
    q = request.args.get("q", "")
    rows = []
    error = None
    if q:
        if not validar_busqueda(q):
            error = "Búsqueda con caracteres no permitidos"
        else:
            # FIX-SQLI: consulta parametrizada
            sql = "SELECT * FROM estudiantes WHERE nombre LIKE ? OR apellido LIKE ?"
            like = f"%{q}%"
            rows = db().execute(sql, (like, like)).fetchall()
    return render_template("buscar.html", rows=rows, q=q, error=error)
    # FIX-XSS: la plantilla ya NO usa |safe sobre q (ver buscar.html)


@app.route("/comentarios", methods=["GET", "POST"])
def comentarios():
    if "usuario" not in session:
        return redirect("/login")
    if request.method == "POST":
        texto = request.form.get("texto", "").strip()[:500]
        c = db()
        c.execute("INSERT INTO comentarios(autor,texto) VALUES(?,?)",
                  (session["usuario"], texto))
        c.commit()
        return redirect("/comentarios")
    rows = db().execute("SELECT * FROM comentarios ORDER BY id DESC").fetchall()
    return render_template("comentarios.html", rows=rows)
    # FIX-XSS: la plantilla ya NO usa |safe sobre texto (ver comentarios.html);
    # Jinja2 autoescapa {{ }} por defecto, así que <script> se muestra como texto.


@app.route("/reporte", methods=["GET", "POST"])
def reporte():
    if "usuario" not in session:
        return redirect("/login")
    msg = None
    error = None
    if request.method == "POST":
        nombre = request.form["nombre"]
        if not validar_nombre_reporte(nombre):
            error = "Nombre de reporte inválido (solo letras, números, guiones)"
        else:
            rows = db().execute("SELECT carnet,nombre,apellido,correo FROM estudiantes").fetchall()
            with open("datos.csv", "w", encoding="utf-8") as f:
                f.write("carnet,nombre,apellido,correo\n")
                for r in rows:
                    f.write(",".join(r) + "\n")
            os.makedirs("reportes", exist_ok=True)
            # FIX-COMANDOS: subprocess con lista de argumentos y shell=False;
            # no hay shell de por medio, así que ";", "&&", "|" no se interpretan.
            subprocess.run(
                ["tar", "-czf", f"reportes/{nombre}.tar.gz", "datos.csv"],
                shell=False, check=True,
            )
            msg = f"Reporte generado: reportes/{nombre}.tar.gz"
    return render_template("reporte.html", msg=msg, error=error)


# ------------------------------------------------------------------
# FIX-LOGS: manejo de errores internos.
#
# INSEGURO (como en vulnerable/, con debug=True): Flask muestra el
# traceback completo en el navegador -> expone rutas del servidor,
# nombres de variables, y a veces hasta fragmentos de consultas SQL.
#
# SEGURO (esto): el usuario solo ve un mensaje genérico con una
# referencia corta; el detalle completo (tipo de error, traceback)
# se guarda únicamente en app.log, nunca llega al cliente.
# ------------------------------------------------------------------
@app.errorhandler(Exception)
def manejar_error(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e  # 404, 405, etc. ya tienen su propia página estándar
    ref = pysecrets.token_hex(4)
    log.error(f"ERROR_INTERNO ref={ref} tipo={type(e).__name__} ruta={request.path}")
    return render_template("error.html", ref=ref), 500


if __name__ == "__main__":
    # FIX-TLS: si existe el certificado, se sirve por HTTPS (puerto 8443).
    # Si no, cae a HTTP en :5000 para no romper las pruebas/desarrollo rápido.
    cert, key = "certs/cert.pem", "certs/key.pem"
    if os.path.exists(cert) and os.path.exists(key):
        print("Sirviendo por HTTPS en https://0.0.0.0:8443 (certificado autofirmado de laboratorio)")
        app.run(host="0.0.0.0", port=8443, debug=False, ssl_context=(cert, key))
    else:
        print("AVISO: no se encontró certs/cert.pem ni certs/key.pem -> sirviendo HTTP sin cifrar en :5000")
        app.run(host="0.0.0.0", port=5000, debug=False)
