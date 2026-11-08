# ============================================================
# PORTAL UNIVERSITARIO - VERSION VULNERABLE (SOLO LABORATORIO)
# Datos y credenciales 100% ficticios.
# ============================================================
import sqlite3, hashlib, os, logging
from flask import Flask, request, render_template, redirect, session

app = Flask(__name__)

# VULN-SECRETOS: credenciales ficticias escritas en el código
app.secret_key = "supersecreto123"
DB_PASSWORD = "Admin_DB_2026!"
API_KEY = "AKIAIOSFODNN7EXAMPLE"

logging.basicConfig(filename="app.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("portal")


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
        u = request.form["usuario"]
        correo = request.form["correo"]
        p = request.form["password"]
        # VULN-PASSWORDS: SHA-256 simple, sin sal. VULN-VALIDACION: nada se valida
        h = hashlib.sha256(p.encode()).hexdigest()
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
        h = hashlib.sha256(p.encode()).hexdigest()
        # VULN-SQLI: concatenación de strings
        q = "SELECT * FROM usuarios WHERE usuario='%s' AND password_hash='%s'" % (u, h)
        row = db().execute(q).fetchone()
        if row:
            session["usuario"] = row["usuario"]
            session["rol"] = row["rol"]
            log.info(f"Login OK usuario={u} password={p}")        # VULN-LOGS: contraseña en el log
            return redirect("/")
        log.warning(f"Login FALLIDO usuario={u} password={p}")     # VULN-LOGS
        return render_template("login.html", error="Credenciales inválidas")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/expediente/<id>")
def expediente(id):
    if "usuario" not in session:
        return redirect("/login")
    # VULN-SQLI: f-string con el parámetro de la URL
    est = db().execute(f"SELECT * FROM estudiantes WHERE id = {id}").fetchone()
    notas = db().execute(f"SELECT * FROM notas WHERE estudiante_id = {id}").fetchall()
    log.info(f"Consulta expediente id={id} usuario={session['usuario']} dpi={est['dpi'] if est else ''}")
    return render_template("expediente.html", est=est, notas=notas)


@app.route("/estudiantes/nuevo", methods=["GET", "POST"])
def estudiante_nuevo():
    if "usuario" not in session:
        return redirect("/login")
    if request.method == "POST":
        f = request.form
        c = db()
        # VULN-VALIDACION: no se valida nada (carnet, nombre, correo, DPI)
        cur = c.execute("INSERT INTO estudiantes(carnet,nombre,apellido,correo,dpi) VALUES(?,?,?,?,?)",
                        (f["carnet"], f["nombre"], f["apellido"], f["correo"], f["dpi"]))
        c.commit()
        return redirect(f"/expediente/{cur.lastrowid}")
    return render_template("estudiante_nuevo.html")


@app.route("/notas/nueva/<int:est_id>", methods=["POST"])
def nota_nueva(est_id):
    if "usuario" not in session:
        return redirect("/login")
    c = db()
    # VULN-VALIDACION: la calificación no se valida (acepta -50, 9999, texto)
    c.execute("INSERT INTO notas(estudiante_id,curso,nota) VALUES(?,?,?)",
              (est_id, request.form["curso"], request.form["nota"]))
    c.commit()
    return redirect(f"/expediente/{est_id}")


@app.route("/notas/editar/<int:nota_id>", methods=["POST"])
def nota_editar(nota_id):
    if "usuario" not in session:
        return redirect("/login")
    c = db()
    # VULN-VALIDACION: sin validar calificación ni verificar rol/permiso
    c.execute("UPDATE notas SET nota=? WHERE id=?", (request.form["nota"], nota_id))
    c.commit()
    est_id = c.execute("SELECT estudiante_id FROM notas WHERE id=?", (nota_id,)).fetchone()[0]
    return redirect(f"/expediente/{est_id}")


@app.route("/buscar")
def buscar():
    if "usuario" not in session:
        return redirect("/login")
    q = request.args.get("q", "")
    rows = []
    if q:
        # VULN-SQLI: búsqueda concatenada
        sql = f"SELECT * FROM estudiantes WHERE nombre LIKE '%{q}%' OR apellido LIKE '%{q}%'"
        rows = db().execute(sql).fetchall()
    return render_template("buscar.html", rows=rows, q=q)   # q se refleja sin escapar (ver plantilla)


@app.route("/comentarios", methods=["GET", "POST"])
def comentarios():
    if "usuario" not in session:
        return redirect("/login")
    if request.method == "POST":
        c = db()
        c.execute("INSERT INTO comentarios(autor,texto) VALUES(?,?)",
                  (session["usuario"], request.form["texto"]))
        c.commit()
        return redirect("/comentarios")
    rows = db().execute("SELECT * FROM comentarios ORDER BY id DESC").fetchall()
    return render_template("comentarios.html", rows=rows)


@app.route("/reporte", methods=["GET", "POST"])
def reporte():
    if "usuario" not in session:
        return redirect("/login")
    msg = None
    if request.method == "POST":
        nombre = request.form["nombre"]
        rows = db().execute("SELECT carnet,nombre,apellido,correo FROM estudiantes").fetchall()
        with open("datos.csv", "w", encoding="utf-8") as f:
            f.write("carnet,nombre,apellido,correo\n")
            for r in rows:
                f.write(",".join(r) + "\n")
        os.makedirs("reportes", exist_ok=True)
        # VULN-COMANDOS: el nombre llega directo a la shell
        os.system(f"tar -czf reportes/{nombre}.tar.gz datos.csv")
        msg = f"Reporte generado: reportes/{nombre}.tar.gz"
    return render_template("reporte.html", msg=msg)


if __name__ == "__main__":
    # VULN-CONFIG: debug=True expone el traceback; HTTP plano; escucha en todas las interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
