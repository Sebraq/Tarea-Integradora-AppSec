import sqlite3, os
from argon2 import PasswordHasher
from crypto import cifrar_dpi

ph = PasswordHasher()

if os.path.exists("portal.db"):
    os.remove("portal.db")
c = sqlite3.connect("portal.db")
c.executescript("""
CREATE TABLE usuarios(id INTEGER PRIMARY KEY, usuario TEXT UNIQUE, correo TEXT, password_hash TEXT, rol TEXT);
CREATE TABLE estudiantes(id INTEGER PRIMARY KEY, carnet TEXT, nombre TEXT, apellido TEXT, correo TEXT, dpi TEXT);
CREATE TABLE notas(id INTEGER PRIMARY KEY, estudiante_id INTEGER, curso TEXT, nota REAL);
CREATE TABLE comentarios(id INTEGER PRIMARY KEY, autor TEXT, texto TEXT);
""")

# FIX-PASSWORDS: Argon2 en vez de SHA-256. Cada hash incluye su propia sal
# aleatoria, por eso dos usuarios con la MISMA clave (ana y luis) ahora
# terminan con hashes DISTINTOS (compáralo con vulnerable/portal.db).
c.executemany("INSERT INTO usuarios(usuario,correo,password_hash,rol) VALUES(?,?,?,?)", [
    ("admin", "admin@uni.test", ph.hash("admin123"), "admin"),
    ("ana",   "ana@uni.test",   ph.hash("clave123"), "docente"),
    ("luis",  "luis@uni.test",  ph.hash("clave123"), "docente"),
])

est = [("20260001","Ana","López"),("20260002","Luis","Pérez"),("20260003","María","García"),
       ("20260004","José","Hernández"),("20260005","Sofía","Martínez"),("20260006","Carlos","Ramírez"),
       ("20260007","Lucía","Morales"),("20260008","Pedro","O'Brien"),("20260009","Elena","Castillo"),
       ("20260010","Diego","Méndez")]
for i,(carnet,n,a) in enumerate(est, start=1):
    # FIX-CRIPTO: el DPI se guarda cifrado con Fernet, nunca en texto plano.
    dpi_plano = f"2{i:03d} 12345 010{i}"
    c.execute("INSERT INTO estudiantes(carnet,nombre,apellido,correo,dpi) VALUES(?,?,?,?,?)",
              (carnet, n, a, f"{n.lower()}@uni.test", cifrar_dpi(dpi_plano)))
    for curso, nota in (("Matemática I", 60+i*3), ("Programación I", 70+i*2)):
        c.execute("INSERT INTO notas(estudiante_id,curso,nota) VALUES(?,?,?)", (i, curso, nota))
c.commit()
print("BD creada: portal.db (contraseñas con Argon2)")
