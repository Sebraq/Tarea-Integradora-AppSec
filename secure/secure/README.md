# Portal seguro (LAB) - Fase I + Fase II-A + Fase II-C (secretos)

## Correcciones aplicadas
Fase I: validación, SQL Injection (parametrizado), XSS (autoescape), inyección de
comandos (subprocess sin shell + validación).

Fase II-A: contraseñas con Argon2, cifrado del DPI en reposo con Fernet.

Fase II-C (secretos):
- FLASK_SECRET_KEY y DPI_ENCRYPTION_KEY ya NO están en el código, se leen
  de variables de entorno (.env, cargado con python-dotenv).
- DB_PASSWORD y API_KEY (de vulnerable/) se eliminaron: eran credenciales
  hardcodeadas que el código nunca llegaba a usar.
- `.env` tiene permisos 600 y está en `.gitignore`. `.env.example` es la
  plantilla pública, sin valores reales.
- Si faltan las variables, la app se niega a arrancar (ver tests).


## Uso
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # si vienes de cero; aquí ya incluimos un .env de ejemplo funcional
python init_db.py
python app.py        # http://localhost:5000
```

## Pruebas automáticas
```bash
python tests/test_fases.py
```
26 verificaciones: Fase I + contraseñas Argon2 + cifrado DPI + gestión de secretos.

Usuarios ficticios: admin/admin123, ana/clave123, luis/clave123

## TLS
Se incluye un certificado autofirmado de laboratorio en `certs/` (cert.pem, key.pem).
La app detecta estos archivos y sirve por **HTTPS en el puerto 8443** automáticamente.
Si no existieran, cae a HTTP en :5000 (solo como respaldo, no usar así para la entrega).

```bash
python app.py
# Sirviendo por HTTPS en https://0.0.0.0:8443
```

Probar el handshake:
```bash
curl -vk https://localhost:8443/
echo | openssl s_client -connect localhost:8443 -tls1_2
```
El navegador mostrará advertencia de certificado no confiable: es normal,
es autofirmado y solo para este laboratorio.

## Secure logging
- Login (éxito/fallo), consultas de expediente, creación de estudiantes y
  modificación de notas quedan en `app.log`, sin contraseñas ni DPI.
- Los accesos de un usuario con rol `admin` se marcan con el prefijo
  `ACCESO_ADMIN` para poder filtrarlos.
- Un error interno (500) muestra al usuario solo una referencia corta
  (`templates/error.html`); el detalle (tipo de excepción, ruta) queda
  únicamente en `app.log`, nunca en la respuesta HTTP.


Nota TLS: además del certificado, la cookie de sesión tiene `Secure` +
`HttpOnly` + `SameSite=Lax`, y cada respuesta incluye el header HSTS
(`Strict-Transport-Security`). Sin esto, la app podía "funcionar" en HTTP
(fallback de desarrollo) y la sesión seguiría viajando sin cifrar.
