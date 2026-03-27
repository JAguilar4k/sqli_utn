"""
=============================================================
  SQL INJECTION SECURE LAB  –  ISW-1013 Calidad del Software
  Universidad Técnica Nacional
=============================================================

  ✅  VERSIÓN CORREGIDA — todas las vulnerabilidades han sido
  mitigadas. Los comentarios FIX-XX indican qué cambio
  corresponde a cada vulnerabilidad original.

  Correcciones aplicadas:
    FIX-01  Consultas parametrizadas en login (sin concatenación)
    FIX-02  Consultas parametrizadas en búsqueda (sin concatenación)
    FIX-03  Contraseñas hasheadas con Werkzeug (PBKDF2-SHA256)
    FIX-04  SECRET_KEY cargada desde variable de entorno
    FIX-05  debug=False en producción; controlado por variable de entorno
    FIX-06  Consulta SQL cruda eliminada de la interfaz
    FIX-07  Enlace "Admin" restringido a rol admin en templates
    FIX-08  Protección CSRF con Flask-WTF

  Dependencias necesarias:
    pip install flask flask-wtf werkzeug

  Variables de entorno requeridas antes de ejecutar:
    export SECRET_KEY="reemplaza-con-una-clave-aleatoria-segura"
    export FLASK_DEBUG=0   # usar 1 solo en desarrollo local
=============================================================
"""

import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf import CSRFProtect                                            # FIX-08
from werkzeug.security import generate_password_hash, check_password_hash   # FIX-03
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH  = BASE_DIR / "db" / "lab.db"

app = Flask(__name__)

# ---------------------------------------------------------------
# FIX-04: SECRET_KEY cargada desde variable de entorno.
# Nunca debe hardcodearse en el código fuente ni commitearse
# al repositorio. Si la variable no existe, se lanza un error
# claro para forzar una configuración explícita.
# ---------------------------------------------------------------
secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError(
        "La variable de entorno SECRET_KEY no está definida. "
        "Ejecútala con: export SECRET_KEY='<clave-aleatoria-segura>'"
    )
app.config["SECRET_KEY"] = secret_key

# ---------------------------------------------------------------
# FIX-08: Protección CSRF activada globalmente con Flask-WTF.
# Genera un token único por sesión que se valida en cada POST.
# Los templates deben incluir dentro de cada <form>:
#   {{ form.hidden_tag() }}
#   — o manualmente —
#   <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
# ---------------------------------------------------------------
csrf = CSRFProtect(app)


# ---------------------------------------------------------------
# Conexión a la base de datos
# ---------------------------------------------------------------
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------
# Inicialización de la base de datos con datos de prueba
# ---------------------------------------------------------------
def init_db():
    conn = get_connection()
    cur  = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT    NOT NULL UNIQUE,
        password TEXT    NOT NULL,
        role     TEXT    NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS books (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        title    TEXT NOT NULL,
        author   TEXT NOT NULL,
        category TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        event      TEXT NOT NULL,
        username   TEXT,
        detail     TEXT,
        timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # -------------------------------------------------------
    # FIX-03: Contraseñas hasheadas con PBKDF2-SHA256
    # mediante werkzeug.security.generate_password_hash.
    # Nunca se almacena la contraseña en texto plano.
    # -------------------------------------------------------
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        users = [
            ("admin",   generate_password_hash("Admin123"),   "admin"),
            ("analyst", generate_password_hash("Analyst123"), "user"),
            ("student", generate_password_hash("Student123"), "user"),
        ]
        cur.executemany(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            users
        )

    cur.execute("SELECT COUNT(*) FROM books")
    if cur.fetchone()[0] == 0:
        books = [
            ("Secure Coding Fundamentals",   "J. Howard",    "security"),
            ("Flask Web Patterns",           "A. Miller",    "development"),
            ("Practical SQL",                "A. DeBarros",  "database"),
            ("Threat Modeling Essentials",   "M. Silva",     "security"),
            ("Performance Testing Handbook", "R. Jones",     "qa"),
            ("OWASP Testing Guide",          "OWASP Team",   "security"),
            ("Clean Code",                   "R. Martin",    "development"),
            ("The Web Application Hacker",   "Stuttard",     "security"),
        ]
        cur.executemany(
            "INSERT INTO books (title, author, category) VALUES (?, ?, ?)",
            books
        )

    conn.commit()
    conn.close()


def log_event(event, username=None, detail=None):
    """Registra un evento en el log de auditoría."""
    conn = get_connection()
    conn.execute(
        "INSERT INTO audit_log (event, username, detail) VALUES (?, ?, ?)",
        (event, username, detail)
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------
# Rutas
# ---------------------------------------------------------------

@app.route("/")
def index():
    if session.get("username"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # ---------------------------------------------------
        # FIX-01: Consulta parametrizada en login.
        # El username se pasa como parámetro (?) separado de
        # la instrucción SQL. SQLite nunca lo interpreta como
        # código, por lo que payloads como:
        #   admin' --
        #   ' OR '1'='1' --
        # son tratados como texto literal y no surten efecto.
        #
        # La columna password se incluye en el SELECT para
        # poder verificar el hash en Python (FIX-03).
        # ---------------------------------------------------
        query = "SELECT id, username, password, role FROM users WHERE username = ?"

        conn = get_connection()
        try:
            user = conn.execute(query, (username,)).fetchone()
        except Exception as e:
            # FIX-06 (parcial): el error interno no se expone
            # al usuario; se registra solo en el log del servidor.
            app.logger.error("Error de BD en login: %s", e)
            flash("Error interno. Intente más tarde.", "error")
            conn.close()
            return render_template("login.html")
        conn.close()

        # FIX-03: la contraseña se verifica comparando el input
        # contra el hash almacenado, nunca en texto plano.
        if user and check_password_hash(user["password"], password):
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            log_event("LOGIN_OK", user["username"])
            flash("Inicio de sesión exitoso.", "success")
            return redirect(url_for("dashboard"))

        log_event("LOGIN_FAIL", username)
        flash("Credenciales incorrectas.", "error")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if not session.get("username"):
        flash("Debe iniciar sesión primero.", "error")
        return redirect(url_for("login"))
    return render_template(
        "dashboard.html",
        username=session.get("username"),
        role=session.get("role")
    )


@app.route("/search", methods=["GET", "POST"])
def search():
    if not session.get("username"):
        flash("Debe iniciar sesión primero.", "error")
        return redirect(url_for("login"))

    books = []

    if request.method == "POST":
        term = request.form.get("term", "")

        # ---------------------------------------------------
        # FIX-02: Consulta parametrizada en búsqueda.
        # El valor con comodines se construye en Python y se
        # pasa como parámetro (?). SQLite lo escapa de forma
        # automática; no puede alterar la lógica de la consulta.
        #
        # Payloads como:
        #   %' UNION SELECT id, username, password, role FROM users --
        # son tratados como texto literal sin efecto.
        # ---------------------------------------------------
        query = (
            "SELECT id, title, author, category FROM books "
            "WHERE title LIKE ? OR author LIKE ? OR category LIKE ?"
        )
        like_term = f"%{term}%"

        conn = get_connection()
        try:
            books = conn.execute(query, (like_term, like_term, like_term)).fetchall()
        except Exception as e:
            # FIX-06 (parcial): el error interno no se expone al usuario.
            app.logger.error("Error de BD en búsqueda: %s", e)
            flash("Error interno. Intente más tarde.", "error")
        conn.close()

    # FIX-06: raw_query eliminada por completo.
    # La consulta SQL interna nunca se pasa al template
    # ni se muestra en la interfaz de usuario.
    return render_template("search.html", books=books)


@app.route("/admin")
def admin():
    if not session.get("username"):
        flash("Debe iniciar sesión primero.", "error")
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        flash("No tiene permisos para acceder al panel de administración.", "error")
        log_event("ACCESS_DENIED", session.get("username"), "Intento de acceso a /admin")
        return redirect(url_for("dashboard"))

    conn  = get_connection()
    # FIX-03: se excluye la columna password de la consulta;
    # los hashes no deben mostrarse en ninguna interfaz.
    users = conn.execute("SELECT id, username, role FROM users ORDER BY id").fetchall()
    logs  = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()

    # FIX-07: el enlace "Admin" en layout.html debe mostrarse
    # únicamente cuando el usuario tiene rol admin.
    # Ejemplo en Jinja2:
    #   {% if session.get('role') == 'admin' %}
    #     <a href="/admin">Admin</a>
    #   {% endif %}
    return render_template("admin.html", users=users, logs=logs)


@app.route("/logout")
def logout():
    log_event("LOGOUT", session.get("username"))
    session.clear()
    flash("Sesión cerrada.", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------
# FIX-05: debug controlado por variable de entorno FLASK_DEBUG.
# Por defecto es False (seguro para producción).
# Solo se activa explícitamente en desarrollo con:
#   export FLASK_DEBUG=1
#
# Con debug=False, Flask NO activa el debugger interactivo,
# por lo que un error no permite ejecutar código en el servidor.
# ---------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)