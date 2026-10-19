import os
import secrets
import subprocess

from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)

# Secret lu dans l'environnement (valeur aleatoire si absent)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Liste blanche de commandes
ALLOWED = {"date": ["date"], "uptime": ["uptime"]}


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/")
def index():
    return """
    <h1>Welcome to our fixed Flask App</h1>
    <ul>
        <li><a href="/hello?name=World">Hello Page</a></li>
        <li><a href="/execute?cmd=date">Execute Command Page (allowed: date, uptime)</a></li>
    </ul>
    """


@app.route("/hello")
def hello():
    name = request.args.get("name", "Guest")
    return f"""
    <h1>Hello Page</h1>
    <p>Hello, {escape(name)}!</p>
    <p><a href="/">Back to Homepage</a></p>
    """


@app.route("/execute")
def execute():
    key = request.args.get("cmd", "date")
    if key not in ALLOWED:
        return "Commande non autorisee", 400
    result = subprocess.run(ALLOWED[key], capture_output=True, text=True)
    return f"""
    <h1>Execute Command Page</h1>
    <pre>{escape(result.stdout)}</pre>
    <p><a href="/">Back to Homepage</a></p>
    """


# La route /admin a ete supprimee (fuite du secret)

if __name__ == "__main__":
    # Lancement local uniquement ; en conteneur c'est gunicorn qui sert l'appli
    app.run(host="127.0.0.1")
