import os
import secrets
import subprocess

from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)

# 1. Secret lu dans l'environnement (valeur aléatoire si absent, pour ne pas planter en CI)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# 3. Liste blanche de commandes
ALLOWED = {"date": ["date"], "uptime": ["uptime"]}


@app.after_request
def security_headers(resp):  # 7. En-têtes de sécurité
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Server"] = "webserver"  # masque Werkzeug/Python
    return resp


@app.route("/hello")
def hello():
    name = request.args.get("name", "Guest")
    return f"<h1>Hello Page</h1><p>Hello, {escape(name)}!</p>"  # 2. anti-XSS


@app.route("/execute")
def execute():
    key = request.args.get("cmd", "date")
    if key not in ALLOWED:
        return "Commande non autorisee", 400  # n'affiche pas l'entrée
    out = subprocess.run(ALLOWED[key], capture_output=True, text=True)  # pas de shell=True
    return f"<pre>{escape(out.stdout)}</pre>"


# 4. Route /admin supprimée

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG") == "1"  # 5. debug désactivé par défaut
    app.run(debug=debug, host="0.0.0.0")
