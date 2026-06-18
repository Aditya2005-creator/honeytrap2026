"""
HoneyTrap - A Honeypot Server for Security Research
=====================================================
This Flask app pretends to be a vulnerable server.
Bots and scanners will probe it, and we log everything silently.
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from config import (
    ALLOWED_DASHBOARD_IPS,
    DASHBOARD_KEY,
    DATABASE,
    IS_PRODUCTION,
    PORT,
    RETENTION_DAYS,
    SECRET_KEY,
    SKIP_LOG_EXACT,
    SKIP_LOG_PREFIXES,
)
from services import (
    enqueue_geo_update,
    get_geo,
    log_attack_event,
    rate_limit_exceeded,
    send_new_ip_alert,
)
from export import build_attacks_workbook, export_filename

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("honeytrap")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

_cleanup_counter = 0


# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
    return db


@app.teardown_appcontext
def close_db(_exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                ip          TEXT,
                country     TEXT,
                city        TEXT,
                method      TEXT,
                path        TEXT,
                user_agent  TEXT,
                payload     TEXT,
                headers     TEXT
            )
        """)
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_attacks_ip ON attacks(ip)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_attacks_path ON attacks(path)"
        )
        db.commit()
        cleanup_old_attacks(db)


def cleanup_old_attacks(db=None):
    if RETENTION_DAYS <= 0:
        return
    if db is None:
        db = get_db()
    db.execute(
        "DELETE FROM attacks WHERE timestamp < datetime('now', ?)",
        (f"-{RETENTION_DAYS} days",),
    )
    db.commit()


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def get_client_ip() -> str:
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or ""
    if "," in ip:
        ip = ip.split(",")[0].strip()
    return ip


def should_skip_logging() -> bool:
    path = request.path.rstrip("/") or "/"
    if path in SKIP_LOG_EXACT:
        return True
    return any(request.path.startswith(prefix) for prefix in SKIP_LOG_PREFIXES)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("dashboard_login"))
        if not _dashboard_ip_allowed():
            return render_template("forbidden.html"), 404
        return f(*args, **kwargs)
    return decorated


def _dashboard_ip_allowed() -> bool:
    if not ALLOWED_DASHBOARD_IPS:
        return True
    return get_client_ip() in ALLOWED_DASHBOARD_IPS


def log_attack():
    ip = get_client_ip()

    if rate_limit_exceeded(ip):
        return

    country, city = get_geo(ip)

    payload = ""
    if request.method == "POST":
        if request.form:
            payload = json.dumps(dict(request.form))
        elif request.data:
            payload = request.data.decode("utf-8", errors="replace")[:500]

    interesting_headers = {
        "User-Agent": request.headers.get("User-Agent", ""),
        "Referer": request.headers.get("Referer", ""),
        "Content-Type": request.headers.get("Content-Type", ""),
        "Accept": request.headers.get("Accept", ""),
    }

    db = get_db()
    is_new_ip = db.execute(
        "SELECT COUNT(*) as c FROM attacks WHERE ip = ?", (ip,)
    ).fetchone()["c"] == 0

    cursor = db.execute(
        """
        INSERT INTO attacks
            (timestamp, ip, country, city, method, path, user_agent, payload, headers)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            country,
            city,
            request.method,
            request.path,
            request.headers.get("User-Agent", ""),
            payload,
            json.dumps(interesting_headers),
        ),
    )
    db.commit()
    attack_id = cursor.lastrowid

    if country == "Unknown":
        enqueue_geo_update(ip, attack_id)

    log_attack_event(
        ip, country, city, request.method, request.path,
        request.headers.get("User-Agent", ""), payload,
    )

    if is_new_ip:
        send_new_ip_alert(ip, request.path, request.method, country)


# ─────────────────────────────────────────────
# MIDDLEWARE
# ─────────────────────────────────────────────

@app.before_request
def honeypot_before_request():
    global _cleanup_counter

    if should_skip_logging():
        return

    log_attack()

    _cleanup_counter += 1
    if _cleanup_counter % 500 == 0:
        cleanup_old_attacks()


@app.after_request
def add_realistic_headers(response):
    if not should_skip_logging():
        response.headers["Server"] = "nginx/1.24.0"
    return response


# ─────────────────────────────────────────────
# SYSTEM ROUTES
# ─────────────────────────────────────────────

@app.route("/health", methods=["GET", "HEAD"], strict_slashes=False)
def health():
    try:
        db = get_db()
        db.execute("SELECT 1").fetchone()
    except sqlite3.Error as exc:
        logger.error("Health check DB failure: %s", exc)
        return jsonify({"status": "error", "db": "unavailable"}), 503
    return jsonify({"status": "ok", "db": "ok"}), 200


@app.route("/robots.txt")
def robots():
    return (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /wp-admin\n"
        "Disallow: /.env\n",
        200,
        {"Content-Type": "text/plain"},
    )


# ─────────────────────────────────────────────
# HONEYPOT ROUTES
# ─────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def fake_login():
    if request.method == "POST":
        return render_template("login.html", error="Invalid username or password.")
    return render_template("login.html", error=None)


@app.route("/admin", methods=["GET", "POST"])
@app.route("/admin/", methods=["GET", "POST"])
def fake_admin():
    return render_template("admin.html")


@app.route("/wp-admin", methods=["GET", "POST"])
@app.route("/wp-admin/", methods=["GET", "POST"])
@app.route("/wp-login.php", methods=["GET", "POST"])
def fake_wordpress():
    return render_template("login.html", error="Invalid username or password.")


@app.route("/phpmyadmin", methods=["GET", "POST"])
@app.route("/phpmyadmin/", methods=["GET", "POST"])
@app.route("/pma", methods=["GET", "POST"])
def fake_phpmyadmin():
    return render_template("phpmyadmin.html")


@app.route("/.env", methods=["GET"])
def fake_env():
    return render_template("forbidden.html"), 404


@app.route("/api/v1/users", methods=["GET", "POST"])
@app.route("/api/users", methods=["GET", "POST"])
def fake_api():
    fake_users = [
        {"id": 1, "username": "admin", "email": "admin@company.com", "role": "superadmin"},
        {"id": 2, "username": "john.doe", "email": "john@company.com", "role": "user"},
        {"id": 3, "username": "jane.smith", "email": "jane@company.com", "role": "user"},
    ]
    return json.dumps(fake_users), 200, {"Content-Type": "application/json"}


@app.route("/config.php", methods=["GET"])
@app.route("/configuration.php", methods=["GET"])
@app.route("/wp-config.php", methods=["GET"])
def fake_config():
    return render_template("forbidden.html"), 403


@app.route("/shell", methods=["GET", "POST"])
@app.route("/cmd", methods=["GET", "POST"])
@app.route("/c99.php", methods=["GET", "POST"])
def fake_shell():
    return render_template("forbidden.html"), 403


# ─────────────────────────────────────────────
# DASHBOARD (session auth — no secrets in URL)
# ─────────────────────────────────────────────

@app.route("/dashboard/login", methods=["GET", "POST"])
def dashboard_login():
    if not _dashboard_ip_allowed():
        return render_template("forbidden.html"), 404

    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == DASHBOARD_KEY:
            session["authenticated"] = True
            session.permanent = True
            return redirect(url_for("dashboard"))
        error = "Invalid password."

    if session.get("authenticated"):
        return redirect(url_for("dashboard"))

    return render_template("dashboard_login.html", error=error)


@app.route("/dashboard/logout", methods=["POST"])
def dashboard_logout():
    session.clear()
    return redirect(url_for("dashboard_login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()

    total = db.execute("SELECT COUNT(*) as count FROM attacks").fetchone()["count"]
    unique_ips = db.execute(
        "SELECT COUNT(DISTINCT ip) as count FROM attacks"
    ).fetchone()["count"]

    top_ips = db.execute("""
        SELECT ip, country, COUNT(*) as hits
        FROM attacks
        GROUP BY ip
        ORDER BY hits DESC
        LIMIT 10
    """).fetchall()

    top_paths = db.execute("""
        SELECT path, COUNT(*) as hits
        FROM attacks
        GROUP BY path
        ORDER BY hits DESC
        LIMIT 10
    """).fetchall()

    by_country = db.execute("""
        SELECT country, COUNT(*) as hits
        FROM attacks
        GROUP BY country
        ORDER BY hits DESC
        LIMIT 15
    """).fetchall()

    by_method = db.execute("""
        SELECT method, COUNT(*) as hits
        FROM attacks
        GROUP BY method
        ORDER BY hits DESC
    """).fetchall()

    recent = db.execute("""
        SELECT * FROM attacks
        ORDER BY id DESC
        LIMIT 30
    """).fetchall()

    by_day = db.execute("""
        SELECT DATE(timestamp) as day, COUNT(*) as hits
        FROM attacks
        WHERE timestamp >= DATE('now', '-7 days')
        GROUP BY day
        ORDER BY day ASC
    """).fetchall()

    return render_template(
        "dashboard.html",
        total=total,
        unique_ips=unique_ips,
        top_ips=top_ips,
        top_paths=top_paths,
        by_country=by_country,
        by_method=by_method,
        recent=recent,
        by_day=by_day,
    )


@app.route("/dashboard/export")
@login_required
def dashboard_export():
    db = get_db()
    buffer = build_attacks_workbook(db)
    return send_file(
        buffer,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name=export_filename(),
    )


# Catch-all must be last — otherwise it shadows /health/, /dashboard, etc.
@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def catch_all(path):
    return render_template("login.html", error=None)


# ─────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────

init_db()

if __name__ == "__main__":
    mode = "production" if IS_PRODUCTION else "development"
    print(f"\n🍯 HoneyTrap running on http://localhost:{PORT} ({mode})")
    print(f"📊 Dashboard: http://localhost:{PORT}/dashboard/login\n")
    app.run(host="0.0.0.0", port=PORT, debug=False)
