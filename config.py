"""HoneyTrap configuration — all settings via environment variables."""

import os
import secrets
import sys


def _env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).lower() in ("1", "true", "yes")


IS_PRODUCTION = _env_bool("PRODUCTION")
PORT = int(os.environ.get("PORT", 5001))
DATABASE = os.environ.get("DATABASE", "attacks.db")

# Flask session signing — auto-generated if unset (sessions reset on restart)
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Dashboard password — must be changed in production
DASHBOARD_KEY = os.environ.get("DASHBOARD_KEY", "honeytrap2024")
if IS_PRODUCTION and DASHBOARD_KEY in ("honeytrap2024", "changeme", ""):
    print("ERROR: Set a strong DASHBOARD_KEY environment variable in production.", file=sys.stderr)
    sys.exit(1)

# Optional comma-separated IP allowlist for dashboard access (empty = allow all)
ALLOWED_DASHBOARD_IPS = {
    ip.strip()
    for ip in os.environ.get("ALLOWED_DASHBOARD_IPS", "").split(",")
    if ip.strip()
}

# Rate limit: max logged requests per IP per window
RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", 60))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", 60))  # seconds

# Auto-delete attacks older than N days (0 = keep forever)
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", 90))

# Optional Slack/Discord webhook URL for new-IP alerts
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")

# Paths excluded from honeypot logging
SKIP_LOG_PREFIXES = ("/dashboard", "/health")

SKIP_LOG_EXACT = {"/robots.txt", "/health"}
