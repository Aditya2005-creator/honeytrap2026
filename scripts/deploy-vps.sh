#!/usr/bin/env bash
# Deploy HoneyTrap on a fresh Ubuntu/Debian VPS (e.g. DigitalOcean, Hetzner, Linode).
# Usage: ./scripts/deploy-vps.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> HoneyTrap VPS deploy"

# ── 1. Install Docker if missing ──
if ! command -v docker &>/dev/null; then
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker "$USER" 2>/dev/null || true
fi

# ── 2. Environment file ──
if [[ ! -f .env ]]; then
    cp .env.example .env
  DASHBOARD_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
  SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    if grep -q "^DASHBOARD_KEY=" .env; then
        sed -i.bak "s|^DASHBOARD_KEY=.*|DASHBOARD_KEY=${DASHBOARD_KEY}|" .env
    else
        echo "DASHBOARD_KEY=${DASHBOARD_KEY}" >> .env
    fi
    if grep -q "^SECRET_KEY=" .env; then
        sed -i.bak "s|^SECRET_KEY=.*|SECRET_KEY=${SECRET_KEY}|" .env
    else
        echo "SECRET_KEY=${SECRET_KEY}" >> .env
    fi
    rm -f .env.bak
    echo ""
    echo "Created .env with random secrets."
    echo "SAVE THIS — dashboard password: ${DASHBOARD_KEY}"
    echo ""
fi

# ── 3. Build and start ──
docker compose --env-file .env up -d --build

echo ""
echo "==> HoneyTrap is running on port 8000"
echo "    Health:  curl http://localhost:8000/health"
echo "    Dashboard login: https://YOUR_DOMAIN/dashboard/login"
echo ""
echo "Next steps:"
echo "  1. Point your domain A-record to this server's public IP"
echo "  2. Edit Caddyfile — replace honeypot.example.com with your domain"
echo "  3. Install Caddy:  sudo apt install -y caddy"
echo "  4. sudo cp Caddyfile /etc/caddy/Caddyfile && sudo systemctl reload caddy"
echo "  5. Open firewall:  sudo ufw allow 80,443/tcp && sudo ufw allow 22/tcp && sudo ufw enable"
echo ""
