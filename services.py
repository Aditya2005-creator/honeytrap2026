"""Background services: geo lookup, rate limiting, webhooks, structured logging."""

import json
import logging
import queue
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

import requests

from config import (
    DATABASE,
    RATE_LIMIT_MAX,
    RATE_LIMIT_WINDOW,
    WEBHOOK_URL,
)

logger = logging.getLogger("honeytrap")

# ── Geo lookup (async via background thread + in-memory cache) ──

_geo_cache: dict[str, tuple[str, str]] = {}
_geo_cache_lock = threading.Lock()
_geo_queue: queue.Queue[tuple[str, int]] = queue.Queue()


def _lookup_geo(ip: str) -> tuple[str, str]:
    if ip in ("127.0.0.1", "::1", "localhost"):
        return "Local", "Localhost"
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = resp.json()
        if data.get("status") == "success":
            return data.get("country", "Unknown"), data.get("city", "Unknown")
    except Exception:
        pass
    return "Unknown", "Unknown"


def get_geo(ip: str) -> tuple[str, str]:
    with _geo_cache_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]
    return "Unknown", "Unknown"


def enqueue_geo_update(ip: str, attack_id: int) -> None:
    with _geo_cache_lock:
        if ip in _geo_cache:
            return
    _geo_queue.put((ip, attack_id))


def _geo_worker() -> None:
    while True:
        ip, attack_id = _geo_queue.get()
        try:
            country, city = _lookup_geo(ip)
            with _geo_cache_lock:
                _geo_cache[ip] = (country, city)
            conn = sqlite3.connect(DATABASE)
            conn.execute(
                "UPDATE attacks SET country = ?, city = ? WHERE id = ?",
                (country, city, attack_id),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.warning("Geo update failed for %s: %s", ip, exc)
        finally:
            _geo_queue.task_done()


_geo_thread = threading.Thread(target=_geo_worker, daemon=True, name="geo-worker")
_geo_thread.start()


# ── Rate limiting (in-memory, per process) ──

_rate_buckets: dict[str, deque[float]] = defaultdict(deque)
_rate_lock = threading.Lock()


def rate_limit_exceeded(ip: str) -> bool:
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW
    with _rate_lock:
        bucket = _rate_buckets[ip]
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT_MAX:
            return True
        bucket.append(now)
    return False


# ── Webhooks ──

def send_new_ip_alert(ip: str, path: str, method: str, country: str) -> None:
    if not WEBHOOK_URL:
        return
    payload = {
        "text": (
            f":warning: *HoneyTrap — new attacker IP*\n"
            f"IP: `{ip}` ({country})\n"
            f"First hit: `{method} {path}`"
        ),
    }
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=5)
    except Exception as exc:
        logger.warning("Webhook delivery failed: %s", exc)


# ── Structured logging ──

def log_attack_event(
    ip: str,
    country: str,
    city: str,
    method: str,
    path: str,
    user_agent: str,
    payload: str,
) -> None:
    logger.info(
        json.dumps(
            {
                "event": "attack",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ip": ip,
                "country": country,
                "city": city,
                "method": method,
                "path": path,
                "user_agent": user_agent,
                "payload_len": len(payload),
            }
        )
    )
