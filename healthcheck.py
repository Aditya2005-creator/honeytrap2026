#!/usr/bin/env python3
"""Docker / orchestrator health probe — exits 0 only when app + DB are healthy."""

import json
import os
import sys
import urllib.error
import urllib.request

PORT = os.environ.get("PORT", "8000")
URL = f"http://127.0.0.1:{PORT}/health"


def main() -> int:
    try:
        with urllib.request.urlopen(URL, timeout=4) as resp:
            if resp.status != 200:
                return 1
            body = json.loads(resp.read().decode())
            if body.get("status") == "ok" and body.get("db") == "ok":
                return 0
    except (urllib.error.URLError, json.JSONDecodeError, KeyError, TimeoutError):
        pass
    return 1


if __name__ == "__main__":
    sys.exit(main())
