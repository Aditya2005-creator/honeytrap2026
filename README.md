# 🍯 HoneyTrap — Internet Honeypot & Attack Analytics

A lightweight honeypot server that mimics common vulnerable endpoints, silently logs every probe and scan it receives, and displays attack patterns on a live analytics dashboard.

> **Ethical Use:** This tool is designed for security research and education on infrastructure you own. Collected IP data must not be used to launch counter-attacks or harass any party. Deploying this on shared hosting without informing your provider may violate their terms of service. The data you collect should be treated responsibly — don't publish raw IP lists.

---

## What it does

Once deployed, your server will start receiving automated probes from bots, vulnerability scanners, and credential stuffers within hours. HoneyTrap logs every single one — silently, with full forensic detail — and shows you the patterns on a private dashboard.

**What gets logged for each hit:**
- IP address
- Country and city (via ip-api.com geolocation)
- HTTP method and path
- POST payload (submitted form data, JSON bodies)
- User-Agent string (often reveals the scanner tool being used)
- Timestamp

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Internet / Bots                    │
└──────────────────────┬──────────────────────────────┘
                       │ HTTP requests
                       ▼
┌─────────────────────────────────────────────────────┐
│              Flask Honeypot Server                  │
│                                                     │
│  /login      → fake login page                     │
│  /admin      → fake admin panel                    │
│  /wp-admin   → fake WordPress login                │
│  /phpmyadmin → fake database UI                    │
│  /.env       → logs probe, returns 404             │
│  /api/v1/users → fake API response                 │
│  /*          → catch-all logger                    │
│                                                     │
│  Every route → log_attack() → SQLite              │
└──────────────────────┬──────────────────────────────┘
                       │ writes
                       ▼
┌─────────────────────────────────────────────────────┐
│              attacks.db (SQLite)                    │
│                                                     │
│  id, timestamp, ip, country, city,                 │
│  method, path, user_agent, payload, headers        │
└──────────────────────┬──────────────────────────────┘
                       │ reads
                       ▼
┌─────────────────────────────────────────────────────┐
│         /dashboard?key=YOUR_SECRET                  │
│                                                     │
│  - Total hits counter                              │
│  - 7-day attack timeline chart                     │
│  - Top attacking IPs                               │
│  - Attacks by country                              │
│  - Most targeted endpoints                         │
│  - Live feed of last 30 hits                       │
└─────────────────────────────────────────────────────┘
```

---

## Project structure

```
honeytrap/
├── app.py              # Main Flask app — all routes and logging logic
├── requirements.txt    # Python dependencies
├── Procfile            # For Render/Heroku deployment
├── render.yaml         # One-click Render config
├── attacks.db          # Created automatically on first run
└── templates/
    ├── login.html      # Fake login page
    ├── admin.html      # Fake admin panel
    ├── phpmyadmin.html # Fake phpMyAdmin UI
    ├── forbidden.html  # 403/404 page
    └── dashboard.html  # Your private analytics dashboard
```

---

## Local setup

**Requirements:** Python 3.9+

```bash
# 1. Clone / download the project
cd honeytrap

# 2. Create a virtual environment (keeps your system Python clean)
python3 -m venv venv
source venv/bin/activate      # Mac/Linux
# venv\Scripts\activate       # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run it
python app.py
```

Your honeypot is now running at `http://localhost:5000`

Visit your dashboard at: `http://localhost:5000/dashboard?key=honeytrap2024`

> To test it locally, just visit `/login`, `/admin`, `/wp-admin` in your browser — each visit gets logged.

---


## What you'll see

Within hours of going live, you'll start seeing entries like:

| Time | IP | Country | Path | User Agent |
|---|---|---|---|---|
| 2024-11-12 04:22:11 | 45.33.32.156 | United States | /wp-login.php | Nmap Scripting Engine |
| 2024-11-12 04:23:44 | 185.220.101.3 | Germany | /.env | python-requests/2.28.0 |
| 2024-11-12 04:31:02 | 103.22.200.1 | China | /admin | Go-http-client/1.1 |
| 2024-11-12 05:01:19 | 194.165.16.3 | Netherlands | /phpmyadmin | zgrab/0.x |

Common scanner User-Agents you'll discover: `Masscan`, `ZGrab`, `Shodan`, `python-requests`, `Go-http-client`, `curl`.

---

## Resume write-up

**Project:** HoneyTrap — Honeypot Server & Attack Analytics Platform  
**Tech stack:** Python, Flask, SQLite, Chart.js, Gunicorn, Render

- Designed and deployed a production honeypot server that mimics real vulnerable web endpoints (`/wp-admin`, `/phpmyadmin`, `/admin`, `/.env`) to attract and log automated attack traffic
- Implemented forensic logging pipeline capturing IP addresses, geolocation (country/city via REST API), HTTP methods, payloads, and browser fingerprints for each probe
- Built a password-protected analytics dashboard displaying attack timelines, top attacking IPs, geographic breakdowns, and a live attack feed using Chart.js
- Collected and analyzed real-world attack data from internet-facing deployment, identifying common scanning tools (Masscan, ZGrab, Shodan) and attack patterns
- Demonstrates knowledge of: web security concepts (honeypots, enumeration attacks, credential stuffing), full-stack development, RESTful API consumption, and data visualization

---

## Ethical use

- This honeypot is for **passive observation only** — it logs attackers, it does not engage or retaliate
- Do not use IP data collected here to target, harass, or attack any party
- If you discover a specific threat actor, the appropriate action is to report to your hosting provider or relevant authorities
- This project does not collect data on real users — it only logs unsolicited attack traffic
