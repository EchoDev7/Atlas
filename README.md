# Atlas — Web-Based VPN Management Panel

> A lightweight, self-hosted VPN management panel designed for resource-constrained servers (1 vCPU / 1 GB RAM).

---

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Proposed Architecture](#proposed-architecture)
- [Tech Stack & Rationale](#tech-stack--rationale)
- [Folder Structure](#folder-structure)
- [Roadmap (Phases)](#roadmap-phases)
- [Target Server Specs](#target-server-specs)

---

## Project Overview

**Atlas** is a web-based administration panel for managing VPN servers. It provides a clean UI for creating users, issuing certificates/keys, monitoring connections, and controlling VPN services — all from a browser.

The core design principle is **radical lightness**: every technology choice is made with the 1 GB RAM constraint in mind.

---

## Proposed Architecture

```
┌─────────────────────────────────────────────────┐
│                  Browser (Client)                │
│            Vanilla JS + Alpine.js + TailwindCSS  │
└───────────────────────┬─────────────────────────┘
                        │ HTTP/REST + SSE
┌───────────────────────▼─────────────────────────┐
│               Backend API Server                 │
│                  Python + FastAPI                │
│          (runs as a single process / systemd)    │
└────────────┬──────────────────────┬─────────────┘
             │                      │
┌────────────▼──────┐   ┌───────────▼─────────────┐
│   SQLite (DB)     │   │  System Layer            │
│  single .db file  │   │  subprocess / D-Bus      │
│  zero server RAM  │   │  OpenVPN / WireGuard /   │
└───────────────────┘   │  Sing-box                │
                        └─────────────────────────┘
```

### Key Design Decisions

| Layer | Choice | Alternative Rejected |
|---|---|---|
| Backend | **FastAPI (Python)** | Node.js/Express, Go |
| Database | **SQLite** | PostgreSQL, MySQL, MongoDB |
| Frontend | **Alpine.js + TailwindCSS (CDN)** | React, Vue, Angular |
| Process manager | **systemd** (native) | Docker, PM2 |
| Auth | **JWT (stateless)** | Session + Redis |
| Web server | **Uvicorn** (built-in with FastAPI) | Nginx + Gunicorn (optional reverse proxy) |

---

## Tech Stack & Rationale

### Why FastAPI (Python)?

- **Async-native**: Handles many concurrent requests on a single worker without spawning threads, keeping RAM usage minimal.
- **Single process**: One `uvicorn` worker can comfortably serve a low-traffic admin panel at ~30–50 MB RAM.
- **stdlib-friendly**: Calling `subprocess` to talk to OpenVPN/WireGuard/Sing-box is idiomatic Python — no extra runtime or runtime dependencies.
- **Rejected Node.js**: V8 + npm dependency tree bloat can easily push baseline RAM to 150+ MB.
- **Rejected Go**: Excellent choice technically, but Python is faster to develop a full panel with (forms, templating, DB ORM).

### Why SQLite?

- **Zero server process**: SQLite is an embedded library — it consumes **0 additional RAM** beyond what Python already uses.
- **Sufficient for the use case**: An admin panel with tens/hundreds of VPN users is a perfect SQLite workload (no high concurrency on writes).
- **Single file**: Easy backup (`cp atlas.db atlas.db.bak`), easy migration, zero config.
- **Rejected PostgreSQL/MySQL**: Each runs a persistent server process consuming 50–200 MB RAM — unacceptable on 1 GB.

### Why Alpine.js + TailwindCSS (via CDN)?

- **Alpine.js** is ~15 KB (gzipped). It gives reactive UI without a build pipeline, node_modules, or a bundler process running on the server.
- **TailwindCSS CDN** (Play CDN) eliminates any build step for the frontend during development; for production a pre-built CSS file will be committed.
- **No SSR/hydration overhead**: The API returns JSON; Alpine.js renders it client-side. The server only serves static HTML + JSON — very cache-friendly.
- **Rejected React/Vue/Angular**: All require a build server (webpack/vite), node_modules (~200 MB disk), and have larger JS bundles — wasteful for an internal admin panel.

### Why JWT (stateless auth)?

- No server-side session store needed (eliminates Redis ~10 MB RAM).
- Token validated entirely in-memory on each request.

---

## Folder Structure

```
Atlas/
├── README.md
├── .gitignore
│
├── backend/                        # FastAPI application
│   ├── main.py                     # App entry point, router registration
│   ├── config.py                   # Settings (env vars, paths)
│   ├── database.py                 # SQLite connection, SQLAlchemy setup
│   ├── dependencies.py             # Shared FastAPI dependencies (auth, db session)
│   │
│   ├── models/                     # SQLAlchemy ORM models
│   │   ├── __init__.py
│   │   ├── user.py                 # Admin user model
│   │   └── vpn_client.py           # VPN client/peer model
│   │
│   ├── schemas/                    # Pydantic request/response schemas
│   │   ├── __init__.py
│   │   ├── user.py
│   │   └── vpn_client.py
│   │
│   ├── routers/                    # API route handlers
│   │   ├── __init__.py
│   │   ├── auth.py                 # Login / token endpoints
│   │   ├── dashboard.py            # System stats endpoint
│   │   ├── openvpn.py              # Phase 1: OpenVPN management
│   │   ├── wireguard.py            # Phase 2: WireGuard management
│   │   └── singbox.py              # Phase 3: Sing-box management
│   │
│   ├── services/                   # Business logic / system interaction layer
│   │   ├── __init__.py
│   │   ├── auth_service.py
│   │   ├── openvpn_service.py      # Phase 1
│   │   ├── wireguard_service.py    # Phase 2
│   │   └── singbox_service.py      # Phase 3
│   │
│   └── utils/                      # Helpers (file I/O, subprocess wrappers, etc.)
│       ├── __init__.py
│       ├── system.py
│       └── crypto.py
│
├── frontend/                       # Static frontend (no build step)
│   ├── index.html                  # Login page
│   ├── dashboard.html              # Main dashboard
│   ├── clients.html                # VPN client list & management
│   ├── settings.html               # Server settings
│   │
│   ├── css/
│   │   └── tailwind.min.css        # Pre-built Tailwind CSS (production)
│   │
│   └── js/
│       ├── app.js                  # Shared Alpine.js store, API client helper
│       ├── dashboard.js
│       └── clients.js
│
├── scripts/                        # Shell scripts for server setup & maintenance
│   ├── install.sh                  # One-shot server installation script
│   ├── openvpn_setup.sh            # Phase 1: OpenVPN initial setup
│   ├── wireguard_setup.sh          # Phase 2: WireGuard initial setup
│   └── singbox_setup.sh            # Phase 3: Sing-box initial setup
│
├── config/                         # Template config files
│   ├── openvpn/
│   │   └── server.conf.template
│   ├── wireguard/
│   │   └── wg0.conf.template
│   └── singbox/
│       └── config.json.template
│
├── data/                           # Runtime data (gitignored)
│   └── .gitkeep
│
└── docs/                           # Extended documentation
    ├── api.md                      # API endpoint reference
    ├── deployment.md               # Step-by-step deployment guide
    └── architecture.md             # Deep-dive architecture notes
```

---

## Roadmap (Phases)

### ✅ Phase 0 — Project Bootstrap *(current)*
- [x] Define architecture and tech stack
- [x] Create folder structure and README
- [ ] Set up `backend/` with FastAPI skeleton (health endpoint)
- [ ] Set up `frontend/` with login page skeleton
- [ ] Configure `.gitignore` and base `config.py`

### 🔲 Phase 1 — OpenVPN Management
- [ ] Backend: PKI management (EasyRSA wrapper via subprocess)
- [ ] Backend: Create / revoke / list VPN clients
- [ ] Backend: Start / stop / restart OpenVPN service
- [ ] Backend: Parse `openvpn-status.log` for live connection stats
- [ ] Frontend: Dashboard with connected users & traffic stats
- [ ] Frontend: Client management UI (add, revoke, download `.ovpn`)
- [ ] Auth: JWT login for admin panel

### 🔲 Phase 2 — WireGuard Management
- [ ] Backend: `wg` and `wg-quick` subprocess integration
- [ ] Backend: Peer add / remove / list
- [ ] Backend: Generate keypairs server-side
- [ ] Frontend: WireGuard peers tab
- [ ] Frontend: QR code display for mobile clients

### 🔲 Phase 3 — Sing-box Integration
- [ ] Backend: Sing-box config file generation (JSON)
- [ ] Backend: Manage inbounds (VLESS, VMess, Trojan, Shadowsocks, etc.)
- [ ] Backend: Restart sing-box service on config change
- [ ] Frontend: Protocol-specific UI tabs per inbound type
- [ ] Frontend: Share links / QR codes per client

---

## Target Server Specs

| Property | Value |
|---|---|
| OS | Ubuntu 22.04 LTS |
| CPU | 1 vCPU (minimum) |
| RAM | **1 GB** |
| Storage | ≥ 10 GB recommended |
| Network | Public IP required |

### Estimated RAM Budget

| Component | Estimated RAM |
|---|---|
| Ubuntu 22.04 base (minimal) | ~150–200 MB |
| FastAPI + Uvicorn (1 worker) | ~40–60 MB |
| SQLite (embedded in Python) | ~0 MB extra |
| OpenVPN daemon | ~5–15 MB |
| WireGuard (kernel module) | ~2–5 MB |
| Sing-box daemon | ~20–40 MB |
| **Total (Phase 3 peak)** | **~220–320 MB** ✅ |

This leaves **~700 MB** of headroom on a 1 GB server — ample buffer.

---

> **Atlas** is built to be the lightest possible VPN panel that doesn't sacrifice usability. No Docker, no Node.js servers, no heavy databases — just Python, SQLite, and a browser.
