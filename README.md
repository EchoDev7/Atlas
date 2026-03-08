# Atlas VPN Panel - Enterprise Grade OpenVPN Management

[![Version](https://img.shields.io/badge/version-v1.0.0-2563eb.svg)](https://github.com/EchoDev7/Atlas/releases)
[![License](https://img.shields.io/badge/license-Not%20Specified-lightgrey.svg)](#license)
[![Status](https://img.shields.io/badge/status-stable%20release-16a34a.svg)](#)

Atlas is a production-ready, self-hosted VPN control panel focused on **OpenVPN automation**, **operational safety**, and a **clean admin experience**.

Built for real servers (including low-resource VPS targets), Atlas gives you a web dashboard for managing users, certificates, runtime operations, and system-level controls with minimal operational complexity.

---

## Why Atlas

- Simple deployment with one command
- Lightweight stack: FastAPI + SQLite + Alpine.js
- Designed for Ubuntu + systemd environments
- Practical for solo operators and small teams

---

## Key Features

- **Live Operational Dashboard**
  - Real-time service health, runtime metrics, and OpenVPN status visibility.

- **Golden Backup & Restore Workflow**
  - Backup and recovery flows designed to protect production data and configs.

- **Security Audit Logs**
  - Trace critical admin and system actions for accountability and incident review.

- **Advanced Protocol Management**
  - OpenVPN-focused management with extensible architecture for multi-protocol control.

- **Certificate & PKI Automation**
  - Easy-RSA/OpenVPN workflows wired into backend operations.

- **Server Operations from UI/API**
  - Service-level control paths designed for real operational usage.

---

## One-Line Installation (Ubuntu/Debian)

Run this on your server as root:

```bash
curl -fsSL https://raw.githubusercontent.com/EchoDev7/Atlas/main/install.sh | sudo bash
```

What installer does:

1. Installs Python, OpenVPN, Easy-RSA, and core system dependencies
2. Creates `.venv` and installs Python requirements
3. Initializes Atlas database and migrations safely
4. Bootstraps OpenVPN PKI and server config
5. Creates and enables `atlas-backend.service`
6. Starts backend and OpenVPN services
7. Prints panel URL and default login credentials

---

## Updating to Latest Version

From project root (or from anywhere using absolute path):

```bash
sudo bash /opt/Atlas/update.sh
```

`update.sh` performs:

- `git pull` from `main`
- Python dependency refresh
- Safe DB migration (`init_db()`)
- Service restart (`atlas-backend.service`, OpenVPN unit if available)

---

## Default Access

After installation, Atlas prints:

- Panel URL: `http://<SERVER_IP>:8000`
- Default username: `admin`
- Default password: `admin123`

> For production hardening, change credentials immediately after first login.

---

## Requirements

- Ubuntu/Debian server
- Root/sudo access
- Public IP for remote panel/VPN clients

---

## Tech Stack

- **Backend:** FastAPI + SQLAlchemy
- **Database:** SQLite
- **Frontend:** Alpine.js + TailwindCSS
- **Process manager:** systemd
- **VPN core:** OpenVPN + Easy-RSA

---

## License

This repository currently does not include a dedicated `LICENSE` file.
If you plan to distribute Atlas publicly, add your preferred license before wider release.

---

## Support & Donate

If Atlas helps your operations and you want to support ongoing development, you can donate via:

- **USDT (Tether - TRC20 Network):** `TUk8ZYSkFnGwf2DaCZTzQqwKsNEYytGt3Z`
- **TRX (Tron Network):** `TUk8ZYSkFnGwf2DaCZTzQqwKsNEYytGt3Z`
- **TON (Toncoin Network):** `UQCO2kUIR5P5OC9ktOdxizyaZ8O5hdSOSMMv3wtcN5ywFmQN`
