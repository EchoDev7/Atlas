# Atlas VPN Panel - Multi-Protocol Control Plane

[![Version](https://img.shields.io/badge/version-v6.0.0-2563eb.svg)](https://github.com/EchoDev7/Atlas/releases)
[![License](https://img.shields.io/badge/license-Not%20Specified-lightgrey.svg)](#license)
[![Status](https://img.shields.io/badge/status-stable%20release-16a34a.svg)](#)

Atlas is a production-ready, self-hosted VPN management panel for modern multi-protocol deployments.

## What's New in v6.0.0

- **Sing-box v1.12+ Native Support**
  - DNS fully migrated to modern server objects and rule-driven resolver flow.
  - Deprecated legacy DNS structures removed.

- **TLS Hardening (Path-Based Certificates)**
  - TLS inbounds now prefer absolute `certificate_path` / `key_path` instead of fragile inline key material.
  - Prevents runtime failures caused by private key corruption/truncation in database payloads.

- **Advanced Client Compatibility**
  - ALPN sanitization and protocol-specific defaults are hardened for strict clients.
  - Fingerprint-aware link generation remains optimized for clients such as Streisand and V2Box.

- **OpenConnect Revived**
  - `ocserv` generation now includes required socket initialization (`socket-file`) to avoid startup failures.

## One-Line Installation (Ubuntu/Debian)

```bash
curl -fsSL https://raw.githubusercontent.com/EchoDev7/Atlas/main/install.sh | sudo bash
```

## Update Existing Installations

```bash
sudo bash /opt/Atlas/update.sh
```

## Requirements

- Ubuntu/Debian server
- Root/sudo access
- Public IP for panel and VPN clients

## Default Access

- Panel URL: `http://<SERVER_IP>:8000`
- Default username: `admin`
- Default password: `admin123`

Change default credentials immediately after first login.

## Tech Stack

- **Backend:** FastAPI + SQLAlchemy
- **Database:** SQLite
- **Frontend:** Alpine.js + TailwindCSS
- **Process Manager:** systemd
- **VPN Components:** OpenVPN, WireGuard, L2TP/IPsec, OpenConnect, Sing-box

## License

This repository currently does not include a dedicated `LICENSE` file.

## Support & Donate

- **USDT (TRC20):** `TUk8ZYSkFnGwf2DaCZTzQqwKsNEYytGt3Z`
- **TRX:** `TUk8ZYSkFnGwf2DaCZTzQqwKsNEYytGt3Z`
- **TON:** `UQCO2kUIR5P5OC9ktOdxizyaZ8O5hdSOSMMv3wtcN5ywFmQN`
