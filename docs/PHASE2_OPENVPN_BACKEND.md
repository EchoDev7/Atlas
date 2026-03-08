# Phase 2: OpenVPN Backend Implementation

**تاریخ:** 25 فوریه 2026  
**وضعیت:** ✅ کامل شد

---

## 📋 خلاصه پیاده‌سازی

Phase 2 Backend با موفقیت پیاده‌سازی شد. تمام کامپوننت‌های زیر ایجاد و تست شدند:

### ✅ فایل‌های ایجاد شده:

1. **`backend/models/vpn_client.py`** - مدل دیتابیس کلاینت‌های VPN
2. **`backend/schemas/vpn_client.py`** - Pydantic schemas برای validation
3. **`backend/core/openvpn.py`** - منطق اصلی OpenVPN با mock support
4. **`backend/routers/openvpn.py`** - API endpoints با authentication
5. **`requirements.txt`** - به‌روزرسانی با qrcode و pillow

---

## 🎯 قوانین رعایت شده

### قانون ۱: هسته مستقل و قابل آپدیت ✅
- استفاده از مسیرهای استاندارد Ubuntu (`/etc/openvpn`)
- استفاده از `systemctl` برای کنترل سرویس
- عدم دستکاری فایل‌های باینری OpenVPN
- سازگاری کامل با آپدیت‌های سیستم‌عامل

### قانون ۲: منابع رسمی ✅
- استفاده از Easy-RSA 3 استاندارد
- پیروی از ساختار PKI رسمی OpenVPN
- استفاده از دستورات رسمی `easyrsa`
- مطابق با مستندات OpenVPN Community

### قانون ۳: جلوگیری از کرش در محیط توسعه ✅
- تمام subprocess calls در try-except
- تشخیص خودکار سیستم‌عامل (Linux vs Mac)
- Mock responses برای محیط development
- لاگ‌های واضح برای debugging

---

## 🏗️ معماری Backend

### 1. Database Model (`vpn_client.py`)

```python
class VPNClient(Base):
    # شناسایی
    id, name, email
    
    # پروتکل و وضعیت
    protocol (openvpn/wireguard/singbox)
    status (active/revoked/expired)
    
    # اطلاعات گواهی (OpenVPN)
    certificate_cn, certificate_serial
    certificate_issued_at, certificate_expires_at
    
    # آمار استفاده
    total_bytes_sent, total_bytes_received
    last_connected_at, last_disconnected_at
    
    # متادیتا
    created_by, created_at, updated_at
    revoked_at, revoked_reason
```

**ویژگی‌های مهم:**
- پشتیبانی از چند پروتکل (آماده برای Phase 3 و 4)
- ردیابی کامل آمار و usage
- Soft delete با revocation tracking

---

### 2. Core Logic (`backend/core/openvpn.py`)

**کلاس `OpenVPNManager`:**

#### متدهای اصلی:

```python
# PKI Management
initialize_pki() -> Dict
create_client_certificate(client_name) -> Dict
revoke_client_certificate(client_name) -> Dict

# Configuration
generate_client_config(client_name, server_address) -> str
generate_qr_code(config_content) -> str

# Service Control
get_service_status() -> Dict
control_service(action) -> Dict
```

#### Mock Support:
```python
IS_LINUX = platform.system() == "Linux"

if not IS_LINUX:
    # Return mock responses
    logger.warning("Running in DEVELOPMENT mode")
```

**مسیرهای استاندارد Ubuntu:**
```python
OPENVPN_DIR = Path("/etc/openvpn")
EASYRSA_DIR = Path("/usr/share/easy-rsa")
PKI_DIR = Path("/etc/openvpn/easy-rsa/pki")
SERVICE_NAME = "openvpn-server@server"
```

---

### 3. API Endpoints (`backend/routers/openvpn.py`)

تمام endpoints با `@Depends(get_current_user)` محافظت شده‌اند.

#### Client Management:

| Method | Endpoint | توضیحات |
|--------|----------|---------|
| GET | `/api/openvpn/clients` | لیست کلاینت‌ها با pagination |
| GET | `/api/openvpn/clients/{id}` | جزئیات یک کلاینت |
| POST | `/api/openvpn/clients` | ایجاد کلاینت جدید + certificate |
| PATCH | `/api/openvpn/clients/{id}` | به‌روزرسانی اطلاعات |
| POST | `/api/openvpn/clients/{id}/revoke` | لغو گواهی |
| DELETE | `/api/openvpn/clients/{id}` | حذف کلاینت |

#### Configuration:

| Method | Endpoint | توضیحات |
|--------|----------|---------|
| GET | `/api/openvpn/clients/{id}/config` | دریافت .ovpn با QR code |
| GET | `/api/openvpn/clients/{id}/config/download` | دانلود فایل .ovpn |

#### Service Control:

| Method | Endpoint | توضیحات |
|--------|----------|---------|
| GET | `/api/openvpn/service/status` | وضعیت سرویس OpenVPN |
| POST | `/api/openvpn/service/control` | start/stop/restart/enable |

---

## 🔐 Authentication Flow

همه endpoints نیاز به JWT token دارند:

```http
Authorization: Bearer <jwt_token>
```

**مثال:**
```bash
# Login
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Response: {"access_token": "...", "token_type": "bearer"}

# Use token
curl -X GET http://localhost:8000/api/openvpn/clients \
  -H "Authorization: Bearer <token>"
```

---

## 📝 نمونه استفاده از API

### 1. ایجاد کلاینت جدید

```bash
curl -X POST http://localhost:8000/api/openvpn/clients \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "client1",
    "email": "client1@example.com",
    "description": "Test client",
    "server_address": "vpn.example.com",
    "server_port": 1194,
    "protocol_type": "udp"
  }'
```

**Response:**
```json
{
  "id": 1,
  "name": "client1",
  "email": "client1@example.com",
  "status": "active",
  "protocol": "openvpn",
  "certificate_cn": "client1",
  "certificate_issued_at": "2026-02-25T14:00:00",
  "is_enabled": true,
  "created_at": "2026-02-25T14:00:00"
}
```

---

### 2. دریافت فایل .ovpn

```bash
curl -X GET "http://localhost:8000/api/openvpn/clients/1/config?include_qr=true&server_address=vpn.example.com" \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "client_name": "client1",
  "config_content": "client\ndev tun\n...",
  "qr_code": "data:image/png;base64,iVBORw0KG...",
  "created_at": "2026-02-25T14:00:00"
}
```

---

### 3. لغو گواهی کلاینت

```bash
curl -X POST http://localhost:8000/api/openvpn/clients/1/revoke \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Security concern"
  }'
```

---

### 4. کنترل سرویس

```bash
curl -X POST http://localhost:8000/api/openvpn/service/control \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "restart"
  }'
```

---

## 🧪 تست در محیط Development (Mac)

در محیط Mac، تمام دستورات Linux به صورت mock اجرا می‌شوند:

```python
[MOCK] Would execute: easyrsa build-client-full client1 nopass
[MOCK] Would execute: systemctl status openvpn-server@server
```

**مزایا:**
- ✅ سرور کرش نمی‌کند
- ✅ می‌توان API را تست کرد
- ✅ UI را بدون نیاز به Linux توسعه داد
- ✅ لاگ‌های واضح برای debug

---

## 🚀 استقرار در Production (Ubuntu)

### 1. نصب Dependencies

```bash
# نصب OpenVPN و Easy-RSA
sudo apt update
sudo apt install openvpn easy-rsa

# نصب Python dependencies
pip install -r requirements.txt
```

### 2. راه‌اندازی PKI

```python
from backend.core.openvpn import OpenVPNManager

manager = OpenVPNManager()
result = manager.initialize_pki()
```

این کار:
- CA می‌سازد
- DH parameters تولید می‌کند
- Server certificate ایجاد می‌کند
- TLS auth key می‌سازد

### 3. راه‌اندازی سرویس

```bash
sudo systemctl enable openvpn-server@server
sudo systemctl start openvpn-server@server
```

---

## 📊 Database Schema

جدول `vpn_clients` با migration خودکار ایجاد می‌شود:

```sql
CREATE TABLE vpn_clients (
    id INTEGER PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255),
    protocol VARCHAR(20) DEFAULT 'openvpn',
    status VARCHAR(20) DEFAULT 'active',
    certificate_cn VARCHAR(255),
    certificate_serial VARCHAR(100),
    certificate_issued_at DATETIME,
    certificate_expires_at DATETIME,
    total_bytes_sent INTEGER DEFAULT 0,
    total_bytes_received INTEGER DEFAULT 0,
    last_connected_at DATETIME,
    created_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME,
    revoked_at DATETIME,
    revoked_reason TEXT,
    is_enabled BOOLEAN DEFAULT 1,
    max_connections INTEGER DEFAULT 1
);
```

---

## 🔒 امنیت

### Authentication:
- ✅ تمام endpoints با JWT محافظت شده
- ✅ فقط admin می‌تواند کلاینت بسازد/حذف کند
- ✅ Token expiry: 24 ساعت

### Certificate Management:
- ✅ استفاده از Easy-RSA 3 (استاندارد صنعت)
- ✅ Revocation با CRL update
- ✅ Certificate tracking در database

### Logging:
- ✅ تمام عملیات لاگ می‌شوند
- ✅ شامل username admin
- ✅ شامل timestamp و action

---

## 📚 مستندات API

مستندات کامل در:
```
http://localhost:8000/api/docs
```

**Swagger UI** با تمام endpoints، schemas، و examples.

---

## ⚠️ نکات مهم

### 1. Server Address
در production، باید server address واقعی را تنظیم کنید:

```python
# TODO: در config.py اضافه کنید
OPENVPN_SERVER_ADDRESS = "your-server-ip-or-domain"
```

### 2. Certificate Expiry
فعلاً certificate expiry tracking وجود دارد ولی auto-renewal نه.  
در آینده باید cron job اضافه شود.

### 3. Client Limit
هر کلاینت `max_connections` دارد (default: 1).  
در آینده باید enforcement اضافه شود.

---

## ✅ چک‌لیست تکمیل

- [x] VPN Client model با support چند پروتکل
- [x] OpenVPN core logic با mock support
- [x] Certificate management (create/revoke)
- [x] .ovpn config generation
- [x] QR code generation
- [x] Service control (start/stop/restart)
- [x] API endpoints با authentication
- [x] Pagination و filtering
- [x] Error handling جامع
- [x] Logging کامل
- [x] مستندات API

---

## 🎯 مرحله بعد: Frontend

Phase 2 Backend کامل است. مرحله بعد:

1. صفحه **Clients Management** در frontend
2. فرم ایجاد کلاینت جدید
3. جدول نمایش کلاینت‌ها
4. دانلود .ovpn و QR code
5. کنترل سرویس OpenVPN

---

## 🐛 Troubleshooting

### مشکل: "easyrsa command not found"
**راه‌حل:** در Mac عادی است (mock mode). در Ubuntu:
```bash
sudo apt install easy-rsa
```

### مشکل: "Permission denied"
**راه‌حل:** دستورات OpenVPN نیاز به sudo دارند:
```bash
sudo python3 -m backend.main
```

یا با systemd service اجرا کنید.

### مشکل: Database locked
**راه‌حل:** SQLite connection pool را چک کنید:
```python
# در database.py
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
```

---

**Phase 2 Backend: ✅ Complete**

آماده برای Frontend Development! 🚀
