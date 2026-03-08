# Phase 2: Commercial Product Enhancements

**تاریخ:** 25 فوریه 2026  
**شاخه:** `phase2-openvpn-enhancements`  
**وضعیت:** ✅ کامل شد

---

## 📋 خلاصه تغییرات

Phase 2 Enhancements با موفقیت پیاده‌سازی شد. این مرحله پنل را از یک نمونه اولیه به یک محصول تجاری آماده تبدیل کرده است.

### ✅ ۷ درخواست اصلی:

1. **اصلاح هدر (UI)** - لینک Dashboard به header اضافه شد
2. **معماری چند پروتکلی** - مدل User + VPNConfig برای پشتیبانی از چند پروتکل
3. **فرم ایجاد کاربر** - حذف ایمیل، تولید نام تصادفی
4. **رمز عبور اتصال** - فیلد password با تولید خودکار و auth-user-pass
5. **محدودیت حجم** - Dropdown انتخاب data limit
6. **محدودیت زمان** - Date picker برای expiry date
7. **اجرای خودکار محدودیت‌ها** - APScheduler برای enforcement

---

## 🏗️ تغییرات معماری

### 1. مدل دیتابیس جدید

#### قبل (VPNClient):
```python
class VPNClient(Base):
    id, name, email, protocol, status
    certificate_cn, wireguard_public_key, singbox_uuid
    total_bytes_sent, total_bytes_received
```

#### بعد (VPNUser + VPNConfig):
```python
class VPNUser(Base):
    # شناسایی
    id, username, password (hashed)
    
    # محدودیت‌ها
    data_limit_gb, expiry_date
    
    # وضعیت
    is_enabled, is_expired, is_data_limit_exceeded
    
    # آمار
    total_bytes_sent, total_bytes_received
    total_gb_used, data_usage_percentage
    
    # روابط
    configs = relationship("VPNConfig")

class VPNConfig(Base):
    # شناسایی
    id, user_id, protocol
    
    # وضعیت
    is_active, revoked_at, revoked_reason
    
    # اطلاعات پروتکل‌ها
    certificate_cn (OpenVPN)
    wireguard_public_key (WireGuard)
    singbox_uuid (Sing-box)
```

**مزایا:**
- ✅ یک کاربر می‌تواند چند پروتکل داشته باشد
- ✅ محدودیت‌ها در سطح کاربر اعمال می‌شوند
- ✅ آماده برای WireGuard و Sing-box
- ✅ مدیریت بهتر credentials

---

## 🎨 تغییرات UI

### 1. Header Navigation

**قبل:**
```html
<!-- فقط لوگو و logout -->
```

**بعد:**
```html
<a href="/dashboard.html">
    <svg><!-- home icon --></svg>
    <span>Dashboard</span>
</a>
```

### 2. فرم ایجاد کاربر

#### فیلدهای جدید:

**Username (اختیاری با تولید تصادفی):**
```html
<input x-model="newClient.username" placeholder="Leave empty for auto-generation">
<button @click="generateRandomUsername()">
    <svg><!-- dice icon --></svg>
</button>
```

**Password (اختیاری با تولید امن):**
```html
<input x-model="newClient.password" placeholder="Leave empty for secure auto-generation">
<button @click="generateSecurePassword()">
    <svg><!-- lock icon --></svg>
</button>
```

**Data Limit (Dropdown):**
```html
<select x-model="newClient.data_limit_gb">
    <option value="">Unlimited</option>
    <option value="5">5 GB</option>
    <option value="10">10 GB</option>
    <option value="25">25 GB</option>
    <option value="50">50 GB</option>
    <option value="100">100 GB</option>
    <option value="250">250 GB</option>
    <option value="500">500 GB</option>
    <option value="1000">1 TB</option>
</select>
```

**Expiry Date (Date Picker):**
```html
<input type="date" 
       x-model="newClient.expiry_date"
       :min="new Date().toISOString().split('T')[0]">
```

#### فیلدهای حذف شده:
- ❌ Email (بی‌کاربر بود)

### 3. جدول کاربران

**Protocol Badges:**
```html
<span x-show="client.has_openvpn" class="badge-blue">OpenVPN</span>
<span x-show="client.has_wireguard" class="badge-purple">WireGuard</span>
<span x-show="client.has_singbox" class="badge-green">Sing-box</span>
```

**Status با اطلاعات اضافی:**
```html
<span>ACTIVE / EXPIRED / LIMIT EXCEEDED / DISABLED</span>

<!-- Data usage -->
<div x-show="client.data_limit_gb">
    2.5 / 10 GB (25%)
</div>

<!-- Expiry -->
<div x-show="client.expiry_date">
    Expires: 2026-03-25
</div>
```

---

## 🔐 احراز هویت با Password

### 1. اسکریپت OpenVPN Auth

**فایل:** `scripts/openvpn_auth_user_pass.py`

```python
#!/usr/bin/env python3
def verify_credentials(username: str, password: str) -> bool:
    # Query database
    user = db.query(VPNUser).filter(VPNUser.username == username).first()
    
    # Check if active
    if not user.is_active:
        return False
    
    # Verify password (bcrypt)
    if not pwd_context.verify(password, user.password):
        return False
    
    return True
```

### 2. تنظیمات OpenVPN Server

در فایل `/etc/openvpn/server.conf`:

```conf
# Enable password authentication
auth-user-pass-verify /path/to/openvpn_auth_user_pass.py via-file
script-security 2

# Username as common name
username-as-common-name
```

### 3. فایل کانفیگ کلاینت

```conf
client
dev tun
proto udp
remote vpn.example.com 1194

# Password authentication
auth-user-pass

# Certificates
ca ca.crt
cert client.crt
key client.key
```

کاربر باید username و password را وارد کند.

---

## ⏰ Scheduler برای Enforcement

### 1. APScheduler Configuration

**فایل:** `backend/services/scheduler_service.py`

```python
from apscheduler.schedulers.asyncio import AsyncIOScheduler

class LimitEnforcementScheduler:
    def start(self):
        self.scheduler = AsyncIOScheduler()
        
        # Run every 5 minutes
        self.scheduler.add_job(
            self.enforce_limits,
            trigger=IntervalTrigger(minutes=5),
            id='enforce_limits'
        )
        
        self.scheduler.start()
```

### 2. Enforcement Logic

```python
async def enforce_limits(self):
    users = db.query(VPNUser).filter(VPNUser.is_enabled == True).all()
    
    for user in users:
        # Check expiry
        if user.expiry_date and datetime.utcnow() > user.expiry_date:
            user.is_expired = True
            user.is_enabled = False
            user.disabled_reason = "Expired"
        
        # Check data limit
        if user.data_limit_gb and user.total_gb_used >= user.data_limit_gb:
            user.is_data_limit_exceeded = True
            user.is_enabled = False
            user.disabled_reason = "Data limit exceeded"
        
        # Revoke all configs
        for config in user.configs:
            config.is_active = False
            config.revoked_reason = "Automatic: " + user.disabled_reason
    
    db.commit()
```

### 3. مصرف منابع

- **RAM:** ~5-10 MB اضافی
- **CPU:** Negligible (هر 5 دقیقه چند میلی‌ثانیه)
- **مناسب برای 1GB RAM** ✅

---

## 📡 API Endpoints جدید

### Base URL: `/api/users`

| Method | Endpoint | توضیحات |
|--------|----------|---------|
| GET | `/api/users` | لیست کاربران |
| POST | `/api/users` | ایجاد کاربر جدید |
| GET | `/api/users/{id}` | جزئیات کاربر |
| PATCH | `/api/users/{id}` | به‌روزرسانی |
| DELETE | `/api/users/{id}` | حذف کاربر |
| GET | `/api/users/{id}/configs/{protocol}` | دریافت config |
| GET | `/api/users/{id}/configs/{protocol}/download` | دانلود config |
| POST | `/api/users/{id}/configs/{protocol}/revoke` | لغو config |
| POST | `/api/users/{id}/password/reset` | Reset password |
| POST | `/api/users/{id}/password/change` | تغییر password |
| GET | `/api/users/{id}/limits/check` | چک محدودیت‌ها |

### نمونه Request/Response:

**ایجاد کاربر:**
```bash
POST /api/users
{
    "username": null,  # auto-generated
    "password": null,  # auto-generated
    "data_limit_gb": 10,
    "expiry_date": "2026-12-31T00:00:00Z",
    "description": "Test user",
    "create_openvpn": true
}
```

**Response:**
```json
{
    "username": "user_8f2a",
    "password": "X7k@mP9#qL2$nR5^",
    "message": "Save these credentials securely..."
}
```

---

## 🎯 Alpine.js Functions جدید

### 1. تولید Username تصادفی

```javascript
generateRandomUsername() {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let suffix = '';
    for (let i = 0; i < 4; i++) {
        suffix += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    this.newClient.username = 'user_' + suffix;
}
```

### 2. تولید Password امن

```javascript
generateSecurePassword() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';
    for (let i = 0; i < 16; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    this.newClient.password = password;
}
```

### 3. ایجاد کاربر با Credentials

```javascript
async createClient() {
    const userData = {
        username: this.newClient.username || null,
        password: this.newClient.password || null,
        data_limit_gb: this.newClient.data_limit_gb ? parseFloat(this.newClient.data_limit_gb) : null,
        expiry_date: this.newClient.expiry_date ? new Date(this.newClient.expiry_date).toISOString() : null,
        create_openvpn: true
    };
    
    const response = await fetch('/api/users', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(userData)
    });
    
    const credentials = await response.json();
    
    // نمایش credentials به admin
    alert(`User Created Successfully!\n\nUsername: ${credentials.username}\nPassword: ${credentials.password}\n\nPlease save these credentials.`);
}
```

---

## 📊 Database Migration

### قبل از Migration:

```bash
# Backup existing database
cp data/atlas.db data/atlas.db.backup
```

### بعد از Deployment:

```python
# Tables will be created automatically
vpn_users (new)
vpn_configs (new)
vpn_clients (deprecated - keep for migration)
```

### Migration Script (اختیاری):

```python
# Migrate old VPNClient to new VPNUser + VPNConfig
for old_client in db.query(VPNClient).all():
    # Create user
    user = VPNUser(
        username=old_client.name,
        password=pwd_context.hash("changeme"),  # Default password
        total_bytes_sent=old_client.total_bytes_sent,
        total_bytes_received=old_client.total_bytes_received
    )
    db.add(user)
    db.flush()
    
    # Create OpenVPN config
    if old_client.protocol == "openvpn":
        config = VPNConfig(
            user_id=user.id,
            protocol="openvpn",
            certificate_cn=old_client.certificate_cn,
            is_active=(old_client.status == "active")
        )
        db.add(config)

db.commit()
```

---

## 🔧 تنظیمات Production

### 1. OpenVPN Server Config

```bash
# Install auth script
sudo cp scripts/openvpn_auth_user_pass.py /etc/openvpn/
sudo chmod +x /etc/openvpn/openvpn_auth_user_pass.py

# Update server.conf
sudo nano /etc/openvpn/server.conf
```

Add:
```conf
auth-user-pass-verify /etc/openvpn/openvpn_auth_user_pass.py via-file
script-security 2
username-as-common-name
```

### 2. Restart OpenVPN

```bash
sudo systemctl restart openvpn-server@server
```

### 3. Test Authentication

```bash
# Create test user via API
# Try to connect with username/password
```

---

## 📈 مزایای تجاری

### 1. مدیریت کاربران حرفه‌ای
- ✅ Username/Password authentication
- ✅ محدودیت حجم و زمان
- ✅ Enforcement خودکار
- ✅ پشتیبانی از چند پروتکل

### 2. امنیت بهتر
- ✅ Password hashing با bcrypt
- ✅ تولید خودکار credentials امن
- ✅ Revocation خودکار در صورت تخطی

### 3. UX عالی
- ✅ فرم ساده و زیبا
- ✅ تولید خودکار username/password
- ✅ نمایش واضح محدودیت‌ها
- ✅ Protocol badges

### 4. مقیاس‌پذیری
- ✅ معماری آماده برای WireGuard
- ✅ معماری آماده برای Sing-box
- ✅ یک کاربر = چند پروتکل

---

## 🧪 تست

### 1. ایجاد کاربر

```bash
# با auto-generation
POST /api/users
{}

# با مقادیر دستی
POST /api/users
{
    "username": "testuser",
    "password": "SecurePass123!",
    "data_limit_gb": 10,
    "expiry_date": "2026-12-31T00:00:00Z"
}
```

### 2. تست محدودیت حجم

```python
# Simulate usage
user.total_bytes_sent = 5 * 1024**3  # 5 GB
user.total_bytes_received = 6 * 1024**3  # 6 GB
# Total = 11 GB > 10 GB limit

# Run scheduler
await scheduler.enforce_limits()

# Check status
assert user.is_data_limit_exceeded == True
assert user.is_enabled == False
```

### 3. تست انقضا

```python
# Set expired date
user.expiry_date = datetime.utcnow() - timedelta(days=1)

# Run scheduler
await scheduler.enforce_limits()

# Check status
assert user.is_expired == True
assert user.is_enabled == False
```

---

## 📝 فایل‌های تغییر یافته

### Backend:
1. `backend/models/vpn_user.py` (جدید)
2. `backend/schemas/vpn_user.py` (جدید)
3. `backend/routers/vpn_users.py` (جدید)
4. `backend/services/scheduler_service.py` (جدید)
5. `backend/main.py` (به‌روزرسانی)
6. `requirements.txt` (به‌روزرسانی)

### Scripts:
7. `scripts/openvpn_auth_user_pass.py` (جدید)

### Frontend:
8. `frontend/templates/clients.html` (به‌روزرسانی کامل)

---

## 🚀 مراحل بعدی

### Phase 3: WireGuard
- مدل VPNConfig آماده است
- فقط نیاز به router و UI

### Phase 4: Sing-box
- مدل VPNConfig آماده است
- فقط نیاز به router و UI

---

## ✅ Checklist تکمیل

- [x] معماری User + VPNConfig
- [x] حذف فیلد email
- [x] تولید خودکار username
- [x] تولید خودکار password
- [x] فیلد data limit
- [x] فیلد expiry date
- [x] APScheduler برای enforcement
- [x] auth-user-pass script
- [x] Protocol badges در UI
- [x] لینک Dashboard در header
- [x] API endpoints جدید
- [x] مستندات کامل

---

**Phase 2 Enhancements: ✅ Complete**

پنل Atlas اکنون آماده برای استفاده تجاری است! 🎉
