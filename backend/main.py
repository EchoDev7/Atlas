# Atlas — FastAPI application entry point
# Phase 0: skeleton only — no operational logic yet

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse
from backend.config import settings
from backend.database import SessionLocal, init_db
from backend.models.general_settings import GeneralSettings
from backend.routers import auth, openvpn, settings as server_settings, vpn_users, audit_logs, dashboard, system, terminal
from backend.services.scheduler_service import get_scheduler


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    
    # Start background scheduler for limit enforcement
    scheduler = get_scheduler()
    scheduler.start()
    
    yield
    
    # Shutdown
    scheduler.stop()


def _format_host_for_origin(host: str) -> str:
    normalized = (host or "").strip().strip("[]")
    if not normalized:
        return ""
    if ":" in normalized:
        return f"[{normalized}]"
    return normalized


def _extract_host_and_port(value: str) -> tuple[str, int | None]:
    raw = (value or "").strip()
    if not raw:
        return "", None

    if "://" in raw:
        parsed = urlparse(raw)
        return (parsed.hostname or ""), parsed.port

    cleaned = raw.split("/", 1)[0].split("?", 1)[0].strip()
    if not cleaned:
        return "", None

    if cleaned.startswith("[") and "]" in cleaned:
        host_part, _, rest = cleaned.partition("]")
        host = host_part.strip("[]")
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, None

    if cleaned.count(":") == 1:
        host, maybe_port = cleaned.rsplit(":", 1)
        if maybe_port.isdigit():
            return host, int(maybe_port)

    return cleaned, None


def _origin_candidates(value: str, default_port: int | None = None) -> set[str]:
    origins: set[str] = set()
    raw = (value or "").strip()
    if not raw:
        return origins

    if "://" in raw:
        parsed = urlparse(raw)
        scheme = (parsed.scheme or "").lower()
        host = _format_host_for_origin(parsed.hostname or "")
        port = parsed.port
        if scheme in {"http", "https"} and host:
            netloc = f"{host}:{port}" if port else host
            origins.add(f"{scheme}://{netloc}")
            if default_port and not port:
                origins.add(f"{scheme}://{host}:{default_port}")
        return origins

    host, port = _extract_host_and_port(raw)
    formatted_host = _format_host_for_origin(host)
    if not formatted_host:
        return origins

    for scheme in ("http", "https"):
        if port:
            origins.add(f"{scheme}://{formatted_host}:{port}")
        else:
            origins.add(f"{scheme}://{formatted_host}")
            if default_port:
                origins.add(f"{scheme}://{formatted_host}:{default_port}")
    return origins


def _build_allowed_cors_origins() -> list[str]:
    origins = {
        "http://localhost",
        "https://localhost",
        "http://127.0.0.1",
        "https://127.0.0.1",
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8000",
    }

    db = SessionLocal()
    try:
        general = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
        if not general:
            return sorted(origins)

        panel_port = int(general.panel_https_port or 0) or None
        origins.update(_origin_candidates(general.panel_domain or "", default_port=panel_port))
        origins.update(_origin_candidates(general.server_address or ""))
        origins.update(_origin_candidates(general.public_ipv4_address or ""))
        origins.update(_origin_candidates(general.public_ipv6_address or ""))
    except Exception:
        pass
    finally:
        db.close()

    return sorted(origins)


app = FastAPI(
    title=settings.PROJECT_NAME,
    version="2.0.0",
    docs_url=f"{settings.API_PREFIX}/docs",
    redoc_url=f"{settings.API_PREFIX}/redoc",
    openapi_url=f"{settings.API_PREFIX}/openapi.json",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_build_allowed_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def force_https_middleware(request: Request, call_next):
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    request_scheme = (forwarded_proto or request.url.scheme).lower()
    host = (request.url.hostname or "").lower()

    if request_scheme == "http" and host not in {"localhost", "127.0.0.1"}:
        db = SessionLocal()
        try:
            general = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
            if general and general.force_https:
                secure_url = request.url.replace(scheme="https")
                return RedirectResponse(url=str(secure_url), status_code=307)
        finally:
            db.close()

    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").lower()
    request_scheme = (forwarded_proto or request.url.scheme).lower()
    if request_scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response

# Register routers
app.include_router(auth.router, prefix=settings.API_PREFIX)
app.include_router(openvpn.router, prefix=settings.API_PREFIX)
app.include_router(vpn_users.router, prefix=settings.API_PREFIX)
app.include_router(server_settings.router, prefix=settings.API_PREFIX)
app.include_router(audit_logs.router, prefix=settings.API_PREFIX)
app.include_router(dashboard.router, prefix=settings.API_PREFIX)
app.include_router(system.router, prefix=settings.API_PREFIX)
app.include_router(terminal.router, prefix=settings.API_PREFIX)

frontend_path = Path(__file__).parent.parent / "frontend"


@app.get("/", include_in_schema=False)
def root_redirect() -> RedirectResponse:
    return RedirectResponse(url="/login", status_code=307)


@app.get("/login", include_in_schema=False)
def login_page() -> FileResponse:
    return FileResponse(frontend_path / "templates" / "login.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard_page() -> FileResponse:
    return FileResponse(frontend_path / "dashboard.html")


@app.get("/clients", include_in_schema=False)
def clients_page() -> FileResponse:
    return FileResponse(frontend_path / "templates" / "clients.html")


@app.get("/settings", include_in_schema=False)
def settings_page() -> FileResponse:
    return FileResponse(frontend_path / "settings.html")


@app.get("/dashboard.html", include_in_schema=False)
def dashboard_legacy_redirect() -> RedirectResponse:
    return RedirectResponse(url="/dashboard", status_code=307)


@app.get("/clients.html", include_in_schema=False)
def clients_legacy_redirect() -> RedirectResponse:
    return RedirectResponse(url="/clients", status_code=307)


@app.get("/settings.html", include_in_schema=False)
def settings_legacy_redirect() -> RedirectResponse:
    return RedirectResponse(url="/settings", status_code=307)


@app.get("/templates/login.html", include_in_schema=False)
def login_legacy_redirect() -> RedirectResponse:
    return RedirectResponse(url="/login", status_code=307)


@app.get("/templates/clients.html", include_in_schema=False)
def clients_template_legacy_redirect() -> RedirectResponse:
    return RedirectResponse(url="/clients", status_code=307)

app.mount("/", StaticFiles(directory=str(frontend_path), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
