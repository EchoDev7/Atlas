# Atlas — FastAPI application entry point
# Phase 0: skeleton only — no operational logic yet

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pathlib import Path
from backend.config import settings
from backend.database import SessionLocal, init_db
from backend.models.general_settings import GeneralSettings
from backend.routers import auth, openvpn, settings as server_settings, vpn_users
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


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    docs_url=f"{settings.API_PREFIX}/docs",
    redoc_url=f"{settings.API_PREFIX}/redoc",
    openapi_url=f"{settings.API_PREFIX}/openapi.json",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

# Register routers
app.include_router(auth.router, prefix=settings.API_PREFIX)
app.include_router(openvpn.router, prefix=settings.API_PREFIX)
app.include_router(vpn_users.router, prefix=settings.API_PREFIX)
app.include_router(server_settings.router, prefix=settings.API_PREFIX)

frontend_path = Path(__file__).parent.parent / "frontend"
app.mount("/", StaticFiles(directory=str(frontend_path), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
