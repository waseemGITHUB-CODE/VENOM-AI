# ============================================================
#  backend/main.py  —  VENOM AI FastAPI Application
#  Virtual Engine for Network Offensive Monitoring
# ============================================================
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn, logging, traceback, os

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s"
)
logger = logging.getLogger("venom")

# ── Environment — "development" enables API docs, anything else disables them ─
ENV = os.getenv("ENV", "production")
_is_dev = ENV == "development"
logger.info(f"[startup] ENV={ENV}  API docs={'ENABLED' if _is_dev else 'DISABLED'}")

app = FastAPI(
    title="VENOM AI API",
    description="Virtual Engine for Network Offensive Monitoring — Agentic Exposure Management Platform",
    version="2.0.0",
    # Docs only available in development — never exposed in production
    docs_url      = "/api/docs"         if _is_dev else None,
    redoc_url     = "/api/redoc"        if _is_dev else None,
    openapi_url   = "/api/openapi.json" if _is_dev else None,
)

# ── CORS — read allowed origins from .env (never hardcode) ───────────────
_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080")
ALLOWED_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]
logger.info(f"CORS allowed origins: {ALLOWED_ORIGINS}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    expose_headers=["X-Session-Id", "X-Model", "X-Searched-Web"],
)

# ── Error handler — logs full detail server-side, returns generic message ─
@app.exception_handler(Exception)
async def global_handler(request: Request, exc: Exception):
    # Full stack trace logged on the server (never sent to client)
    logger.error(
        f"Unhandled error on {request.method} {request.url}: "
        f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Please try again."},
    )

# ── DB — auto-create tables on startup (dev convenience) ──────────────
@app.on_event("startup")
def _ensure_tables():
    """Create any missing tables. In production, use Alembic migrations instead."""
    try:
        from db.database import Base, engine, SessionLocal
        # Import models so SQLAlchemy registers them on Base.metadata
        import db.models  # noqa: F401
        Base.metadata.create_all(bind=engine)
        logger.info("[startup] DB tables ensured")

        # Seed billing plans
        try:
            from billing.plans import seed_plans
            db = SessionLocal()
            try:
                seed_plans(db)
            finally:
                db.close()
        except Exception as pe:
            logger.error(f"[startup] plan seeding failed: {pe}")

        # Seed forbidden targets (legal/safety blocklist)
        try:
            from security.forbidden_targets import seed_forbidden_targets
            db = SessionLocal()
            try:
                seed_forbidden_targets(db)
            finally:
                db.close()
        except Exception as fe:
            logger.error(f"[startup] forbidden targets seeding failed: {fe}")
    except Exception as e:
        logger.error(f"[startup] could not ensure DB tables: {e}")

# ── Routes ─────────────────────────────────────────────────────────────
# NOTE: billing/payments removed in the open-source edition. Everything is
# unlimited and free — see backend/billing/quotas.py (no-op stubs).
from routes import (
    chatbot, scanning, reports, dashboard, monitoring,
    threat_intel, auth, verify, recon, attack,
)

app.include_router(auth.router,         prefix="/api/auth",       tags=["Authentication"])
app.include_router(chatbot.router,      prefix="/api/chat",       tags=["AI Assistant"])
app.include_router(scanning.router,     prefix="/api/scan",       tags=["Security Scanning"])
app.include_router(reports.router,      prefix="/api/reports",    tags=["Reports"])
app.include_router(dashboard.router,    prefix="/api/dashboard",  tags=["Dashboard"])
app.include_router(monitoring.router,   prefix="/api/monitor",    tags=["Continuous Monitoring"])
app.include_router(threat_intel.router, prefix="/api/threat",     tags=["Threat Intelligence"])
app.include_router(verify.router,       prefix="/api/verify",     tags=["Domain Verification"])
app.include_router(recon.router,        prefix="/api/recon",      tags=["Reconnaissance"])
app.include_router(attack.router,       prefix="/api/attack",     tags=["Active OWASP Scanner"])

@app.get("/api/health")
async def health():
    return {
        "status":  "ok",
        "product": "VENOM AI",
        "version": "2.0.0",
        "tagline": "Virtual Engine for Network Offensive Monitoring",
    }

@app.get("/")
async def root():
    return {"message": "VENOM AI API — visit /api/docs for documentation"}

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
