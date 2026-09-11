import os
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from .config import settings
from .database import engine, Base
from .seed import seed_database
from .routes import auth_routes, portal_routes, soc_routes, simulate_routes, websocket_routes

Base.metadata.create_all(bind=engine)
seed_database()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Enterprise Multi-Portal AI-SOC Defense & Incident Response Platform"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth_routes.router)
app.include_router(portal_routes.router)
app.include_router(soc_routes.router)
app.include_router(simulate_routes.router)
app.include_router(websocket_routes.router)

# Directories
BASE_DIR = Path(__file__).resolve().parent.parent.parent
PORTAL_DIR = BASE_DIR / "frontend" / "portal"
SOC_DIR = BASE_DIR / "frontend" / "soc"

# Static File Mounts
if PORTAL_DIR.exists():
    app.mount("/static-portal", StaticFiles(directory=str(PORTAL_DIR)), name="static_portal")
if SOC_DIR.exists():
    app.mount("/static-soc", StaticFiles(directory=str(SOC_DIR)), name="static_soc")

# Serve Company Website at / and /portal
@app.get("/")
@app.get("/portal")
async def serve_company_portal():
    index_file = PORTAL_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "Company Portal"}

# Serve SOC Operations Console at /soc
@app.get("/soc")
async def serve_soc_console():
    soc_file = SOC_DIR / "index.html"
    if soc_file.exists():
        return FileResponse(str(soc_file))
    return {"message": "SOC Operations Console"}

@app.get("/health")
async def health_check():
    return {
        "status": "HEALTHY",
        "system": settings.PROJECT_NAME,
        "company_portal_url": "/",
        "soc_console_url": "/soc",
        "detection_engine": "ACTIVE (Brute Force Velocity Analyzer)",
        "password_policy": "3-Password History Rule Enforced"
    }
