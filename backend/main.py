from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.database.db import initialize_database, check_db_connectivity
from app.discovery.network_telemetry import get_nmap_info, get_network_info
from backend.api import discovery, scans, history, stats, network, assets, reports


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure SQLite database and tables exist
    initialize_database()
    yield
    # Shutdown logic if needed


app = FastAPI(
    title="VigiCore API",
    description="VigiCore — CCTV Security Assessment Platform API.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for local Vite frontend and general access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(network.router)
app.include_router(assets.router)
app.include_router(discovery.router)
app.include_router(scans.router)
app.include_router(history.router)
app.include_router(stats.router)
app.include_router(reports.router)


@app.get("/api/health")
def health_check():
    db_status = check_db_connectivity()
    nmap_status = get_nmap_info()
    net_status = get_network_info()

    return {
        "status": "healthy" if db_status.get("connected") else "degraded",
        "service": "VigiCore Scanner Backend",
        "product": "VigiCore",
        "tagline": "Discover. Assess. Secure.",
        "version": "1.0.0",
        "database": db_status,
        "nmap": nmap_status,
        "network": {
            "active_interface": net_status.get("active_interface"),
            "ip": net_status.get("ip"),
            "cidr": net_status.get("cidr"),
            "gateway": net_status.get("gateway"),
            "ssid": net_status.get("ssid")
        }
    }


# Mount built frontend static files if available
FRONTEND_DIST = Path(__file__).resolve().parents[1] / "frontend" / "dist"
if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)

