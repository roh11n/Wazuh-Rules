"""OSINT Pipeline FastAPI backend."""
from fastapi import FastAPI, APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import os
import uuid
import logging
import asyncio

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

from osint.models import ScanRequest
from osint.orchestrator import Orchestrator
from osint.report import render_html
from osint.config import set_overrides

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

app = FastAPI(title="OSINT Pipeline API")
api = APIRouter(prefix="/api")


# ── Models ──────────────────────────────────────────────
class ScanCreate(BaseModel):
    target: str
    dork_queries: list[str] = Field(default_factory=list)
    skip_screenshots: bool = False
    skip_dorking: bool = False


class ScanStatus(BaseModel):
    id: str
    target: str
    status: str  # queued | running | completed | failed
    phase: str | None = None
    progress: int = 0
    message: str | None = None
    severity: str | None = None
    risk_score: int | None = None
    created_at: str
    completed_at: str | None = None
    error: str | None = None


class SettingsIn(BaseModel):
    ipinfo_token: str | None = None
    abuseipdb_key: str | None = None
    virustotal_key: str | None = None
    otx_key: str | None = None
    discord_webhook: str | None = None


# ── helpers ─────────────────────────────────────────────
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _load_settings_overrides():
    doc = await db.settings.find_one({"_id": "api_keys"}, {"_id": 0})
    if doc:
        set_overrides({
            "IPINFO_TOKEN": doc.get("ipinfo_token"),
            "ABUSEIPDB_KEY": doc.get("abuseipdb_key"),
            "VIRUSTOTAL_KEY": doc.get("virustotal_key"),
            "OTX_KEY": doc.get("otx_key"),
            "DISCORD_WEBHOOK": doc.get("discord_webhook"),
        })


# ── Background scan runner ──────────────────────────────
async def _run_scan(scan_id: str, req: ScanRequest):
    await _load_settings_overrides()
    orch = Orchestrator()

    async def progress_cb(phase: str, pct: int, msg: str):
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {"phase": phase, "progress": pct, "message": msg}},
        )

    try:
        await db.scans.update_one(
            {"id": scan_id}, {"$set": {"status": "running", "progress": 1}}
        )
        result = await orch.run(req, progress=progress_cb)
        payload = result.model_dump(mode="json")
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "status": "completed",
                "progress": 100,
                "phase": "done",
                "message": "Complete",
                "completed_at": now_iso(),
                "result": payload,
                "severity": result.risk.severity if result.risk else None,
                "risk_score": result.risk.risk_score if result.risk else None,
            }},
        )
    except Exception as e:
        logger.exception("scan failed")
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {"status": "failed", "error": str(e), "completed_at": now_iso()}},
        )


# ── Routes ──────────────────────────────────────────────
@api.get("/")
async def root():
    return {"message": "OSINT Pipeline API", "status": "ok"}


@api.post("/scans", response_model=ScanStatus)
async def create_scan(body: ScanCreate):
    target = body.target.strip().lower().replace("https://", "").replace("http://", "").strip("/")
    if not target or "." not in target:
        raise HTTPException(400, "Invalid target domain")

    scan_id = str(uuid.uuid4())
    doc = {
        "id": scan_id,
        "target": target,
        "status": "queued",
        "phase": None,
        "progress": 0,
        "message": "Queued",
        "severity": None,
        "risk_score": None,
        "created_at": now_iso(),
        "completed_at": None,
        "error": None,
        "result": None,
        "dork_queries": body.dork_queries,
        "skip_screenshots": body.skip_screenshots,
        "skip_dorking": body.skip_dorking,
    }
    await db.scans.insert_one(doc)

    req = ScanRequest(
        target=target,
        dork_queries=body.dork_queries,
        skip_screenshots=body.skip_screenshots,
        skip_dorking=body.skip_dorking,
    )
    asyncio.create_task(_run_scan(scan_id, req))

    return ScanStatus(**{k: v for k, v in doc.items() if k in ScanStatus.model_fields})


@api.get("/scans", response_model=list[ScanStatus])
async def list_scans():
    cur = db.scans.find(
        {},
        {"_id": 0, "result": 0, "dork_queries": 0, "skip_screenshots": 0, "skip_dorking": 0},
    ).sort("created_at", -1).limit(200)
    return [ScanStatus(**doc) async for doc in cur]


@api.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    doc = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Scan not found")
    return doc


@api.get("/scans/{scan_id}/status", response_model=ScanStatus)
async def get_status(scan_id: str):
    doc = await db.scans.find_one(
        {"id": scan_id},
        {"_id": 0, "result": 0, "dork_queries": 0, "skip_screenshots": 0, "skip_dorking": 0},
    )
    if not doc:
        raise HTTPException(404, "Scan not found")
    return ScanStatus(**doc)


@api.get("/scans/{scan_id}/report", response_class=HTMLResponse)
async def get_report(scan_id: str):
    doc = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Scan not found")
    if doc.get("status") != "completed" or not doc.get("result"):
        raise HTTPException(400, "Scan not completed")

    from osint.models import ScanResult
    r = ScanResult(**doc["result"])
    return HTMLResponse(render_html(r))


@api.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    res = await db.scans.delete_one({"id": scan_id})
    if res.deleted_count == 0:
        raise HTTPException(404, "Scan not found")
    return {"ok": True}


@api.get("/settings")
async def get_settings():
    doc = await db.settings.find_one({"_id": "api_keys"}, {"_id": 0})
    if not doc:
        doc = {}
    # return masked (just indicate present/absent)
    out = {}
    for k in ("ipinfo_token", "abuseipdb_key", "virustotal_key", "otx_key", "discord_webhook"):
        v = doc.get(k) or ""
        out[k] = ("•" * 8 + v[-4:]) if v and len(v) > 4 else ""
        out[f"{k}_set"] = bool(v)
    return out


@api.put("/settings")
async def update_settings(body: SettingsIn):
    updates = {k: v for k, v in body.model_dump(exclude_none=True).items() if v}
    if not updates:
        return {"ok": True, "updated": 0}
    await db.settings.update_one(
        {"_id": "api_keys"}, {"$set": updates}, upsert=True
    )
    await _load_settings_overrides()
    return {"ok": True, "updated": len(updates)}


app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def _startup():
    await _load_settings_overrides()
    logger.info("OSINT Pipeline API ready")


@app.on_event("shutdown")
async def _shutdown():
    client.close()
