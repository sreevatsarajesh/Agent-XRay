import json
import os

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from scanner import scan_config


MAX_UPLOAD_BYTES = 2 * 1024 * 1024

app = FastAPI(
    title="Agent X-Ray API",
    description="Local-first static security analysis for AI agent MCP configurations.",
    version="1.0.0",
)

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "FRONTEND_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "agent-xray", "version": "1.0.0"}


@app.get("/api/rules")
def rules():
    return {
        "analysis_mode": "static",
        "executes_agent_code": False,
        "finding_fields": ["severity", "confidence", "evidence", "remediation", "node_id"],
        "limitations": [
            "Tool capability matches are heuristic and depend on supplied metadata.",
            "Input-schema signals do not prove that an implementation is vulnerable.",
            "A clean scan does not guarantee that a configuration or agent is secure.",
        ],
    }


@app.post("/api/scan")
async def scan(file: UploadFile = File(...)):
    filename = file.filename or "configuration.json"

    if not filename.lower().endswith(".json"):
        raise HTTPException(status_code=400, detail="Upload a JSON configuration file.")

    try:
        content = await file.read(MAX_UPLOAD_BYTES + 1)

        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Configuration file exceeds the 2 MB limit.")

        try:
            config = json.loads(content.decode("utf-8-sig"))
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="The file must be valid UTF-8 JSON.")
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON. Check the configuration syntax.")

        try:
            return scan_config(config)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    finally:
        await file.close()
