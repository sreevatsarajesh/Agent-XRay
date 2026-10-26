import json
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from scanner import scan_config
app = FastAPI(
    title="Agent X-Ray API",
    description="Static security analysis for AI agent MCP configurations.",
    version="0.1.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
@app.get("/health")
def health():
    return {"status": "ok", "service": "agent-xray"}
@app.post("/api/scan")
async def scan(file: UploadFile = File(...)):
    filename = file.filename or "configuration.json"
    if not filename.lower().endswith(".json"):
        raise HTTPException(
            status_code=400,
            detail="Upload a JSON MCP configuration file.",
        )
    try:
        content = await file.read(2 * 1024 * 1024 + 1)
        if len(content) > 2 * 1024 * 1024:
            raise HTTPException(
                status_code=413,
                detail="Configuration file exceeds the 2 MB limit.",
            )
        config = json.loads(content.decode("utf-8-sig"))
        return scan_config(config)
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="The file must be valid UTF-8 JSON.",
        )
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=400,
            detail="Invalid JSON. Check the configuration syntax.",
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    finally:
        await file.close()
