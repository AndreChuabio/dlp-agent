"""FastAPI server — POST /scan wraps the full DLP pipeline."""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from agent.orchestrator import run

app = FastAPI(title="DLP Agent API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    text: str
    user_id: str = "anonymous"


@app.post("/scan")
def scan(req: ScanRequest):
    try:
        result = run(text=req.text, user_id=req.user_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
def health():
    return {"status": "ok"}
