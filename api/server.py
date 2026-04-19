"""FastAPI server — POST /scan and POST /chat for Veris simulation."""

import os
import json
import logging
from fastapi import FastAPI, HTTPException, Security, Request
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
from agent.orchestrator import run
from agent.tools import scan_and_clean, extract_patient_info, search_insurance_coverage
import anthropic

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="MediGuard AI API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------------------------------------------------------------------------
# CORS — whitelist only known origins
# ---------------------------------------------------------------------------

_raw_origins = os.getenv("CORS_ORIGINS", "http://localhost:8501,https://dlphealth-production.up.railway.app")
_allowed_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# API key auth
# Configured via API_KEYS env var — comma-separated list of valid keys.
# If API_KEYS is not set the server runs unauthenticated (dev/demo mode).
# ---------------------------------------------------------------------------

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_valid_keys: set[str] = {
    k.strip() for k in os.getenv("API_KEYS", "").split(",") if k.strip()
}


def _require_api_key(api_key: str = Security(_api_key_header)) -> str:
    if not _valid_keys:
        return "unauthenticated"
    if api_key not in _valid_keys:
        raise HTTPException(status_code=401, detail={"error": "Invalid or missing API key", "code": "UNAUTHORIZED"})
    return api_key


# ---------------------------------------------------------------------------
# Global error handler — never leak raw exception text
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def _global_error_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "code": "INTERNAL_ERROR"},
    )

# ---------------------------------------------------------------------------
# Session store + system prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are MediGuard AI, a HIPAA-compliant patient onboarding assistant. "
    "Your job is to collect patient information conversationally — no forms, no paperwork. "
    "All patient messages have been scanned and redacted by a DLP layer. You never see raw PHI. "
    "Keep responses brief and warm — one question at a time.\n\n"
    "Onboarding flow: ask for name → reason for visit → insurance ID → DOB → callback number → confirm.\n"
    "If a message contains [REDACTED:...] tokens, acknowledge the info was protected and move on."
)

_sessions: dict = {}


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    text: str
    user_id: str = "anonymous"


class ChatRequest(BaseModel):
    message: str
    session_id: str = "default"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/scan")
@limiter.limit("60/minute")
def scan(request: Request, req: ScanRequest, api_key: str = Security(_require_api_key)):
    result = run(text=req.text, user_id=req.user_id)
    return result


@app.post("/chat")
@limiter.limit("30/minute")
def chat(request: Request, req: ChatRequest, api_key: str = Security(_require_api_key)):
    """Veris-compatible chat endpoint. Runs full DLP pipeline before LLM."""
    session = _sessions.setdefault(req.session_id, {"messages": [], "patient_info": {}, "coverage": None})

    dlp_result = scan_and_clean(req.message, user_id=req.session_id)
    clean_message = dlp_result["clean"]

    session["messages"].append({"role": "user", "content": clean_message})

    patient_info = extract_patient_info(session["messages"])
    if patient_info:
        session["patient_info"].update({k: v for k, v in patient_info.items() if v and v != "null"})

    insurance_id = session["patient_info"].get("insurance_id")
    if insurance_id and not session["coverage"]:
        session["coverage"] = search_insurance_coverage(
            insurance_id=insurance_id,
            reason=session["patient_info"].get("reason", ""),
        )

    system = SYSTEM_PROMPT
    if session["patient_info"]:
        system += f"\n\nCollected so far: {json.dumps(session['patient_info'])}"
    if session["coverage"] and session["coverage"].get("results"):
        snippets = " | ".join(r["snippet"] for r in session["coverage"]["results"][:2] if r.get("snippet"))
        system += f"\n\nInsurance coverage info: {snippets}"

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=300,
        system=system,
        messages=session["messages"],
    )
    reply = response.content[0].text

    session["messages"].append({"role": "assistant", "content": reply})

    return {
        "response": reply,
        "session_id": req.session_id,
        "dlp": {
            "safe_to_send": dlp_result["safe_to_send"],
            "findings_count": len(dlp_result["regex_findings"]) + len(dlp_result["semantic_findings"]),
        },
    }


@app.get("/health")
def health():
    return {"status": "ok"}
