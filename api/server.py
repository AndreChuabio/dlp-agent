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
from agent.tools import (
    MAX_INPUT_CHARS,
    scan_and_clean,
    extract_patient_info,
    search_insurance_coverage,
    regex_scan,
    redact_text,
)
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
    # Log the exception type but never the message or traceback -- SDK
    # exceptions from Anthropic / OpenAI / psycopg2 can echo the request
    # body on .body / .request attributes, which would put PHI into app logs.
    logger.error(
        "Unhandled error on %s (%s)", request.url.path, type(exc).__name__,
    )
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

# Session store. TTL prevents unbounded growth, and the max-size cap evicts
# the oldest session when full. This is still in-process memory -- Redis
# with per-tenant isolation is tracked for a follow-up.
_SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "1800"))
_SESSION_MAX = int(os.getenv("SESSION_MAX", "1000"))
_sessions: dict = {}


def _get_session(session_id: str) -> dict:
    """Return the session for session_id, evicting stale or oldest entries."""
    import time
    now = time.monotonic()

    # Drop expired.
    expired = [
        sid for sid, s in _sessions.items()
        if now - s.get("_last_seen", now) > _SESSION_TTL_SECONDS
    ]
    for sid in expired:
        _sessions.pop(sid, None)

    # Size cap -- evict oldest by last_seen if at capacity and creating new.
    if session_id not in _sessions and len(_sessions) >= _SESSION_MAX:
        oldest = min(_sessions, key=lambda k: _sessions[k].get("_last_seen", 0))
        _sessions.pop(oldest, None)

    session = _sessions.setdefault(session_id, {
        "messages": [], "patient_info": {}, "coverage": None,
    })
    session["_last_seen"] = now
    return session


def _sanitize_patient_info_for_prompt(info: dict) -> dict:
    """Drop PHI fields before injecting collected info into a system prompt.

    We tell the model what has been collected (so it does not re-ask), but
    not the values themselves. If the model needs the real value (e.g. to
    confirm back to the patient), that is a tool call, not a prompt leak.
    """
    return {
        "has_name":         bool(info.get("patient_name")),
        "has_dob":          bool(info.get("dob")),
        "has_phone":        bool(info.get("phone")),
        "has_insurance_id": bool(info.get("insurance_id")),
        "reason_collected": bool(info.get("reason")),
    }


def _scrub_outbound(text: str) -> str:
    """Final-gate redaction on text leaving the service.

    LLMs occasionally regurgitate prior-turn content. Running the same regex
    pass on the outbound reply closes the loop so structured PHI cannot exit
    the service even if the model echoes it.
    """
    if not text:
        return text
    findings = regex_scan(text)
    return redact_text(text, findings) if findings else text


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

def _reject_if_oversized(text: str) -> None:
    if len(text) > MAX_INPUT_CHARS:
        raise HTTPException(
            status_code=413,
            detail={
                "error": f"Input exceeds maximum of {MAX_INPUT_CHARS} characters",
                "code": "INPUT_TOO_LARGE",
            },
        )


@app.post("/scan")
@limiter.limit("60/minute")
def scan(request: Request, req: ScanRequest, api_key: str = Security(_require_api_key)):
    _reject_if_oversized(req.text)
    result = run(text=req.text, user_id=req.user_id)
    return result


@app.post("/chat")
@limiter.limit("30/minute")
def chat(request: Request, req: ChatRequest, api_key: str = Security(_require_api_key)):
    """Veris-compatible chat endpoint. Runs full DLP pipeline before LLM."""
    _reject_if_oversized(req.message)
    session = _get_session(req.session_id)

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

    # Inject only presence-flags into the system prompt -- the model does not
    # need the actual values to drive the conversation, so keep PHI out of the
    # prompt entirely. The model is told which fields have been collected.
    system = SYSTEM_PROMPT
    if session["patient_info"]:
        system += (
            "\n\nFields collected so far (values withheld for HIPAA): "
            f"{json.dumps(_sanitize_patient_info_for_prompt(session['patient_info']))}"
        )
    if session["coverage"] and session["coverage"].get("results"):
        # Coverage snippets come from a third-party search; scrub them too.
        snippets = " | ".join(
            _scrub_outbound(r["snippet"])
            for r in session["coverage"]["results"][:2]
            if r.get("snippet")
        )
        system += f"\n\nInsurance coverage info: {snippets}"

    client = anthropic.Anthropic(
        api_key=os.getenv("ANTHROPIC_API_KEY"),
        timeout=float(os.getenv("DLP_CLAUDE_TIMEOUT", "15")),
    )
    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=300,
        system=system,
        messages=session["messages"],
    )
    raw_reply = response.content[0].text

    # Outbound scrubber: catch any structured PHI the model may have echoed.
    reply = _scrub_outbound(raw_reply)

    session["messages"].append({"role": "assistant", "content": reply})

    return {
        "response": reply,
        "session_id": req.session_id,
        "dlp": {
            "safe_to_send": dlp_result["safe_to_send"],
            "findings_count": len(dlp_result["regex_findings"]) + len(dlp_result["semantic_findings"]),
            "outbound_scrubbed": reply != raw_reply,
        },
    }


@app.get("/health")
def health():
    return {"status": "ok"}
