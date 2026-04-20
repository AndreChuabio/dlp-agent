"""
Session replay engine for MediGuard DLP.

Takes a raw production interaction log, DLP-strips it, and reruns it
turn-by-turn through the agent pipeline — showing exactly where and why
the agent went off script.

The raw payload is scanned and redacted in-memory only; nothing containing
raw PHI is ever persisted to disk. Only the redacted session file and the
replay trace (derived from the redacted text) are written.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

SESSIONS_DIR = Path(os.getenv("SESSIONS_DIR", "sessions"))


# ---------------------------------------------------------------------------
# Payload ingestion
# ---------------------------------------------------------------------------

def ingest_payload(raw_payload: str, session_name: str) -> dict:
    """
    Accept a raw production log/payload (may contain real PHI).

    Steps:
      1. Parse into turns (JSON array or freeform text treated as a single user turn)
      2. DLP-scan and redact every user turn in-memory
      3. Save redacted only → sessions/<name>.redacted.json
      4. Return a summary of what was found — never the raw PHI

    session_name: short slug for this debug session, e.g. "ticket-1234"
    """
    from agent.tools import scan_and_clean

    SESSIONS_DIR.mkdir(exist_ok=True)

    # --- Parse payload ---
    turns = _parse_payload(raw_payload)

    # --- DLP-scan every user turn ---
    redacted_turns: list[dict] = []
    total_regex = 0
    total_semantic = 0
    all_finding_types: list[str] = []

    for turn in turns:
        if turn.get("role") == "user":
            result = scan_and_clean(turn.get("text", ""), user_id=f"replay:{session_name}")
            total_regex    += len(result["regex_findings"])
            total_semantic += len(result["semantic_findings"])
            all_finding_types += (
                [f["type"] for f in result["regex_findings"]] +
                [f["type"] for f in result["semantic_findings"]]
            )
            redacted_turns.append({**turn, "text": result["clean"]})
        else:
            redacted_turns.append(turn)

    # --- Persist only the redacted copy ---
    redacted_path = SESSIONS_DIR / f"{session_name}.redacted.json"
    redacted_path.write_text(json.dumps({
        "session_name": session_name,
        "ingested_at":  datetime.utcnow().isoformat(),
        "turns":        redacted_turns,
    }, indent=2))

    logger.info(f"Session '{session_name}' saved (redacted only) → {redacted_path}")

    return {
        "session_name":   session_name,
        "turns_total":    len(turns),
        "user_turns":     sum(1 for t in turns if t.get("role") == "user"),
        "phi_findings":   total_regex + total_semantic,
        "finding_types":  list(set(all_finding_types)),
        "redacted_saved": str(redacted_path),
        "note": "Raw payload was scanned in-memory only and is not persisted to disk.",
    }


# ---------------------------------------------------------------------------
# Session replay
# ---------------------------------------------------------------------------

def replay_session(session_name: str) -> dict:
    """
    Replay a saved redacted session turn-by-turn through the agent pipeline.

    For each user turn, runs:
      - DLP scan (to verify redaction is clean)
      - Patient info extraction
      - Patient lookup (new vs. returning)
      - Specialist triage (when concern is present)

    Returns a structured debug trace — no PHI, all findings are on the
    redacted text.
    """
    from agent.tools import scan_and_clean, extract_patient_info, lookup_patient, triage_specialist

    redacted_path = SESSIONS_DIR / f"{session_name}.redacted.json"
    if not redacted_path.exists():
        return {"error": f"No session found: '{session_name}'. Run ingest_payload first."}

    session = json.loads(redacted_path.read_text())
    turns   = session.get("turns", [])

    trace: list[dict] = []
    accumulated_messages: list[dict] = []
    context: dict = {
        "patient_info": {},
        "is_returning":  None,
        "db_patient":    None,
        "triage_result": None,
    }
    issues: list[str] = []

    for i, turn in enumerate(turns):
        role = turn.get("role", "user")
        text = turn.get("text", "")

        if role != "user":
            accumulated_messages.append({"role": "assistant", "content": text})
            trace.append({"turn": i, "role": role, "text": text})
            continue

        accumulated_messages.append({"role": "user", "content": text})

        # --- DLP verify (should be clean after ingest, flag if not) ---
        dlp = scan_and_clean(text, user_id=f"replay:{session_name}")
        if not dlp["safe_to_send"]:
            issues.append(
                f"Turn {i}: PHI still present after redaction — "
                f"types: {[f['type'] for f in dlp['regex_findings'] + dlp['semantic_findings']]}"
            )

        # --- Extract patient info ---
        new_info = extract_patient_info(accumulated_messages)
        if new_info:
            merged = {**context["patient_info"]}
            for k, v in new_info.items():
                if v and v not in ("null", None, ""):
                    merged[k] = v
            context["patient_info"] = merged

        # --- Patient lookup (once) ---
        lookup_result = None
        name = context["patient_info"].get("patient_name")
        if name and context["is_returning"] is None:
            db_patient = lookup_patient(name)
            context["is_returning"] = db_patient is not None
            context["db_patient"]   = db_patient
            lookup_result = {
                "queried_name": name,
                "found_in_db":  db_patient is not None,
                "record":       db_patient,
            }
            if db_patient is None:
                issues.append(
                    f"Turn {i}: Patient '{name}' not found in DB — "
                    "new patient flow should trigger."
                )

        # --- Triage (once, when concern is known) ---
        triage_result = None
        reason = context["patient_info"].get("reason")
        if reason and not context["triage_result"] and context["is_returning"] is not None:
            result = triage_specialist(reason)
            if result:
                context["triage_result"] = result
                triage_result = result
            else:
                issues.append(f"Turn {i}: Triage failed for reason: '{reason}'")

        trace.append({
            "turn":    i,
            "role":    "user",
            "text":    text,   # already redacted
            "dlp": {
                "safe":          dlp["safe_to_send"],
                "regex_hits":    len(dlp["regex_findings"]),
                "semantic_hits": len(dlp["semantic_findings"]),
                "finding_types": [f["type"] for f in dlp["regex_findings"] + dlp["semantic_findings"]],
            },
            "patient_info_so_far": context["patient_info"].copy(),
            "patient_lookup":      lookup_result,
            "triage":              triage_result,
        })

    return {
        "session_name":  session_name,
        "turns_replayed": len(trace),
        "final_context": {
            "patient_info": context["patient_info"],
            "is_returning":  context["is_returning"],
            "triage_result": context["triage_result"],
        },
        "issues_detected": issues,
        "trace":           trace,
        "summary": _summarize_trace(trace, context, issues),
    }


def list_sessions() -> list[dict]:
    """List all saved debug sessions."""
    SESSIONS_DIR.mkdir(exist_ok=True)
    sessions = []
    for path in sorted(SESSIONS_DIR.glob("*.redacted.json")):
        try:
            data = json.loads(path.read_text())
            turns = data.get("turns", [])
            sessions.append({
                "session_name": data.get("session_name", path.stem.replace(".redacted", "")),
                "ingested_at":  data.get("ingested_at", "unknown"),
                "turns":        len(turns),
                "user_turns":   sum(1 for t in turns if t.get("role") == "user"),
            })
        except Exception:
            pass
    return sessions


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_payload(raw: str) -> list[dict]:
    """
    Parse a raw payload into a list of turns.

    Accepts:
      - JSON array of {role, text} objects
      - JSON object with a "turns" key
      - Plain text → wrapped as a single user turn
    """
    raw = raw.strip()
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return _normalise_turns(data)
        if isinstance(data, dict):
            if "turns" in data:
                return _normalise_turns(data["turns"])
            if "messages" in data:
                return _normalise_turns(data["messages"])
            # Single object treated as one turn
            return [_normalise_turn(data)]
    except json.JSONDecodeError:
        pass
    # Freeform text — treat as a single user message
    return [{"role": "user", "text": raw}]


def _normalise_turns(turns: list) -> list[dict]:
    return [_normalise_turn(t) for t in turns if isinstance(t, dict)]


def _normalise_turn(t: dict) -> dict:
    """Normalise field names: content/message/body → text."""
    text = t.get("text") or t.get("content") or t.get("message") or t.get("body") or ""
    role = t.get("role") or ("user" if t.get("type") == "input" else "agent")
    out = {"role": role, "text": str(text)}
    # Preserve any extra metadata (timestamps, turn ids, etc.)
    for k, v in t.items():
        if k not in ("text", "content", "message", "body", "role", "type"):
            out[k] = v
    return out


def _summarize_trace(trace: list[dict], context: dict, issues: list[str]) -> str:
    user_turns   = [t for t in trace if t.get("role") == "user"]
    triage       = context.get("triage_result")
    is_returning = context.get("is_returning")
    patient_info = context.get("patient_info", {})

    lines = []

    if issues:
        lines.append(f"⚠ {len(issues)} issue(s) detected:")
        for issue in issues:
            lines.append(f"  • {issue}")
    else:
        lines.append("✓ No issues detected in replay.")

    lines.append(f"\nSession had {len(user_turns)} user turn(s).")

    if patient_info.get("patient_name"):
        lines.append(f"Patient identified: {patient_info['patient_name']} "
                     f"({'returning' if is_returning else 'new'}).")

    if triage:
        lines.append(f"Triage resolved to: {triage['specialist_name']} ({triage['specialty']}).")
    elif patient_info.get("reason"):
        lines.append(f"Concern noted ('{patient_info['reason']}') but triage did not complete.")
    else:
        lines.append("No patient concern extracted — triage never ran.")

    return " ".join(lines)
