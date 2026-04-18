"""
MediGuard DLP — MCP Server

Installable plugin for Claude Code (and any MCP-compatible client).
Gives you a local DLP firewall, secrets vault, and session replay debugger
so you can investigate production bugs without leaking PHI to any LLM.

Install (one-time, per employee):
  1. pip install -e ".[mcp]"          # or: pip install mcp
  2. Add to ~/.claude/settings.json:
       {
         "mcpServers": {
           "mediguard-dlp": {
             "command": "python",
             "args": ["/absolute/path/to/dlp-agent/mcp_server.py"],
             "env": { "SECRETS_FILE": "/absolute/path/to/your.secrets" }
           }
         }
       }
  3. Restart Claude Code.

Or use the project-level .mcp.json for team-wide config (no absolute paths needed).

Available tools:
  dlp_scan          — full DLP scan (regex + Baseten + Claude semantic)
  quick_redact      — regex-only redaction, no API calls, instant
  ingest_payload    — load a raw production log, strip PHI, save locally
  replay_session    — rerun a saved session through the agent pipeline
  list_sessions     — list saved debug sessions
  check_secrets     — show which secret keys are loaded (never values)
"""

import os
import sys
import logging

# Ensure project root is on the path regardless of where the server is invoked from
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

from mcp.server.fastmcp import FastMCP

from agent.tools import scan_and_clean, regex_scan, redact_text
from agent.secrets import load_secrets, list_secret_keys, redact_with_secrets
from agent.replay import ingest_payload as _ingest_payload, replay_session as _replay_session, list_sessions as _list_sessions

logging.basicConfig(level=logging.WARNING)  # keep MCP output clean

mcp = FastMCP(
    "MediGuard DLP",
    instructions=(
        "You are connected to MediGuard DLP — a local HIPAA privacy layer. "
        "Use dlp_scan or quick_redact before sending any patient data, logs, or debug payloads to an LLM. "
        "Use ingest_payload + replay_session to debug production incidents without exposing PHI. "
        "Raw session files stay on the employee's machine. Only redacted versions are shared."
    ),
)


# ---------------------------------------------------------------------------
# Tool 1: Full DLP scan
# ---------------------------------------------------------------------------

@mcp.tool()
def dlp_scan(text: str, user_id: str = "mcp-user") -> dict:
    """
    Scan text for PHI and sensitive information using the full DLP pipeline
    (regex → Baseten triage → Claude semantic scan).

    Returns whether the text is safe to send to an LLM, what was found,
    and the redacted version with PHI replaced by [REDACTED:TYPE] tokens.

    Use this before pasting any patient data, logs, or debug output into
    a conversation or prompt.
    """
    result = scan_and_clean(text, user_id=user_id)
    return {
        "safe_to_send":     result["safe_to_send"],
        "redacted_text":    result["clean"],
        "regex_findings":   len(result["regex_findings"]),
        "semantic_findings": len(result["semantic_findings"]),
        "finding_types":    (
            [f["type"] for f in result["regex_findings"]] +
            [f["type"] for f in result["semantic_findings"]]
        ),
        "recommendation": (
            "Safe to use." if result["safe_to_send"]
            else "Contains PHI — use the redacted_text field instead of the original."
        ),
    }


# ---------------------------------------------------------------------------
# Tool 2: Quick regex-only redaction (no API calls, instant)
# ---------------------------------------------------------------------------

@mcp.tool()
def quick_redact(text: str) -> dict:
    """
    Fast regex-only redaction — no API calls, runs in under 1ms.
    Catches structured PII/PHI: SSNs, MRNs, DOBs, phone numbers,
    credit cards, email addresses, API keys, insurance IDs, ICD codes.

    Does NOT catch semantic/contextual PHI (e.g. "the patient responded
    well to treatment"). Use dlp_scan for full coverage.

    Good for: quick clipboard checks, log sanitisation before sharing,
    CI/CD pre-commit hooks.
    """
    findings = regex_scan(text)
    redacted = redact_text(text, findings)
    return {
        "redacted_text":  redacted,
        "findings_count": len(findings),
        "finding_types":  list({f["type"] for f in findings}),
        "safe":           len(findings) == 0,
    }


# ---------------------------------------------------------------------------
# Tool 3: Ingest a raw production payload
# ---------------------------------------------------------------------------

@mcp.tool()
def ingest_payload(payload: str, session_name: str) -> dict:
    """
    Load a raw production interaction log or patient payload for local debugging.

    The payload may contain real PHI — it is DLP-scanned and redacted before
    anything is returned. The raw file is saved locally (gitignored, never
    sent to any LLM). The redacted version is saved as sessions/<name>.redacted.json
    and is safe to share with teammates.

    Accepts:
      - JSON array of {role, text} turns
      - JSON object with a "turns" or "messages" key
      - Plain text (treated as a single user message)

    session_name: short slug for this debug session, e.g. "ticket-1234" or "acme-onboard-bug"

    After ingesting, call replay_session(session_name) to step through it.
    """
    secrets = load_secrets()
    result  = _ingest_payload(payload, session_name)

    # Also check if any loaded secrets appear in the payload
    if secrets:
        _, secret_findings = redact_with_secrets(payload, secrets)
        if secret_findings:
            result["secrets_detected"] = [f["type"] for f in secret_findings]
            result["warning"] = (
                "Loaded secrets were found in this payload. "
                "They have been redacted from the saved version."
            )

    return result


# ---------------------------------------------------------------------------
# Tool 4: Replay a saved session
# ---------------------------------------------------------------------------

@mcp.tool()
def replay_session(session_name: str) -> dict:
    """
    Replay a previously ingested debug session turn-by-turn through the
    agent pipeline (DLP → patient extraction → lookup → triage).

    Shows exactly what the agent did at each step:
      - Which PHI was caught (on the already-redacted text)
      - What patient info was extracted
      - Whether the patient was found in the DB (new vs. returning)
      - What specialist triage resolved to
      - Any steps where the pipeline failed or produced unexpected output

    Use this to pinpoint where the agent went off script for a given
    production ticket.

    Call list_sessions() to see available sessions.
    """
    return _replay_session(session_name)


# ---------------------------------------------------------------------------
# Tool 5: List saved sessions
# ---------------------------------------------------------------------------

@mcp.tool()
def list_sessions() -> dict:
    """
    List all saved debug sessions in the sessions/ directory.
    Returns session names, ingestion timestamps, and turn counts.
    """
    sessions = _list_sessions()
    return {
        "sessions": sessions,
        "count":    len(sessions),
        "hint":     "Use replay_session(session_name) to step through any of these.",
    }


# ---------------------------------------------------------------------------
# Tool 6: Check loaded secrets (keys only, never values)
# ---------------------------------------------------------------------------

@mcp.tool()
def check_secrets(secrets_file: str | None = None) -> dict:
    """
    Show which secret keys are loaded from the employee's .secrets file.
    Never returns values — only confirms which keys exist.

    Useful to verify your secrets file is set up correctly before running
    a debug workflow that depends on specific keys.

    The SECRETS_FILE environment variable controls the default path.
    Pass secrets_file to override.
    """
    path = secrets_file or os.getenv("SECRETS_FILE", "secrets/local.secrets")
    keys = list_secret_keys(path)
    return {
        "secrets_file":  path,
        "keys_loaded":   keys,
        "count":         len(keys),
        "note":          "Values are never shown. Set SECRETS_FILE env var to change the path.",
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
