"""
MediGuard DLP — MCP Server.

Installable plugin for Claude Code, Claude Desktop, Cursor, Windsurf, and any
MCP-compatible client. Gives you a local DLP firewall, secrets vault, and
session replay debugger so you can investigate production bugs without
leaking PHI to any LLM.

Runs as a stdio MCP server. Exposed tools:
  dlp_scan         — full pipeline scan (regex + Baseten + Claude semantic)
  quick_redact     — regex-only redaction, no API calls, instant
  ingest_payload   — load a raw log, strip PHI locally, save redacted copy
  replay_session   — step a saved session through the agent pipeline
  list_sessions    — list saved debug sessions
  check_secrets    — show which secret keys are loaded (never values)

API keys are read from the environment. If Anthropic / Baseten keys are
missing, the server degrades to regex-only mode and logs a warning.
"""

import os
import sys
import logging

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from mcp.server.fastmcp import FastMCP

from agent.tools import scan_and_clean, regex_scan, redact_text
from agent.secrets import load_secrets, list_secret_keys, redact_with_secrets
from agent.replay import (
    ingest_payload as _ingest_payload,
    replay_session as _replay_session,
    list_sessions as _list_sessions,
)

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("mediguard-dlp")


def _check_degraded_mode() -> list[str]:
    """Return a list of tiers that will be skipped due to missing API keys."""
    missing = []
    if not os.getenv("ANTHROPIC_API_KEY"):
        missing.append("Claude semantic scan (ANTHROPIC_API_KEY)")
    if not os.getenv("BASETEN_API_KEY"):
        missing.append("Baseten triage (BASETEN_API_KEY)")
    return missing


_MISSING_KEYS = _check_degraded_mode()
_DEGRADED_NOTE = ""
if _MISSING_KEYS:
    _DEGRADED_NOTE = (
        " Running in degraded mode — missing: "
        + ", ".join(_MISSING_KEYS)
        + ". Regex tier still active."
    )
    logger.warning(_DEGRADED_NOTE.strip())


mcp = FastMCP(
    "MediGuard DLP",
    instructions=(
        "You are connected to MediGuard DLP — a local HIPAA privacy layer. "
        "Use dlp_scan or quick_redact before sending any patient data, logs, "
        "or debug payloads to an LLM. Use ingest_payload + replay_session to "
        "debug production incidents without exposing PHI. Raw session files "
        "stay on the employee's machine; only redacted versions are shared."
        + _DEGRADED_NOTE
    ),
)


@mcp.tool()
def dlp_scan(text: str, user_id: str = "mcp-user") -> dict:
    """
    Scan text for PHI and sensitive information using the full DLP pipeline
    (regex → Baseten triage → Claude semantic scan).

    Returns whether the text is safe to send to an LLM, what was found, and
    the redacted version with PHI replaced by [REDACTED:TYPE] tokens.

    Call this before pasting any patient data, logs, or debug output into
    a conversation or prompt.
    """
    result = scan_and_clean(text, user_id=user_id)
    return {
        "safe_to_send":      result["safe_to_send"],
        "redacted_text":     result["clean"],
        "regex_findings":    len(result["regex_findings"]),
        "semantic_findings": len(result["semantic_findings"]),
        "finding_types": (
            [f["type"] for f in result["regex_findings"]]
            + [f["type"] for f in result["semantic_findings"]]
        ),
        "degraded_tiers":    _MISSING_KEYS,
        "recommendation": (
            "Safe to use." if result["safe_to_send"]
            else "Contains PHI — use the redacted_text field instead of the original."
        ),
    }


@mcp.tool()
def quick_redact(text: str) -> dict:
    """
    Fast regex-only redaction — no API calls, runs in under 1ms.
    Catches structured PII/PHI: SSNs, MRNs, DOBs, phone numbers, credit
    cards, emails, API keys, insurance IDs, ICD codes, ZIP codes.

    Does NOT catch semantic/contextual PHI (e.g. "the patient responded
    well to treatment"). Use dlp_scan for full coverage.

    Good for: quick clipboard checks, log sanitization before sharing,
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


@mcp.tool()
def ingest_payload(payload: str, session_name: str) -> dict:
    """
    Load a raw production interaction log or patient payload for local debugging.

    The payload may contain real PHI — it is DLP-scanned and redacted before
    anything is returned. The raw file is saved locally (gitignored, never
    sent to any LLM). The redacted version is saved as
    sessions/<name>.redacted.json and is safe to share with teammates.

    Accepts:
      - JSON array of {role, text} turns
      - JSON object with a "turns" or "messages" key
      - Plain text (treated as a single user message)

    session_name: short slug for this debug session,
                  e.g. "ticket-1234" or "acme-onboard-bug".

    After ingesting, call replay_session(session_name) to step through it.
    """
    secrets = load_secrets()
    result  = _ingest_payload(payload, session_name)

    if secrets:
        _, secret_findings = redact_with_secrets(payload, secrets)
        if secret_findings:
            result["secrets_detected"] = [f["type"] for f in secret_findings]
            result["warning"] = (
                "Loaded secrets were found in this payload. "
                "They have been redacted from the saved version."
            )

    return result


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
      - Any step where the pipeline failed or produced unexpected output

    Use this to pinpoint where the agent went off script for a given
    production ticket. Call list_sessions() to see available sessions.
    """
    return _replay_session(session_name)


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
        "secrets_file": path,
        "keys_loaded":  keys,
        "count":        len(keys),
        "note":         "Values are never shown. Set SECRETS_FILE env var to change the path.",
    }


def main() -> None:
    """CLI entry point for `mediguard-dlp`. Runs the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
