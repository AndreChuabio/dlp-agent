"""
Secrets manager for MediGuard DLP.

Loads per-employee .secrets files (never committed to git).
Resolves {{PLACEHOLDER}} syntax in workflow templates.
Builds dynamic DLP patterns from secret values so they're caught if they leak.
"""

import re
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_SECRETS_FILE = os.getenv("SECRETS_FILE", "secrets/local.secrets")

# Minimum length for a secret value to be added as a DLP pattern.
# Avoids false positives from very short values like "US" or "42".
_MIN_SECRET_LEN = 6


def load_secrets(path: str | None = None) -> dict[str, str]:
    """
    Load key=value pairs from a .secrets file.
    Lines starting with # are comments. Blank lines are ignored.
    Values may be optionally quoted with ' or ".
    Returns {} (not an error) if the file doesn't exist.
    """
    path = Path(path or DEFAULT_SECRETS_FILE)
    if not path.exists():
        logger.info(f"No secrets file at {path} — continuing without secrets.")
        return {}

    secrets: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            secrets[key] = value

    logger.info(f"Loaded {len(secrets)} secret(s) from {path}")
    return secrets


def list_secret_keys(path: str | None = None) -> list[str]:
    """Return only the key names — never the values."""
    return list(load_secrets(path).keys())


def resolve_placeholders(template: str, secrets: dict[str, str]) -> tuple[str, list[str]]:
    """
    Replace {{KEY}} placeholders in a template with values from secrets.

    Returns:
        resolved_text — template with placeholders substituted
        keys_used     — list of secret keys that were resolved

    Unresolved placeholders (key not in secrets) are left as {{KEY}}.
    """
    keys_used: list[str] = []

    def replacer(match: re.Match) -> str:
        key = match.group(1)
        if key in secrets:
            keys_used.append(key)
            return secrets[key]
        return match.group(0)  # leave unresolved placeholders intact

    resolved = re.sub(r"\{\{(\w+)\}\}", replacer, template)
    return resolved, keys_used


def build_secret_patterns(secrets: dict[str, str]) -> dict[str, str]:
    """
    Build regex patterns from secret values for dynamic DLP detection.
    Keys use "secret:<NAME>" format so findings are clearly labelled
    in audit logs and redacted output.
    """
    patterns: dict[str, str] = {}
    for key, value in secrets.items():
        if len(value) >= _MIN_SECRET_LEN:
            patterns[f"secret:{key}"] = re.escape(value)
    return patterns


def redact_with_secrets(text: str, secrets: dict[str, str]) -> tuple[str, list[dict]]:
    """
    Scan and redact text using dynamic patterns built from secret values.
    Used to ensure secrets never appear in text sent to an LLM.

    Returns:
        redacted_text — text with secret values replaced by [REDACTED:SECRET:<KEY>] tokens
        findings      — list of dicts with type, start, end
    """
    findings: list[dict] = []
    patterns = build_secret_patterns(secrets)

    for label, pattern in patterns.items():
        for match in re.finditer(pattern, text, re.IGNORECASE):
            findings.append({
                "type":  label,
                "value": match.group(),
                "start": match.start(),
                "end":   match.end(),
            })

    for finding in sorted(findings, key=lambda x: x["start"], reverse=True):
        replacement = f"[REDACTED:{finding['type'].upper()}]"
        text = text[:finding["start"]] + replacement + text[finding["end"]:]

    return text, findings
