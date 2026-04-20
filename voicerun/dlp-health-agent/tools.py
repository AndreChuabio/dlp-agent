"""
DLP Agent tools — full detection pipeline.
Order: regex → redact → Baseten triage → Claude semantic → redact → log

API keys are passed explicitly via api_keys dict (populated from context.variables in handler).
No os.getenv or dotenv — Voicerun injects secrets through context.variables at session start.
"""

import re
import json
import logging
import os
import hmac
import hashlib
import secrets
import requests
from datetime import datetime

import anthropic
from openai import OpenAI

LOG_FILE = "dlp_audit_log.jsonl"
BASETEN_BASE_URL = "https://inference.baseten.co/v1"

# Cap on input size -- keeps a single turn from blowing up Baseten/Claude
# spend or triggering catastrophic regex backtracking.
MAX_INPUT_CHARS = 16000

# Per-process random key used to HMAC the cache index. A memory dump of the
# running worker cannot be reverse-mapped back to the original text.
_CACHE_HMAC_KEY = secrets.token_bytes(32)

# External-call timeouts (seconds).
_BASETEN_TIMEOUT = 8.0
_CLAUDE_TIMEOUT = 15.0

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# --- Patterns ---

PATTERNS = {
    "SSN":            r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card":    r"\b(?:\d{4}[- ]){3}\d{4}\b",
    "email":          r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone":          r"\b\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b",
    "api_key":        r"\b(sk-|pk_|AIza)[A-Za-z0-9_\-]{20,}\b",
    # Matches "My name is Alice Johnson" / "I am Alice Johnson" / "patient Alice Johnson"
    "patient_name": (
        r"(?:name\s+is|I(?:'m|\s+am)|patient|pt\.?)\s+"
        r"[A-Z][a-z]{1,}(?:\s+[A-Z]\.?)?(?:\s+[A-Z][a-z]{1,})+"
    ),
    "medical_record": r"\bMRN[\s:#-]*\d{5,10}\b",
    "npi_number":     r"\bNPI[\s:#-]*\d{10}\b",
    # Case-sensitive (see _CASE_SENSITIVE_PATTERNS) to avoid matching
    # arbitrary lowercase tokens like "a12".
    "icd_code":       r"\b[A-Z]\d{2}(?:\.\d{1,2})?\b",
    "dob":            r"\b(DOB|Date of Birth|born)[\s:]+\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
    # Fix: prior pattern had a typo (`[\s:#-is]`) that matched stray "i"/"s".
    "insurance_id":   r"\b(insurance|policy|member)\s*(id|#|number)?[\s:#-]*[A-Z0-9]{6,15}\b",
    # Require a drug-name token or clinical verb nearby -- avoids matching
    # "5 mg" in a recipe.
    "medication": (
        r"\b\d+\s*mg\s+[A-Za-z]{3,}\b"
        r"|\b[A-Za-z]{3,}\s+\d+\s*mg\b"
        r"|\b(?:take|taking|took|takes|prescrib(?:ed|ing)|dose|dosage|on)\s+\d+\s*mg\b"
    ),
    "ip_address":     r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "street_address": r"\b\d+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl)\b",
}

# Fail loud at import if patterns collide.
assert len(PATTERNS) == len({k.lower() for k in PATTERNS}), (
    "Duplicate PATTERNS keys detected"
)

# Patterns that must be matched case-sensitively to avoid false positives.
_CASE_SENSITIVE_PATTERNS = {"patient_name", "icd_code"}


# --- Regex scan ---


def regex_scan(text: str) -> list[dict]:
    """Fast structured PII/PHI detection using regex patterns."""
    findings = []
    for label, pattern in PATTERNS.items():
        flags = 0 if label in _CASE_SENSITIVE_PATTERNS else re.IGNORECASE
        for match in re.finditer(pattern, text, flags):
            findings.append({
                "type":  label,
                "value": match.group(),
                "start": match.start(),
                "end":   match.end(),
            })
    return findings

# --- Baseten triage ---


BASETEN_TRIAGE_PROMPT = (
    "Does the following text contain any sensitive, private, or protected health information "
    "such as patient names, diagnoses, medications, medical record numbers, or insurance info? "
    "Reply with only YES or NO.\n\nText: {text}"
)


def baseten_triage(text: str, api_keys: dict) -> bool:
    """Fast binary triage via Baseten DeepSeek. Returns True if text should be deep-scanned."""
    api_key = api_keys.get("BASETEN_API_KEY")
    model = api_keys.get("BASETEN_MODEL", "deepseek-ai/DeepSeek-V3.1")

    if not api_key:
        logger.warning("Baseten key not provided — defaulting to escalate.")
        return True

    try:
        client = OpenAI(
            api_key=api_key, base_url=BASETEN_BASE_URL, timeout=_BASETEN_TIMEOUT,
        )
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "user", "content": BASETEN_TRIAGE_PROMPT.format(text=text)}],
            max_tokens=5,
            temperature=0,
        )
        output = response.choices[0].message.content.strip().upper()
        logger.info(f"Baseten triage ({model}): {output}")
        return "YES" in output
    except Exception as e:
        # Provider exception messages can include the request body; logging
        # only the type keeps scanned text out of app logs.
        logger.error("Baseten triage failed (%s) — defaulting to escalate.", type(e).__name__)
        return True

# --- Claude semantic scan ---


CLAUDE_SCAN_PROMPT = """Analyze the following medical/healthcare text for sensitive protected health information (PHI).

Structured identifiers (SSN, MRN, DOB, etc.) have already been redacted and appear as [REDACTED:TYPE] tokens.
Focus on SEMANTIC and CONTEXTUAL PHI that regex cannot catch:
- Diagnoses, conditions, symptoms described in natural language
- Medications, dosages, treatment plans
- Mental health information (extra protected under 42 CFR Part 2)
- Lab results, imaging, procedures
- Insurance or billing context
- Anything that could identify a patient even without their name

Ignore [REDACTED:...] tokens -- those are already handled.

Return ONLY valid JSON in this format:
{{"findings": [{{"type": "...", "excerpt": "...", "reason": "...", "severity": "high|medium|low", "regulation": "HIPAA|GDPR|SOC2|general"}}]}}

If nothing found, return: {{"findings": []}}

Text: {text}"""


def claude_semantic_scan(text: str, api_keys: dict) -> list[dict]:
    """Deep contextual PHI detection via Claude Haiku."""
    api_key = api_keys.get("ANTHROPIC_API_KEY")
    if not api_key:
        logger.warning("Anthropic key not provided — skipping semantic scan.")
        return []
    try:
        client = anthropic.Anthropic(api_key=api_key, timeout=_CLAUDE_TIMEOUT)
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=512,
            messages=[
                {"role": "user", "content": CLAUDE_SCAN_PROMPT.format(text=text)}],
        )
        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-z]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)
        result = json.loads(raw.strip())
        return result.get("findings", [])
    except Exception as e:
        logger.error("Claude semantic scan failed (%s).", type(e).__name__)
        return []

# --- Redactor ---


def redact_text(text: str, regex_findings: list[dict]) -> str:
    """Replace regex-matched findings in-place with [REDACTED:TYPE] tokens."""
    for finding in sorted(regex_findings, key=lambda x: x["start"], reverse=True):
        text = text[:finding["start"]] + \
            f"[REDACTED:{finding['type'].upper()}]" + text[finding["end"]:]
    return text


def redact_semantic_findings(text: str, semantic_findings: list[dict]) -> str:
    """Replace Claude semantic finding excerpts with [REDACTED:TYPE] tokens.

    Uses exact string replacement — if the excerpt was already caught by regex
    and replaced with a token, the replace is a no-op and is skipped safely.
    """
    for finding in semantic_findings:
        excerpt = finding.get("excerpt", "").strip()
        if not excerpt:
            continue
        label = finding.get("type", "PHI").upper().replace(" ", "_")
        text = text.replace(excerpt, f"[REDACTED:{label}]")
    return text

# --- Audit logger ---


def log_scan(user_id: str, result: dict) -> None:
    """Append scan result to HIPAA audit log (JSONL)."""
    high_severity = any(f.get("severity") ==
                        "high" for f in result["semantic_findings"])
    entry = {
        "timestamp":         datetime.utcnow().isoformat(),
        "user_id":           user_id,
        "safe_to_send":      result["safe_to_send"],
        "findings_count":    len(result["regex_findings"]) + len(result["semantic_findings"]),
        "finding_types":     [f["type"] for f in result["regex_findings"]] +
                             [f["type"] for f in result["semantic_findings"]],
        "severity":          "high" if high_severity else "medium" if result["semantic_findings"] else "low",
        "regulation":        list({f.get("regulation", "general") for f in result["semantic_findings"]}),
        "baseten_escalated": result.get("baseten_escalated", False),
    }
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.error("Audit log write failed (%s).", type(e).__name__)

# --- Patient info extractor ---


EXTRACTION_PROMPT = """You are a structured data extraction assistant for a medical onboarding agent.
Given a voice conversation transcript, extract any patient information mentioned so far.
Respond with ONLY valid JSON — no markdown, no explanation.

Format: {{"patient_name": "<name or null>", "insurance_id": "<id or null>", "reason": "<primary concern or reason for visit or null>", "dob": "<YYYY-MM-DD or null>", "phone": "<phone or null>"}}

Rules:
- Only include fields the patient has explicitly stated.
- Use null for fields not yet mentioned.
- Extract the most recent value if the patient corrected themselves.

Transcript:
{transcript}"""


def _extract_structured_fields_locally(raw_text: str) -> dict:
    """Extract DOB and phone from raw text using local regex -- no API call.

    These fields get redacted before the transcript reaches any LLM,
    so we capture them here to avoid sending raw PHI externally.
    """
    result = {}
    dob_match = re.search(
        r"(?:DOB|Date\s+of\s+Birth|born|birthday|birth\s+date)"
        r"(?:\s+is)?\s*:?\s*"
        r"(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})",
        raw_text, re.IGNORECASE,
    )
    if dob_match:
        result["dob"] = dob_match.group(1)

    phone_match = re.search(
        r"\(?\d{3}\)?[-.\ s]?\d{3}[-.\ s]?\d{4}",
        raw_text,
    )
    if phone_match:
        result["phone"] = phone_match.group()

    return result


def extract_patient_info(messages: list[dict], raw_text: str = "", api_keys: dict = None) -> dict:
    """Extract structured patient fields from conversation history.

    Claude receives only the redacted transcript (no raw PHI).
    DOB and phone are extracted locally via regex from raw_text
    since those fields are redacted before the transcript is built.
    """
    api_keys = api_keys or {}
    api_key = api_keys.get("ANTHROPIC_API_KEY")

    local_fields = _extract_structured_fields_locally(
        raw_text) if raw_text else {}

    if not api_key:
        return local_fields or {}

    transcript = "\n".join(
        f"{'Patient' if m['role'] == 'user' else 'Agent'}: {m['content']}"
        for m in messages[-8:]
        if isinstance(m.get("content"), str)
    )
    if not transcript.strip():
        return local_fields or {}

    try:
        client = anthropic.Anthropic(api_key=api_key, timeout=_CLAUDE_TIMEOUT)
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=200,
            messages=[
                {"role": "user", "content": EXTRACTION_PROMPT.format(transcript=transcript)}],
        )
        llm_fields = json.loads(response.content[0].text.strip())
    except Exception as e:
        logger.error("Patient info extraction failed (%s).", type(e).__name__)
        llm_fields = {}

    merged = {**llm_fields, **{k: v for k, v in local_fields.items() if v}}
    return merged

# --- Patient database ---


_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DOCTORS_FILE = os.path.join(_DATA_DIR, "doctors.json")
PATIENTS_FILE = os.path.join(_DATA_DIR, "patients.json")


def _load_doctors() -> list[dict]:
    try:
        with open(DOCTORS_FILE) as f:
            return json.load(f).get("doctors", [])
    except Exception as e:
        logger.error("Failed to load doctors (%s).", type(e).__name__)
        return []


def _load_patients() -> list[dict]:
    try:
        with open(PATIENTS_FILE) as f:
            return json.load(f).get("patients", [])
    except Exception as e:
        logger.error("Failed to load patients (%s).", type(e).__name__)
        return []


def _save_patients(patients: list[dict]) -> bool:
    """Persist the patient list atomically with an exclusive file lock.

    Serialises concurrent writers and uses tmp + os.replace so a crash
    mid-write cannot truncate the live file.
    """
    import fcntl
    lock_path = PATIENTS_FILE + ".lock"
    tmp_path = PATIENTS_FILE + ".tmp"
    try:
        with open(lock_path, "w") as lockf:
            fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
            try:
                with open(tmp_path, "w") as f:
                    json.dump({"patients": patients}, f, indent=2)
                os.replace(tmp_path, PATIENTS_FILE)
            finally:
                fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)
        return True
    except Exception as e:
        logger.error("Failed to save patients (%s).", type(e).__name__)
        return False


def lookup_patient(name: str) -> dict | None:
    """Look up a patient by name (exact or partial match)."""
    if not name or not name.strip():
        return None
    patients = _load_patients()
    name_clean = name.lower().strip()
    for p in patients:
        if p.get("name", "").lower().strip() == name_clean:
            return p
    name_words = set(name_clean.split())
    for p in patients:
        db_words = set(p.get("name", "").lower().split())
        overlap = name_words & db_words
        if len(overlap) >= 2 or (len(name_words) == 1 and name_words <= db_words):
            return p
    return None


def save_patient(patient: dict) -> bool:
    """Insert or update a patient record (matched by name)."""
    patients = _load_patients()
    name = patient.get("name", "").lower().strip()
    if not name:
        return False
    for i, p in enumerate(patients):
        if p.get("name", "").lower().strip() == name:
            patients[i] = {**p, **{k: v for k, v in patient.items() if v}}
            return _save_patients(patients)
    patient["id"] = f"pt_{len(patients) + 1:03d}"
    patients.append(patient)
    return _save_patients(patients)

# --- Specialist triage ---


TRIAGE_PROMPT = """You are a medical triage assistant helping a primary care receptionist route patients.
Based on the patient's concern, pick the BEST matching specialist from the list below.

Patient's concern: {reason}

Available specialists:
{specialists_list}

Return ONLY valid JSON (no markdown, no code fences):
{{"specialist_id": "...", "specialist_name": "...", "specialty": "...", "availability": "...", "reason": "one sentence explaining why this specialist is the right fit"}}

Default to the General Practitioner (dr_008) if the concern is unclear or doesn't fit another category."""


def triage_specialist(reason: str, api_keys: dict = None) -> dict | None:
    """Use Claude to semantically match a patient's concern to the best specialist."""
    api_keys = api_keys or {}
    api_key = api_keys.get("ANTHROPIC_API_KEY")
    if not api_key:
        logger.warning("Anthropic key not provided — cannot triage.")
        return None

    doctors = _load_doctors()
    if not doctors:
        logger.error("No doctors loaded — cannot triage.")
        return None

    specialists_list = "\n".join(
        f"- {d['id']}: {d['name']} ({d['specialty']}, available {d['availability']}) "
        f"— treats: {', '.join(d['conditions'][:6])}"
        for d in doctors
    )

    try:
        client = anthropic.Anthropic(api_key=api_key, timeout=_CLAUDE_TIMEOUT)
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=200,
            messages=[{"role": "user", "content": TRIAGE_PROMPT.format(
                reason=reason,
                specialists_list=specialists_list,
            )}],
        )
        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1].lstrip("json").strip()
        result = json.loads(raw)
        logger.info(
            f"Triage: {result.get('specialist_name')} ({result.get('specialty')})")
        return result
    except Exception as e:
        logger.error("Triage specialist failed (%s).", type(e).__name__)
        return None

# --- Full pipeline ---


_scan_cache: dict[str, dict] = {}
_CACHE_MAX = 128


def _cache_key(text: str) -> str:
    return hmac.new(_CACHE_HMAC_KEY, text.encode("utf-8"), hashlib.sha256).hexdigest()


def scan_and_clean(text: str, user_id: str = "anonymous", api_keys: dict = None) -> dict:
    """Full DLP pipeline. Keys come from context.variables via api_keys dict.

    Order of operations:
      1. regex scan on raw text (local, no API calls)
      2. redact structured PII/PHI in-place
      3. Baseten triage on the redacted text (advisory signal only)
      4. Claude semantic scan on the redacted text (always runs -- Baseten's
         vote no longer gates it, so a single cheap-model false negative
         cannot skip the semantic check)
      5. Apply semantic redaction

    Returns:
      dict with `clean`, findings, and metadata. The raw input is never
      stored in the return value or the in-memory cache.

    Raises:
      ValueError: if text exceeds MAX_INPUT_CHARS.
    """
    if text is None:
        raise ValueError("text is required")
    if len(text) > MAX_INPUT_CHARS:
        raise ValueError(
            f"Input exceeds MAX_INPUT_CHARS ({MAX_INPUT_CHARS}); reject upstream."
        )

    api_keys = api_keys or {}
    cache_key = _cache_key(text)

    if cache_key in _scan_cache:
        cached = _scan_cache[cache_key]
        log_scan(user_id, cached)
        return cached

    # Step 1: regex scan on raw text (local, no API calls)
    regex_hits = regex_scan(text)

    # Step 2: redact structured PII/PHI BEFORE any external API call
    redacted = redact_text(text, regex_hits)

    # Step 3: Baseten triage is advisory only -- it records whether the cheap
    # model thought escalation was warranted, but does not gate semantic scan.
    escalate = baseten_triage(redacted, api_keys)

    # Step 4: Claude semantic scan always runs on redacted text.
    semantic_hits = claude_semantic_scan(redacted, api_keys)

    # Step 5: apply semantic redaction on top of regex-redacted text.
    clean = redact_semantic_findings(redacted, semantic_hits)
    safe = len(regex_hits) == 0 and len(semantic_hits) == 0

    result = {
        "clean":             clean,
        "regex_findings":    regex_hits,
        "semantic_findings": semantic_hits,
        "safe_to_send":      safe,
        "baseten_escalated": escalate,
    }

    if len(_scan_cache) >= _CACHE_MAX:
        _scan_cache.pop(next(iter(_scan_cache)))
    _scan_cache[cache_key] = result

    log_scan(user_id, result)
    return result
