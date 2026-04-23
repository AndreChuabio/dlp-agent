"""
DLP Agent tools — full detection pipeline.
Order: Voicerun → regex → redact → Baseten triage → Claude semantic → OpenAI second opinion → log
"""

import re
import json
import logging
import os
import hmac
import hashlib
import secrets
import requests
from datetime import datetime, timezone

import anthropic
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

LOG_FILE = "dlp_audit_log.jsonl"

# Hard cap on input size. Above this, scan_and_clean raises ValueError.
# Protects against cost/latency blowups and catastrophic-backtracking DoS on
# greedy regex patterns like street_address.
MAX_INPUT_CHARS = int(os.getenv("DLP_MAX_INPUT_CHARS", "16000"))

# Per-process random key used to HMAC the cache index so a memory/swap dump
# never yields a recoverable hash of raw PHI.
_CACHE_HMAC_KEY = secrets.token_bytes(32)

# Timeouts (seconds) for external calls. Prevents a hung provider from stalling
# a worker and causing queue backup.
_BASETEN_TIMEOUT = float(os.getenv("DLP_BASETEN_TIMEOUT", "8"))
_CLAUDE_TIMEOUT = float(os.getenv("DLP_CLAUDE_TIMEOUT", "15"))
_OPENAI_TIMEOUT = float(os.getenv("DLP_OPENAI_TIMEOUT", "20"))

# Opt-in debug flag. When true, callers may retrieve the original text via
# scan_and_clean(..., include_original=True). Off by default to prevent
# accidental raw-PHI exposure in logs, caches, or UIs.
DLP_DEBUG = os.getenv("DLP_DEBUG", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Audit log backend — Postgres when DATABASE_URL is set, JSONL fallback
# ---------------------------------------------------------------------------

_db_conn = None


def _get_db_conn():
    """Lazy singleton Postgres connection. Returns None if DATABASE_URL unset."""
    global _db_conn
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        return None
    if _db_conn is None or _db_conn.closed:
        try:
            import psycopg2
            _db_conn = psycopg2.connect(database_url, sslmode="require")
            _db_conn.autocommit = True
            _ensure_audit_table(_db_conn)
        except Exception as e:
            logging.getLogger(__name__).error(
                "Postgres connection failed (%s), falling back to JSONL.",
                type(e).__name__,
            )
            return None
    return _db_conn


def _ensure_audit_table(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS dlp_audit_log (
                id               SERIAL PRIMARY KEY,
                timestamp        TIMESTAMPTZ NOT NULL,
                user_id          TEXT,
                safe_to_send     BOOLEAN,
                findings_count   INTEGER,
                finding_types    JSONB,
                severity         TEXT,
                regulation       JSONB,
                baseten_escalated BOOLEAN,
                openai_confirmed  JSONB
            )
        """)


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

_anthropic_client = None
_openai_client = None


def _get_anthropic_client():
    global _anthropic_client
    if _anthropic_client is None:
        _anthropic_client = anthropic.Anthropic(
            api_key=os.getenv("ANTHROPIC_API_KEY"),
            timeout=_CLAUDE_TIMEOUT,
        )
    return _anthropic_client


def _get_openai_client():
    global _openai_client
    if _openai_client is None:
        _openai_client = OpenAI(
            api_key=os.getenv("OPENAI_API_KEY"),
            timeout=_OPENAI_TIMEOUT,
        )
    return _openai_client

# --- Patterns ---


PATTERNS = {
    # ── Standard PII ──────────────────────────────────────────────────────────
    "SSN":           r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card":   r"\b(?:\d{4}[- ]){3}\d{4}\b",
    "email":         r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone":         r"\b\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b",
    "api_key":       r"\b(sk-|pk_|AIza)[A-Za-z0-9_\-]{20,}\b",

    # ── HIPAA Safe Harbor — 18 identifiers ────────────────────────────────────
    # 1. Names
    # Case-sensitive (see _CASE_SENSITIVE_PATTERNS) — requires Capitalized words so
    # "I am going to the store" does NOT match, but "I am Alice Johnson" does.
    # Allows optional single-letter middle initial: "David K Kim"
    "patient_name": (
        r"(?:name\s+is|I(?:'m|\s+am)|patient|pt\.?)\s+"
        r"[A-Z][a-z]{1,}(?:\s+[A-Z]\.?)?(?:\s+[A-Z][a-z]{1,})+"
    ),
    # 2. Geographic subdivisions smaller than state
    # Catches "123 Main St", "42 Elm Street", "1600 Pennsylvania Ave"
    "street_address": (
        r"\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*"
        r"\s+(?:St(?:reet)?|Ave(?:nue)?|Blvd|Rd|Road|Dr(?:ive)?|Ln|Lane|Ct|Court|Pl|Place|Way)\b"
    ),
    # 3. Dates (except year) — tied to an individual
    # Catches numeric dates (03/22/1975) AND text dates (March 22nd, 1975)
    "dob": (
        r"\b(?:DOB|Date\s+of\s+Birth|born|birthday|birth\s+date)"
        r"(?:\s+is)?\s*:?\s*"
        r"(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}"
        r"|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?"
        r"|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
        r"\.?\s+\d{1,2}(?:st|nd|rd|th)?[,\s]+\d{4})"
    ),
    # 4/5. Phone & fax numbers (same format)
    # (phone already defined above under Standard PII)
    # 6. Email — see above
    # 7. SSN — see above
    # 8. Medical record numbers
    "medical_record": r"\bMRN[\s:#-]*\d{5,10}\b",
    # 9. Health plan beneficiary / insurance IDs
    "insurance_id":  r"\b(insurance|policy|member)\s*(id|#|number)?[\s:#-]*[A-Z0-9]{6,15}\b",
    # 10. Account numbers — catch generic "account #" references
    "account_number": r"\b(?:account|acct)[\s:#-]*\d{6,20}\b",
    # 11. Certificate/license numbers
    "license_number": r"\b(?:license|cert(?:ificate)?|lic)[\s:#-]*[A-Z0-9]{5,20}\b",
    # 12. Vehicle identifiers (VIN = 17 alphanumeric, license plates vary)
    "vehicle_id": r"\bVIN[\s:#-]*[A-HJ-NPR-Z0-9]{17}\b",
    # 13. Device identifiers (serial numbers, device IDs in session metadata)
    "device_id": r"\b(?:device[\s_-]?id|serial[\s_-]?(?:number|no\.?)|IMEI)[\s:#-]*[A-Z0-9]{8,20}\b",
    # 14. URLs
    "url": r"\bhttps?://[^\s\]>\"')]{4,}\b",
    # 15. IP addresses (common in session logs — exact IP is PHI when tied to a patient)
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    # 16. Biometric identifiers — can't regex audio/images; flagged at semantic layer
    # 17. Full-face photos — same; handled semantically
    # NPI
    "npi_number":    r"\bNPI[\s:#-]*\d{10}\b",
    # ICD-10 code — case-sensitive (see _CASE_SENSITIVE_PATTERNS) to avoid matching
    # arbitrary lowercase tokens like "a12" or "the123".
    "icd_code":      r"\b[A-Z]\d{2}(?:\.\d{1,2})?\b",
    # Medication dosage — require a drug-name token or clinical verb nearby so
    # "5 mg" in a recipe doesn't trip redaction. Matches "50mg sertraline",
    # "sertraline 50 mg", "taking 10 mg", "prescribed 25mg".
    "medication": (
        r"\b\d+\s*mg\s+[A-Za-z]{3,}\b"
        r"|\b[A-Za-z]{3,}\s+\d+\s*mg\b"
        r"|\b(?:take|taking|took|takes|prescrib(?:ed|ing)|dose|dosage|on)\s+\d+\s*mg\b"
    ),
}

# Fail loud at import if patterns collide — silent dict overwrite was the
# source of the duplicate-key bug that dropped earlier pattern definitions.
assert len(PATTERNS) == len({k.lower() for k in PATTERNS}), (
    "Duplicate PATTERNS keys detected"
)

# --- Step 1: Voicerun transcription ---


def transcribe_audio(audio_source) -> str:
    """Transcribe audio input to text via Voicerun. Returns raw transcript."""
    try:
        import voicerun as vr
        transcript = vr.transcribe(audio_source)
        logger.info("Voicerun transcription complete.")
        return transcript
    except Exception as e:
        logger.error("Voicerun transcription failed (%s).", type(e).__name__)
        raise

# --- Step 2: Regex scan ---


# Patterns that need case-sensitive matching to avoid false positives.
# - patient_name: requires capitalized words so "I am going to the store" doesn't match.
# - icd_code: prevents "a12", "the123" etc. from being flagged as ICD-10 codes.
_CASE_SENSITIVE_PATTERNS = {"patient_name", "icd_code"}


def regex_scan(text: str) -> list[dict]:
    """Fast structured PII/PHI detection using regex patterns."""
    findings = []
    for label, pattern in PATTERNS.items():
        flags = 0 if label in _CASE_SENSITIVE_PATTERNS else re.IGNORECASE
        for match in re.finditer(pattern, text, flags):
            findings.append({
                "type": label,
                "value": match.group(),
                "start": match.start(),
                "end": match.end(),
            })
    return findings

# --- Step 3: Baseten triage ---


# Swap BASETEN_MODEL to test different models — uses OpenAI-compatible API
BASETEN_BASE_URL = "https://inference.baseten.co/v1"
BASETEN_MODEL = os.getenv("BASETEN_MODEL", "deepseek-ai/DeepSeek-V3.1")


def baseten_triage(text: str, api_keys: dict = None) -> bool:
    """
    Fast binary triage via Baseten DeepSeek. Returns True if text should be deep-scanned.
    Uses OpenAI-compatible endpoint -- swap BASETEN_MODEL in env to test different models.
    """
    api_keys = api_keys or {}
    api_key = api_keys.get("BASETEN_API_KEY") or os.getenv("BASETEN_API_KEY")
    model = api_keys.get("BASETEN_MODEL") or BASETEN_MODEL

    if not api_key:
        logger.warning("Baseten not configured — defaulting to escalate.")
        return True

    prompt = (
        "Does the following text contain any sensitive, private, or protected health information "
        "such as patient names, diagnoses, medications, medical record numbers, or insurance info? "
        "Reply with only YES or NO.\n\n"
        f"Text: {text}"
    )

    try:
        baseten_client = OpenAI(
            api_key=api_key, base_url=BASETEN_BASE_URL, timeout=_BASETEN_TIMEOUT,
        )
        response = baseten_client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=5,
            temperature=0,
        )
        output = response.choices[0].message.content.strip().upper()
        logger.info(f"Baseten triage result ({model}): {output}")
        return "YES" in output
    except Exception as e:
        # Never log the exception message — provider SDK errors can echo the
        # request body, which would put the scanned text into app logs.
        logger.error("Baseten triage failed (%s) — defaulting to escalate.", type(e).__name__)
        return True

# --- Step 4: Claude semantic scan ---


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


def claude_semantic_scan(text: str, api_keys: dict = None) -> list[dict]:
    """Deep contextual PHI detection via Claude. Catches what regex misses."""
    api_keys = api_keys or {}
    anthropic_key = api_keys.get("ANTHROPIC_API_KEY")
    client = (
        anthropic.Anthropic(api_key=anthropic_key, timeout=_CLAUDE_TIMEOUT)
        if anthropic_key
        else anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"), timeout=_CLAUDE_TIMEOUT)
    )
    try:
        response = client.messages.create(
            # Haiku: 3-5x faster than Opus, same quality for classification
            model="claude-haiku-4-5-20251001",
            max_tokens=512,
            messages=[
                {"role": "user", "content": CLAUDE_SCAN_PROMPT.format(text=text)}],
        )
        raw = response.content[0].text.strip()
        # Strip markdown code fences if Claude wraps the response
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-z]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)
        raw = raw.strip()
        if not raw:
            return []
        result = json.loads(raw)
        return result.get("findings", [])
    except Exception as e:
        logger.error("Claude semantic scan failed (%s).", type(e).__name__)
        return []

# --- Step 5: OpenAI second opinion (high severity only) ---


OPENAI_VALIDATION_PROMPT = """A medical AI safety system flagged PHI of the following categories at HIGH severity.
Validate whether these category/severity assignments are plausible given the stated reason.
Do NOT request or infer the underlying text -- it has been withheld for HIPAA reasons.

Flagged findings: {findings}

Reply with ONLY valid JSON: {{"confirmed": true|false, "notes": "brief explanation"}}"""


# Fields sent to the OpenAI validator. The `excerpt` field (containing the raw
# PHI Claude identified) is intentionally excluded -- sending it would bypass
# the "redacted-only egress" promise.
_OPENAI_VALIDATION_FIELDS = ("type", "reason", "severity", "regulation")


def openai_second_opinion(findings: list[dict], api_keys: dict = None) -> dict:
    """Cross-validate high-severity Claude findings via OpenAI.

    Receives finding metadata only -- never the `excerpt` field, which
    may contain the raw PHI that Claude extracted.
    """
    api_keys = api_keys or {}
    openai_key = api_keys.get("OPENAI_API_KEY")
    client = (
        OpenAI(api_key=openai_key, timeout=_OPENAI_TIMEOUT)
        if openai_key
        else OpenAI(api_key=os.getenv("OPENAI_API_KEY"), timeout=_OPENAI_TIMEOUT)
    )

    sanitized = [
        {k: f.get(k) for k in _OPENAI_VALIDATION_FIELDS if k in f}
        for f in findings
    ]

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{
                "role": "user",
                "content": OPENAI_VALIDATION_PROMPT.format(
                    findings=json.dumps(sanitized),
                )
            }],
            max_tokens=256,
        )
        raw = response.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-z]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)
        raw = raw.strip()
        return json.loads(raw)
    except Exception as e:
        logger.error("OpenAI second opinion failed (%s).", type(e).__name__)
        return {"confirmed": True, "notes": "validation unavailable — defaulting to confirmed"}

# --- Step 6: Redactor ---


def redact_text(text: str, regex_findings: list[dict]) -> str:
    """Replace regex-matched findings in-place with [REDACTED:TYPE] tokens."""
    for finding in sorted(regex_findings, key=lambda x: x["start"], reverse=True):
        replacement = f"[REDACTED:{finding['type'].upper()}]"
        text = text[:finding["start"]] + replacement + text[finding["end"]:]
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

# --- Step 7: Audit logger ---


def log_scan(user_id: str, result: dict) -> None:
    """Append scan result to HIPAA audit log.

    Writes to Postgres when DATABASE_URL is set, falls back to JSONL otherwise.
    """
    high_severity = any(f.get("severity") ==
                        "high" for f in result["semantic_findings"])
    entry = {
        "timestamp":          datetime.now(timezone.utc).isoformat(),
        "user_id":            user_id,
        "safe_to_send":       result["safe_to_send"],
        "findings_count":     len(result["regex_findings"]) + len(result["semantic_findings"]),
        "finding_types":      [f["type"] for f in result["regex_findings"]] +
                              [f["type"] for f in result["semantic_findings"]],
        "severity":           "high" if high_severity else "medium" if result["semantic_findings"] else "low",
        "regulation":         list({f.get("regulation", "general") for f in result["semantic_findings"]}),
        "baseten_escalated":  result.get("baseten_escalated", False),
        "openai_confirmed":   result.get("openai_confirmed"),
    }

    conn = _get_db_conn()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO dlp_audit_log
                       (timestamp, user_id, safe_to_send, findings_count,
                        finding_types, severity, regulation, baseten_escalated, openai_confirmed)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        entry["timestamp"], entry["user_id"], entry["safe_to_send"],
                        entry["findings_count"], json.dumps(
                            entry["finding_types"]),
                        entry["severity"], json.dumps(entry["regulation"]),
                        entry["baseten_escalated"], json.dumps(
                            entry["openai_confirmed"]),
                    ),
                )
            logger.info(
                f"Audit log → Postgres for user {user_id} — severity: {entry['severity']}")
            return
        except Exception as e:
            logger.error(
                "Postgres audit log failed (%s), falling back to JSONL.",
                type(e).__name__,
            )

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    logger.info(
        f"Audit log → JSONL for user {user_id} — severity: {entry['severity']}")

# --- You.com insurance coverage search ---


def search_insurance_coverage(insurance_id: str, reason: str = "") -> dict:
    """
    Search for insurance coverage info via You.com.
    Only receives insurance_id — never patient name or diagnosis.
    DLP enforces this upstream before this function is called.
    """
    api_key = os.getenv("YOUCOM_API_KEY")
    if not api_key:
        logger.warning("You.com API key not configured.")
        return {"error": "Search unavailable", "results": []}

    query = f"insurance coverage {insurance_id}"
    if reason:
        query += f" {reason} coverage benefits"

    try:
        resp = requests.get(
            "https://api.ydc-index.io/search",
            params={"query": query, "num_web_results": 3},
            headers={"X-API-Key": api_key},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        hits = data.get("hits", [])
        results = [{"title": h.get("title", ""), "snippet": h.get(
            "description", "")} for h in hits[:3]]
        logger.info(
            f"You.com search returned {len(results)} results for insurance_id: {insurance_id[:4]}****")
        return {"results": results, "query": query}
    except Exception as e:
        logger.error("You.com search failed (%s).", type(e).__name__)
        return {"error": "search_unavailable", "results": []}


# --- Patient info extractor ---

EXTRACTION_SYSTEM = """You are a JSON-only extraction function. You MUST respond with exactly one JSON object and nothing else: no conversation, no explanation, no role-play, no invented dialogue, no markdown code fences.

Extract ONLY information the patient has EXPLICITLY stated in their own words. If a field has not been explicitly stated by the patient, it MUST be null. Never infer, guess, paraphrase, or fabricate any value.

Required output format (no extra keys, no extra text):
{"patient_name": "<name or null>", "insurance_id": "<id or null>", "reason": "<primary concern in patient's own words or null>", "dob": "<YYYY-MM-DD or null>", "phone": "<phone or null>"}

CRITICAL RULES:
- If the patient has only greeted, asked a question, or said anything that does not contain a name, patient_name MUST be null. Do NOT continue the conversation. Do NOT invent a name.
- If a field appears only as a [REDACTED:...] token in the transcript, that field MUST be null. Redaction tokens are not values.
- Use the most recent value if the patient corrected themselves.
- For "reason", capture the patient's health concern in their own words; if no concern is stated, null.
- Output the JSON object only. No preamble, no follow-up turns."""


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
        r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
        raw_text,
    )
    if phone_match:
        result["phone"] = phone_match.group()

    return result


def extract_patient_info(messages: list[dict], raw_text: str = "") -> dict:
    """Extract structured patient fields from conversation history.

    Claude receives only the redacted transcript (no raw PHI).
    DOB and phone are extracted locally via regex from raw_text
    since those fields are redacted before the transcript is built.
    """
    local_fields = _extract_structured_fields_locally(
        raw_text) if raw_text else {}

    transcript = "\n".join(
        f"{'Patient' if m['role'] == 'user' else 'Agent'}: {m['content']}"
        for m in messages[-8:]
        if isinstance(m.get("content"), str)
    )
    if not transcript.strip():
        return local_fields or {}

    try:
        response = _get_anthropic_client().messages.create(
            model="claude-opus-4-6",
            max_tokens=200,
            system=EXTRACTION_SYSTEM,
            messages=[
                {"role": "user", "content": f"Transcript:\n{transcript}"}],
        )
        raw = response.content[0].text.strip()
        # Strip markdown code fences if Claude wraps the JSON.
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-z]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)
        llm_fields = json.loads(raw.strip())
        if not isinstance(llm_fields, dict):
            llm_fields = {}
    except Exception as e:
        logger.error("Patient info extraction failed (%s).", type(e).__name__)
        llm_fields = {}

    # Anti-fabrication validation: any name or free-text value the LLM
    # returned must actually appear in the patient's own messages. Without
    # this guard, sparse transcripts cause Claude to invent names that get
    # stored in session state and surfaced back as if they were real.
    patient_text = " ".join(
        m["content"] for m in messages
        if m.get("role") == "user" and isinstance(m.get("content"), str)
    ).lower()
    validated_llm = {}
    for k, v in llm_fields.items():
        if v is None or v == "null":
            validated_llm[k] = None
            continue
        v_str = str(v)
        if "[REDACTED" in v_str.upper():
            validated_llm[k] = None
            continue
        # Names and free-text fields must appear (case-insensitive) in the
        # patient's own messages. Structured fields (dob, phone) are extracted
        # locally from raw_text; insurance_id is captured upstream from regex
        # findings; both are trusted without substring validation.
        if k in ("patient_name", "reason"):
            if v_str.lower() not in patient_text:
                validated_llm[k] = None
                continue
        validated_llm[k] = v

    merged = {**validated_llm, **{k: v for k, v in local_fields.items() if v}}
    return merged


# --- Patient database ---

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "voicerun", "data")
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

    Concurrent save_patient calls used to race on read-modify-write and
    silently clobber each other. flock serialises writers, and writing to a
    temp file + os.replace makes the swap atomic so a crash mid-write cannot
    truncate the live file.
    """
    import fcntl
    lock_path = PATIENTS_FILE + ".lock"
    tmp_path = PATIENTS_FILE + ".tmp"
    try:
        # Acquire an exclusive lock on a sidecar lock file. The lock is held
        # for the write + rename, not for arbitrary caller work.
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
    """Look up a patient by name (exact or partial first/last name match)."""
    if not name or not name.strip():
        return None
    patients = _load_patients()
    name_clean = name.lower().strip()
    # Exact match first
    for p in patients:
        if p.get("name", "").lower().strip() == name_clean:
            return p
    # Partial match: at least 2 shared words, or single-word query matches a name token
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
            logger.info(f"Updated patient record: {name}")
            return _save_patients(patients)
    patient["id"] = f"pt_{len(patients) + 1:03d}"
    patients.append(patient)
    logger.info(f"Saved new patient record: {name}")
    return _save_patients(patients)


# --- Specialist triage ---

TRIAGE_PROMPT = """You are a medical triage assistant helping a primary care receptionist route patients.
Based on the patient's concern, pick the BEST matching specialist from the list below.

Patient's concern: {reason}

Available specialists:
{specialists_list}

Return ONLY valid JSON (no markdown, no code fences):
{{"specialist_id": "...", "specialist_name": "...", "specialty": "...", "availability": "...", "reason": "one sentence explaining why this specialist is the right fit"}}

Default to the General Practitioner (dr_008) if the concern is unclear, general, or doesn't fit another category."""


def triage_specialist(reason: str, api_keys: dict = None) -> dict | None:
    """Use Claude to semantically match a patient's concern to the best specialist."""
    api_keys = api_keys or {}
    doctors = _load_doctors()
    if not doctors:
        logger.error("No doctors loaded -- cannot triage.")
        return None

    specialists_list = "\n".join(
        f"- {d['id']}: {d['name']} ({d['specialty']}, available {d['availability']}) "
        f"-- treats: {', '.join(d['conditions'][:6])}"
        for d in doctors
    )

    anthropic_key = api_keys.get("ANTHROPIC_API_KEY")
    client = (
        anthropic.Anthropic(api_key=anthropic_key, timeout=_CLAUDE_TIMEOUT)
        if anthropic_key
        else _get_anthropic_client()
    )
    try:
        response = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=200,
            messages=[{"role": "user", "content": TRIAGE_PROMPT.format(
                reason=reason,
                specialists_list=specialists_list,
            )}],
        )
        raw = response.content[0].text.strip()
        # Strip accidental markdown fences
        if raw.startswith("```"):
            raw = raw.split("```")[1].lstrip("json").strip()
        result = json.loads(raw)
        logger.info(
            f"Triage result: {result.get('specialist_name')} ({result.get('specialty')})")
        return result
    except Exception as e:
        logger.error("Triage specialist failed (%s).", type(e).__name__)
        return None


# --- Full pipeline ---

# In-memory cache of redacted results. Never stores raw text.
# Keys are HMAC(text, per-process key) so a memory dump cannot be reverse-mapped
# back to the input text with a precomputed dictionary.
_scan_cache: dict[str, dict] = {}
_CACHE_MAX = 128

# Set DLP_ENABLE_VALIDATION=true to turn on the OpenAI second-opinion step.
# Off by default — it adds 1-2s latency and is redundant for most voice/realtime paths.
_ENABLE_VALIDATION = os.getenv(
    "DLP_ENABLE_VALIDATION", "false").lower() == "true"


def _cache_key(text: str) -> str:
    return hmac.new(_CACHE_HMAC_KEY, text.encode("utf-8"), hashlib.sha256).hexdigest()


def scan_and_clean(
    text: str,
    user_id: str = "anonymous",
    api_keys: dict = None,
    include_original: bool = False,
) -> dict:
    """Full DLP pipeline. Input: raw text. Output: redacted text + findings.

    The returned dict never contains the raw input unless `include_original=True`
    is passed explicitly AND the DLP_DEBUG env flag is set. Callers that need
    the original text should keep their own reference to what they passed in.

    Order of operations:
      1. regex scan on raw text (local, no API calls)
      2. redact structured PII/PHI in-place
      3. Baseten triage on the redacted text (cost-gate for OpenAI only)
      4. Claude semantic scan on the redacted text (always runs)
      5. Apply semantic redaction
      6. Optional OpenAI second opinion on high-severity findings (metadata only)

    Raises:
      ValueError: if text exceeds MAX_INPUT_CHARS.
    """
    if text is None:
        raise ValueError("text is required")
    if len(text) > MAX_INPUT_CHARS:
        raise ValueError(
            f"Input exceeds DLP_MAX_INPUT_CHARS ({MAX_INPUT_CHARS}); reject upstream."
        )

    api_keys = api_keys or {}
    cache_key = _cache_key(text)
    if cache_key in _scan_cache:
        cached = _scan_cache[cache_key]
        log_scan(user_id, cached)  # still audit-log every access
        return cached

    # Step 1: regex scan on raw text (local, no API calls)
    regex_hits = regex_scan(text)

    # Step 2: redact structured PII/PHI BEFORE any external API call
    redacted = redact_text(text, regex_hits)

    # Step 3: Baseten triage runs on redacted text. Result is advisory ONLY --
    # a single cheap-model miss must not skip the semantic scan, or one false
    # negative defeats the whole detector. Baseten's vote now gates only the
    # (more expensive) OpenAI second-opinion step.
    escalate = baseten_triage(redacted, api_keys=api_keys)

    # Step 4: Claude semantic scan always runs on the redacted text.
    semantic_hits = claude_semantic_scan(redacted, api_keys=api_keys)

    # Step 5: Apply semantic redaction on top of regex-redacted text.
    clean = redact_semantic_findings(redacted, semantic_hits)
    safe = len(regex_hits) == 0 and len(semantic_hits) == 0

    # Step 6: Optional OpenAI validation -- gated by both Baseten-escalated AND
    # the explicit DLP_ENABLE_VALIDATION flag.
    openai_result = None
    if _ENABLE_VALIDATION and escalate:
        high_severity = [f for f in semantic_hits if f.get("severity") == "high"]
        if high_severity:
            openai_result = openai_second_opinion(high_severity, api_keys=api_keys)

    result = {
        "clean":              clean,
        "regex_findings":     regex_hits,
        "semantic_findings":  semantic_hits,
        "safe_to_send":       safe,
        "baseten_escalated":  escalate,
        "openai_confirmed":   openai_result,
    }

    # Evict oldest entry if cache is full.
    if len(_scan_cache) >= _CACHE_MAX:
        _scan_cache.pop(next(iter(_scan_cache)))
    _scan_cache[cache_key] = result

    log_scan(user_id, result)

    # `original` is a debug-only field. Both the env flag and the caller kwarg
    # must be set -- prevents an accidental True in one place from leaking PHI.
    if include_original and DLP_DEBUG:
        return {**result, "original": text}
    return result
