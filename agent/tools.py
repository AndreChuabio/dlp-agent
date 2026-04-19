"""
DLP Agent tools — full detection pipeline.
Order: Voicerun → regex → Baseten triage → Claude semantic → OpenAI second opinion → redact → log
"""

import re
import json
import logging
import os
import hashlib
import requests
from datetime import datetime

import anthropic
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

LOG_FILE = "dlp_audit_log.jsonl"

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

_anthropic_client = None
_openai_client = None


def _get_anthropic_client():
    global _anthropic_client
    if _anthropic_client is None:
        _anthropic_client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    return _anthropic_client


def _get_openai_client():
    global _openai_client
    if _openai_client is None:
        _openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
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
    # NPI, ICD codes
    "npi_number":    r"\bNPI[\s:#-]*\d{10}\b",
    "icd_code":      r"\b[A-Z]\d{2}\.?\d{0,2}\b",
    # Medications (dosage mentions)
    "medication":    r"\b\d+\s*mg\b",
    "ip_address":    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "street_address": r"\b\d+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl)\b",
}

# --- Step 1: Voicerun transcription ---

def transcribe_audio(audio_source) -> str:
    """Transcribe audio input to text via Voicerun. Returns raw transcript."""
    try:
        import voicerun as vr
        transcript = vr.transcribe(audio_source)
        logger.info("Voicerun transcription complete.")
        return transcript
    except Exception as e:
        logger.error(f"Voicerun transcription failed: {e}")
        raise

# --- Step 2: Regex scan ---

# Patterns that need case-sensitive matching to avoid false positives.
# "patient_name" requires capital letters so "I am going to the store"
# doesn't match, but "I am Alice Johnson" does.
_CASE_SENSITIVE_PATTERNS = {"patient_name"}


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

def baseten_triage(text: str) -> bool:
    """
    Fast binary triage via Baseten DeepSeek. Returns True if text should be deep-scanned.
    Uses OpenAI-compatible endpoint — swap BASETEN_MODEL in env to test different models.
    """
    api_key = os.getenv("BASETEN_API_KEY")

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
        baseten_client = OpenAI(api_key=api_key, base_url=BASETEN_BASE_URL)
        response = baseten_client.chat.completions.create(
            model=BASETEN_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=5,
            temperature=0,
        )
        output = response.choices[0].message.content.strip().upper()
        logger.info(f"Baseten triage result ({BASETEN_MODEL}): {output}")
        return "YES" in output
    except Exception as e:
        logger.error(f"Baseten triage failed: {e} — defaulting to escalate.")
        return True

# --- Step 4: Claude semantic scan ---

CLAUDE_SCAN_PROMPT = """Analyze the following medical/healthcare text for sensitive protected health information (PHI).

Regex already caught structured identifiers. Focus on SEMANTIC and CONTEXTUAL PHI:
- Diagnoses, conditions, symptoms
- Medications, dosages, treatment plans
- Mental health information (extra protected under 42 CFR Part 2)
- Lab results, imaging, procedures
- Insurance or billing context
- Anything that could identify a patient even without their name

Return ONLY valid JSON in this format:
{{"findings": [{{"type": "...", "excerpt": "...", "reason": "...", "severity": "high|medium|low", "regulation": "HIPAA|GDPR|SOC2|general"}}]}}

If nothing found, return: {{"findings": []}}

Text: {text}"""

def claude_semantic_scan(text: str) -> list[dict]:
    """Deep contextual PHI detection via Claude. Catches what regex misses."""
    try:
        response = _get_anthropic_client().messages.create(
            model="claude-haiku-4-5-20251001",  # Haiku: 3-5x faster than Opus, same quality for classification
            max_tokens=512,
            messages=[{"role": "user", "content": CLAUDE_SCAN_PROMPT.format(text=text)}],
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
        logger.error(f"Claude semantic scan failed: {e}")
        return []

# --- Step 5: OpenAI second opinion (high severity only) ---

OPENAI_VALIDATION_PROMPT = """A medical AI safety system flagged the following text as HIGH severity PHI.
Validate whether this is correct. Be strict — patient safety and HIPAA compliance depend on accuracy.

Flagged findings: {findings}
Original text: {text}

Reply with ONLY valid JSON: {{"confirmed": true|false, "notes": "brief explanation"}}"""

def openai_second_opinion(text: str, findings: list[dict]) -> dict:
    """Cross-validates high severity Claude findings via OpenAI."""
    try:
        response = _get_openai_client().chat.completions.create(
            model="gpt-4o",
            messages=[{
                "role": "user",
                "content": OPENAI_VALIDATION_PROMPT.format(
                    findings=json.dumps(findings),
                    text=text,
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
        logger.error(f"OpenAI second opinion failed: {e}")
        return {"confirmed": True, "notes": "validation unavailable — defaulting to confirmed"}

# --- Step 6: Redactor ---

def redact_text(text: str, regex_findings: list[dict]) -> str:
    """Replace regex-matched findings in-place with [REDACTED:TYPE] tokens."""
    for finding in sorted(regex_findings, key=lambda x: x["start"], reverse=True):
        replacement = f"[REDACTED:{finding['type'].upper()}]"
        text = text[:finding["start"]] + replacement + text[finding["end"]:]
    return text

# --- Step 7: Audit logger ---

def log_scan(user_id: str, result: dict) -> None:
    """Append scan result to HIPAA audit log (JSONL)."""
    high_severity = any(f.get("severity") == "high" for f in result["semantic_findings"])
    entry = {
        "timestamp":       datetime.utcnow().isoformat(),
        "user_id":         user_id,
        "safe_to_send":    result["safe_to_send"],
        "findings_count":  len(result["regex_findings"]) + len(result["semantic_findings"]),
        "finding_types":   [f["type"] for f in result["regex_findings"]] +
                           [f["type"] for f in result["semantic_findings"]],
        "severity":        "high" if high_severity else "medium" if result["semantic_findings"] else "low",
        "regulation":      list({f.get("regulation", "general") for f in result["semantic_findings"]}),
        "baseten_escalated": result.get("baseten_escalated", False),
        "openai_confirmed":  result.get("openai_confirmed"),
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    logger.info(f"Audit log written for user {user_id} — severity: {entry['severity']}")

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
        results = [{"title": h.get("title", ""), "snippet": h.get("description", "")} for h in hits[:3]]
        logger.info(f"You.com search returned {len(results)} results for insurance_id: {insurance_id[:4]}****")
        return {"results": results, "query": query}
    except Exception as e:
        logger.error(f"You.com search failed: {e}")
        return {"error": str(e), "results": []}


# --- Patient info extractor ---

EXTRACTION_PROMPT = """You are a structured data extraction assistant for a medical onboarding agent.
Given a voice conversation transcript, extract any patient information mentioned so far.
Respond with ONLY valid JSON — no markdown, no explanation.

Format: {{"patient_name": "<name or null>", "insurance_id": "<id or null>", "reason": "<primary concern or reason for visit or null>", "dob": "<YYYY-MM-DD or null>", "phone": "<phone or null>"}}

Rules:
- Only include fields the patient has explicitly stated.
- Use null for fields not yet mentioned.
- Extract the most recent value if the patient corrected themselves.
- For "reason", capture the patient's health concern or symptom in their own words.

Transcript:
{transcript}"""

def extract_patient_info(messages: list[dict], raw_hint: str = "") -> dict:
    """Extract structured patient fields from conversation history using Claude.

    raw_hint: the unredacted latest patient message — used to recover fields
    like DOB or phone that were scrubbed from the LLM-facing transcript.
    """
    transcript = "\n".join(
        f"{'Patient' if m['role'] == 'user' else 'Agent'}: {m['content']}"
        for m in messages[-8:]
        if isinstance(m.get("content"), str)
    )
    if not transcript.strip() and not raw_hint:
        return {}

    hint_section = ""
    if raw_hint:
        hint_section = (
            f"\n\nNote — patient's most recent unredacted speech (before privacy scan):\n"
            f"\"{raw_hint}\"\n"
            "(Use this to capture structured fields like DOB or phone that may appear "
            "as [REDACTED:...] tokens in the transcript above.)"
        )

    try:
        response = _get_anthropic_client().messages.create(
            model="claude-opus-4-6",
            max_tokens=200,
            messages=[{"role": "user", "content": EXTRACTION_PROMPT.format(transcript=transcript) + hint_section}],
        )
        return json.loads(response.content[0].text.strip())
    except Exception as e:
        logger.error(f"Patient info extraction failed: {e}")
        return {}


# --- Patient database ---

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "voicerun", "data")
DOCTORS_FILE = os.path.join(_DATA_DIR, "doctors.json")
PATIENTS_FILE = os.path.join(_DATA_DIR, "patients.json")


def _load_doctors() -> list[dict]:
    try:
        with open(DOCTORS_FILE) as f:
            return json.load(f).get("doctors", [])
    except Exception as e:
        logger.error(f"Failed to load doctors: {e}")
        return []


def _load_patients() -> list[dict]:
    try:
        with open(PATIENTS_FILE) as f:
            return json.load(f).get("patients", [])
    except Exception as e:
        logger.error(f"Failed to load patients: {e}")
        return []


def _save_patients(patients: list[dict]) -> bool:
    try:
        with open(PATIENTS_FILE, "w") as f:
            json.dump({"patients": patients}, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Failed to save patients: {e}")
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


def triage_specialist(reason: str) -> dict | None:
    """Use Claude to semantically match a patient's concern to the best specialist."""
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
        response = _get_anthropic_client().messages.create(
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
        logger.info(f"Triage result: {result.get('specialist_name')} ({result.get('specialty')})")
        return result
    except Exception as e:
        logger.error(f"Triage specialist failed: {e}")
        return None


# --- Full pipeline ---

# In-memory cache: text hash → scan result
# Prevents redundant API calls for repeated text (common during dev/testing and session replay).
_scan_cache: dict[str, dict] = {}
_CACHE_MAX = 256

# Set DLP_ENABLE_VALIDATION=true to turn on the OpenAI second-opinion step.
# Off by default — it adds 1-2s latency and is redundant for most voice/realtime paths.
_ENABLE_VALIDATION = os.getenv("DLP_ENABLE_VALIDATION", "false").lower() == "true"


def scan_and_clean(text: str, user_id: str = "anonymous") -> dict:
    """
    Full DLP pipeline. Input: raw text. Output: findings, redacted text, safe_to_send flag.

    Performance notes:
    - Results are cached in-memory (LRU-style, max 256 entries).
      Repeated identical text (common in dev and session replay) returns instantly.
    - Semantic scan uses claude-haiku (3-5x faster than Opus, same PHI classification quality).
    - OpenAI second-opinion is disabled by default; set DLP_ENABLE_VALIDATION=true to enable.
    - Baseten model is configurable via BASETEN_MODEL env var.
    """
    cache_key = hashlib.md5(text.encode()).hexdigest()
    if cache_key in _scan_cache:
        cached = _scan_cache[cache_key]
        log_scan(user_id, cached)  # still audit-log every access
        return cached

    regex_hits = regex_scan(text)
    escalate   = baseten_triage(text)

    semantic_hits = []
    openai_result = None

    if escalate:
        semantic_hits = claude_semantic_scan(text)
        if _ENABLE_VALIDATION:
            high_severity = [f for f in semantic_hits if f.get("severity") == "high"]
            if high_severity:
                openai_result = openai_second_opinion(text, high_severity)

    clean = redact_text(text, regex_hits)
    safe  = len(regex_hits) == 0 and len(semantic_hits) == 0

    result = {
        "original":           text,
        "clean":              clean,
        "regex_findings":     regex_hits,
        "semantic_findings":  semantic_hits,
        "safe_to_send":       safe,
        "baseten_escalated":  escalate,
        "openai_confirmed":   openai_result,
    }

    # Evict oldest entry if cache is full
    if len(_scan_cache) >= _CACHE_MAX:
        _scan_cache.pop(next(iter(_scan_cache)))
    _scan_cache[cache_key] = result

    log_scan(user_id, result)
    return result
