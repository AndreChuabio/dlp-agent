"""
DLP Agent tools — full detection pipeline.
Order: Voicerun → regex → Baseten triage → Claude semantic → OpenAI second opinion → redact → log
"""

import re
import json
import logging
import os
import requests
from datetime import datetime

import anthropic
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

LOG_FILE = "dlp_audit_log.jsonl"

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

anthropic_client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# --- Patterns ---

PATTERNS = {
    # Standard PII
    "SSN":           r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card":   r"\b(?:\d{4}[- ]){3}\d{4}\b",
    "email":         r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone":         r"\b\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b",
    "api_key":       r"\b(sk-|pk_|AIza)[A-Za-z0-9_\-]{20,}\b",
    # HIPAA / PHI
    "patient_name":  r"\b(patient|pt\.?)\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b",
    "medical_record": r"\bMRN[\s:#-]*\d{5,10}\b",
    "npi_number":    r"\bNPI[\s:#-]*\d{10}\b",
    "icd_code":      r"\b[A-Z]\d{2}\.?\d{0,2}\b",
    "dob":           r"\b(DOB|Date of Birth|born)[\s:]+\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
    "insurance_id":  r"\b(insurance|policy|member)\s*(id|#|number)?[\s:#-]*[A-Z0-9]{6,15}\b",
    "medication":    r"\b\d+\s*mg\b",
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

def regex_scan(text: str) -> list[dict]:
    """Fast structured PII/PHI detection using regex patterns."""
    findings = []
    for label, pattern in PATTERNS.items():
        for match in re.finditer(pattern, text, re.IGNORECASE):
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
        response = anthropic_client.messages.create(
            model="claude-opus-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": CLAUDE_SCAN_PROMPT.format(text=text)}],
        )
        raw = response.content[0].text.strip()
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
        response = openai_client.chat.completions.create(
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

# --- Full pipeline ---

def scan_and_clean(text: str, user_id: str = "anonymous") -> dict:
    """
    Full DLP pipeline. Input: raw text. Output: findings, redacted text, safe_to_send flag.
    Baseten model is configurable via BASETEN_MODEL_ID env var — swap freely for testing.
    """
    regex_hits = regex_scan(text)
    escalate = baseten_triage(text)

    semantic_hits = []
    openai_result = None

    if escalate:
        semantic_hits = claude_semantic_scan(text)
        high_severity = [f for f in semantic_hits if f.get("severity") == "high"]
        if high_severity:
            openai_result = openai_second_opinion(text, high_severity)

    clean = redact_text(text, regex_hits)
    safe = len(regex_hits) == 0 and len(semantic_hits) == 0

    result = {
        "original":           text,
        "clean":              clean,
        "regex_findings":     regex_hits,
        "semantic_findings":  semantic_hits,
        "safe_to_send":       safe,
        "baseten_escalated":  escalate,
        "openai_confirmed":   openai_result,
    }

    log_scan(user_id, result)
    return result
