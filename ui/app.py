"""MediGuard AI — Streamlit demo dashboard."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import io
import re
import streamlit as st
from openai import OpenAI
from agent.orchestrator import run
from agent.tools import scan_and_clean, extract_patient_info, search_insurance_coverage
from agent.replay import ingest_payload, replay_session
import anthropic

st.set_page_config(page_title="MediGuard AI", layout="wide")

# Try to import the Veris simulation runner (works on Python 3.11 / Railway, may fail locally on 3.9)
try:
    _tests_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests")
    sys.path.insert(0, _tests_dir)
    from veris_simulation import run_regex_simulation as _run_veris_sim
    _VERIS_LOCAL = True
except Exception:
    _VERIS_LOCAL = False

# --- Session state init ---
if "messages"       not in st.session_state: st.session_state.messages       = []
if "patient_info"   not in st.session_state: st.session_state.patient_info   = {}
if "coverage"       not in st.session_state: st.session_state.coverage        = None
if "replay_result"  not in st.session_state: st.session_state.replay_result   = None
if "ingest_result"  not in st.session_state: st.session_state.ingest_result   = None
if "active_scenario" not in st.session_state: st.session_state.active_scenario = None
if "pr_result"       not in st.session_state: st.session_state.pr_result       = None
if "gen_regex"       not in st.session_state: st.session_state.gen_regex        = ""
if "sim_triggered_at" not in st.session_state: st.session_state.sim_triggered_at = None
if "sim_run_cache"    not in st.session_state: st.session_state.sim_run_cache    = None
if "veris_local_report" not in st.session_state: st.session_state.veris_local_report = None

# ============================================================
# Mock production interaction payloads
# These represent real-looking logs an employee would receive
# in a bug ticket — complete with PHI that can't be pasted
# directly into Claude.
# ============================================================

MOCK_SCENARIOS = {
    "ticket-1234 — Returning patient, correct triage": {
        "badge": "✅ Happy Path",
        "badge_color": "green",
        "description": "Alice Johnson (returning patient) calls about chest tightness. Agent identifies her from the DB, skips re-collection, and triages correctly to Cardiology.",
        "known_issue": None,
        "expected": "Triage → Dr. Sarah Chen (Cardiologist)",
        "turns": [
            {"role": "user",  "text": "Hi, my name is Alice Johnson. My date of birth is March 22nd, 1975."},
            {"role": "agent", "text": "Welcome back, Alice! I can see you were last in on October 15th. What brings you in today?"},
            {"role": "user",  "text": "I've been having chest tightness lately, and sometimes I feel short of breath when I climb stairs."},
            {"role": "agent", "text": "I'd recommend Dr. Sarah Chen, our Cardiologist — she's available Monday, Wednesday, and Friday and is the right fit for those symptoms. Our team will follow up to schedule the referral."},
            {"role": "user",  "text": "Perfect, my callback number is 212-555-0101. Thank you!"},
            {"role": "agent", "text": "Got it, Alice. We'll be in touch. Take care!"}
        ]
    },

    "ticket-5678 — New patient, full onboarding": {
        "badge": "✅ Happy Path",
        "badge_color": "green",
        "description": "James Park calls for the first time. Agent runs full onboarding — collects DOB and phone, triages stomach symptoms to Gastroenterology, saves record.",
        "known_issue": None,
        "expected": "Triage → Dr. Marcus Rivera (Gastroenterologist)",
        "turns": [
            {"role": "user",  "text": "Hi, I'm James Park. First time calling."},
            {"role": "agent", "text": "Nice to meet you, James! I don't have you in our system yet. What's your date of birth?"},
            {"role": "user",  "text": "March 4th, 1988."},
            {"role": "agent", "text": "Got it. And a good callback number for you?"},
            {"role": "user",  "text": "646-555-0192."},
            {"role": "agent", "text": "Thanks! What's the main reason you're calling today?"},
            {"role": "user",  "text": "My stomach has been really hurting, especially after I eat. Lots of bloating and acid reflux too."},
            {"role": "agent", "text": "That sounds like a great fit for Dr. Marcus Rivera, our Gastroenterologist — available Tuesday and Thursday. We'll reach out to schedule the referral directly, no extra GP visit needed."}
        ]
    },

    "ticket-9012 — PHI leak inside raw log (critical)": {
        "badge": "🔴 PHI in Log",
        "badge_color": "red",
        "description": "A production session log that has raw PHI embedded in system metadata — SSN in the log header, MRN and DOB in turn metadata. Exactly what would cause a HIPAA violation if pasted into Claude.",
        "known_issue": "Production logging pipeline is writing PHI into turn metadata. Bug filed against logging service.",
        "expected": "DLP should catch SSN, MRN, DOB, phone across multiple turns",
        "turns": [
            {"role": "system", "text": "Session init. Patient SSN: 234-56-7890. Lookup result: MRN-445521. Insurance: AETNA-112233.", "metadata": {"patient_id": "MRN-445521", "dob": "1968-11-30"}},
            {"role": "user",  "text": "Hi, I'm Maria Santos. Born November 30, 1968. My MRN is MRN-445521."},
            {"role": "agent", "text": "Welcome back, Maria! What brings you in today?"},
            {"role": "user",  "text": "My lower back has been killing me again — same arthritis issue. I'm still taking 800mg ibuprofen twice a day. My phone is 917-555-0789."},
            {"role": "agent", "text": "I'd recommend Dr. James Kim, our Orthopedic Specialist, who can help with that. We'll follow up to schedule."}
        ]
    },

    "ticket-3456 — Vague concern, triage defaults to GP": {
        "badge": "⚠️ Edge Case",
        "badge_color": "orange",
        "description": "Robert Chen calls but can't articulate a specific concern. Triage should default to the General Practitioner — verify it does and doesn't leave him unrouted.",
        "known_issue": None,
        "expected": "Triage → Dr. Robert Walsh (General Practitioner)",
        "turns": [
            {"role": "user",  "text": "Hey, my name is Robert Chen."},
            {"role": "agent", "text": "Hi Robert! What brings you in today?"},
            {"role": "user",  "text": "Honestly I'm not sure. I just haven't been feeling great lately. Kind of tired, maybe a headache here and there. Nothing specific."},
            {"role": "agent", "text": "I understand — let me get a few details. What's your date of birth?"},
            {"role": "user",  "text": "February 14, 1992. My insurance member ID is UHC-778899."},
            {"role": "agent", "text": "Thanks, Robert. For a general wellness concern like this, I'd start with Dr. Robert Walsh, our General Practitioner, available Monday through Friday. He can help figure out what's going on and refer you from there."}
        ]
    },

    "ticket-7890 — Incomplete session, triage never ran (bug)": {
        "badge": "🐛 Bug",
        "badge_color": "red",
        "description": "David Kim (returning patient) is identified but hangs up before stating a concern. Triage never ran. This session was escalated because the patient called back angry — use replay to find the exact turn where the session dropped off.",
        "known_issue": "Agent should have prompted for concern more proactively after identifying the patient. Current system prompt waits for user to volunteer it.",
        "expected": "Issue detected: triage never ran, no concern extracted",
        "turns": [
            {"role": "user",  "text": "Hi, it's David Kim, date of birth July 8, 1990."},
            {"role": "agent", "text": "Welcome back, David! What brings you in today?"},
            {"role": "user",  "text": "Actually you know what, I need to go. I'll call back later, sorry about that."},
            {"role": "agent", "text": "Of course! Feel free to call back anytime. Have a great day!"}
        ]
    },
}

# ============================================================
# DLP Coverage Dashboard — pattern metadata for display
# ============================================================

PATTERN_DISPLAY = [
    # Standard PII
    {"type": "SSN",           "category": "Standard PII",       "label": "Social Security Number",   "example": "123-45-6789",                   "hipaa": None},
    {"type": "credit_card",   "category": "Standard PII",       "label": "Credit Card Number",       "example": "4111 1111 1111 1111",            "hipaa": None},
    {"type": "email",         "category": "Standard PII",       "label": "Email Address",            "example": "alice@hospital.org",             "hipaa": None},
    {"type": "phone",         "category": "Standard PII",       "label": "Phone / Fax",              "example": "(212) 555-0101",                 "hipaa": "4/5"},
    {"type": "api_key",       "category": "Standard PII",       "label": "API Key / Secret",         "example": "sk-abc1234...",                  "hipaa": None},
    # HIPAA Safe Harbor
    {"type": "patient_name",  "category": "HIPAA — Identity",   "label": "Patient Name",             "example": "my name is Alice Johnson",       "hipaa": "1"},
    {"type": "street_address","category": "HIPAA — Geographic", "label": "Street Address",           "example": "42 Elm Street",                  "hipaa": "2"},
    {"type": "dob",           "category": "HIPAA — Dates",      "label": "Date of Birth",            "example": "born March 22nd, 1975",          "hipaa": "3"},
    {"type": "medical_record","category": "HIPAA — Medical",    "label": "Medical Record (MRN)",     "example": "MRN-445521",                     "hipaa": "8"},
    {"type": "npi_number",    "category": "HIPAA — Medical",    "label": "NPI Number",               "example": "NPI 1234567890",                 "hipaa": None},
    {"type": "icd_code",      "category": "HIPAA — Medical",    "label": "ICD Diagnosis Code",       "example": "diagnosis I10",                  "hipaa": None},
    {"type": "medication",    "category": "HIPAA — Medical",    "label": "Medication Dosage",        "example": "50mg sertraline",                "hipaa": None},
    {"type": "insurance_id",  "category": "HIPAA — Insurance",  "label": "Insurance / Member ID",    "example": "member ID BCBS789012",           "hipaa": "9"},
    {"type": "account_number","category": "HIPAA — Insurance",  "label": "Account Number",           "example": "acct 123456789",                 "hipaa": "10"},
    {"type": "license_number","category": "HIPAA — Insurance",  "label": "Certificate / License",    "example": "license CA-DL-X7829",            "hipaa": "11"},
    {"type": "vehicle_id",    "category": "HIPAA — Technical",  "label": "Vehicle ID / VIN",         "example": "VIN 1HGCM82633A004352",          "hipaa": "12"},
    {"type": "device_id",     "category": "HIPAA — Technical",  "label": "Device / Serial Number",   "example": "IMEI 490154203237518",           "hipaa": "13"},
    {"type": "url",           "category": "HIPAA — Technical",  "label": "URL / Portal Link",        "example": "https://portal.example.com/42",  "hipaa": "14"},
    {"type": "ip_address",    "category": "HIPAA — Technical",  "label": "IP Address (session logs)","example": "192.168.1.1",                    "hipaa": "15"},
]

CATEGORY_ORDER = [
    "Standard PII",
    "HIPAA — Identity",
    "HIPAA — Geographic",
    "HIPAA — Dates",
    "HIPAA — Medical",
    "HIPAA — Insurance",
    "HIPAA — Technical",
]

GITHUB_REPO = "AndreChuabio/dlp-agent"


def _gh_headers():
    token = os.getenv("GITHUB_TOKEN", "")
    if not token:
        return None
    return {
        "Authorization":        f"Bearer {token}",
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def github_add_pattern(pattern_name: str, regex: str, description: str, example: str) -> dict:
    """Create branch → commit pattern + test case → open PR → trigger CI."""
    import base64
    import requests as req

    headers = _gh_headers()
    if not headers:
        return {"error": "GITHUB_TOKEN not configured — add it in Railway → Variables to enable PR creation."}

    branch = f"feat/dlp-{pattern_name.replace('_', '-')}"
    api    = f"https://api.github.com/repos/{GITHUB_REPO}"

    # 1. Get develop SHA (PRs target develop, not main)
    r = req.get(f"{api}/git/ref/heads/develop", headers=headers, timeout=10)
    if r.status_code != 200:
        return {"error": f"Could not read develop ref ({r.status_code}) — make sure the develop branch exists."}
    main_sha = r.json()["object"]["sha"]

    # 2. Create branch (422 = already exists, that's fine)
    r = req.post(f"{api}/git/refs", headers=headers, timeout=10,
                 json={"ref": f"refs/heads/{branch}", "sha": main_sha})
    if r.status_code not in (201, 422):
        return {"error": f"Could not create branch ({r.status_code}): {r.text[:200]}"}

    # 3. Read + patch agent/tools.py
    r = req.get(f"{api}/contents/agent/tools.py", headers=headers, timeout=10,
                params={"ref": branch})
    if r.status_code != 200:
        return {"error": f"Could not read tools.py ({r.status_code})"}
    fd      = r.json()
    content = base64.b64decode(fd["content"]).decode("utf-8")

    # Find the closing } of PATTERNS robustly — works regardless of last entry
    import re as _re
    m = _re.search(r'(\n\})\n\n# ---', content)
    if not m:
        return {"error": "Could not locate end of PATTERNS dict in tools.py — check that the file still has a '# ---' comment after the closing brace."}
    insert_pos = m.start(1)
    new_entry  = f'\n    # {description}\n    "{pattern_name}": r"{regex}",'
    patched    = content[:insert_pos] + new_entry + content[insert_pos:]

    r = req.put(f"{api}/contents/agent/tools.py", headers=headers, timeout=10,
                json={
                    "message": f"feat(dlp): add {pattern_name} redaction pattern",
                    "content": base64.b64encode(patched.encode()).decode(),
                    "sha": fd["sha"], "branch": branch,
                })
    if r.status_code not in (200, 201):
        return {"error": f"Could not commit tools.py ({r.status_code}): {r.text[:200]}"}

    # 4. Read + patch tests/veris_simulation.py
    r = req.get(f"{api}/contents/tests/veris_simulation.py", headers=headers, timeout=10,
                params={"ref": branch})
    if r.status_code == 200:
        sd  = r.json()
        sim = base64.b64decode(sd["content"]).decode("utf-8")
        new_case = (
            f'\n    # ── User-added: {pattern_name} ──\n'
            f'    Case("{pattern_name} — auto-added",\n'
            f'         "{example}",\n'
            f'         True, "{pattern_name}", "user_added"),\n'
        )
        sim = sim.replace(
            'False, None, "clean"),\n]',
            f'False, None, "clean"),\n{new_case}]',
            1,
        )
        req.put(f"{api}/contents/tests/veris_simulation.py", headers=headers, timeout=10,
                json={
                    "message": f"test(veris): add adversarial case for {pattern_name}",
                    "content": base64.b64encode(sim.encode()).decode(),
                    "sha": sd["sha"], "branch": branch,
                })

    # 4b. Always pin the correct workflow file so feature branches run reliably
    _correct_workflow = (
        "name: DLP Veris Simulation\n\n"
        "on:\n  workflow_dispatch:\n\n"
        "jobs:\n  veris-simulation:\n    runs-on: ubuntu-latest\n"
        "    name: Veris Adversarial Detection Test\n\n    steps:\n"
        "      - uses: actions/checkout@v4\n\n"
        "      - name: Set up Python\n        uses: actions/setup-python@v5\n"
        "        with:\n          python-version: \"3.11\"\n\n"
        "      - name: Install dependencies\n        run: pip install python-dotenv requests anthropic openai\n\n"
        "      - name: Run Veris simulation\n"
        "        run: python tests/veris_simulation.py --github\n"
        "        env:\n"
        "          PYTHONPATH: ${{ github.workspace }}\n"
        "          ANTHROPIC_API_KEY: placeholder\n"
        "          OPENAI_API_KEY: placeholder\n"
        "          BASETEN_API_KEY: placeholder\n\n"
        "      - name: Upload simulation report\n        if: always()\n"
        "        uses: actions/upload-artifact@v4\n        with:\n"
        "          name: veris-simulation-report\n          path: \"*.jsonl\"\n"
        "          if-no-files-found: ignore\n"
    )
    wf_r = req.get(f"{api}/contents/.github/workflows/dlp-simulation.yml",
                   headers=headers, timeout=10, params={"ref": branch})
    wf_payload = {
        "message": "ci: pin requirements.txt install in simulation workflow",
        "content": base64.b64encode(_correct_workflow.encode()).decode(),
        "branch":  branch,
    }
    if wf_r.status_code == 200:
        wf_payload["sha"] = wf_r.json()["sha"]
    req.put(f"{api}/contents/.github/workflows/dlp-simulation.yml",
            headers=headers, timeout=10, json=wf_payload)

    # 5. Open PR
    r = req.post(f"{api}/pulls", headers=headers, timeout=10,
                 json={
                     "title": f"feat(dlp): add `{pattern_name}` redaction",
                     "body": (
                         f"## New DLP rule: `{pattern_name}`\n\n"
                         f"**Description:** {description}\n"
                         f"**Regex:** `{regex}`\n"
                         f"**Example caught:** `{example}`\n\n"
                         "Added via the MediGuard DLP Coverage Dashboard.\n\n"
                         "🤖 Generated with [Claude Code](https://claude.com/claude-code)"
                     ),
                     "head": branch, "base": "develop",
                 })
    if r.status_code not in (200, 201):
        return {"error": f"Could not open PR ({r.status_code}): {r.text[:200]}"}
    pr = r.json()

    # Simulation is NOT auto-triggered — user clicks "Run Simulation" manually
    return {
        "pr_url":    pr["html_url"],
        "pr_number": pr["number"],
        "branch":    branch,
        "repo":      GITHUB_REPO,
    }


def veris_trigger_run() -> dict:
    """Trigger a real Veris sandbox simulation run via the Veris REST API."""
    import requests as req
    api_key = os.getenv("VERIS_API_KEY", "").strip()
    env_id  = os.getenv("VERIS_ENV_ID", "env_28owwq0q0dng0633a5glk").strip()
    set_id  = os.getenv("VERIS_SCENARIO_SET_ID", "scenset_mczzu6keewjb3r6aanlm0").strip()
    if not api_key:
        return {"error": "VERIS_API_KEY not set"}
    r = req.post(
        "https://sandbox.api.veris.ai/v1/runs",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={"environment_id": env_id, "scenario_set_id": set_id, "image_tag": "latest"},
        timeout=15,
    )
    if r.status_code in (200, 201):
        run = r.json()
        return {"ok": True, "run_id": run["id"], "total": run.get("total_simulations", 0)}
    if r.status_code == 409:
        return {"error": "A simulation is already running — wait for it to finish then retry."}
    return {"error": f"Veris API error ({r.status_code}): {r.text[:200]}"}


def veris_fetch_run_report(run_id: str) -> dict:
    """Fetch status + simulation results for a Veris run ID."""
    import requests as req
    api_key = os.getenv("VERIS_API_KEY", "").strip()
    if not api_key:
        return {"error": "VERIS_API_KEY not set"}
    headers = {"Authorization": f"Bearer {api_key}"}
    r = req.get(f"https://sandbox.api.veris.ai/v1/runs/{run_id}", headers=headers, timeout=15)
    if r.status_code != 200:
        return {"error": f"Veris API {r.status_code}: {r.text[:200]}"}
    run = r.json()
    status = run["status"]
    result = {
        "run_id":      run_id,
        "status":      status,
        "completed":   run["completed_simulations"],
        "total":       run["total_simulations"],
        "failed":      run["failed_simulations"],
        "started_at":  run.get("started_at"),
        "completed_at": run.get("completed_at"),
        "duration":    run.get("duration_seconds"),
    }
    if status == "completed":
        s = req.get(f"https://sandbox.api.veris.ai/v1/runs/{run_id}/simulations", headers=headers, timeout=15)
        if s.status_code == 200:
            sims_data = s.json()
            result["simulations"] = sims_data.get("items", sims_data) if isinstance(sims_data, dict) else sims_data
    return result


def fetch_latest_sim_run(force: bool = False) -> dict:
    """Fetch the most recent dlp-simulation.yml run from GitHub Actions.

    Returns a dict with keys: id, status, conclusion, created_at, html_url,
    run_number, branch  — or  {"error": "..."} / {"none": True}.
    Results are cached for 15 s to avoid hammering the API on every Streamlit rerun.
    Pass force=True (e.g., right after triggering) to bypass the cache.
    """
    import requests as req
    import time

    cache = st.session_state.get("sim_run_cache")
    if not force and cache and (time.time() - cache.get("_fetched_at", 0)) < 15:
        return cache

    headers = _gh_headers()
    if not headers:
        return {"error": "no_token"}
    try:
        r = req.get(
            f"https://api.github.com/repos/{GITHUB_REPO}/actions/workflows/dlp-simulation.yml/runs",
            headers=headers,
            params={"per_page": 5},
            timeout=10,
        )
        if r.status_code != 200:
            return {"error": f"GitHub API {r.status_code}"}
        runs = r.json().get("workflow_runs", [])
        if not runs:
            return {"none": True}
        latest = runs[0]
        result = {
            "_fetched_at": time.time(),
            "id":          latest["id"],
            "status":      latest["status"],
            "conclusion":  latest.get("conclusion"),
            "created_at":  latest["created_at"],
            "html_url":    latest["html_url"],
            "run_number":  latest["run_number"],
            "branch":      latest.get("head_branch", ""),
            "recent":      [
                {
                    "run_number": x["run_number"],
                    "conclusion": x.get("conclusion"),
                    "created_at": x["created_at"],
                    "html_url":   x["html_url"],
                    "branch":     x.get("head_branch", ""),
                }
                for x in runs[:5]
            ],
        }
        st.session_state.sim_run_cache = result
        return result
    except Exception as e:
        return {"error": str(e)}


def _generate_regex_claude(pattern_name: str, example: str, description: str) -> str:
    """Ask Claude Haiku to suggest a regex for the new pattern."""
    try:
        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        resp   = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=150,
            messages=[{"role": "user", "content": (
                f"Write a Python regex to detect this type of PII/PHI in text:\n"
                f"Type: {pattern_name}\n"
                f"Description: {description}\n"
                f"Must match: {example}\n\n"
                "Return ONLY the raw regex string — no r'' wrapper, no quotes, "
                "no backticks, no explanation. Just the pattern itself."
            )}],
        )
        raw = resp.content[0].text.strip()
        # Strip any wrapping quotes the model might add
        for wrap in ('r"', "r'", '"', "'", '`'):
            raw = raw.strip(wrap)
        return raw
    except Exception:
        return r"\b" + re.escape(pattern_name.replace("_", " ")) + r"\b"


SYSTEM_PROMPT = (
    "You are MediGuard AI, a HIPAA-compliant patient onboarding assistant. "
    "Your job is to collect patient information conversationally — no forms, no paperwork. "
    "All patient messages have been scanned and redacted by a DLP layer. You never see raw PHI. "
    "Keep responses brief and warm — one question at a time.\n\n"
    "Onboarding flow: ask for name → reason for visit → insurance ID → DOB → callback number → confirm and close.\n"
    "If a message contains [REDACTED:...] tokens, acknowledge the info was protected and move on.\n"
    "Never ask for SSNs or full medical record numbers."
)

# --- Sidebar ---
with st.sidebar:
    st.markdown("## MediGuard AI")
    st.caption("HIPAA-compliant patient onboarding")
    st.markdown("---")
    user_id = st.text_input("Session / User ID", value="demo-patient")
    st.markdown("---")
    st.markdown("**Triage Model**")
    st.caption(f"`{os.getenv('BASETEN_MODEL', 'deepseek-ai/DeepSeek-V3.1')}`")
    st.markdown("---")
    st.markdown("**Pipeline**")
    st.markdown("1. Regex scan\n2. Baseten triage\n3. Claude Haiku semantic\n4. Redact + Log")
    st.markdown("---")
    if st.session_state.patient_info:
        st.markdown("**Collected Patient Info**")
        for k, v in st.session_state.patient_info.items():
            if v and v != "null":
                st.markdown(f"- `{k}`: {v}")
    if st.session_state.coverage and st.session_state.coverage.get("results"):
        st.markdown("**Coverage Found**")
        st.caption(st.session_state.coverage["results"][0].get("snippet", "")[:150])
    if st.button("Clear Conversation", key="clear"):
        st.session_state.messages     = []
        st.session_state.patient_info = {}
        st.session_state.coverage     = None
        st.rerun()

# --- Header ---
st.title("MediGuard AI — Patient Onboarding")
st.caption("Patients speak or type naturally. PHI is intercepted before it reaches any AI model.")
st.markdown("---")

# --- Tabs ---
chat_tab, scan_tab, voice_tab, debug_tab, coverage_tab = st.tabs(
    ["Agent Chat", "DLP Scanner", "Voice Input", "🔍 Debug Replay", "🛡️ DLP Coverage"]
)

# ============================================================
# TAB 1 — Conversational agent chat
# ============================================================
with chat_tab:
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if msg.get("dlp_findings"):
                with st.expander(f"DLP — {msg['dlp_findings']['total']} finding(s) redacted"):
                    for f in msg["dlp_findings"].get("regex", []):
                        st.markdown(f"- `{f['type'].upper()}` — `{f['value']}`")
                    for f in msg["dlp_findings"].get("semantic", []):
                        sev   = f.get("severity", "low")
                        color = "red" if sev == "high" else "orange"
                        st.markdown(f"- :{color}[**{sev.upper()}**] `{f['type']}` — {f['reason']}")

    patient_input = st.chat_input("Type your message as the patient...")

    if patient_input:
        dlp_result   = scan_and_clean(patient_input, user_id=user_id)
        clean_message = dlp_result["clean"]

        findings_summary = {
            "total":    len(dlp_result["regex_findings"]) + len(dlp_result["semantic_findings"]),
            "regex":    dlp_result["regex_findings"],
            "semantic": dlp_result["semantic_findings"],
        }

        with st.chat_message("user"):
            st.markdown(clean_message)
            if findings_summary["total"] > 0:
                with st.expander(f"DLP — {findings_summary['total']} finding(s) redacted"):
                    for f in findings_summary["regex"]:
                        st.markdown(f"- `{f['type'].upper()}` — `{f['value']}`")
                    for f in findings_summary["semantic"]:
                        sev   = f.get("severity", "low")
                        color = "red" if sev == "high" else "orange"
                        st.markdown(f"- :{color}[**{sev.upper()}**] `{f['type']}` — {f['reason']}")

        st.session_state.messages.append({
            "role": "user", "content": clean_message, "dlp_findings": findings_summary,
        })

        raw_msgs    = [{"role": m["role"], "content": m["content"]} for m in st.session_state.messages]
        patient_info = extract_patient_info(raw_msgs)
        if patient_info:
            merged = {**st.session_state.patient_info, **{k: v for k, v in patient_info.items() if v and v != "null"}}
            st.session_state.patient_info = merged

        insurance_id = st.session_state.patient_info.get("insurance_id")
        if insurance_id and not st.session_state.coverage:
            with st.spinner("Searching coverage via You.com..."):
                st.session_state.coverage = search_insurance_coverage(
                    insurance_id=insurance_id,
                    reason=st.session_state.patient_info.get("reason", ""),
                )

        system = SYSTEM_PROMPT
        if st.session_state.patient_info:
            collected = {k: v for k, v in st.session_state.patient_info.items() if v and v != "null"}
            system += f"\n\nCollected so far: {json.dumps(collected)}"
        if st.session_state.coverage and st.session_state.coverage.get("results"):
            snippets = " | ".join(r["snippet"] for r in st.session_state.coverage["results"][:2] if r.get("snippet"))
            system += f"\n\nInsurance coverage info: {snippets}"

        with st.chat_message("assistant"):
            with st.spinner(""):
                try:
                    client   = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
                    history  = [{"role": m["role"], "content": m["content"]} for m in st.session_state.messages]
                    response = client.messages.create(
                        model="claude-opus-4-6", max_tokens=300, system=system, messages=history,
                    )
                    agent_reply = response.content[0].text
                except Exception as e:
                    agent_reply = f"Sorry, I ran into an issue. ({e})"
            st.markdown(agent_reply)

        st.session_state.messages.append({"role": "assistant", "content": agent_reply})
        st.rerun()

# ============================================================
# TAB 2 — Raw DLP scanner
# ============================================================
with scan_tab:
    text_input = st.text_area(
        "Patient message:",
        height=120,
        placeholder="Hi, my name is John Smith, MRN 123456, DOB 04/12/1985. I'm on 50mg sertraline for F32.1. My insurance ID is BCX884521.",
    )
    if st.button("Scan Message", type="primary", key="text_scan"):
        if text_input.strip():
            with st.spinner("Scanning..."):
                result = run(text=text_input, user_id=user_id)

            if result["safe_to_send"]:
                st.success("SAFE TO SEND — No PHI detected")
            else:
                total = len(result["regex_findings"]) + len(result["semantic_findings"])
                st.error(f"BLOCKED — {total} PHI finding(s) detected and redacted")

            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Original**")
                st.text_area("", value=result["original"], height=120, disabled=True, key="orig")
            with col2:
                st.markdown("**Redacted (sent to AI)**")
                st.text_area("", value=result["clean"],    height=120, disabled=True, key="clean")

            fcol1, fcol2, fcol3 = st.columns(3)
            fcol1.metric("Regex Hits",        len(result["regex_findings"]))
            fcol2.metric("Semantic Hits",     len(result["semantic_findings"]))
            fcol3.metric("Baseten Escalated", "Yes" if result["baseten_escalated"] else "No")

            if result["regex_findings"]:
                st.markdown("**Structured PHI (Regex)**")
                for f in result["regex_findings"]:
                    st.markdown(f"- `{f['type'].upper()}` — `{f['value']}`")

            if result["semantic_findings"]:
                st.markdown("**Contextual PHI (Claude)**")
                for f in result["semantic_findings"]:
                    color = "red" if f["severity"] == "high" else "orange"
                    st.markdown(f"- :{color}[**{f['severity'].upper()}**] `{f['type']}` ({f.get('regulation', '')}) — {f['reason']}")
        else:
            st.warning("Enter a message to scan.")

# ============================================================
# TAB 3 — Voice input
# ============================================================
with voice_tab:
    voicerun_number = os.getenv("VOICERUN_PHONE_NUMBER", "")
    if voicerun_number:
        st.info(f"Live phone demo: call **{voicerun_number}** — speak naturally, PHI is intercepted before reaching any AI.")
    else:
        st.info("Set VOICERUN_PHONE_NUMBER in .env to enable live phone demo.")
    st.markdown("---")
    st.caption("Or record a patient message below. Transcribed via Whisper then scanned before reaching any model.")
    audio = st.audio_input("Record patient message")
    if audio and st.button("Transcribe + Scan", type="primary", key="voice_scan"):
        with st.spinner("Transcribing..."):
            try:
                client       = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
                audio_bytes  = io.BytesIO(audio.read())
                audio_bytes.name = "recording.wav"
                transcript   = client.audio.transcriptions.create(model="whisper-1", file=audio_bytes)
                transcribed_text = transcript.text
                st.info(f"Transcript: {transcribed_text}")
            except Exception as e:
                st.error(f"Transcription failed: {e}")
                transcribed_text = None

        if transcribed_text:
            with st.spinner("Scanning..."):
                result = run(text=transcribed_text, user_id=user_id)
            st.success("SAFE TO SEND") if result["safe_to_send"] else st.error(
                f"BLOCKED — {len(result['regex_findings']) + len(result['semantic_findings'])} finding(s)"
            )
            st.text_area("Redacted output", value=result["clean"], disabled=True)

# ============================================================
# TAB 4 — Debug Replay
# ============================================================
with debug_tab:
    st.markdown("### Debug a production ticket — without leaking PHI")
    st.caption(
        "Load a mock production interaction log. "
        "The raw payload (with real patient data) is DLP-stripped locally. "
        "Only the redacted version is replayed through the agent pipeline — no PHI ever reaches Claude."
    )
    st.markdown("---")

    left_col, right_col = st.columns([1, 2], gap="large")

    with left_col:
        scenario_key = st.selectbox(
            "Load scenario",
            list(MOCK_SCENARIOS.keys()),
            index=0,
        )
        scenario = MOCK_SCENARIOS[scenario_key]

        # Badge + description
        badge_color = scenario["badge_color"]
        st.markdown(f":{badge_color}[**{scenario['badge']}**]")
        st.markdown(scenario["description"])

        if scenario["known_issue"]:
            st.warning(f"**Known issue:** {scenario['known_issue']}")
        else:
            st.markdown(f"**Expected outcome:** {scenario['expected']}")

        st.markdown("")

        # Raw payload preview
        with st.expander("View raw payload ⚠️ contains PHI", expanded=False):
            st.caption("This is what arrives from the production logging system — exactly what an employee should NOT paste into Claude.")
            st.code(
                json.dumps(scenario["turns"], indent=2),
                language="json",
            )

        run_button = st.button("Ingest + Replay", type="primary", use_container_width=True)

        if run_button:
            session_name = "demo-" + scenario_key.split("—")[0].strip().replace(" ", "-").lower()
            st.session_state.active_scenario = scenario_key

            progress = st.progress(0, text="Running DLP scan on raw payload...")
            try:
                ingest_result = ingest_payload(
                    json.dumps(scenario["turns"]),
                    session_name=session_name,
                )
                st.session_state.ingest_result = ingest_result
                progress.progress(50, text="Replaying through agent pipeline...")

                replay_result = replay_session(session_name)
                st.session_state.replay_result = replay_result
                progress.progress(100, text="Done.")
            except Exception as e:
                st.error(f"Replay failed: {e}")
                progress.empty()
            st.rerun()

    # ── Right column: results ──────────────────────────────────────
    with right_col:
        if st.session_state.replay_result and st.session_state.active_scenario:
            result = st.session_state.replay_result
            ingest = st.session_state.ingest_result or {}
            active = MOCK_SCENARIOS.get(st.session_state.active_scenario, {})

            # ── Summary metrics ──
            ctx          = result.get("final_context", {})
            triage       = ctx.get("triage_result")
            is_returning = ctx.get("is_returning")
            issues       = result.get("issues_detected", [])
            phi_found    = ingest.get("phi_findings", 0)

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("PHI in raw log",    phi_found,
                      delta="blocked" if phi_found else None,
                      delta_color="inverse" if phi_found else "off")
            m2.metric("Issues detected",   len(issues),
                      delta="⚠ needs fix" if issues else None,
                      delta_color="inverse" if issues else "off")
            m3.metric("Triage",            "✓ resolved" if triage else "✗ failed")
            m4.metric("Patient type",
                      "Returning" if is_returning else "New" if is_returning is False else "Unknown")

            st.markdown("")

            # ── Issues banner ──
            if issues:
                with st.container(border=True):
                    st.error("**Issues detected in this session**")
                    for issue in issues:
                        st.markdown(f"- {issue}")
            else:
                st.success("**No issues detected** — session ran cleanly.")

            # ── Triage result ──
            if triage:
                st.info(
                    f"**Triage resolved to:** {triage['specialist_name']} "
                    f"({triage['specialty']})  \n"
                    f"*{triage.get('reason', '')}*"
                )
            elif ctx.get("patient_info", {}).get("reason"):
                st.warning("Concern was extracted but triage did not complete.")
            else:
                st.warning("No concern extracted — triage never ran.")

            # ── PHI summary from ingest ──
            if phi_found:
                ft = ingest.get("finding_types", [])
                st.error(
                    f"**{phi_found} PHI finding(s) stripped from raw log** — "
                    f"types: `{', '.join(ft)}`  \n"
                    "These would have been exposed if pasted directly into Claude."
                )

            st.markdown("---")
            st.markdown("#### Turn-by-turn trace")
            st.caption("Each user turn shows what DLP found, what the agent pipeline extracted, and where state changed.")

            # ── Turn trace ──
            for turn in result.get("trace", []):
                role = turn.get("role", "user")
                text = turn.get("text", "")
                i    = turn.get("turn", 0)

                if role != "user":
                    with st.expander(f"Turn {i} — **Agent:** {text[:70]}{'...' if len(text) > 70 else ''}"):
                        st.markdown(f"> {text}")
                    continue

                dlp      = turn.get("dlp", {})
                hits     = dlp.get("regex_hits", 0) + dlp.get("semantic_hits", 0)
                has_info = bool(turn.get("patient_lookup") or turn.get("triage"))

                if hits:
                    label = f"🔴 Turn {i} — **Patient** — {hits} PHI finding(s)"
                elif has_info:
                    label = f"🟢 Turn {i} — **Patient** — clean + state update"
                else:
                    label = f"Turn {i} — **Patient** — clean"

                with st.expander(label, expanded=(hits > 0 or has_info)):
                    # Redacted text
                    st.markdown(f"**Redacted message sent to LLM:**")
                    st.code(text, language=None)

                    # DLP findings
                    if hits:
                        st.error(
                            f"DLP caught {hits} finding(s): "
                            f"`{', '.join(dlp.get('finding_types', []))}`"
                        )
                    else:
                        st.success("DLP: clean")

                    detail_col1, detail_col2 = st.columns(2)

                    # Patient info extracted
                    with detail_col1:
                        info = {
                            k: v for k, v in (turn.get("patient_info_so_far") or {}).items()
                            if v and v not in ("null", None, "")
                        }
                        if info:
                            st.markdown("**Patient info so far:**")
                            for k, v in info.items():
                                st.markdown(f"- `{k}`: {v}")

                    # Lookup + triage events
                    with detail_col2:
                        lookup = turn.get("patient_lookup")
                        if lookup:
                            if lookup.get("found_in_db"):
                                st.success(f"Found in DB: **{lookup['queried_name']}**")
                                record = lookup.get("record", {})
                                if record.get("conditions"):
                                    st.caption(f"Known conditions: {', '.join(record['conditions'])}")
                            else:
                                st.info(f"New patient: **{lookup['queried_name']}**")

                        t = turn.get("triage")
                        if t:
                            st.success(
                                f"Triage → **{t['specialist_name']}**  \n"
                                f"*{t['specialty']}*"
                            )

            # ── Summary text ──
            summary = result.get("summary", "")
            if summary:
                st.markdown("---")
                st.markdown("#### Replay summary")
                st.markdown(summary)

        else:
            # Placeholder before first run
            st.markdown("")
            st.info(
                "Select a scenario and click **Ingest + Replay** to see the debug trace.  \n\n"
                "The raw payload (with PHI) stays on your machine. "
                "Only the redacted version is replayed through the pipeline."
            )
            st.markdown("")
            st.markdown("**Available scenarios:**")
            for key, s in MOCK_SCENARIOS.items():
                badge_color = s["badge_color"]
                st.markdown(f"- :{badge_color}[**{s['badge']}**] {key.split('—')[1].strip()}")

# ============================================================
# TAB 5 — DLP Coverage Dashboard
# ============================================================
with coverage_tab:
    st.markdown("### Active Redaction Rules")
    st.caption(
        "Every message passes through these patterns before reaching any AI model. "
        "Biometric identifiers (fingerprints, voiceprints, retinal scans) and full-face photos "
        "— HIPAA identifiers 16 & 17 — cannot be caught by regex and are flagged by the Claude semantic layer."
    )

    # ── Top metrics ──────────────────────────────────────────
    hipaa_count   = sum(1 for p in PATTERN_DISPLAY if p["hipaa"])
    total_count   = len(PATTERN_DISPLAY)
    cat_count     = len(set(p["category"] for p in PATTERN_DISPLAY))

    # Run live Veris simulation (cached in session state)
    if _VERIS_LOCAL and st.session_state.veris_local_report is None:
        try:
            st.session_state.veris_local_report = _run_veris_sim()
        except Exception:
            st.session_state.veris_local_report = {}

    _vr = st.session_state.veris_local_report or {}
    detection_pct = _vr.get("detection_rate", "—")
    fp_count      = _vr.get("false_positives", "—")
    total_cases   = _vr.get("total", "—")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total rules",          total_count)
    m2.metric("HIPAA Safe Harbor",    f"{hipaa_count} / 18")
    m3.metric("Veris detection rate", f"{detection_pct}%" if isinstance(detection_pct, (int, float)) else detection_pct)
    m4.metric("False positives",      fp_count)

    st.markdown("")

    # ── Veris Simulation panel ────────────────────────────────
    st.markdown("---")
    st.markdown("### Veris Adversarial Simulation")

    sim_col_left, sim_col_right = st.columns([2, 1])
    with sim_col_left:
        if _vr:
            accuracy  = _vr.get("accuracy", "—")
            precision = _vr.get("precision", "—")
            tp = _vr.get("true_positives", 0)
            tn = _vr.get("true_negatives", 0)
            fp_n = _vr.get("false_positives", 0)
            fn = _vr.get("false_negatives", 0)
            pass_icon = "🟢 PASS" if (isinstance(detection_pct, (int, float)) and detection_pct >= 70 and fp_n <= 2) else "🔴 FAIL"
            st.markdown(
                f"**{pass_icon}** &nbsp;|&nbsp; "
                f"Detection rate: **{detection_pct}%** &nbsp;|&nbsp; "
                f"Accuracy: **{accuracy}%** &nbsp;|&nbsp; "
                f"Precision: **{precision}%**\n\n"
                f"TP=**{tp}** &nbsp; TN=**{tn}** &nbsp; FP=**{fp_n}** &nbsp; FN=**{fn}** &nbsp; "
                f"Total cases=**{total_cases}**"
            )
            by_cat = _vr.get("by_category", {})
            if by_cat:
                cat_lines = []
                for cat, stats in by_cat.items():
                    pct = round(stats["correct"] / stats["total"] * 100) if stats["total"] else 0
                    bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
                    cat_lines.append(f"`{cat:<14}` {bar} {pct}%  ({stats['correct']}/{stats['total']})")
                with st.expander("Category breakdown"):
                    st.code("\n".join(cat_lines), language=None)
        else:
            st.caption("Live simulation not available in this environment.")

    with sim_col_right:
        # Latest GitHub Actions run
        run_data = fetch_latest_sim_run()

        # Check if a recently triggered run is still in progress
        import time as _time
        triggered_recently = (
            st.session_state.sim_triggered_at is not None
            and _time.time() - st.session_state.sim_triggered_at < 300
        )
        if triggered_recently and run_data.get("status") in ("queued", "in_progress"):
            st.info("⏳ Simulation in progress…")

        if "error" in run_data:
            if run_data["error"] == "no_token":
                st.caption("Add `GITHUB_TOKEN` to see CI run history.")
            else:
                st.caption(f"Could not fetch run history: {run_data['error']}")
        elif "none" in run_data:
            st.caption("No simulation runs found — trigger one below.")
        else:
            status     = run_data.get("status", "")
            conclusion = run_data.get("conclusion", "")
            if status == "completed":
                badge = "🟢 passed" if conclusion == "success" else "🔴 failed" if conclusion == "failure" else f"⚪ {conclusion}"
            elif status == "in_progress":
                badge = "⏳ running"
            else:
                badge = f"⏳ {status}"

            created_str = run_data.get("created_at", "")[:16].replace("T", " ")
            st.markdown(
                f"**Latest CI run:** {badge}\n\n"
                f"Run #{run_data['run_number']} · `{run_data.get('branch', '')}` · {created_str} UTC"
            )
            st.markdown(f"[**→ View full results on GitHub Actions**]({run_data['html_url']})")

            if run_data.get("recent"):
                with st.expander("Run history (last 5)"):
                    for rx in run_data["recent"]:
                        conc = rx.get("conclusion") or rx.get("status", "")
                        ico  = "🟢" if conc == "success" else "🔴" if conc == "failure" else "⏳"
                        ts   = rx.get("created_at", "")[:16].replace("T", " ")
                        st.markdown(f"{ico} [Run #{rx['run_number']}]({rx['html_url']}) · `{rx['branch']}` · {ts}")

        if st.button("↺ Refresh run status", key="refresh_sim_status", use_container_width=True):
            st.session_state.sim_run_cache = None
            st.rerun()

    st.markdown("---")

    # ── Rules grid by category ────────────────────────────────
    for category in CATEGORY_ORDER:
        rules = [p for p in PATTERN_DISPLAY if p["category"] == category]
        if not rules:
            continue

        st.markdown(f"**{category}** — {len(rules)} rule{'s' if len(rules) != 1 else ''}")
        cols = st.columns(3)
        for i, rule in enumerate(rules):
            with cols[i % 3]:
                with st.container(border=True):
                    hipaa_tag = f"  `HIPAA #{rule['hipaa']}`" if rule["hipaa"] else ""
                    st.markdown(f"**{rule['label']}**{hipaa_tag}")
                    st.caption(f"`{rule['type']}`")
                    st.code(rule["example"], language=None)
        st.markdown("")

    # ── Add new rule ──────────────────────────────────────────
    st.markdown("---")
    st.markdown("### ➕ Add New Redaction Rule")
    st.caption(
        "Describe the new PHI type. MediGuard will generate the regex, "
        "open a PR, and trigger the Veris adversarial simulation — no manual coding needed."
    )

    has_github = bool(os.getenv("GITHUB_TOKEN"))
    if not has_github:
        st.warning(
            "**GitHub integration not configured.** "
            "Add `GITHUB_TOKEN` to Railway → Variables to enable automatic PR creation. "
            "The form below shows what would happen."
        )

    with st.form("add_rule_form", clear_on_submit=False):
        fc1, fc2 = st.columns(2)
        with fc1:
            new_type = st.text_input(
                "Pattern name (snake_case)",
                value="zip_code",
                help="Used as the redaction label, e.g. [REDACTED:zip_code]",
            )
            new_desc = st.text_input(
                "Description",
                value="US zip codes — HIPAA geographic identifier (#2)",
            )
        with fc2:
            new_example = st.text_input(
                "Example that should be caught",
                value="My zip code is 10013",
            )
            new_regex = st.text_input(
                "Regex (leave blank to auto-generate with Claude)",
                value=r"\bzip(?:\s+code)?\s*:?\s*\d{5}(?:-\d{4})?\b",
            )

        submitted = st.form_submit_button(
            "Add Rule + Open PR",
            type="primary",
            use_container_width=True,
            disabled=(not new_type or not new_example),
        )

    if submitted and new_type and new_example:
        # Validate pattern name
        import re as _re
        if not _re.match(r'^[a-z][a-z0-9_]*$', new_type):
            st.error("Pattern name must be lowercase letters, digits, and underscores only (e.g. zip_code).")
        else:
            regex_to_use = new_regex.strip()

            if not regex_to_use:
                with st.spinner("Generating regex with Claude Haiku..."):
                    regex_to_use = _generate_regex_claude(new_type, new_example, new_desc or new_type)
                st.info(f"Auto-generated regex: `{regex_to_use}`")

            # Validate regex compiles
            try:
                _re.compile(regex_to_use)
            except _re.error as e:
                st.error(f"Regex syntax error: {e}")
                regex_to_use = None

            if regex_to_use:
                with st.spinner("Creating branch, committing pattern, opening PR, triggering Veris simulation..."):
                    result = github_add_pattern(
                        pattern_name=new_type,
                        regex=regex_to_use,
                        description=new_desc or new_type,
                        example=new_example,
                    )
                st.session_state.pr_result = result

    # ── PR result ─────────────────────────────────────────────
    if st.session_state.pr_result:
        result = st.session_state.pr_result
        if "error" in result:
            st.error(f"**Error:** {result['error']}")
        else:
            st.success(f"**PR opened → `develop`**")
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.markdown(
                    f"#### [View PR #{result['pr_number']} →]({result['pr_url']})\n"
                    f"`{result['branch']}` → `develop`"
                )
            with col_b:
                if st.button("▶ Run Veris Simulation", type="primary", key="trigger_sim", use_container_width=True):
                    with st.spinner("Triggering Veris simulation..."):
                        trig = veris_trigger_run()
                    if "error" in trig:
                        st.error(trig["error"])
                    else:
                        import time as _t
                        st.session_state.sim_triggered_at = _t.time()
                        st.session_state.veris_run_id = trig["run_id"]
                        st.session_state.sim_run_cache = None
                        st.success(f"Veris run started — {trig['total']} simulations queued.")
                        st.markdown(f"Run ID: `{trig['run_id']}`")
            with col_c:
                if st.button("Clear", key="clear_pr", use_container_width=True):
                    st.session_state.pr_result = None
                    st.session_state.pop("veris_run_id", None)
                    st.session_state.pop("veris_report", None)
                    st.rerun()

            run_id = st.session_state.get("veris_run_id")
            if run_id:
                st.markdown(f"**Active Veris run:** `{run_id}` — scroll down to Check Results.")


# ============================================================
# Veris Run Results
# ============================================================
st.markdown("---")
st.markdown("### Veris Simulation Results")
st.caption("Check the status of any Veris run by ID.")

_default_run_id = st.session_state.get("veris_run_id", "")
_run_id_input = st.text_input("Veris Run ID", value=_default_run_id, placeholder="run_abc123...", key="veris_run_id_input")

if st.button("🔄 Check Results", key="check_veris_standalone"):
    if not _run_id_input:
        st.warning("Enter a run ID above.")
    else:
        with st.spinner("Fetching from Veris..."):
            _report = veris_fetch_run_report(_run_id_input)
        st.session_state.veris_report = _report

_report = st.session_state.get("veris_report")
if _report:
    if "error" in _report:
        st.error(_report["error"])
    else:
        _status = _report["status"]
        _color  = {"completed": "green", "failed": "red", "running": "orange", "provisioning": "blue"}.get(_status, "gray")
        st.markdown(f"**Status:** :{_color}[**{_status}**]")
        st.markdown(f"{_report['completed']}/{_report['total']} simulations complete · {_report['failed']} failed")
        if _report.get("duration"):
            st.caption(f"Duration: {_report['duration']:.0f}s")
        if _status != "completed":
            st.info("Run still in progress — hit Check Results again to refresh.")
        elif _report.get("simulations"):
            _sims = _report["simulations"]
            _passed = sum(1 for s in _sims if not s.get("failed"))
            st.markdown(f"**{_passed}/{len(_sims)} passed**")
            for _sim in _sims[:10]:
                _sid = _sim.get("id", "")[:20]
                _res = _sim.get("result") or _sim.get("status", "")
                st.markdown(f"- `{_sid}` — {_res}")
            if len(_sims) > 10:
                st.caption(f"…and {len(_sims) - 10} more")


# ============================================================
# Live Audit Log
# ============================================================
st.markdown("---")
st.markdown("### Live HIPAA Audit Log")
st.caption("Every scan is logged. This is the compliance trail your legal team needs.")
try:
    with open("dlp_audit_log.jsonl") as f:
        entries = [json.loads(line) for line in f.readlines()[-10:]]
    for entry in reversed(entries):
        sev   = entry["severity"]
        color = "red" if sev == "high" else "orange" if sev == "medium" else "green"
        types = ", ".join(entry.get("finding_types", [])) or "none"
        st.markdown(
            f"`{entry['timestamp']}` &nbsp;|&nbsp; user: `{entry['user_id']}` &nbsp;|&nbsp; "
            f"severity: :{color}[**{sev}**] &nbsp;|&nbsp; findings: `{entry['findings_count']}` &nbsp;|&nbsp; "
            f"types: `{types}` &nbsp;|&nbsp; safe: `{entry['safe_to_send']}`"
        )
except FileNotFoundError:
    st.caption("No scans yet.")
