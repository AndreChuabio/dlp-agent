# MediGuard AI

HIPAA-compliant patient onboarding agent. Patients call in, speak naturally, and get onboarded — no forms, no paperwork. Every message is scanned and redacted before it reaches any AI model.

---

## The Problem

Healthcare companies cannot let employees or patients use AI tools. One message containing patient data is a HIPAA violation and a $1M fine. And traditional onboarding means patients filling out long forms before their first visit.

MediGuard AI fixes both problems.

---

## What It Does

A patient calls in. The agent collects their info conversationally — name, reason for visit, insurance ID. It searches their coverage in real time via You.com. All of this happens without a single form, and without any PHI ever reaching an AI model unprotected.

---

## How It Works

```
Patient speaks (Voicerun)
      |
      v
Regex scan — SSN, MRN, ICD codes, DOB, insurance IDs
      |
      v
Baseten triage — fast binary flag: sensitive or not?
      |
    NO  → skip Claude, return safe
    YES ↓
      |
      v
Claude semantic scan — contextual PHI: diagnoses, medications, treatment plans
      |
    high severity ↓
      |
      v
OpenAI second opinion — cross-validates high severity findings
      |
      v
Redact + Audit log (HIPAA-compliant trail)
      |
      v
Claude extracts structured fields from conversation
(patient name, insurance ID, reason, DOB)
      |
      v
You.com searches insurance coverage using ID only — never raw PHI
      |
      v
Agent responds: "You're covered for that visit, copay is $30"
```

---

## Quickstart

```bash
# Install dependencies
pip install -r requirements.txt

# Copy and fill in your API keys
cp .env.example .env

# Run via CLI
python main.py "Hi I'm John Smith, MRN 123456, I'm on 50mg sertraline for F32.1"

# Run Streamlit UI
streamlit run ui/app.py

# Run API server
uvicorn api.server:app --reload
```

---

## Environment Variables

```
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
BASETEN_API_KEY=
BASETEN_MODEL=deepseek-ai/DeepSeek-V3.1   # swap to test different triage models
YOUCOM_API_KEY=
VOICERUN_API_KEY=
```

---

## What Gets Detected

| Layer | Catches |
|---|---|
| Regex | SSN, credit card, email, phone, MRN, NPI, ICD codes, DOB, insurance IDs, medication dosages |
| Baseten | Binary triage — routes to deep scan only when needed |
| Claude | Contextual PHI — diagnoses, medications, mental health info, treatment plans |
| OpenAI | Cross-validates high severity Claude findings |

---

## Repo Structure

```
dlp-agent/
├── main.py                        — CLI entry point
├── agent/
│   ├── tools.py                   — full DLP pipeline + You.com search + patient extractor
│   ├── orchestrator.py            — agent loop
│   └── prompts.py                 — system prompts
├── api/server.py                  — FastAPI POST /scan
├── ui/app.py                      — Streamlit demo UI
├── voicerun/
│   └── dlp-health-agent/
│       └── handler.py             — Voicerun onboarding agent with DLP middleware
└── tests/test_agent.py            — smoke tests
```

---

## API

```
POST /scan
{
  "text": "patient message here",
  "user_id": "optional-user-id"
}
```

Returns: original text, redacted text, all findings, severity, `safe_to_send` boolean.

---

Built at Enterprise Agent Jam NYC.
