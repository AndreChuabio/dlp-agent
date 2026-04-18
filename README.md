# DLP Agent

HIPAA-compliant AI guardrail layer for healthcare and regulated industries.

Intercepts, redacts, and logs sensitive patient data before it reaches any AI model.

---

## The Problem

Healthcare companies, law firms, and banks cannot let employees use AI tools. One paste of patient data into ChatGPT is a HIPAA violation and a $1M fine. This agent is the privacy layer that unblocks them.

---

## How It Works

```
Patient speaks
      |
      v
Voicerun (speech-to-text)
      |
      v
Regex scan — SSN, MRN, ICD codes, DOB, API keys
      |
      v
Baseten triage — fast binary flag: sensitive or not?
      |
    NO  → return safe, skip Claude
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
Redact + Audit log
      |
      v
Clean text → AI assistant responds
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
BASETEN_MODEL_ID=     # swap to test different triage models
VOICERUN_API_KEY=
```

---

## What Gets Detected

| Layer | Catches |
|---|---|
| Regex | SSN, credit card, email, phone, API keys, MRN, NPI, ICD codes, DOB, insurance IDs |
| Baseten | Binary triage — routes to deep scan only when needed |
| Claude | Contextual PHI — diagnoses, medications, mental health info, treatment plans |
| OpenAI | Cross-validates high severity Claude findings |

---

## Repo Structure

```
dlp-agent/
├── main.py              — CLI entry point
├── agent/
│   ├── tools.py         — full detection pipeline
│   ├── orchestrator.py  — agent loop
│   └── prompts.py       — system prompts
├── api/server.py        — FastAPI POST /scan
├── ui/app.py            — Streamlit demo UI
└── tests/test_agent.py  — smoke tests
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
