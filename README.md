# MediGuard AI

HIPAA-compliant AI middleware for healthtech startups. Drop it in front of any LLM and your patient conversations are automatically scanned, redacted, and logged — no private infrastructure required.

---

## The Problem

Healthtech startups want to use AI. They can't afford a private LLM. One message containing patient data is a HIPAA violation and a $1M fine. Compliance teams and private hosting are out of reach for early-stage companies.

MediGuard AI is the middleware layer that fixes that.

---

## What It Does

A patient calls or chats with your AI assistant. MediGuard intercepts every message, scans it for PHI, redacts it, and logs it — before it ever reaches the model. The AI gets clean, anonymized input. Your compliance trail is built automatically.

No forms. No paperwork. No PHI leaks.

---

## How It Works

```
Patient speaks or types
        |
        v
Voicerun (speech-to-text, optional)
        |
        v
Regex scan — SSN, MRN, ICD codes, DOB, insurance IDs, medication dosages
        |
        v
Baseten triage — fast binary flag via DeepSeek V3.1 (skip Claude if safe)
        |
      NO  → return safe immediately
      YES ↓
        |
        v
Claude semantic scan — contextual PHI: diagnoses, medications, mental health
        |
      high severity ↓
        |
        v
OpenAI second opinion — cross-validates high severity findings
        |
        v
Redact — replace findings with [REDACTED:TYPE] tokens
        |
        v
Audit log — append to dlp_audit_log.jsonl (HIPAA compliance trail)
        |
        v
Claude extracts structured fields from conversation
(patient name, insurance ID, reason for visit, DOB)
        |
        v
You.com searches insurance coverage using ID only — never raw PHI
        |
        v
Agent responds with coverage info. Patient never fills out a form.
```

---

## Quickstart

```bash
# Install dependencies
pip install -r requirements.txt

# Copy and fill in your API keys
cp .env.example .env

# Run via CLI
python main.py "Hi I'm John Smith, MRN 123456, DOB 04/12/1985. I'm on 50mg sertraline for F32.1. My insurance ID is BCX884521."

# Run the dashboard
streamlit run ui/app.py

# Run the API server
uvicorn api.server:app --reload --port 8008
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
| Baseten (DeepSeek V3.1) | Binary triage — skips Claude if message is clean |
| Claude (claude-opus-4-6) | Contextual PHI — diagnoses, medications, mental health treatment, insurance context |
| OpenAI (gpt-4o) | Cross-validates high severity Claude findings |

---

## Dashboard

Three tabs:

- **Agent Chat** — conversational onboarding. Patient types naturally, DLP fires on every message, agent collects info and searches insurance coverage in real time
- **DLP Scanner** — paste any text, see findings broken down by layer with original vs redacted side by side
- **Voice Input** — record audio, transcribed via Whisper, then scanned

Sidebar shows collected patient info and coverage results as the conversation builds. Live HIPAA audit log at the bottom updates after every scan.

---

## API

```
POST /chat
{
  "message": "patient message here",
  "session_id": "optional-session-id"
}

→ {
  "response": "agent reply",
  "session_id": "...",
  "dlp": {
    "safe_to_send": false,
    "findings_count": 12
  }
}

POST /scan
{
  "text": "raw text to scan",
  "user_id": "optional"
}

GET /health
```

---

## Repo Structure

```
dlp-agent/
├── main.py                          — CLI entry point
├── agent/
│   ├── tools.py                     — full DLP pipeline + You.com search + patient extractor
│   ├── orchestrator.py              — agent loop
│   └── prompts.py                   — system prompts
├── api/
│   └── server.py                    — FastAPI /chat + /scan endpoints
├── ui/
│   └── app.py                       — Streamlit dashboard
├── voicerun/
│   └── dlp-health-agent/
│       └── handler.py               — Voicerun voice agent with DLP middleware
├── .veris/
│   ├── Dockerfile.sandbox           — Veris simulation container
│   └── veris.yaml                   — Veris environment config
├── tests/
│   └── test_agent.py                — smoke tests
├── .env.example                     — environment variable template
└── requirements.txt
```

---

## Sponsor Integrations

| Sponsor | Role |
|---|---|
| Anthropic Claude | Semantic PHI detection + agent responses + patient info extraction |
| Baseten (DeepSeek V3.1) | Fast triage gate — skips Claude when message is clean |
| OpenAI (Whisper + GPT-4o) | Voice transcription + high severity validation |
| You.com | Insurance coverage search using ID only |
| Voicerun | Voice agent layer — patients call in, no typing required |
| Veris AI | Adversarial simulation sandbox — validates detection rate |

---

Built at Enterprise Agent Jam NYC.
