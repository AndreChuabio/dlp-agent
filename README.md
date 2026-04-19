# MediGuard AI

[![PyPI version](https://img.shields.io/pypi/v/mediguard-dlp.svg)](https://pypi.org/project/mediguard-dlp/)
[![Python](https://img.shields.io/pypi/pyversions/mediguard-dlp.svg)](https://pypi.org/project/mediguard-dlp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

HIPAA-compliant AI middleware and primary care onboarding agent. Drop it in front of any LLM and patient conversations are automatically scanned, redacted, and logged. The voice agent layer onboards patients and routes them directly to the right specialist — no forms, no waiting room, no GP appointment just to get a referral.

Ships as both a **standalone app** (voice agent, dashboard, FastAPI) and an **installable MCP server** (`pipx install mediguard-dlp`) that plugs into Claude Code, Claude Desktop, Cursor, and Windsurf.

---

## The Problem

Healthtech companies want to use AI. One message containing patient data is a HIPAA violation and a $1M fine. On top of that, the traditional path to a specialist is broken: patients book a GP appointment, wait weeks, get a referral slip, then wait again. Half those GP visits exist only to route the patient somewhere else.

MediGuard AI fixes both problems.

---

## What It Does

A patient calls in. The agent:

1. **Identifies them** — looks up their name against the patient database
2. **Returning patient** — skips re-collection, welcomes them back, asks what brings them in
3. **New patient** — collects name, DOB, and callback number conversationally (no forms)
4. **Triages** — uses Claude to semantically match their concern to the right specialist from a doctor database
5. **Recommends** — tells them exactly who to see and why, in plain language
6. **Saves** — new patients are written to the database so they never repeat themselves on the next call

Every message is intercepted by the DLP pipeline before reaching any model — the AI gets clean, anonymized input and your compliance trail is built automatically.

---

## Architecture

```
Patient speaks (Voicerun STT)
        |
        v
  ┌─────────────────────────────┐
  │       DLP Pipeline          │
  │                             │
  │  1. Regex scan              │  ← SSN, MRN, DOB, phone, insurance IDs
  │  2. Baseten triage          │  ← fast binary: sensitive or not?
  │  3. Claude semantic scan    │  ← contextual PHI (diagnoses, meds, etc.)
  │  4. OpenAI second opinion   │  ← cross-validates high-severity findings
  │  5. Redact + Audit log      │  ← HIPAA trail, safe message out
  └─────────────────────────────┘
        |
        | (redacted message)
        v
  ┌─────────────────────────────┐
  │    Onboarding & Triage      │
  │                             │
  │  Extract patient fields     │  ← name, DOB, phone, reason (raw_hint bypass)
  │  Lookup patient DB          │  ← returning vs. new patient
  │  Triage to specialist       │  ← Claude semantic match → doctors DB
  │  Save new patient record    │  ← written back to patients.json
  └─────────────────────────────┘
        |
        v
  LLM responds with full context
  (system prompt adapts to: new/returning, triage done/pending)
        |
        v
  Voicerun TTS → patient hears response
```

---

## Two Conversation Flows

### Returning Patient
```
Agent:   "Can I start by getting your name?"
Patient: "Alice Johnson"
Agent:   "Welcome back, Alice! I can see you were last in on October 15th.
          What brings you in today?"
Patient: "I've been having chest tightness lately."
Agent:   "Based on that, I'd recommend Dr. Sarah Chen, our Cardiologist —
          she's available Monday, Wednesday, and Friday. Our team will reach
          out to schedule the referral directly, no extra GP visit needed."
```

### New Patient
```
Agent:   "Can I start by getting your name?"
Patient: "James Park"
         [not found → new patient flow]
Agent:   "Nice to meet you, James! I don't have you in our system yet —
          let me get a few quick details. What's your date of birth?"
Patient: "March 4th, 1988"
Agent:   "Got it. And a callback number?"
Patient: "646-555-0192"
Agent:   "What's the main reason you're calling in today?"
Patient: "My stomach has been hurting a lot, especially after eating."
         [triage fires → Dr. Marcus Rivera, Gastroenterologist]
Agent:   "That sounds like a great fit for Dr. Marcus Rivera, our Gastroenterologist —
          he specializes in exactly that and is available Tuesday and Thursday.
          We'll follow up to get you scheduled."
         [James Park saved to patient DB]
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

# Run Voicerun agent
cd voicerun/dlp-health-agent
vr push && vr open
```

---

## Use as an MCP Server (Claude Code / Desktop / Cursor / Windsurf)

MediGuard ships as an installable MCP server — add a few lines to your client's config and every chat gets a local PHI firewall, redactor, and session replay debugger. Raw data never leaves your machine.

### Install

```bash
pipx install mediguard-dlp
# or, from this repo:
pip install -e .
```

This registers a `mediguard-dlp` CLI on your PATH. Verify with `which mediguard-dlp`.

### Configure your MCP client

**Claude Code** — add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "mediguard-dlp": {
      "command": "mediguard-dlp"
    }
  }
}
```

**Claude Desktop** — edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%/Claude/claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "mediguard-dlp": {
      "command": "mediguard-dlp",
      "env": {
        "ANTHROPIC_API_KEY": "sk-ant-...",
        "BASETEN_API_KEY": "...",
        "OPENAI_API_KEY": "sk-..."
      }
    }
  }
}
```

**Cursor / Windsurf** — same config block under their MCP settings.

If `ANTHROPIC_API_KEY` and `BASETEN_API_KEY` aren't set, the server runs in **regex-only mode** — still catches structured identifiers (SSN, MRN, DOB, phone, insurance IDs, ZIP) with zero network calls.

### Tools exposed

| Tool             | Purpose                                                                |
|------------------|------------------------------------------------------------------------|
| `dlp_scan`       | Full pipeline scan — regex + Baseten triage + Claude semantic          |
| `quick_redact`   | Regex-only redaction, sub-millisecond, no API calls                    |
| `ingest_payload` | Load a production log, redact PHI locally, save the clean version      |
| `replay_session` | Step a saved session through the agent pipeline                        |
| `list_sessions`  | List saved debug sessions                                              |
| `check_secrets`  | Show which secret keys are loaded (values never returned)              |

### Claude Code plugin (alternative install)

This repo is also a Claude Code plugin. From Claude Code:

```
/plugin marketplace add AndreChuabio/dlp-agent
/plugin install mediguard-dlp
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

## DLP Detection Layers

| Layer | What it catches |
|---|---|
| Regex | SSN, credit card, email, phone, MRN, NPI, ICD codes, DOB, insurance IDs, medication dosages |
| Baseten (DeepSeek V3.1) | Binary triage — skips Claude if message is clean |
| Claude (claude-opus-4-6) | Contextual PHI — diagnoses, medications, mental health treatment, insurance context |
| OpenAI (gpt-4o) | Cross-validates high severity Claude findings |

---

## Specialist Database

8 mocked specialists in `voicerun/data/doctors.json`, covering the most common referral paths:

| Specialist | Handles |
|---|---|
| Dr. Sarah Chen — Cardiologist | Chest pain, high cholesterol, hypertension, palpitations |
| Dr. Marcus Rivera — Gastroenterologist | Stomach pain, acid reflux, IBS, bloating |
| Dr. Priya Patel — Endocrinologist & Dietitian | Diabetes, thyroid, weight management, blood sugar |
| Dr. James Kim — Orthopedic Specialist | Back pain, joint pain, sports injuries, arthritis |
| Dr. Leila Hassan — Dermatologist | Rashes, acne, eczema, skin infections |
| Dr. Michael Torres — Psychiatrist | Anxiety, depression, insomnia, PTSD, burnout |
| Dr. Aisha Okonkwo — Pulmonologist | Cough, asthma, breathing difficulty, sleep apnea |
| Dr. Robert Walsh — General Practitioner | Annual physical, flu, fever, anything unclear |

Triage is powered by Claude semantic matching — it understands "my stomach has been off" the same as "abdominal discomfort post-meals."

---

## Dashboard

Three tabs:

- **Agent Chat** — conversational onboarding. Patient types naturally, DLP fires on every message, agent collects info and triages in real time
- **DLP Scanner** — paste any text, see findings broken down by layer with original vs redacted side by side
- **Voice Input** — record audio, transcribed via Whisper, then scanned

Sidebar shows collected patient info as the conversation builds. Live HIPAA audit log at the bottom updates after every scan.

---

## Repo Structure

```
dlp-agent/
├── main.py                          — CLI entry point
├── agent/
│   ├── tools.py                     — DLP pipeline, patient DB, triage logic
│   ├── orchestrator.py              — agent loop
│   └── prompts.py                   — system prompts
├── api/
│   └── server.py                    — FastAPI /chat + /scan endpoints
├── ui/
│   └── app.py                       — Streamlit dashboard
├── voicerun/
│   ├── data/
│   │   ├── doctors.json             — specialist database (8 doctors)
│   │   └── patients.json            — patient records (persistent across calls)
│   └── dlp-health-agent/
│       ├── handler.py               — onboarding + triage voice agent
│       └── README.md                — Voicerun-specific docs
├── .veris/
│   ├── Dockerfile.sandbox           — Veris simulation container
│   └── veris.yaml                   — Veris environment config
└── tests/
    └── test_agent.py                — smoke tests
```

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

## Sponsor Integrations

| Sponsor | Role |
|---|---|
| Anthropic Claude | Semantic PHI detection + agent responses + patient info extraction + triage matching |
| Baseten (DeepSeek V3.1) | Fast triage gate — skips Claude when message is clean |
| OpenAI (Whisper + GPT-4o) | Voice transcription + high severity validation + agent LLM |
| You.com | Insurance coverage search using ID only |
| Voicerun | Voice agent layer — patients call in, no typing required |
| Veris AI | Adversarial simulation sandbox — validates detection rate |

---

Built at Enterprise Agent Jam NYC.
