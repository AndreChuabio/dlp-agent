# DLP Agent — VS Code Copilot Instructions

## What This Project Is

Enterprise Data Loss Prevention (DLP) agent built for the Enterprise Agent Jam NYC hackathon.
Target users: healthcare companies, law firms, banks — regulated industries blocked from using AI tools due to data leakage risk.

Core pitch: "Healthcare companies, law firms, banks — they can't let employees use AI tools. One paste of patient data into ChatGPT is a HIPAA violation and a $1M fine. We built the guardrail layer that fixes that."

Nikki (teammate) lived this problem — her team couldn't use Claude until they had privacy controls. She speaks from personal experience in the demo.

## Detection Pipeline

```
Patient speaks
      |
      v
Voicerun (speech-to-text)
      |
      v
Raw transcript text
      |
      v
1. Regex scan        — SSN, MRN, ICD codes, DOB, API keys (instant, free)
      |
      v
2. Baseten triage    — fast open-source model: "is this sensitive?" YES/NO
      |
    NO  → skip Claude, return safe immediately
    YES ↓
      |
      v
3. Claude semantic   — contextual PHI: diagnoses, medications, treatment plans
      |
    severity=high ↓
      |
      v
4. OpenAI second opinion — cross-validates high severity findings only
      |
      v
5. Redact            — replace findings with [REDACTED:TYPE] tokens
      |
      v
6. Audit log         — append to dlp_audit_log.jsonl (HIPAA audit trail)
      |
      v
Clean text → AI assistant responds
```

## Repo Structure

```
dlp-agent/
├── main.py                  — CLI entry point
├── agent/
│   ├── tools.py             — full pipeline: all 6 steps above
│   ├── orchestrator.py      — thin loop: text/audio in → result dict out
│   └── prompts.py           — Claude + OpenAI prompt strings
├── api/
│   └── server.py            — FastAPI POST /scan
├── ui/
│   └── app.py               — Streamlit demo UI
├── tests/
│   └── test_agent.py        — smoke tests
├── .env                     — API keys (never commit)
├── .env.example             — template
└── requirements.txt
```

## Sponsor Integrations

| Sponsor | Role | Points | Notes |
|---|---|---|---|
| Veris AI | Adversarial sandbox — run before demo, screenshot detection rate | 4 pts | Sign up at console.veris.ai — they whitelist and email back |
| Baseten | Triage gate in pipeline — binary flag before Claude | 2 pts | Set BASETEN_MODEL_ID in .env — swap freely when testing |
| OpenAI | Second opinion on high severity findings only | 2 pts | Promo code PJTJR5VEGMNDQR9J at platform.openai.com |
| Voicerun | Speech-to-text input layer | 2 pts | pip install voicerun-cli && vr setup |

**Baseten model swap:** change `BASETEN_MODEL_ID` in `.env`, restart — zero code changes needed.

## Environment Variables

```
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
BASETEN_API_KEY=
BASETEN_MODEL_ID=        # swap freely when testing models against Veris sandbox
VOICERUN_API_KEY=
```

Never commit `.env`. It is in `.gitignore`.

## What We Detect

**Regex (structured):**
- SSN, credit card, email, phone, API keys
- MRN (medical record number), NPI, ICD codes, DOB
- Insurance IDs, medication dosages

**Claude semantic (contextual):**
- Diagnoses, conditions, symptoms — PHI even without a patient name
- Medications, dosages, treatment plans
- Mental health info (extra protected under 42 CFR Part 2)
- Lab results, imaging, procedures
- Insurance and billing context

**OpenAI:** validates Claude's high severity flags — adds cross-model credibility

## Scoring

| Category | Points | Our play |
|---|---|---|
| Sponsor Solutions | 10 pts (2 each, 4 Veris) | All 4 sponsors integrated |
| Usefulness & Impact | 5 pts | Real HIPAA problem Nikki lived |
| Technical Execution | 5 pts | Multi-model pipeline, live redaction |
| Creativity & Innovation | 5 pts | Voice → scan → redact loop |
| Presentation | 5 pts | Nikki tells her story, live demo |

## Build Order

1. `agent/tools.py` — core pipeline (already built)
2. `agent/prompts.py` — prompt strings (already built)
3. `agent/orchestrator.py` — thin loop (already built)
4. `main.py` — CLI (already built)
5. `api/server.py` — FastAPI wrapper (already built)
6. `ui/app.py` — Streamlit UI (already built)
7. `tests/test_agent.py` — smoke tests (already built)

## Time Plan

| Time | Goal |
|---|---|
| Now | Fill .env, pip install, run CLI test |
| 12:30 PM | All sponsors integrated and tested |
| 2:30 PM | Agent handles 3+ realistic clinical inputs |
| 3:30 PM | Run Veris adversarial sandbox, screenshot report |
| 4:30 PM | Demo rehearsal — Nikki leads pitch |
| 5:00 PM | Code freeze |
| 5:30 PM | Demo |

## Demo Flow

1. Nikki tells her story: "My team couldn't use Claude until we had this."
2. Patient speaks: "Hi I'm John Smith, MRN 123456, DOB 04/12/1985, I'm on 50mg sertraline for F32.1..."
3. Voicerun transcribes
4. Agent intercepts — regex + Baseten + Claude fire
5. Show redacted output side by side with original
6. Audit log updates live on screen
7. Show Veris report: "X% detection rate across 50 adversarial attempts"

## Coding Standards

- Python, PEP8, docstrings on all functions
- No hardcoded secrets — always `os.getenv()`
- Logging and exceptions over silent failures
- Expand existing files — do not create new ones
- Keep `requirements.txt` updated

## Scope Cut Priority

1. Cut polish
2. Cut secondary features
3. Cut Streamlit UI (CLI is fine for demo)
4. Never cut: regex + Claude semantic + audit log + happy path demo flow

## Do Not

- Do not hardcode API keys
- Do not create new files unless absolutely necessary
- Do not add features beyond demo scope
- Do not leave TODOs or half-finished implementations
- Do not commit `.env`, credentials, or instruction files
