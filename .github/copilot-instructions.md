# MediGuard AI — VS Code Copilot Instructions

## What This Project Is

HIPAA-compliant AI middleware for healthtech startups. Intercepts patient messages, scans for PHI, redacts, logs, then passes clean text to any LLM. Patients onboard conversationally — no forms.

Built at Enterprise Agent Jam NYC.

---

## Pitch

"Healthtech startups want to use AI. They can't afford a private LLM. One PHI leak and they're done. Drop MediGuard in front of any model — you're compliant. Pay per use, no infrastructure."

Nikki (teammate) lived this — her company couldn't use Claude until they had privacy controls.

---

## Full Pipeline

```
Patient speaks/types
      |
      v
Voicerun (speech-to-text, optional)
      |
      v
1. Regex scan        — SSN, MRN, ICD codes, DOB, insurance IDs, medication dosages
2. Baseten triage    — DeepSeek V3.1 binary flag (skip Claude if safe)
3. Claude semantic   — contextual PHI: diagnoses, medications, mental health
4. OpenAI validation — cross-validates high severity findings
5. Redact            — [REDACTED:TYPE] tokens replace findings
6. Audit log         — append to dlp_audit_log.jsonl
7. Patient extractor — Claude pulls structured fields from conversation
8. You.com search    — insurance coverage lookup using ID only
9. Agent response    — Claude responds with coverage info
```

---

## Repo Structure

```
dlp-agent/
├── main.py                        — CLI entry point
├── agent/
│   ├── tools.py                   — all pipeline functions
│   ├── orchestrator.py            — thin agent loop
│   └── prompts.py                 — system prompts
├── api/server.py                  — FastAPI: POST /chat, POST /scan, GET /health
├── ui/app.py                      — Streamlit dashboard (3 tabs)
├── voicerun/dlp-health-agent/
│   └── handler.py                 — Voicerun voice agent handler
├── .veris/
│   ├── Dockerfile.sandbox         — Veris container config
│   └── veris.yaml                 — Veris simulation config
└── tests/test_agent.py            — smoke tests
```

---

## Key Functions in agent/tools.py

| Function | Does |
|---|---|
| `regex_scan(text)` | Fast structured PHI detection, returns list of findings with offsets |
| `baseten_triage(text)` | Calls DeepSeek V3.1 via Baseten — returns bool (escalate or not) |
| `claude_semantic_scan(text)` | Deep contextual PHI via Claude — catches what regex misses |
| `openai_second_opinion(text, findings)` | Validates high severity findings via GPT-4o |
| `redact_text(text, findings)` | Replaces regex findings with [REDACTED:TYPE] in-place |
| `log_scan(user_id, result)` | Appends to dlp_audit_log.jsonl |
| `extract_patient_info(messages)` | Claude extracts structured fields from conversation history |
| `search_insurance_coverage(insurance_id, reason)` | You.com search — never sends raw PHI |
| `scan_and_clean(text, user_id)` | Full pipeline — call this for everything |

---

## API Endpoints

```
POST /chat      — Veris-compatible conversational endpoint, runs full pipeline
POST /scan      — Raw DLP scan, returns findings + redacted text
GET  /health    — Health check
```

---

## Sponsor Integrations

| Sponsor | Points | Role |
|---|---|---|
| Veris AI | 4 pts | Adversarial sandbox — run before demo |
| Baseten | 2 pts | Triage gate — BASETEN_MODEL in .env to swap models |
| OpenAI | 2 pts | Whisper (voice) + GPT-4o (validation) |
| You.com | 2 pts | Insurance coverage search |
| Voicerun | 2 pts | Voice agent layer |

---

## Environment Variables

```
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
BASETEN_API_KEY=
BASETEN_MODEL=deepseek-ai/DeepSeek-V3.1
YOUCOM_API_KEY=
VOICERUN_API_KEY=
```

---

## Coding Standards

- Python, PEP8, docstrings on all functions
- No hardcoded secrets — always `os.getenv()`
- Expand existing files — do not create new ones
- Keep `requirements.txt` updated
- Logging and exceptions over silent failures

---

## Demo Flow

1. Nikki tells her story: "My team couldn't use Claude until we had this."
2. Open dashboard — Agent Chat tab
3. Paste: "Hi, my name is John Smith, DOB 04/12/1985, MRN 123456. I've been dealing with major depression and my doctor has me on 50mg sertraline. My insurance ID is BCX884521 and I need help finding a specialist."
4. Show: 12 findings redacted, DLP expander, agent response, sidebar patient info
5. Show: Live HIPAA audit log updating
6. Show: Veris detection rate report

---

## Scope Cut Priority

1. Cut polish
2. Cut Voicerun phone integration
3. Cut secondary features
4. Never cut: DLP pipeline, chat UI, audit log, happy path demo
