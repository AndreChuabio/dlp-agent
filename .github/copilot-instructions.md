# DLP Agent — VS Code Copilot Instructions

## What This Project Is

Enterprise Data Loss Prevention (DLP) agent built for the Enterprise Agent Jam NYC hackathon.
Target users: healthcare companies, law firms, banks — regulated industries that cannot safely use AI tools without a guardrail layer.

Core pitch: "One paste of patient data into ChatGPT is a HIPAA violation and a $1M fine. We built the layer that prevents that."

## Architecture

```
user message → regex scan → Claude semantic scan → redact → log → clean output
```

- `main.py` — entry point
- `agent/orchestrator.py` — main agent loop
- `agent/tools.py` — all tool definitions (regex scan, semantic scan, redactor, logger)
- `agent/prompts.py` — system prompts for Claude
- `api/server.py` — FastAPI app
- `ui/app.py` — Streamlit demo UI
- `tests/test_agent.py` — smoke tests

## Tech Stack

- Python, FastAPI, Streamlit
- Anthropic Claude API (`claude-opus-4-6`) — semantic scanning
- Regex — fast structured PII detection
- python-dotenv — all secrets via `.env`
- Logging to `dlp_audit_log.jsonl`

## Sensitive Data Patterns We Detect

- SSN, credit card, email, phone
- API keys (`sk-`, `pk_`, `AIza` prefixes)
- HIPAA/PHI: medical record numbers (MRN), NPI numbers, ICD codes, date of birth
- Semantic: diagnoses, treatment plans, medications, insurance info — caught by Claude even without structured identifiers

## Coding Standards

- Python, PEP8, docstrings on all functions
- Vectorized/efficient code — prefer NumPy/Pandas over loops
- Logging and exceptions over silent failures
- No hardcoded secrets — always use `os.getenv()`
- No redundant functions
- Keep `requirements.txt` updated

## What the Agent Must Do

1. Accept raw user text as input
2. Run regex scan (fast, no API)
3. Run Claude semantic scan (catches contextual PHI/PII regex misses)
4. Redact findings from original text
5. Log every scan to `dlp_audit_log.jsonl` with timestamp, user_id, finding types, severity
6. Return: original, cleaned text, all findings, and `safe_to_send` boolean

## Priority Order (hackathon scope)

1. Working happy-path demo — never cut this
2. Observability/audit log — judges want to see it
3. HIPAA/PHI detection — core differentiator
4. Streamlit UI — nice to have, not required
5. Polish — cut first if time runs short

## Environment Variables (via .env)

```
ANTHROPIC_API_KEY=
YOUCOM_API_KEY=
BASETEN_API_KEY=
```

Never commit `.env`. It is in `.gitignore`.

## Do Not

- Do not hardcode API keys
- Do not create new files unless absolutely necessary — expand existing ones
- Do not add features beyond the demo scope
- Do not leave TODOs or half-finished implementations
- Do not use `any` in TypeScript if you touch JS
- Do not commit `.env`, credentials, or this instructions file
