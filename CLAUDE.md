# Enterprise Agent Jam NYC — CLAUDE.md

You are the AI backbone for a hackathon project building an **enterprise AI agent** in 6 hours.
Code freeze is at 5:00 PM. Demo is at 5:30 PM. All code must be written today.

## Project Context

- **Event:** Enterprise Agent Jam NYC — hosted at **Veris AI's office**, SoHo (organized by Andi Partovi)
- **Goal:** Build a working enterprise AI agent, demo it live
- **Judging vibe:** Real demo > slides, working tool use > vaporware, enterprise use case > consumer toy
- **Stack:** Claude (you) as the orchestration brain + sponsor APIs as tools
- **Key insight:** Veris AI is the HOST — judges are their team. Integrating or demoing Veris AI's simulation sandbox is a strategic win, not just a technical one

## Teammate Context — Nikki

Nikki works at a company that handles **healthcare data (PHI/HIPAA)**. Key things she said that sharpen the idea:
- "We couldn't use Claude until we were able to get private" — the DLP agent IS the solution that would have unblocked them
- "I like the guardrails / observability part of AI agents" — she wants to see logging, audit trails, monitoring, not just redaction
- Her CTO built an internal agent routing system (like OpenClaw) and is **stuck on guardrails** — we are literally building those guardrails
- Her team has had real incidents of prod data leaking from local environments

**What this means for the build:**
- Lead the pitch with healthcare/regulated industries — "Companies with sensitive data can't use AI tools. We fix that."
- HIPAA/PHI detection is now a core feature, not an afterthought
- Add an **observability layer** — every scan gets logged with what was found, severity, and timestamp. Nikki will push for this and it makes the demo stronger
- Framing shift: this isn't just about preventing leaks — it's about **enabling AI adoption** in industries that are currently locked out

## Ground Rules

- Ship working > ship perfect. Cut scope before cutting the demo
- Always prefer a live demo path over a polished one that might break
- No pre-built project code — everything written today
- Keep the main agent loop simple: input → LLM reasoning → tool call → output
- Commit working checkpoints every ~30 min so we can always roll back

## Repo Structure

```
project/
├── CLAUDE.md           ← you are here
├── main.py             ← agent entry point
├── agent/
│   ├── orchestrator.py ← main agent loop
│   ├── tools.py        ← all tool definitions
│   └── prompts.py      ← system prompts
├── api/
│   └── server.py       ← FastAPI app (if needed)
├── ui/
│   └── app.py          ← Streamlit demo UI
├── tests/
│   └── test_agent.py   ← basic smoke tests
├── .env                ← API keys (never commit)
└── requirements.txt
```

## Available APIs & Tools

### Anthropic / Claude — ready to use
```python
import anthropic
client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from .env

response = client.messages.create(
    model="claude-opus-4-6",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Scan this for sensitive data: ..."}]
)
print(response.content[0].text)
```

### You.com Search API — regulatory grounding
Get your API key at the You.com table when you arrive.
```python
import requests, os

def search_regulatory_context(query: str) -> str:
    resp = requests.get(
        "https://api.you.com/search",
        params={"q": query, "num_web_results": 3},
        headers={"X-API-Key": os.getenv("YOUCOM_API_KEY")}
    )
    results = resp.json().get("web", {}).get("results", [])
    return "\n".join(r["snippet"] for r in results)

# Usage: search_regulatory_context("what counts as PII under GDPR")
```

### Baseten — open source model inference
Get your API key + a model ID from the Baseten table. Swap in the model_id they give you.
```python
import requests, os

def run_baseten_model(prompt: str, model_id: str) -> str:
    resp = requests.post(
        f"https://model-{model_id}.api.baseten.co/production/predict",
        headers={"Authorization": f"Api-Key {os.getenv('BASETEN_API_KEY')}"},
        json={"prompt": prompt}
    )
    return resp.json().get("output", "")
```

### Veris AI ⭐ (HOST — judges are their team)
Talk to the Veris AI team at 9:30 AM — ask for sandbox access. They will help you set it up.
- Run adversarial test scenarios against the DLP agent
- Outputs detection rate reports you can screenshot for the demo
- **The move:** show "we ran 50 simulated leak attempts, here's our detection rate" → instant credibility
- If API access isn't ready in time, ask them to demo their sandbox on your agent live — they'll love it

## DLP Agent — Core Building Blocks

This is the core code to get the scanner working. Start here at 11 AM.

### 1. Regex scanner (fast, no API needed)
```python
import re

PATTERNS = {
    # Standard PII
    "SSN":              r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card":      r"\b(?:\d{4}[- ]){3}\d{4}\b",
    "email":            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone":            r"\b\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b",
    "api_key":          r"\b(sk-|pk_|AIza)[A-Za-z0-9_\-]{20,}\b",
    # HIPAA / Healthcare PHI
    "medical_record":   r"\bMRN[\s:#-]*\d{5,10}\b",
    "npi_number":       r"\bNPI[\s:#-]*\d{10}\b",
    "icd_code":         r"\b[A-Z]\d{2}\.?\d{0,2}\b",
    "dob":              r"\b(DOB|Date of Birth|born)[\s:]+\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
}

def regex_scan(text: str) -> list[dict]:
    findings = []
    for label, pattern in PATTERNS.items():
        for match in re.finditer(pattern, text):
            findings.append({"type": label, "value": match.group(), "start": match.start(), "end": match.end()})
    return findings
```

### 2. Claude semantic scanner (catches what regex misses)
```python
import anthropic, json

client = anthropic.Anthropic()

SCAN_PROMPT = """Analyze the following text for sensitive enterprise information.
Look for: unreleased financials, trade secrets, internal project names, employee data, legal terms, strategic plans, patient health information, diagnoses, medications, treatment plans, insurance info, anything that would violate HIPAA or GDPR.
Regex already caught structured PII — focus on semantic/contextual sensitivity (e.g. "the patient responded well to treatment" is PHI even without a name).

Return JSON: {{"findings": [{{"type": "...", "excerpt": "...", "reason": "...", "severity": "high|medium|low", "regulation": "HIPAA|GDPR|SOC2|general"}}]}}

Text: {text}"""

def claude_semantic_scan(text: str) -> list[dict]:
    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": SCAN_PROMPT.format(text=text)}]
    )
    result = json.loads(response.content[0].text)
    return result.get("findings", [])
```

### 3. Redactor
```python
def redact_text(text: str, regex_findings: list[dict]) -> str:
    for finding in sorted(regex_findings, key=lambda x: x["start"], reverse=True):
        replacement = f"[REDACTED:{finding['type']}]"
        text = text[:finding["start"]] + replacement + text[finding["end"]:]
    return text
```

### 4. Observability logger (audit trail)
```python
import json
from datetime import datetime

LOG_FILE = "dlp_audit_log.jsonl"

def log_scan(user_id: str, result: dict):
    entry = {
        "timestamp":      datetime.utcnow().isoformat(),
        "user_id":        user_id,
        "safe_to_send":   result["safe_to_send"],
        "findings_count": len(result["regex_findings"]) + len(result["semantic_findings"]),
        "finding_types":  [f["type"] for f in result["regex_findings"]] +
                          [f["type"] for f in result["semantic_findings"]],
        "severity":       "high" if any(f.get("severity") == "high" for f in result["semantic_findings"]) else "medium"
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
```

### 5. Full pipeline
```python
def scan_and_clean(user_message: str, user_id: str = "anonymous") -> dict:
    regex_hits    = regex_scan(user_message)
    semantic_hits = claude_semantic_scan(user_message)
    clean_message = redact_text(user_message, regex_hits)
    result = {
        "original":          user_message,
        "clean":             clean_message,
        "regex_findings":    regex_hits,
        "semantic_findings": semantic_hits,
        "safe_to_send":      len(regex_hits) == 0 and len(semantic_hits) == 0
    }
    log_scan(user_id, result)
    return result
```

---

## Subagents

### /architect
System designer. Called at the start and when scope needs cutting.
- Think in data flow: input → processing → output → action
- Propose the simplest architecture that could win
- Flag anything that could blow up in the demo
- Output: ASCII diagram + one-line rationale per decision

### /builder
Focused coder. Writes clean, working code fast.
- Always runnable code, never pseudocode
- Real error handling — agents fail in demos, handle it gracefully
- `python-dotenv` for all API keys, never hardcode
- After each implementation: tell me what to run to test it

### /researcher
Fast context gatherer.
- Search for SDK docs, API examples, error explanations
- Return most relevant snippet + source URL, nothing more
- If undocumented, say so immediately — don't guess

### /qa
Adversarial tester. Breaks things before the demo does.
- Think like a judge who wants the agent to fail
- Write smoke tests covering the demo scenario end-to-end
- Output: risks ordered by likelihood × impact

### /demo
Demo director.
- Script the exact demo flow: what gets typed, what the agent does, what we say
- Identify the "wow moment"
- Prepare a fallback if live demo breaks
- Draft the 3-sentence pitch

---

## Time Checkpoints

| Time | Goal | Subagent |
|------|------|----------|
| 9:30 AM | Arrive early — get Veris AI sandbox access | — |
| ~10:00 AM | Keynote — listen for judging criteria | — |
| 11:00 AM | Idea locked, repo created | `/architect` |
| 11:30 AM | Core agent loop running | `/builder` |
| 12:30 PM | First tool integration working | `/builder` |
| 1:30 PM | You.com + observability logger done | `/builder` |
| 2:30 PM | Agent handles 3+ realistic inputs | `/qa` |
| 3:30 PM | Streamlit UI live | `/builder` |
| 4:30 PM | Demo rehearsal | `/demo` |
| 5:00 PM | **Code freeze** — commit, tag v1.0 | — |
| 5:30 PM | **Demo** | `/demo` |

## Scope Cut Priority
1. Cut polish
2. Cut secondary features
3. Cut frontend (CLI is fine)
4. **Never cut:** the happy path demo flow

## Demo Pitch

> "Healthcare companies, law firms, banks — they can't let employees use AI tools. One paste of patient data into ChatGPT is a HIPAA violation and a $1M fine. We built the guardrail layer that fixes that."

Nikki speaks from personal experience. Then demo. Then stop talking.

## Winning Meta-Strategy

Veris AI runs this event. They care about:
1. Does the agent actually work?
2. Does it handle failure gracefully?
3. Is it a real enterprise problem?

Show agent working → edge case handled → Veris AI simulation results. That's production-readiness. That's what wins.
