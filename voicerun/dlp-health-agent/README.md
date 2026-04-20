# dlp-health-agent

Primary care onboarding and triage voice agent. Identifies returning patients, onboards new ones, and routes every caller to the right specialist — all over a phone call, with HIPAA-compliant DLP scanning every message before it touches an LLM.

---

## Deploy

```bash
cd voicerun/dlp-health-agent
vr push    # deploy to Voicerun
vr open    # open debugger UI
```

---

## What the Agent Does Per Turn

Every patient message goes through this sequence:

```
1. DLP scan (regex + Baseten + Claude + OpenAI)
        ↓ redacted message
2. Extract patient fields (name, DOB, phone, reason)
        ↓
3. Patient lookup  ← fires once, as soon as name is known
   - Found    → returning patient, skip re-collection
   - Not found → new patient, collect DOB + phone
        ↓
4. Triage  ← fires once, as soon as reason/concern is known
   - Claude semantic match against doctors DB
   - Specialist recommendation injected into system prompt
        ↓
5. LLM responds (system prompt adapts to current state)
        ↓
6. Save new patient to DB (after triage completes)
```

---

## Conversation Flows

### Returning Patient

Patient is already in `voicerun/data/patients.json`.

```
Agent:   "Can I start by getting your name?"
Patient: "Alice Johnson"
         → lookup_patient("Alice Johnson") → found
Agent:   "Welcome back, Alice! I see you were last in on October 15th.
          What's bringing you in today?"
Patient: "My chest has been feeling tight."
         → triage_specialist("chest tightness") → Dr. Sarah Chen, Cardiologist
Agent:   "I'd recommend Dr. Sarah Chen, our Cardiologist — she's available
          Monday, Wednesday, and Friday and is exactly the right fit for that.
          Our team will reach out to get you scheduled directly."
```

DOB, phone, and insurance are never asked again.

### New Patient

Patient is not in the database.

```
Agent:   "Can I start by getting your name?"
Patient: "James Park"
         → lookup_patient("James Park") → not found
Agent:   "Nice to meet you, James! I don't have you in our system yet.
          What's your date of birth?"
Patient: "March 4th, 1988"
Agent:   "Got it. And a callback number?"
Patient: "646-555-0192"
Agent:   "What's the main reason you're calling in today?"
Patient: "My stomach has been hurting a lot after I eat."
         → triage_specialist("stomach pain after eating") → Dr. Marcus Rivera, Gastroenterologist
Agent:   "That sounds like a great fit for Dr. Marcus Rivera, our Gastroenterologist —
          he specializes in exactly that and is available Tuesday and Thursday.
          We'll follow up to schedule the referral."
         → save_patient({name: "James Park", dob: ..., phone: ..., conditions: [...], last_visit: today})
```

---

## Debug Events

All events are visible in the Voicerun debugger under the **Debug** tab.

| Event | When it fires | Key fields |
|---|---|---|
| `dlp_scan` | Every turn | `safe_to_send`, `regex_hits`, `semantic_hits`, `baseten_escalated`, `finding_types` |
| `patient_info` | Every turn | Presence flags + lengths only: `has_name`, `has_dob`, `has_phone`, `has_reason`, `name_len`, `reason_len` — values never leave the process |
| `patient_lookup` | Once, after name extracted | `found` (bool), `queried_name_len` — the actual name is not emitted |
| `triage_result` | Once, after concern extracted | `specialist_name`, `specialty`, `availability`, `reason` |

Collected values are held only in session state for the system prompt and the `save_patient` call; the debugger UI cannot shoulder-surf PHI. See `docs/P1-hardening.md`.

---

## Data Files

Both files live at `voicerun/data/` and are read/written at runtime.

### `doctors.json`

8 specialists. Claude uses this list for semantic triage — it reads the conditions each doctor treats and picks the best match for the patient's concern.

```json
{
  "doctors": [
    {
      "id": "dr_001",
      "name": "Dr. Sarah Chen",
      "specialty": "Cardiologist",
      "availability": "Mon, Wed, Fri",
      "conditions": ["chest pain", "high cholesterol", "hypertension", ...]
    }
  ]
}
```

To add a specialist: append an entry with `id`, `name`, `specialty`, `availability`, and a `conditions` array. No code changes needed — triage reads this file at call time.

### `patients.json`

Patient records. Pre-seeded with 3 returning patients for demo/testing:
- **Alice Johnson** — hypertension, high cholesterol
- **David Kim** — type 2 diabetes, obesity
- **Maria Santos** — lower back pain, arthritis

New patients are appended automatically after their first call completes triage. Records include: `id`, `name`, `dob`, `phone`, `insurance_id`, `conditions`, `last_visit`, `notes`.

---

## System Prompt Behavior

The system prompt passed to the LLM adapts every turn based on session state:

| State | What the LLM is told |
|---|---|
| Name unknown | Ask for name |
| Returning patient identified | Here's their history — don't re-ask for info |
| New patient, info incomplete | Here's what's collected, here's what's still needed — ask one at a time |
| Triage complete | Here's the recommended specialist and why — present it warmly |

This keeps responses short (1–2 sentences) and context-aware without the LLM needing to track state itself.

---

## Configuration

All settings are at the top of `handler.py`:

```python
PROVIDER = "openai"
MODEL    = "gpt-4o"
VOICE    = "alloy"
TEMPERATURE      = 0.7
MAX_TOKENS       = 300
TIMEOUT          = 30.0
TIMEOUT_MAX_COUNT = 9
```

To change the TTS voice, swap `VOICE` to any Voicerun-supported value (`alloy`, `echo`, `fable`, `onyx`, `nova`, `shimmer`).

---

## Project Structure

```
dlp-health-agent/
├── handler.py          — agent entry point (onboarding + triage logic)
├── tools.py            — local DLP pipeline copy (kept in parity with agent/tools.py via tests)
├── README.md
└── .voicerun/
    └── agent.yaml      — agent metadata

voicerun/data/          — shared data (one level up)
├── doctors.json        — specialist database
└── patients.json       — patient records
```

The voicerun deploy unit must be self-contained for `vr push`, so `tools.py` is duplicated here. Parity tests in `tests/test_leaks.py` fail loudly if the two copies drift on the invariants that matter.

---

## Resources

- [Voicerun Documentation](https://docs.voicerun.com)
- Root project README: `../../README.md`
