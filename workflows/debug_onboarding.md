---
workflow: debug-onboarding
description: Reproduce a patient onboarding failure from a production ticket
secrets_required:
  - TEST_PATIENT_MRN     # or TICKET_XXXX pointing to an ingested session
---

# Debug: Patient Onboarding Failure

## What this workflow does
Replays a production onboarding interaction locally to identify where the
agent went off script — without sending any patient data to an LLM.

## Prerequisites
1. Get the interaction payload from the production logs (Voicerun session export,
   API response log, or a copy-paste of the turn transcript).
2. Have your `.secrets` file set up with at minimum `TEST_PATIENT_MRN` or a
   `TICKET_XXXX` reference pointing to an already-ingested session.

## Steps

### Step 1 — Ingest the raw payload
In Claude Code, call the MCP tool:
```
ingest_payload(
  payload="<paste raw log here>",
  session_name="ticket-{{TICKET_ID}}"
)
```
This strips PHI, saves the raw file locally (gitignored), and saves a
redacted version you can share with the team.

### Step 2 — Replay and inspect
```
replay_session("ticket-{{TICKET_ID}}")
```
This reruns every turn through the DLP → extraction → lookup → triage
pipeline and returns a trace showing:
- What PHI was caught at each turn
- Whether the patient was identified (new vs. returning)
- What the triage result was — and at which turn it resolved
- Any steps where something failed or diverged from expected behavior

### Step 3 — Identify the failure point
Look at `issues_detected` in the replay output. Common causes:
- **Triage never ran** — patient didn't state a clear concern before the session ended
- **Wrong specialist** — concern was ambiguous (e.g. "feeling off" → GP instead of Endocrinologist)
- **Patient not found** — name extracted incorrectly, lookup missed a match
- **PHI leaked past DLP** — check `dlp.finding_types` on each turn

### Step 4 — Fix and verify
After making changes to the agent, replay the same session again and
compare the trace to confirm the fix worked.

## Notes
- All `{{PLACEHOLDER}}` values are substituted from your local `.secrets` file.
  The workflow file itself never contains real patient data.
- The redacted session file (`sessions/ticket-{{TICKET_ID}}.redacted.json`)
  is safe to commit and share with teammates for collaborative debugging.
- Raw payloads are scanned in-memory and never written to disk. Any
  `*.raw.json` files from older runs should be deleted — they were produced
  by a previous version of `ingest_payload` and are no longer created.
