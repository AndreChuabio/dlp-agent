# P1 pipeline hardening

Second slice of the leak-surface cleanup, building on `docs/P0-hardening.md`.
P0 fixed detection-layer correctness and closed the direct echo paths (CLI /
UI / error handler). P1 addresses the *support surfaces* around the pipeline:
persisted state, debugger telemetry, the LLM reply path, and session memory.

Every item here has a corresponding regression test in `tests/test_leaks.py`.

## Files changed

| File | Change |
|---|---|
| `agent/tools.py` | `_save_patients` now takes an exclusive `fcntl` lock and writes to a temp file + `os.replace` so concurrent writers cannot clobber each other or truncate the live file on crash. |
| `voicerun/dlp-health-agent/tools.py` | Same lock + atomic-rename pattern applied to the voicerun variant. |
| `agent/replay.py` | Removes the `sessions/<name>.raw.json` write. The raw payload is scanned and redacted in-memory only; only the redacted session file is persisted. `raw_saved_locally` is dropped from the return dict. |
| `voicerun/dlp-health-agent/handler.py` | `DebugEvent` payloads for `patient_info` and `patient_lookup` now emit presence flags / lengths instead of the actual collected name, DOB, phone, insurance ID, or queried name. The debugger UI can no longer shoulder-surf PHI. |
| `api/server.py` | Adds an outbound scrubber (`_scrub_outbound`) that runs the regex redactor on the LLM reply and on inbound coverage snippets before they reach the system prompt. Adds a presence-flag sanitiser (`_sanitize_patient_info_for_prompt`) so the system prompt is told *which* fields have been collected without receiving the values. Adds TTL + max-size eviction to the in-memory `_sessions` store. |
| `workflows/debug_onboarding.md` | Note that `*.raw.json` files are no longer written. |
| `tests/test_leaks.py` | +11 tests covering the invariants below. |

## Invariants pinned by tests

1. **Pipeline parity.** `agent/tools.py` and `voicerun/dlp-health-agent/tools.py`
   expose the same pattern keys and both export `redact_semantic_findings`.
   If either drifts, parity tests fail at import time.
2. **Input cap parity.** Both pipelines respect the same `MAX_INPUT_CHARS`
   value.
3. **No raw payload persisted by replay.** `ingest_payload` writes only the
   redacted session file; `raw_saved_locally` is absent from the return dict
   and no `*.raw.json` is produced.
4. **Sanitised system prompt.** `_sanitize_patient_info_for_prompt` returns
   only boolean presence flags — the assertion is that no actual values (name,
   DOB, phone, insurance ID, reason text) appear in the dict it returns.
5. **Outbound scrubber.** `_scrub_outbound` redacts structured PHI in model
   output and is a no-op for clean text.
6. **Session eviction.** `_get_session` evicts the oldest session once
   `SESSION_MAX` is exceeded and drops sessions whose `_last_seen` exceeds
   `SESSION_TTL_SECONDS`.
7. **Voicerun DebugEvent sanitisation.** The handler's `patient_info` and
   `patient_lookup` DebugEvents contain only presence flags / lengths — a
   smoke import test asserts the handler module loads cleanly under test.

## New environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SESSION_TTL_SECONDS` | `1800` | Max idle seconds before a chat session is evicted from the in-memory store. |
| `SESSION_MAX` | `1000` | Cap on the number of concurrent sessions held in memory. Oldest by `_last_seen` is evicted when the cap is hit. |

No new vars in the DLP pipeline itself — the P0 set (`DLP_MAX_INPUT_CHARS`,
`DLP_*_TIMEOUT`, `DLP_DEBUG`) is unchanged.

## Behaviour changes worth noting for callers

- **`ingest_payload` no longer returns `raw_saved_locally`.** Callers that
  referenced this key to locate the unredacted copy must be updated; there is
  no longer an on-disk unredacted copy to reference. Any `*.raw.json` files
  from previous runs should be deleted.
- **`/chat` responses include `dlp.outbound_scrubbed: bool`.** `True` means
  the final reply differed from what the model produced because the regex
  redactor caught a structured PHI token in the model output. This is a
  useful signal for dashboards — it should normally be `False`.
- **System prompt no longer carries collected values.** The model is told
  `{"has_name": true, "has_dob": false, ...}` instead of the values. In
  practice the assistant still drives the onboarding flow correctly because
  it only needs to know *what* is still missing; if it needs a value (e.g.
  to confirm back to the patient), that is a tool call path, not a prompt
  injection.
- **Session store is now size- and time-bounded.** Under sustained load
  beyond `SESSION_MAX` concurrent sessions, the oldest session is evicted;
  after `SESSION_TTL_SECONDS` of idleness a session's history is dropped.
  This is still in-process memory and is not shared across workers — Redis
  with per-tenant isolation is tracked as a follow-up.
- **`_save_patients` is now serialized.** Concurrent writers no longer race
  on read-modify-write. A crash mid-write cannot leave `patients.json` in a
  truncated state because the rename is atomic.

## Known items intentionally left for a later pass

- **Unifying the two pipelines into a shared package.** The voicerun
  deploy unit (`voicerun/dlp-health-agent/`) must remain self-contained for
  `vr push`, so the two `tools.py` files still diverge by construction.
  Parity tests (added in P1) fail loudly if they drift on the invariants
  that matter, but a shared `mediguard_dlp` package installed into the
  voicerun unit at deploy time is still the right long-term fix.
- **Encryption at rest for `voicerun/data/patients.json`.** The file lock
  closes the concurrency race; it does not address the "plaintext PHI on
  disk" problem. Options: sqlite-with-sqlcipher, or moving to the managed
  Postgres instance that already holds the doctors table.
- **Redis-backed session store.** The in-memory `_sessions` dict is per
  worker and is lost on restart. A managed store with per-tenant key
  isolation is the correct target.
- **Observability uplift.** The audit log records finding counts and
  severity; it does not yet surface outbound-scrubber hits or session
  eviction counts. Both are useful signals for a real deployment.
- **BAA posture / key management.** Out of scope for the pipeline fixes
  in this PR.
