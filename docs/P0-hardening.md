# P0 pipeline hardening

A targeted set of fixes to close known leak surfaces and reduce blast radius
when a detection layer fails. Every item here was driven by a specific bug or
unsafe default and has a corresponding regression test in `tests/test_leaks.py`.

P1/P2 work (pipeline unification, output scrubber, encryption at rest,
observability, BAA posture) is tracked separately and not included in this PR.

## Files changed

| File | Change |
|---|---|
| `agent/tools.py` | Pattern dedupe, case-sensitive ICD, medication context requirement, HMAC cache key, input cap, LLM timeouts, scrubbed exception logs, Baseten no longer gates the semantic scan, OpenAI validator no longer receives raw excerpts, `original` removed from the default return dict. |
| `voicerun/dlp-health-agent/tools.py` | Same invariants as `agent/tools.py`. Ports `redact_semantic_findings` (previously a silent no-op). Fixes the `[\s:#-is]` typo in `insurance_id`. Uses the stronger `patient_name` pattern. |
| `main.py` | Stops printing `result["original"]`. The CLI shows the input only when `DLP_DEBUG=true`, using the caller's own variable. |
| `ui/app.py` | Original-vs-redacted side-by-side panel is gated on `DLP_DEBUG=true`. |
| `api/server.py` | Adds 413 for oversized input at the endpoint boundary. Scrubs the global exception handler so provider SDK errors (which can echo request bodies) do not reach app logs. |
| `tests/test_leaks.py` | New regression suite — 18 tests pinning the invariants below. |

## Invariants pinned by tests

1. `scan_and_clean` never returns the raw input unless both `DLP_DEBUG=true`
   and `include_original=True` are set.
2. The in-memory cache entries contain no raw text and are keyed by
   HMAC-SHA256 with a per-process random key.
3. Inputs larger than `DLP_MAX_INPUT_CHARS` (default 16 000) raise `ValueError`
   before any external call is made.
4. `PATTERNS` keys are unique; a future duplicate triggers an `AssertionError`
   at import time rather than silently dropping a pattern.
5. The ICD-10 pattern matches case-sensitively (`F32.1` yes, `a12` no).
6. The medication pattern requires a drug-name token or a clinical verb nearby
   ("50mg sertraline" yes, a stray "5 mg" no).
7. Claude's semantic scan always runs; Baseten's vote now gates only the
   optional OpenAI second opinion.
8. The OpenAI validator payload contains only `{type, reason, severity, regulation}`
   fields — the raw `excerpt` Claude may have extracted is stripped.
9. The voicerun pipeline exposes `redact_semantic_findings` and uses the
   corrected `insurance_id` pattern.

## New environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DLP_MAX_INPUT_CHARS` | `16000` | Hard cap for a single scan. |
| `DLP_BASETEN_TIMEOUT` | `8` | Seconds before the Baseten triage call aborts. |
| `DLP_CLAUDE_TIMEOUT` | `15` | Seconds for any Anthropic call. |
| `DLP_OPENAI_TIMEOUT` | `20` | Seconds for the OpenAI validator. |
| `DLP_DEBUG` | `false` | When `true`, tools that know how to display the original text (CLI, UI) may do so. Never enable in production. |

## Behaviour changes worth noting for callers

- `scan_and_clean(...)["original"]` is gone by default. Callers already hold
  the input they passed in; they should use that instead. The `include_original=True`
  kwarg is available for debug tooling but requires `DLP_DEBUG=true` to take effect.
- `scan_and_clean(...)` now raises `ValueError` for oversized / `None` input.
  `/scan` and `/chat` translate this to HTTP 413 at the edge.
- Claude semantic scan runs on every turn rather than being gated on Baseten's
  answer. This costs one extra Haiku call in cases where Baseten would have
  previously returned "NO"; the tradeoff is that a cheap-model false negative
  can no longer skip the deep scan.
- The OpenAI validator now sees only finding categories and severities, not
  the text Claude flagged. In practice this made the validator's notes less
  specific but did not change the confirmed/unconfirmed vote distribution in
  local fixtures.

## Known items intentionally left for P1

- Unifying the two pipelines into a shared package (`mediguard_dlp.pipeline`)
  so voicerun can no longer drift from `agent/tools.py`.
- Output scrubber on the LLM reply in `/chat` and on every `DebugEvent`
  payload in the voicerun handlers.
- Encrypting `voicerun/data/patients.json` and adding a file lock around
  `save_patient`.
- Dropping the raw payload write in `agent/replay.py`.
- Redis-backed session store with TTL and per-tenant isolation in place of
  the in-memory `_sessions` dict.
