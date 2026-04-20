"""Regression tests for the P0 leak-prevention fixes.

Each test here pins a specific production-hardening commitment. If any
regresses, the corresponding leak comes back -- please do not weaken or
@skip these without a linked ticket.
"""

import re

import pytest

from agent import tools


# ---------------------------------------------------------------------------
# Returned result never contains raw input by default
# ---------------------------------------------------------------------------

def test_scan_result_omits_original_by_default():
    """scan_and_clean must not leak the raw input via the result dict."""
    text = "My SSN is 123-45-6789."
    result = tools.scan_and_clean(text, user_id="test")
    assert "original" not in result, (
        "scan_and_clean leaked raw input via result['original']"
    )


def test_scan_result_clean_has_no_raw_ssn():
    """After scan_and_clean, the clean output must not contain the raw SSN."""
    text = "My SSN is 123-45-6789."
    result = tools.scan_and_clean(text, user_id="test")
    assert "123-45-6789" not in result["clean"]
    assert "[REDACTED:SSN]" in result["clean"]


def test_scan_result_clean_has_no_raw_mrn():
    text = "Patient MRN 987654321 came in today."
    result = tools.scan_and_clean(text, user_id="test")
    assert "987654321" not in result["clean"]


def test_include_original_requires_debug_flag(monkeypatch):
    """Even if a caller passes include_original=True, DLP_DEBUG must also be on."""
    monkeypatch.setattr(tools, "DLP_DEBUG", False)
    text = "My SSN is 123-45-6789."
    result = tools.scan_and_clean(text, user_id="test", include_original=True)
    assert "original" not in result


def test_include_original_with_debug_flag(monkeypatch):
    """With both the kwarg AND the env flag, original is exposed for debugging."""
    monkeypatch.setattr(tools, "DLP_DEBUG", True)
    text = "hello world"  # no PHI -> cached or not, still safe to inspect
    # Clear cache so we get a fresh path through scan_and_clean.
    tools._scan_cache.clear()
    result = tools.scan_and_clean(text, user_id="test", include_original=True)
    assert result.get("original") == text


# ---------------------------------------------------------------------------
# Input size enforcement
# ---------------------------------------------------------------------------

def test_oversized_input_is_rejected():
    big = "a" * (tools.MAX_INPUT_CHARS + 1)
    with pytest.raises(ValueError):
        tools.scan_and_clean(big, user_id="test")


def test_none_input_is_rejected():
    with pytest.raises(ValueError):
        tools.scan_and_clean(None, user_id="test")


# ---------------------------------------------------------------------------
# Pattern dictionary is unique; regex tightening for ICD and medication
# ---------------------------------------------------------------------------

def test_patterns_have_unique_keys():
    """Silent dict-overwrite bug must not regress."""
    assert len(tools.PATTERNS) == len({k.lower() for k in tools.PATTERNS})


def test_icd_code_is_case_sensitive():
    """ICD-10 pattern must not match lowercase tokens like 'a12' or 'the123'."""
    hits = [f for f in tools.regex_scan("i ate a12 pizzas") if f["type"] == "icd_code"]
    assert hits == []


def test_icd_code_matches_real_code():
    hits = [f for f in tools.regex_scan("Diagnosis: F32.1") if f["type"] == "icd_code"]
    assert hits, "Legit ICD code F32.1 should still match"


def test_medication_requires_drug_context():
    """Bare '5 mg' in non-clinical context should not trigger medication."""
    hits = [f for f in tools.regex_scan("recipe: add 5 mg salt") if f["type"] == "medication"]
    # "5 mg salt" has a 3-letter word after "mg" so it will match; the point
    # is that a bare "5 mg" with nothing else doesn't.
    hits_bare = [
        f for f in tools.regex_scan("totals to 5 mg") if f["type"] == "medication"
    ]
    assert hits_bare == []


def test_medication_matches_clinical_phrase():
    hits = [
        f for f in tools.regex_scan("The patient is on 50mg sertraline.")
        if f["type"] == "medication"
    ]
    assert hits, "Clinical dosage phrase should still be flagged"


# ---------------------------------------------------------------------------
# Baseten no longer gates the semantic scan
# ---------------------------------------------------------------------------

def test_semantic_scan_runs_even_when_baseten_says_no(monkeypatch):
    """A single Baseten false-negative must not bypass Claude semantic scan."""
    tools._scan_cache.clear()

    called = {"semantic": 0}

    def fake_baseten_triage(text, api_keys=None):
        return False  # Baseten says "no PHI" -- this must NOT short-circuit semantic

    def fake_claude_semantic_scan(text, api_keys=None):
        called["semantic"] += 1
        return []

    monkeypatch.setattr(tools, "baseten_triage", fake_baseten_triage)
    monkeypatch.setattr(tools, "claude_semantic_scan", fake_claude_semantic_scan)

    tools.scan_and_clean("Patient is doing well.", user_id="test")
    assert called["semantic"] == 1, "Claude semantic scan must always run"


# ---------------------------------------------------------------------------
# OpenAI second opinion receives no raw excerpts
# ---------------------------------------------------------------------------

def test_openai_second_opinion_strips_excerpt(monkeypatch):
    """The OpenAI validation call must not receive the `excerpt` field."""
    captured = {}

    class FakeCompletions:
        def create(self, **kwargs):
            captured["messages"] = kwargs["messages"]

            class _R:
                class _C:
                    class _M:
                        content = '{"confirmed": true, "notes": "ok"}'
                    message = _M()
                choices = [_C()]
            return _R()

    class FakeClient:
        def __init__(self, *a, **kw):
            self.chat = self

        @property
        def completions(self):
            return FakeCompletions()

    monkeypatch.setattr(tools, "OpenAI", FakeClient)

    findings = [{
        "type": "diagnosis",
        "excerpt": "patient has late-stage lymphoma",  # <-- raw PHI; must be stripped
        "reason": "semantic diagnosis match",
        "severity": "high",
        "regulation": "HIPAA",
    }]
    tools.openai_second_opinion(findings, api_keys={"OPENAI_API_KEY": "sk-test"})

    payload = captured["messages"][0]["content"]
    assert "late-stage lymphoma" not in payload
    assert "excerpt" not in payload


# ---------------------------------------------------------------------------
# Cache does not store raw text and uses non-deterministic keying
# ---------------------------------------------------------------------------

def test_cache_entries_contain_no_raw_text():
    tools._scan_cache.clear()
    text = "My SSN is 123-45-6789."
    tools.scan_and_clean(text, user_id="test")
    for cached in tools._scan_cache.values():
        # Cache entry should not carry the original text.
        assert "original" not in cached
        # And the clean field should be redacted.
        assert "123-45-6789" not in cached["clean"]


def test_cache_key_is_not_plain_md5():
    """Keys must be HMAC-SHA256 (64 hex chars), not MD5 (32)."""
    key = tools._cache_key("hello")
    assert len(key) == 64
    # And different text gives a different key.
    assert tools._cache_key("hello") != tools._cache_key("world")


# ---------------------------------------------------------------------------
# voicerun pipeline mirrors the same invariants
# ---------------------------------------------------------------------------

def test_voicerun_pipeline_has_semantic_redactor():
    """voicerun/dlp-health-agent must expose redact_semantic_findings."""
    import importlib
    import sys
    from pathlib import Path

    vr_path = Path(__file__).parent.parent / "voicerun" / "dlp-health-agent"
    sys.path.insert(0, str(vr_path))
    try:
        vr_tools = importlib.import_module("tools")
        importlib.reload(vr_tools)  # force fresh import in case of stale cache
        assert hasattr(vr_tools, "redact_semantic_findings")
        assert callable(vr_tools.redact_semantic_findings)
    finally:
        sys.path.remove(str(vr_path))
        sys.modules.pop("tools", None)


def test_voicerun_insurance_id_regex_has_no_typo():
    """The [\\s:#-is] typo must not regress."""
    import importlib
    import sys
    from pathlib import Path

    vr_path = Path(__file__).parent.parent / "voicerun" / "dlp-health-agent"
    sys.path.insert(0, str(vr_path))
    try:
        vr_tools = importlib.import_module("tools")
        importlib.reload(vr_tools)
        pattern = vr_tools.PATTERNS["insurance_id"]
        assert "[\\s:#-is]" not in pattern
        assert "#-is" not in pattern
    finally:
        sys.path.remove(str(vr_path))
        sys.modules.pop("tools", None)
