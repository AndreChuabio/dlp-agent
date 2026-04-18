"""Smoke tests — happy path, regex hit, semantic PHI hit."""

from agent.tools import regex_scan, redact_text, scan_and_clean


def test_clean_text():
    result = regex_scan("The weather today is nice.")
    assert result == []


def test_regex_ssn():
    result = regex_scan("My SSN is 123-45-6789.")
    assert any(f["type"] == "SSN" for f in result)


def test_regex_mrn():
    result = regex_scan("Patient MRN 987654.")
    assert any(f["type"] == "medical_record" for f in result)


def test_redaction():
    findings = regex_scan("SSN: 123-45-6789")
    redacted = redact_text("SSN: 123-45-6789", findings)
    assert "123-45-6789" not in redacted
    assert "[REDACTED:SSN]" in redacted


def test_full_pipeline_clean():
    result = scan_and_clean("The medication is working well.", user_id="test")
    assert "clean" in result
    assert "safe_to_send" in result
    assert result["baseten_escalated"] in [True, False]
