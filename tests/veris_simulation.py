"""
Veris-style adversarial DLP simulation.

Covers every pattern type listed in the DLP Coverage Dashboard (PATTERN_DISPLAY),
ensuring the test suite and the UI stay in sync.

Usage:
    python tests/veris_simulation.py          # full report
    python tests/veris_simulation.py --json   # raw JSON
    python tests/veris_simulation.py --github # GitHub Actions step summary
"""

import os
import sys
import json
import argparse
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv()

from agent.tools import regex_scan, redact_text

# ── Test cases ────────────────────────────────────────────────────────────────

@dataclass
class Case:
    description:   str
    text:          str
    should_detect: bool
    expected_type: str | None = None
    category:      str = "general"


CASES: list[Case] = [

    # ══════════════════════════════════════════════════════
    # STANDARD PII
    # ══════════════════════════════════════════════════════

    # ── SSN ──────────────────────────────────────────────
    Case("SSN standard format",
         "My social security number is 123-45-6789.",
         True, "SSN", "ssn"),
    Case("SSN in sentence",
         "SSN: 234-56-7890 for patient record.",
         True, "SSN", "ssn"),
    Case("Clean — 9 digits without dashes",
         "Flight 123456789 is boarding.",
         False, None, "ssn"),

    # ── Credit card ───────────────────────────────────────
    Case("Credit card with spaces",
         "Card number 4111 1111 1111 1111 on file.",
         True, "credit_card", "standard_pii"),
    Case("Credit card with dashes",
         "Billing card 4111-1111-1111-1111 charged.",
         True, "credit_card", "standard_pii"),
    Case("Clean — random 16 digits no separators",
         "Reference 4111111111111111 generated.",
         False, None, "standard_pii"),

    # ── Email ─────────────────────────────────────────────
    Case("Email address",
         "Please email me at alice@hospital.org.",
         True, "email", "standard_pii"),
    Case("Email in log",
         "User contact: j.smith@example.com registered.",
         True, "email", "standard_pii"),

    # ── Phone ─────────────────────────────────────────────
    Case("Phone standard format",
         "Call me back at 212-555-0101.",
         True, "phone", "phone"),
    Case("Phone with area code parens",
         "My number is (646) 555-0192.",
         True, "phone", "phone"),
    Case("Phone in context",
         "My callback number is 917-555-0789.",
         True, "phone", "phone"),

    # ── API key ───────────────────────────────────────────
    Case("OpenAI-style API key",
         "Key sk-abc12345678901234567890 has expired.",
         True, "api_key", "standard_pii"),
    Case("Google API key",
         "Token AIzaSyD-abc1234567890abcdefghij in config.",
         True, "api_key", "standard_pii"),
    Case("Clean — short sk- prefix",
         "The ski resort sk-valley opens Saturday.",
         False, None, "standard_pii"),

    # ══════════════════════════════════════════════════════
    # HIPAA SAFE HARBOR — IDENTITY
    # ══════════════════════════════════════════════════════

    # ── Patient names ─────────────────────────────────────
    Case("Name via 'my name is'",
         "Hi, my name is Alice Johnson.",
         True, "patient_name", "names"),
    Case("Name via 'I'm'",
         "I'm James Park and I need to see a doctor.",
         True, "patient_name", "names"),
    Case("Name via 'I am'",
         "I am Maria Santos calling about an appointment.",
         True, "patient_name", "names"),
    Case("Name via 'patient'",
         "patient Robert Chen is on line 2.",
         True, "patient_name", "names"),
    Case("Name with middle initial",
         "My name is David K Kim.",
         True, "patient_name", "names"),
    Case("Clean — verb phrase after 'I am'",
         "I am going to need to reschedule.",
         False, None, "names"),
    Case("Clean — first person statement",
         "I'm calling about my prescription refill.",
         False, None, "names"),

    # ══════════════════════════════════════════════════════
    # HIPAA SAFE HARBOR — GEOGRAPHIC
    # ══════════════════════════════════════════════════════

    # ── Street address ────────────────────────────────────
    Case("Street address — Street suffix",
         "I live at 123 Main Street, please send records.",
         True, "street_address", "geographic"),
    Case("Street address — Avenue suffix",
         "Office is at 1600 Pennsylvania Avenue.",
         True, "street_address", "geographic"),
    Case("Clean — no street number",
         "Turn left on Main Street.",
         False, None, "geographic"),

    # ══════════════════════════════════════════════════════
    # HIPAA SAFE HARBOR — DATES
    # ══════════════════════════════════════════════════════

    # ── Dates of birth ────────────────────────────────────
    Case("DOB text format — long month",
         "My date of birth is March 22nd, 1975.",
         True, "dob", "dob"),
    Case("DOB text format — short month",
         "Born Nov 30, 1968.",
         True, "dob", "dob"),
    Case("DOB numeric format",
         "DOB: 03/22/1975",
         True, "dob", "dob"),
    Case("DOB keyword 'birthday'",
         "My birthday is July 8th, 1990.",
         True, "dob", "dob"),
    Case("DOB with 'is' separator",
         "Date of birth is February 14, 1992.",
         True, "dob", "dob"),
    Case("Clean — year mention without DOB keyword",
         "I graduated in 1995.",
         False, None, "dob"),

    # ══════════════════════════════════════════════════════
    # HIPAA SAFE HARBOR — MEDICAL
    # ══════════════════════════════════════════════════════

    # ── Medical record numbers ────────────────────────────
    Case("MRN with prefix",
         "Looking up MRN-445521 in the system.",
         True, "medical_record", "mrn"),
    Case("MRN with colon",
         "Patient MRN: 987654 checked in.",
         True, "medical_record", "mrn"),

    # ── NPI numbers ───────────────────────────────────────
    Case("NPI number",
         "Provider NPI 1234567890 on file.",
         True, "npi_number", "medical"),
    Case("NPI with colon",
         "Referring physician NPI: 9876543210.",
         True, "npi_number", "medical"),

    # ── ICD codes ─────────────────────────────────────────
    Case("ICD code — hypertension",
         "Diagnosed with I10 hypertension.",
         True, "icd_code", "medical"),
    Case("ICD code — diabetes with decimal",
         "Condition E11.9 documented.",
         True, "icd_code", "medical"),

    # ── Medications ───────────────────────────────────────
    Case("Medication dosage",
         "I'm currently on 50mg sertraline.",
         True, "medication", "medication"),
    Case("Multiple dosages",
         "Taking 800mg ibuprofen and 10mg lisinopril daily.",
         True, "medication", "medication"),

    # ══════════════════════════════════════════════════════
    # HIPAA SAFE HARBOR — INSURANCE / FINANCIAL
    # ══════════════════════════════════════════════════════

    # ── Insurance IDs ─────────────────────────────────────
    Case("Insurance member ID",
         "My insurance member ID is BCBS789012.",
         True, "insurance_id", "insurance"),
    Case("Policy number",
         "Policy number UHC445566 on file.",
         True, "insurance_id", "insurance"),

    # ── Account numbers ───────────────────────────────────
    Case("Account number",
         "Account 123456789 linked to profile.",
         True, "account_number", "insurance"),
    Case("Account abbreviated",
         "Acct: 987654321 charged.",
         True, "account_number", "insurance"),

    # ── License / certificate ─────────────────────────────
    Case("License number",
         "License DL98765 issued to patient.",
         True, "license_number", "insurance"),
    Case("Certificate number",
         "Certificate ABC12345 on record.",
         True, "license_number", "insurance"),

    # ══════════════════════════════════════════════════════
    # HIPAA SAFE HARBOR — TECHNICAL IDENTIFIERS
    # ══════════════════════════════════════════════════════

    # ── Vehicle identifiers ───────────────────────────────
    Case("VIN number",
         "Vehicle VIN 1HGCM82633A004352 registered.",
         True, "vehicle_id", "technical"),

    # ── Device identifiers ────────────────────────────────
    Case("IMEI device ID",
         "IMEI 490154203237518 flagged in session.",
         True, "device_id", "technical"),
    Case("Serial number",
         "Serial number AB12345678 on device.",
         True, "device_id", "technical"),

    # ── URLs ──────────────────────────────────────────────
    Case("Patient portal URL",
         "Access your records at https://patient.example.com/records/42",
         True, "url", "technical"),
    Case("HTTPS link in message",
         "Reset password: https://portal.hospital.org/reset?token=abc123",
         True, "url", "technical"),

    # ── IP addresses ──────────────────────────────────────
    Case("IPv4 in session log",
         "Session initiated from 192.168.1.1.",
         True, "ip_address", "technical"),
    Case("IP in audit trail",
         "Login attempt from 10.0.0.254 blocked.",
         True, "ip_address", "technical"),
    Case("Clean — version number looks like IP",
         "Running version 3.11.2 of the agent.",
         False, None, "technical"),

    # ══════════════════════════════════════════════════════
    # COMPOUND PHI (multiple types in one message)
    # ══════════════════════════════════════════════════════

    Case("Name + DOB + phone (full intake)",
         "Hi, my name is Alice Johnson. My date of birth is March 22nd, 1975. "
         "Callback: 212-555-0101.",
         True, None, "compound"),
    Case("MRN + SSN in system log",
         "Session init. Patient SSN: 234-56-7890. Lookup result: MRN-445521.",
         True, None, "compound"),
    Case("Email + IP in access log",
         "User alice@hospital.org logged in from 10.0.0.254.",
         True, None, "compound"),

    # ══════════════════════════════════════════════════════
    # OBFUSCATION ATTEMPTS (known gaps — documented)
    # ══════════════════════════════════════════════════════

    Case("SSN with spaces (obfuscated)",
         "My number is 123 45 6789.",
         False, None, "obfuscation"),   # known gap — spaced SSN not caught
    Case("Name split across sentences",
         "Call me Alice. My last name is Johnson.",
         False, None, "obfuscation"),   # known gap — multi-sentence names
    Case("Date without keyword",
         "I was born on 03/22/1975.",
         False, None, "obfuscation"),   # known gap — date without trigger word

    # ══════════════════════════════════════════════════════
    # CLEAN MESSAGES (should pass through undetected)
    # ══════════════════════════════════════════════════════

    Case("Generic medical question",
         "What are the clinic hours on weekends?",
         False, None, "clean"),
    Case("Appointment request",
         "I need to schedule a follow-up appointment.",
         False, None, "clean"),
    Case("Symptom without identifiers",
         "I've been having chest tightness when climbing stairs.",
         False, None, "clean"),
    Case("General statement",
         "The medication seems to be working well.",
         False, None, "clean"),

    # ── User-added: zip_code ──
    Case("zip_code — auto-added",
         "My zip code is 10013",
         True, "zip_code", "user_added"),
]


# ── Runner ────────────────────────────────────────────────────────────────────

def run_regex_simulation() -> dict:
    results = []
    by_category: dict[str, dict] = {}

    for case in CASES:
        findings = regex_scan(case.text)
        detected = len(findings) > 0
        correct  = detected == case.should_detect

        type_match = True
        if case.expected_type and case.should_detect:
            type_match = any(f["type"] == case.expected_type for f in findings)

        results.append({
            "description":   case.description,
            "category":      case.category,
            "should_detect": case.should_detect,
            "detected":      detected,
            "correct":       correct and type_match,
            "finding_types": [f["type"] for f in findings],
            "text_preview":  case.text[:60] + ("..." if len(case.text) > 60 else ""),
        })

        cat = case.category
        if cat not in by_category:
            by_category[cat] = {"total": 0, "correct": 0}
        by_category[cat]["total"]   += 1
        by_category[cat]["correct"] += 1 if (correct and type_match) else 0

    total   = len(results)
    correct = sum(1 for r in results if r["correct"])
    tp      = sum(1 for r in results if r["should_detect"]  and r["detected"])
    tn      = sum(1 for r in results if not r["should_detect"] and not r["detected"])
    fp      = sum(1 for r in results if not r["should_detect"] and r["detected"])
    fn      = sum(1 for r in results if r["should_detect"]  and not r["detected"])

    return {
        "total":           total,
        "correct":         correct,
        "accuracy":        round(correct / total * 100, 1),
        "true_positives":  tp,
        "true_negatives":  tn,
        "false_positives": fp,
        "false_negatives": fn,
        "detection_rate":  round(tp / (tp + fn) * 100, 1) if (tp + fn) else 0,
        "precision":       round(tp / (tp + fp) * 100, 1) if (tp + fp) else 0,
        "by_category":     by_category,
        "results":         results,
    }


def print_report(report: dict) -> None:
    print()
    print("=" * 65)
    print("  MEDIGUARD DLP — Veris Adversarial Simulation Report")
    print("=" * 65)
    print(f"\n  Total cases:      {report['total']}")
    print(f"  Accuracy:         {report['accuracy']}%  ({report['correct']}/{report['total']})")
    print(f"  Detection rate:   {report['detection_rate']}%  "
          f"(caught {report['true_positives']} of "
          f"{report['true_positives'] + report['false_negatives']} PHI inputs)")
    print(f"  Precision:        {report['precision']}%  "
          f"({report['false_positives']} false positive(s))")
    print(f"\n  TP={report['true_positives']}  TN={report['true_negatives']}  "
          f"FP={report['false_positives']}  FN={report['false_negatives']}")

    print("\n  By category:")
    for cat, stats in report["by_category"].items():
        pct = round(stats["correct"] / stats["total"] * 100)
        bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
        print(f"    {cat:<14} {bar}  {pct:>3}%  ({stats['correct']}/{stats['total']})")

    failures = [r for r in report["results"] if not r["correct"]]
    if failures:
        print(f"\n  Failures ({len(failures)}):")
        for r in failures:
            expected = "DETECT" if r["should_detect"] else "CLEAN"
            got      = f"detected {r['finding_types']}" if r["detected"] else "clean"
            print(f"    ✗ [{expected}] {r['description']}")
            print(f"      Expected: {expected.lower()} | Got: {got}")
            print(f"      Text: \"{r['text_preview']}\"")
    else:
        print("\n  No failures.")

    print()
    print("=" * 65)
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--json",   action="store_true")
    parser.add_argument("--github", action="store_true")
    args = parser.parse_args()

    report = run_regex_simulation()

    if args.json:
        print(json.dumps(report, indent=2))
    elif args.github:
        summary_file = os.getenv("GITHUB_STEP_SUMMARY")
        lines = [
            "## MediGuard DLP — Veris Simulation Results\n",
            "| Metric | Value |", "|---|---|",
            f"| Accuracy | {report['accuracy']}% ({report['correct']}/{report['total']}) |",
            f"| Detection rate | {report['detection_rate']}% "
            f"(TP={report['true_positives']}, FN={report['false_negatives']}) |",
            f"| Precision | {report['precision']}% (FP={report['false_positives']}) |",
            "", "### By category", "| Category | Score |", "|---|---|",
        ]
        for cat, stats in report["by_category"].items():
            pct = round(stats["correct"] / stats["total"] * 100)
            lines.append(f"| {cat} | {pct}% ({stats['correct']}/{stats['total']}) |")

        failures = [r for r in report["results"] if not r["correct"]]
        if failures:
            lines += ["", "### Failures", "| Case | Expected | Got |", "|---|---|---|"]
            for r in failures:
                expected = "detect" if r["should_detect"] else "clean"
                got = f"detected {r['finding_types']}" if r["detected"] else "clean"
                lines.append(f"| {r['description']} | {expected} | {got} |")

        output = "\n".join(lines)
        if summary_file:
            with open(summary_file, "w") as f:
                f.write(output)
        print(output)
    else:
        print_report(report)

    threshold = 70
    if report["detection_rate"] < threshold:
        print(f"FAIL: detection rate {report['detection_rate']}% below threshold {threshold}%")
        sys.exit(1)
    if report["false_positives"] > 2:
        print(f"FAIL: {report['false_positives']} false positives (max 2)")
        sys.exit(1)

    print(f"PASS: detection rate {report['detection_rate']}%, "
          f"{report['false_positives']} false positive(s), "
          f"{report['total']} total cases")
