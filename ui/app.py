"""MediGuard AI — Streamlit demo dashboard."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import io
import streamlit as st
from openai import OpenAI
from agent.orchestrator import run
from agent.tools import scan_and_clean, extract_patient_info, search_insurance_coverage
import anthropic

st.set_page_config(page_title="MediGuard AI", layout="wide")

# --- Session state init ---
if "messages" not in st.session_state:
    st.session_state.messages = []
if "patient_info" not in st.session_state:
    st.session_state.patient_info = {}
if "coverage" not in st.session_state:
    st.session_state.coverage = None

SYSTEM_PROMPT = (
    "You are MediGuard AI, a HIPAA-compliant patient onboarding assistant. "
    "Your job is to collect patient information conversationally — no forms, no paperwork. "
    "All patient messages have been scanned and redacted by a DLP layer. You never see raw PHI. "
    "Keep responses brief and warm — one question at a time.\n\n"
    "Onboarding flow: ask for name → reason for visit → insurance ID → DOB → callback number → confirm and close.\n"
    "If a message contains [REDACTED:...] tokens, acknowledge the info was protected and move on.\n"
    "Never ask for SSNs or full medical record numbers."
)

# --- Sidebar ---
with st.sidebar:
    st.markdown("## MediGuard AI")
    st.caption("HIPAA-compliant patient onboarding")
    st.markdown("---")
    user_id = st.text_input("Session / User ID", value="demo-patient")
    st.markdown("---")
    st.markdown("**Triage Model**")
    st.caption(f"`{os.getenv('BASETEN_MODEL', 'deepseek-ai/DeepSeek-V3.1')}`")
    st.markdown("---")
    st.markdown("**Pipeline**")
    st.markdown("1. Regex scan\n2. Baseten triage\n3. Claude semantic\n4. OpenAI validation\n5. Redact + Log")
    st.markdown("---")
    if st.session_state.patient_info:
        st.markdown("**Collected Patient Info**")
        for k, v in st.session_state.patient_info.items():
            if v and v != "null":
                st.markdown(f"- `{k}`: {v}")
    if st.session_state.coverage and st.session_state.coverage.get("results"):
        st.markdown("**Coverage Found**")
        st.caption(st.session_state.coverage["results"][0].get("snippet", "")[:150])
    if st.button("Clear Conversation", key="clear"):
        st.session_state.messages = []
        st.session_state.patient_info = {}
        st.session_state.coverage = None
        st.rerun()

# --- Header ---
st.title("MediGuard AI — Patient Onboarding")
st.caption("Patients speak or type naturally. PHI is intercepted before it reaches any AI model.")
st.markdown("---")

# --- Tabs ---
chat_tab, scan_tab, voice_tab = st.tabs(["Agent Chat", "DLP Scanner", "Voice Input"])

# ============================================================
# TAB 1 — Conversational agent chat
# ============================================================
with chat_tab:
    # Render conversation history
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if msg.get("dlp_findings"):
                with st.expander(f"DLP — {msg['dlp_findings']['total']} finding(s) redacted"):
                    for f in msg["dlp_findings"].get("regex", []):
                        st.markdown(f"- `{f['type'].upper()}` — `{f['value']}`")
                    for f in msg["dlp_findings"].get("semantic", []):
                        sev = f.get("severity", "low")
                        color = "red" if sev == "high" else "orange"
                        st.markdown(f"- :{color}[**{sev.upper()}**] `{f['type']}` — {f['reason']}")

    # Chat input
    patient_input = st.chat_input("Type your message as the patient...")

    if patient_input:
        # Run DLP scan on patient message
        dlp_result = scan_and_clean(patient_input, user_id=user_id)
        clean_message = dlp_result["clean"]

        # Build findings summary for display
        findings_summary = {
            "total": len(dlp_result["regex_findings"]) + len(dlp_result["semantic_findings"]),
            "regex": dlp_result["regex_findings"],
            "semantic": dlp_result["semantic_findings"],
        }

        # Show patient message (redacted version)
        with st.chat_message("user"):
            st.markdown(clean_message)
            if findings_summary["total"] > 0:
                with st.expander(f"DLP — {findings_summary['total']} finding(s) redacted"):
                    for f in findings_summary["regex"]:
                        st.markdown(f"- `{f['type'].upper()}` — `{f['value']}`")
                    for f in findings_summary["semantic"]:
                        sev = f.get("severity", "low")
                        color = "red" if sev == "high" else "orange"
                        st.markdown(f"- :{color}[**{sev.upper()}**] `{f['type']}` — {f['reason']}")

        st.session_state.messages.append({
            "role": "user",
            "content": clean_message,
            "dlp_findings": findings_summary,
        })

        # Extract patient info from conversation so far
        raw_msgs = [{"role": m["role"], "content": m["content"]} for m in st.session_state.messages]
        patient_info = extract_patient_info(raw_msgs)
        if patient_info:
            merged = {**st.session_state.patient_info, **{k: v for k, v in patient_info.items() if v and v != "null"}}
            st.session_state.patient_info = merged

        # Search coverage if insurance ID just captured
        insurance_id = st.session_state.patient_info.get("insurance_id")
        if insurance_id and not st.session_state.coverage:
            with st.spinner("Searching coverage via You.com..."):
                st.session_state.coverage = search_insurance_coverage(
                    insurance_id=insurance_id,
                    reason=st.session_state.patient_info.get("reason", ""),
                )

        # Build system prompt with context
        system = SYSTEM_PROMPT
        if st.session_state.patient_info:
            collected = {k: v for k, v in st.session_state.patient_info.items() if v and v != "null"}
            system += f"\n\nCollected so far: {json.dumps(collected)}"
        if st.session_state.coverage and st.session_state.coverage.get("results"):
            snippets = " | ".join(r["snippet"] for r in st.session_state.coverage["results"][:2] if r.get("snippet"))
            system += f"\n\nInsurance coverage info: {snippets}"

        # Get agent response from Claude
        with st.chat_message("assistant"):
            with st.spinner(""):
                try:
                    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
                    history = [{"role": m["role"], "content": m["content"]} for m in st.session_state.messages]
                    response = client.messages.create(
                        model="claude-opus-4-6",
                        max_tokens=300,
                        system=system,
                        messages=history,
                    )
                    agent_reply = response.content[0].text
                except Exception as e:
                    agent_reply = f"Sorry, I ran into an issue. ({e})"

            st.markdown(agent_reply)

        st.session_state.messages.append({"role": "assistant", "content": agent_reply})
        st.rerun()

# ============================================================
# TAB 2 — Raw DLP scanner
# ============================================================
with scan_tab:
    text_input = st.text_area(
        "Patient message:",
        height=120,
        placeholder="Hi, my name is John Smith, MRN 123456, DOB 04/12/1985. I'm on 50mg sertraline for F32.1. My insurance ID is BCX884521.",
    )
    if st.button("Scan Message", type="primary", key="text_scan"):
        if text_input.strip():
            with st.spinner("Scanning..."):
                result = run(text=text_input, user_id=user_id)

            if result["safe_to_send"]:
                st.success("SAFE TO SEND — No PHI detected")
            else:
                total = len(result["regex_findings"]) + len(result["semantic_findings"])
                st.error(f"BLOCKED — {total} PHI finding(s) detected and redacted")

            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Original**")
                st.text_area("", value=result["original"], height=120, disabled=True, key="orig")
            with col2:
                st.markdown("**Redacted (sent to AI)**")
                st.text_area("", value=result["clean"], height=120, disabled=True, key="clean")

            fcol1, fcol2, fcol3 = st.columns(3)
            fcol1.metric("Regex Hits", len(result["regex_findings"]))
            fcol2.metric("Semantic Hits", len(result["semantic_findings"]))
            fcol3.metric("Baseten Escalated", "Yes" if result["baseten_escalated"] else "No")

            if result["regex_findings"]:
                st.markdown("**Structured PHI (Regex)**")
                for f in result["regex_findings"]:
                    st.markdown(f"- `{f['type'].upper()}` — `{f['value']}`")

            if result["semantic_findings"]:
                st.markdown("**Contextual PHI (Claude)**")
                for f in result["semantic_findings"]:
                    color = "red" if f["severity"] == "high" else "orange"
                    st.markdown(f"- :{color}[**{f['severity'].upper()}**] `{f['type']}` ({f.get('regulation', '')}) — {f['reason']}")
        else:
            st.warning("Enter a message to scan.")

# ============================================================
# TAB 3 — Voice input
# ============================================================
with voice_tab:
    st.caption("Record a patient message. Transcribed via Whisper then scanned before reaching any model.")
    audio = st.audio_input("Record patient message")
    if audio and st.button("Transcribe + Scan", type="primary", key="voice_scan"):
        with st.spinner("Transcribing..."):
            try:
                client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
                audio_bytes = io.BytesIO(audio.read())
                audio_bytes.name = "recording.wav"
                transcript = client.audio.transcriptions.create(model="whisper-1", file=audio_bytes)
                transcribed_text = transcript.text
                st.info(f"Transcript: {transcribed_text}")
            except Exception as e:
                st.error(f"Transcription failed: {e}")
                transcribed_text = None

        if transcribed_text:
            with st.spinner("Scanning..."):
                result = run(text=transcribed_text, user_id=user_id)
            st.success("SAFE TO SEND") if result["safe_to_send"] else st.error(f"BLOCKED — {len(result['regex_findings']) + len(result['semantic_findings'])} finding(s)")
            st.text_area("Redacted output", value=result["clean"], disabled=True)

# ============================================================
# Live Audit Log
# ============================================================
st.markdown("---")
st.markdown("### Live HIPAA Audit Log")
st.caption("Every scan is logged. This is the compliance trail your legal team needs.")
try:
    with open("dlp_audit_log.jsonl") as f:
        entries = [json.loads(line) for line in f.readlines()[-10:]]
    for entry in reversed(entries):
        sev = entry["severity"]
        color = "red" if sev == "high" else "orange" if sev == "medium" else "green"
        types = ", ".join(entry.get("finding_types", [])) or "none"
        st.markdown(
            f"`{entry['timestamp']}` &nbsp;|&nbsp; user: `{entry['user_id']}` &nbsp;|&nbsp; "
            f"severity: :{color}[**{sev}**] &nbsp;|&nbsp; findings: `{entry['findings_count']}` &nbsp;|&nbsp; "
            f"types: `{types}` &nbsp;|&nbsp; safe: `{entry['safe_to_send']}`"
        )
except FileNotFoundError:
    st.caption("No scans yet.")
