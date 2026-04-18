"""MediGuard AI — Streamlit demo dashboard."""

import json
import io
import os
import streamlit as st
from openai import OpenAI
from agent.orchestrator import run

st.set_page_config(page_title="MediGuard AI", layout="wide", page_icon="🏥")

# --- Sidebar ---
with st.sidebar:
    st.markdown("## MediGuard AI")
    st.caption("HIPAA-compliant patient onboarding agent")
    st.markdown("---")
    user_id = st.text_input("Session / User ID", value="demo-patient")
    st.markdown("---")
    st.markdown("**Triage Model**")
    st.caption(f"`{os.getenv('BASETEN_MODEL', 'deepseek-ai/DeepSeek-V3.1')}`")
    st.markdown("Swap `BASETEN_MODEL` in `.env` to test different models.")
    st.markdown("---")
    st.markdown("**Pipeline**")
    st.markdown("1. Regex scan\n2. Baseten triage\n3. Claude semantic\n4. OpenAI validation\n5. Redact + Log")

# --- Header ---
st.title("MediGuard AI — Patient Onboarding")
st.caption("Patients speak or type naturally. PHI is intercepted before it reaches any AI model.")
st.markdown("---")

# --- Input tabs ---
text_tab, voice_tab = st.tabs(["Text Input", "Voice Input"])

result = None

with text_tab:
    text_input = st.text_area(
        "Patient message:",
        height=120,
        placeholder="Hi, my name is John Smith, MRN 123456, DOB 04/12/1985. I'm on 50mg sertraline for F32.1. My insurance ID is BCX884521.",
    )
    if st.button("Scan Message", type="primary", key="text_scan"):
        if text_input.strip():
            with st.spinner("Scanning..."):
                result = run(text=text_input, user_id=user_id)
        else:
            st.warning("Enter a message to scan.")

with voice_tab:
    st.caption("Record a patient message. Audio is transcribed then scanned before reaching any model.")
    audio = st.audio_input("Record patient message")
    if audio and st.button("Transcribe + Scan", type="primary", key="voice_scan"):
        with st.spinner("Transcribing via Whisper..."):
            try:
                client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
                audio_bytes = io.BytesIO(audio.read())
                audio_bytes.name = "recording.wav"
                transcript = client.audio.transcriptions.create(
                    model="whisper-1",
                    file=audio_bytes,
                )
                transcribed_text = transcript.text
                st.info(f"Transcript: {transcribed_text}")
            except Exception as e:
                st.error(f"Transcription failed: {e}")
                transcribed_text = None

        if transcribed_text:
            with st.spinner("Scanning transcript..."):
                result = run(text=transcribed_text, user_id=user_id)

# --- Detection Report ---
if result:
    st.markdown("---")
    st.markdown("## Detection Report")

    # Status banner
    if result["safe_to_send"]:
        st.success("SAFE TO SEND — No PHI detected")
    else:
        total = len(result["regex_findings"]) + len(result["semantic_findings"])
        st.error(f"BLOCKED — {total} PHI finding(s) detected and redacted")

    # Side by side: original vs redacted
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Original Message**")
        st.text_area("", value=result["original"], height=120, disabled=True, key="orig")
    with col2:
        st.markdown("**Redacted Output (sent to AI)**")
        st.text_area("", value=result["clean"], height=120, disabled=True, key="clean")

    # Findings breakdown
    st.markdown("### Findings Breakdown")
    fcol1, fcol2, fcol3 = st.columns(3)
    fcol1.metric("Regex Hits", len(result["regex_findings"]))
    fcol2.metric("Semantic Hits", len(result["semantic_findings"]))
    fcol3.metric("Baseten Escalated", "Yes" if result["baseten_escalated"] else "No")

    if result["regex_findings"]:
        st.markdown("**Structured PHI (Regex)**")
        for f in result["regex_findings"]:
            st.markdown(f"- `{f['type'].upper()}` — `{f['value']}`")

    if result["semantic_findings"]:
        st.markdown("**Contextual PHI (Claude Semantic)**")
        for f in result["semantic_findings"]:
            severity_color = "red" if f["severity"] == "high" else "orange"
            st.markdown(
                f"- :{severity_color}[**{f['severity'].upper()}**] "
                f"`{f['type']}` ({f.get('regulation', 'general')}) — {f['reason']}"
            )

    if result.get("openai_confirmed"):
        confirmed = result["openai_confirmed"].get("confirmed")
        notes = result["openai_confirmed"].get("notes", "")
        st.markdown(f"**OpenAI Validation:** `{'confirmed' if confirmed else 'not confirmed'}` — {notes}")

# --- Live Audit Log ---
st.markdown("---")
st.markdown("### Live HIPAA Audit Log")
st.caption("Every scan is logged. This is the compliance trail your legal team needs.")

try:
    with open("dlp_audit_log.jsonl") as f:
        entries = [json.loads(line) for line in f.readlines()[-10:]]

    if entries:
        for entry in reversed(entries):
            sev = entry["severity"]
            color = "red" if sev == "high" else "orange" if sev == "medium" else "green"
            types = ", ".join(entry.get("finding_types", [])) or "none"
            st.markdown(
                f"`{entry['timestamp']}` &nbsp;|&nbsp; "
                f"user: `{entry['user_id']}` &nbsp;|&nbsp; "
                f"severity: :{color}[**{sev}**] &nbsp;|&nbsp; "
                f"findings: `{entry['findings_count']}` &nbsp;|&nbsp; "
                f"types: `{types}` &nbsp;|&nbsp; "
                f"safe: `{entry['safe_to_send']}`"
            )
    else:
        st.caption("No scans yet.")
except FileNotFoundError:
    st.caption("No scans yet — run a scan above to populate the audit log.")
