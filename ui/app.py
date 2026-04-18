"""MediGuard AI — Streamlit demo dashboard."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import io
import tempfile
import subprocess
import streamlit as st
from openai import OpenAI
from agent.orchestrator import run

VOICERUN_AGENT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "voicerun", "dlp-health-agent"
)

def run_voicerun_agent(messages: list[str]) -> dict:
    """Send messages to Voicerun agent headless and parse JSONL events back."""
    script = json.dumps(messages)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(script)
        script_path = f.name

    try:
        proc = subprocess.run(
            ["vr", "debug", "--headless", "--skip-push", "--script", script_path],
            capture_output=True,
            text=True,
            cwd=VOICERUN_AGENT_DIR,
            timeout=60,
        )
        output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return {"error": "Voicerun agent timed out.", "responses": [], "dlp_events": []}
    finally:
        os.unlink(script_path)

    responses = []
    dlp_events = []
    patient_info_events = []
    coverage_events = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            etype = event.get("type") or event.get("event_type") or ""

            if "tts" in etype.lower() or "speech" in etype.lower():
                text = event.get("text") or event.get("data", {}).get("text", "")
                if text:
                    responses.append(text)

            elif "dlp_scan" in str(event):
                data = event.get("event_data") or event.get("data", {})
                if data:
                    dlp_events.append(data)

            elif "patient_info" in str(event):
                data = event.get("event_data") or event.get("data", {})
                if data:
                    patient_info_events.append(data)

            elif "coverage" in str(event):
                data = event.get("event_data") or event.get("data", {})
                if data:
                    coverage_events.append(data)

        except (json.JSONDecodeError, KeyError):
            # Non-JSON lines are status messages — ignore
            if line and not line.startswith("["):
                responses.append(line) if "error" in line.lower() else None

    return {
        "responses": responses,
        "dlp_events": dlp_events,
        "patient_info": patient_info_events[-1] if patient_info_events else {},
        "coverage": coverage_events[-1] if coverage_events else {},
        "raw": output,
    }

st.set_page_config(page_title="MediGuard AI", layout="wide")

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
text_tab, voice_tab, agent_tab = st.tabs(["Text Input", "Voice Input", "Voicerun Agent"])

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

with agent_tab:
    st.caption("Chat directly with the Voicerun onboarding agent. Full pipeline runs server-side — DLP, You.com search, LLM response.")
    agent_input = st.text_area(
        "Patient message to agent:",
        height=100,
        placeholder="Hi, my name is John Smith. My insurance ID is BCX884521. I need to see someone about depression.",
        key="agent_input",
    )
    if st.button("Send to Agent", type="primary", key="agent_scan"):
        if agent_input.strip():
            with st.spinner("Running Voicerun agent pipeline..."):
                vr_result = run_voicerun_agent([agent_input.strip()])

            st.markdown("### Agent Response")
            if vr_result["responses"]:
                for r in vr_result["responses"]:
                    st.info(r)
            else:
                st.warning("No response from agent — check Voicerun deployment.")
                with st.expander("Raw output"):
                    st.text(vr_result.get("raw", ""))

            if vr_result["dlp_events"]:
                st.markdown("### DLP Scan (from Voicerun pipeline)")
                for ev in vr_result["dlp_events"]:
                    safe = ev.get("safe_to_send", True)
                    if safe:
                        st.success("SAFE TO SEND")
                    else:
                        st.error(f"BLOCKED — types detected: {', '.join(ev.get('finding_types', []))}")
                    st.markdown(
                        f"- Regex hits: `{ev.get('regex_hits', 0)}` "
                        f"| Semantic hits: `{ev.get('semantic_hits', 0)}` "
                        f"| Baseten escalated: `{ev.get('baseten_escalated')}`"
                    )

            if vr_result["patient_info"]:
                st.markdown("### Extracted Patient Info")
                st.json({k: v for k, v in vr_result["patient_info"].items() if v and v != "null"})

            if vr_result["coverage"] and vr_result["coverage"].get("results"):
                st.markdown("### Insurance Coverage (You.com)")
                for r in vr_result["coverage"]["results"]:
                    st.markdown(f"- **{r.get('title', '')}** — {r.get('snippet', '')}")
        else:
            st.warning("Enter a message to send.")

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
