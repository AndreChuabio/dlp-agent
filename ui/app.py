"""Streamlit demo UI for the DLP agent."""

import json
import streamlit as st
from agent.orchestrator import run

st.set_page_config(page_title="DLP Agent", layout="wide")
st.title("Healthcare DLP Agent")
st.caption("HIPAA-compliant AI guardrail layer — PHI is intercepted before it reaches any model.")

user_id = st.sidebar.text_input("User ID", value="demo-user")
st.sidebar.markdown("---")
st.sidebar.markdown("**Model Config**")
st.sidebar.markdown("Swap `BASETEN_MODEL_ID` in `.env` to test different triage models.")

st.markdown("### Patient Message Input")
text_input = st.text_area("Paste or type patient message:", height=150,
                           placeholder="Hi, my name is John Smith, MRN 123456, DOB 04/12/1985. I'm on 50mg sertraline for F32.1...")

scan_btn = st.button("Scan Message", type="primary")

if scan_btn and text_input.strip():
    with st.spinner("Scanning..."):
        result = run(text=text_input, user_id=user_id)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Original Message")
        st.text_area("", value=result["original"], height=150, disabled=True)

        st.markdown("### Findings")
        if result["regex_findings"]:
            st.error(f"Regex: {len(result['regex_findings'])} structured PHI hit(s)")
            for f in result["regex_findings"]:
                st.markdown(f"- `{f['type']}` — `{f['value']}`")
        else:
            st.success("Regex: no structured PHI found")

        if result["semantic_findings"]:
            st.error(f"Semantic: {len(result['semantic_findings'])} contextual PHI hit(s)")
            for f in result["semantic_findings"]:
                badge = "🔴" if f["severity"] == "high" else "🟡"
                st.markdown(f"- {badge} `{f['type']}` ({f['regulation']}) — {f['reason']}")
        else:
            st.success("Semantic: no contextual PHI found")

    with col2:
        st.markdown("### Redacted Output (sent to AI)")
        st.text_area("", value=result["clean"], height=150, disabled=True)

        st.markdown("### Scan Summary")
        safe = result["safe_to_send"]
        if safe:
            st.success("SAFE TO SEND")
        else:
            st.error("BLOCKED — PHI detected")

        st.markdown(f"- Baseten escalated: `{result['baseten_escalated']}`")
        if result["openai_confirmed"] is not None:
            st.markdown(f"- OpenAI confirmed: `{result['openai_confirmed']}`")

    st.markdown("### Audit Log Entry")
    st.json(result)

elif scan_btn:
    st.warning("Enter a message to scan.")

st.markdown("---")
st.markdown("### Live Audit Log")
try:
    with open("dlp_audit_log.jsonl") as f:
        entries = [json.loads(line) for line in f.readlines()[-10:]]
    for entry in reversed(entries):
        color = "red" if entry["severity"] == "high" else "orange" if entry["severity"] == "medium" else "green"
        st.markdown(
            f"`{entry['timestamp']}` — user: `{entry['user_id']}` — "
            f"severity: :{color}[{entry['severity']}] — "
            f"findings: `{entry['findings_count']}` — safe: `{entry['safe_to_send']}`"
        )
except FileNotFoundError:
    st.caption("No scans yet — run a scan above to populate the audit log.")
