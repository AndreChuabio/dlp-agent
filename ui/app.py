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
from agent.replay import ingest_payload, replay_session
import anthropic

st.set_page_config(page_title="MediGuard AI", layout="wide")

# --- Session state init ---
if "messages"       not in st.session_state: st.session_state.messages       = []
if "patient_info"   not in st.session_state: st.session_state.patient_info   = {}
if "coverage"       not in st.session_state: st.session_state.coverage        = None
if "replay_result"  not in st.session_state: st.session_state.replay_result   = None
if "ingest_result"  not in st.session_state: st.session_state.ingest_result   = None
if "active_scenario" not in st.session_state: st.session_state.active_scenario = None

# ============================================================
# Mock production interaction payloads
# These represent real-looking logs an employee would receive
# in a bug ticket — complete with PHI that can't be pasted
# directly into Claude.
# ============================================================

MOCK_SCENARIOS = {
    "ticket-1234 — Returning patient, correct triage": {
        "badge": "✅ Happy Path",
        "badge_color": "green",
        "description": "Alice Johnson (returning patient) calls about chest tightness. Agent identifies her from the DB, skips re-collection, and triages correctly to Cardiology.",
        "known_issue": None,
        "expected": "Triage → Dr. Sarah Chen (Cardiologist)",
        "turns": [
            {"role": "user",  "text": "Hi, my name is Alice Johnson. My date of birth is March 22nd, 1975."},
            {"role": "agent", "text": "Welcome back, Alice! I can see you were last in on October 15th. What brings you in today?"},
            {"role": "user",  "text": "I've been having chest tightness lately, and sometimes I feel short of breath when I climb stairs."},
            {"role": "agent", "text": "I'd recommend Dr. Sarah Chen, our Cardiologist — she's available Monday, Wednesday, and Friday and is the right fit for those symptoms. Our team will follow up to schedule the referral."},
            {"role": "user",  "text": "Perfect, my callback number is 212-555-0101. Thank you!"},
            {"role": "agent", "text": "Got it, Alice. We'll be in touch. Take care!"}
        ]
    },

    "ticket-5678 — New patient, full onboarding": {
        "badge": "✅ Happy Path",
        "badge_color": "green",
        "description": "James Park calls for the first time. Agent runs full onboarding — collects DOB and phone, triages stomach symptoms to Gastroenterology, saves record.",
        "known_issue": None,
        "expected": "Triage → Dr. Marcus Rivera (Gastroenterologist)",
        "turns": [
            {"role": "user",  "text": "Hi, I'm James Park. First time calling."},
            {"role": "agent", "text": "Nice to meet you, James! I don't have you in our system yet. What's your date of birth?"},
            {"role": "user",  "text": "March 4th, 1988."},
            {"role": "agent", "text": "Got it. And a good callback number for you?"},
            {"role": "user",  "text": "646-555-0192."},
            {"role": "agent", "text": "Thanks! What's the main reason you're calling today?"},
            {"role": "user",  "text": "My stomach has been really hurting, especially after I eat. Lots of bloating and acid reflux too."},
            {"role": "agent", "text": "That sounds like a great fit for Dr. Marcus Rivera, our Gastroenterologist — available Tuesday and Thursday. We'll reach out to schedule the referral directly, no extra GP visit needed."}
        ]
    },

    "ticket-9012 — PHI leak inside raw log (critical)": {
        "badge": "🔴 PHI in Log",
        "badge_color": "red",
        "description": "A production session log that has raw PHI embedded in system metadata — SSN in the log header, MRN and DOB in turn metadata. Exactly what would cause a HIPAA violation if pasted into Claude.",
        "known_issue": "Production logging pipeline is writing PHI into turn metadata. Bug filed against logging service.",
        "expected": "DLP should catch SSN, MRN, DOB, phone across multiple turns",
        "turns": [
            {"role": "system", "text": "Session init. Patient SSN: 234-56-7890. Lookup result: MRN-445521. Insurance: AETNA-112233.", "metadata": {"patient_id": "MRN-445521", "dob": "1968-11-30"}},
            {"role": "user",  "text": "Hi, I'm Maria Santos. Born November 30, 1968. My MRN is MRN-445521."},
            {"role": "agent", "text": "Welcome back, Maria! What brings you in today?"},
            {"role": "user",  "text": "My lower back has been killing me again — same arthritis issue. I'm still taking 800mg ibuprofen twice a day. My phone is 917-555-0789."},
            {"role": "agent", "text": "I'd recommend Dr. James Kim, our Orthopedic Specialist, who can help with that. We'll follow up to schedule."}
        ]
    },

    "ticket-3456 — Vague concern, triage defaults to GP": {
        "badge": "⚠️ Edge Case",
        "badge_color": "orange",
        "description": "Robert Chen calls but can't articulate a specific concern. Triage should default to the General Practitioner — verify it does and doesn't leave him unrouted.",
        "known_issue": None,
        "expected": "Triage → Dr. Robert Walsh (General Practitioner)",
        "turns": [
            {"role": "user",  "text": "Hey, my name is Robert Chen."},
            {"role": "agent", "text": "Hi Robert! What brings you in today?"},
            {"role": "user",  "text": "Honestly I'm not sure. I just haven't been feeling great lately. Kind of tired, maybe a headache here and there. Nothing specific."},
            {"role": "agent", "text": "I understand — let me get a few details. What's your date of birth?"},
            {"role": "user",  "text": "February 14, 1992. My insurance member ID is UHC-778899."},
            {"role": "agent", "text": "Thanks, Robert. For a general wellness concern like this, I'd start with Dr. Robert Walsh, our General Practitioner, available Monday through Friday. He can help figure out what's going on and refer you from there."}
        ]
    },

    "ticket-7890 — Incomplete session, triage never ran (bug)": {
        "badge": "🐛 Bug",
        "badge_color": "red",
        "description": "David Kim (returning patient) is identified but hangs up before stating a concern. Triage never ran. This session was escalated because the patient called back angry — use replay to find the exact turn where the session dropped off.",
        "known_issue": "Agent should have prompted for concern more proactively after identifying the patient. Current system prompt waits for user to volunteer it.",
        "expected": "Issue detected: triage never ran, no concern extracted",
        "turns": [
            {"role": "user",  "text": "Hi, it's David Kim, date of birth July 8, 1990."},
            {"role": "agent", "text": "Welcome back, David! What brings you in today?"},
            {"role": "user",  "text": "Actually you know what, I need to go. I'll call back later, sorry about that."},
            {"role": "agent", "text": "Of course! Feel free to call back anytime. Have a great day!"}
        ]
    },
}

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
    st.markdown("1. Regex scan\n2. Baseten triage\n3. Claude Haiku semantic\n4. Redact + Log")
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
        st.session_state.messages     = []
        st.session_state.patient_info = {}
        st.session_state.coverage     = None
        st.rerun()

# --- Header ---
st.title("MediGuard AI — Patient Onboarding")
st.caption("Patients speak or type naturally. PHI is intercepted before it reaches any AI model.")
st.markdown("---")

# --- Tabs ---
chat_tab, scan_tab, voice_tab, debug_tab = st.tabs(
    ["Agent Chat", "DLP Scanner", "Voice Input", "🔍 Debug Replay"]
)

# ============================================================
# TAB 1 — Conversational agent chat
# ============================================================
with chat_tab:
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if msg.get("dlp_findings"):
                with st.expander(f"DLP — {msg['dlp_findings']['total']} finding(s) redacted"):
                    for f in msg["dlp_findings"].get("regex", []):
                        st.markdown(f"- `{f['type'].upper()}` — `{f['value']}`")
                    for f in msg["dlp_findings"].get("semantic", []):
                        sev   = f.get("severity", "low")
                        color = "red" if sev == "high" else "orange"
                        st.markdown(f"- :{color}[**{sev.upper()}**] `{f['type']}` — {f['reason']}")

    patient_input = st.chat_input("Type your message as the patient...")

    if patient_input:
        dlp_result   = scan_and_clean(patient_input, user_id=user_id)
        clean_message = dlp_result["clean"]

        findings_summary = {
            "total":    len(dlp_result["regex_findings"]) + len(dlp_result["semantic_findings"]),
            "regex":    dlp_result["regex_findings"],
            "semantic": dlp_result["semantic_findings"],
        }

        with st.chat_message("user"):
            st.markdown(clean_message)
            if findings_summary["total"] > 0:
                with st.expander(f"DLP — {findings_summary['total']} finding(s) redacted"):
                    for f in findings_summary["regex"]:
                        st.markdown(f"- `{f['type'].upper()}` — `{f['value']}`")
                    for f in findings_summary["semantic"]:
                        sev   = f.get("severity", "low")
                        color = "red" if sev == "high" else "orange"
                        st.markdown(f"- :{color}[**{sev.upper()}**] `{f['type']}` — {f['reason']}")

        st.session_state.messages.append({
            "role": "user", "content": clean_message, "dlp_findings": findings_summary,
        })

        raw_msgs    = [{"role": m["role"], "content": m["content"]} for m in st.session_state.messages]
        patient_info = extract_patient_info(raw_msgs)
        if patient_info:
            merged = {**st.session_state.patient_info, **{k: v for k, v in patient_info.items() if v and v != "null"}}
            st.session_state.patient_info = merged

        insurance_id = st.session_state.patient_info.get("insurance_id")
        if insurance_id and not st.session_state.coverage:
            with st.spinner("Searching coverage via You.com..."):
                st.session_state.coverage = search_insurance_coverage(
                    insurance_id=insurance_id,
                    reason=st.session_state.patient_info.get("reason", ""),
                )

        system = SYSTEM_PROMPT
        if st.session_state.patient_info:
            collected = {k: v for k, v in st.session_state.patient_info.items() if v and v != "null"}
            system += f"\n\nCollected so far: {json.dumps(collected)}"
        if st.session_state.coverage and st.session_state.coverage.get("results"):
            snippets = " | ".join(r["snippet"] for r in st.session_state.coverage["results"][:2] if r.get("snippet"))
            system += f"\n\nInsurance coverage info: {snippets}"

        with st.chat_message("assistant"):
            with st.spinner(""):
                try:
                    client   = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
                    history  = [{"role": m["role"], "content": m["content"]} for m in st.session_state.messages]
                    response = client.messages.create(
                        model="claude-opus-4-6", max_tokens=300, system=system, messages=history,
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
                st.text_area("", value=result["clean"],    height=120, disabled=True, key="clean")

            fcol1, fcol2, fcol3 = st.columns(3)
            fcol1.metric("Regex Hits",        len(result["regex_findings"]))
            fcol2.metric("Semantic Hits",     len(result["semantic_findings"]))
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
                client       = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
                audio_bytes  = io.BytesIO(audio.read())
                audio_bytes.name = "recording.wav"
                transcript   = client.audio.transcriptions.create(model="whisper-1", file=audio_bytes)
                transcribed_text = transcript.text
                st.info(f"Transcript: {transcribed_text}")
            except Exception as e:
                st.error(f"Transcription failed: {e}")
                transcribed_text = None

        if transcribed_text:
            with st.spinner("Scanning..."):
                result = run(text=transcribed_text, user_id=user_id)
            st.success("SAFE TO SEND") if result["safe_to_send"] else st.error(
                f"BLOCKED — {len(result['regex_findings']) + len(result['semantic_findings'])} finding(s)"
            )
            st.text_area("Redacted output", value=result["clean"], disabled=True)

# ============================================================
# TAB 4 — Debug Replay
# ============================================================
with debug_tab:
    st.markdown("### Debug a production ticket — without leaking PHI")
    st.caption(
        "Load a mock production interaction log. "
        "The raw payload (with real patient data) is DLP-stripped locally. "
        "Only the redacted version is replayed through the agent pipeline — no PHI ever reaches Claude."
    )
    st.markdown("---")

    left_col, right_col = st.columns([1, 2], gap="large")

    with left_col:
        scenario_key = st.selectbox(
            "Load scenario",
            list(MOCK_SCENARIOS.keys()),
            index=0,
        )
        scenario = MOCK_SCENARIOS[scenario_key]

        # Badge + description
        badge_color = scenario["badge_color"]
        st.markdown(f":{badge_color}[**{scenario['badge']}**]")
        st.markdown(scenario["description"])

        if scenario["known_issue"]:
            st.warning(f"**Known issue:** {scenario['known_issue']}")
        else:
            st.markdown(f"**Expected outcome:** {scenario['expected']}")

        st.markdown("")

        # Raw payload preview
        with st.expander("View raw payload ⚠️ contains PHI", expanded=False):
            st.caption("This is what arrives from the production logging system — exactly what an employee should NOT paste into Claude.")
            st.code(
                json.dumps(scenario["turns"], indent=2),
                language="json",
            )

        run_button = st.button("Ingest + Replay", type="primary", use_container_width=True)

        if run_button:
            session_name = "demo-" + scenario_key.split("—")[0].strip().replace(" ", "-").lower()
            st.session_state.active_scenario = scenario_key

            progress = st.progress(0, text="Running DLP scan on raw payload...")
            try:
                ingest_result = ingest_payload(
                    json.dumps(scenario["turns"]),
                    session_name=session_name,
                )
                st.session_state.ingest_result = ingest_result
                progress.progress(50, text="Replaying through agent pipeline...")

                replay_result = replay_session(session_name)
                st.session_state.replay_result = replay_result
                progress.progress(100, text="Done.")
            except Exception as e:
                st.error(f"Replay failed: {e}")
                progress.empty()
            st.rerun()

    # ── Right column: results ──────────────────────────────────────
    with right_col:
        if st.session_state.replay_result and st.session_state.active_scenario:
            result = st.session_state.replay_result
            ingest = st.session_state.ingest_result or {}
            active = MOCK_SCENARIOS.get(st.session_state.active_scenario, {})

            # ── Summary metrics ──
            ctx          = result.get("final_context", {})
            triage       = ctx.get("triage_result")
            is_returning = ctx.get("is_returning")
            issues       = result.get("issues_detected", [])
            phi_found    = ingest.get("phi_findings", 0)

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("PHI in raw log",    phi_found,
                      delta="blocked" if phi_found else None,
                      delta_color="inverse" if phi_found else "off")
            m2.metric("Issues detected",   len(issues),
                      delta="⚠ needs fix" if issues else None,
                      delta_color="inverse" if issues else "off")
            m3.metric("Triage",            "✓ resolved" if triage else "✗ failed")
            m4.metric("Patient type",
                      "Returning" if is_returning else "New" if is_returning is False else "Unknown")

            st.markdown("")

            # ── Issues banner ──
            if issues:
                with st.container(border=True):
                    st.error("**Issues detected in this session**")
                    for issue in issues:
                        st.markdown(f"- {issue}")
            else:
                st.success("**No issues detected** — session ran cleanly.")

            # ── Triage result ──
            if triage:
                st.info(
                    f"**Triage resolved to:** {triage['specialist_name']} "
                    f"({triage['specialty']})  \n"
                    f"*{triage.get('reason', '')}*"
                )
            elif ctx.get("patient_info", {}).get("reason"):
                st.warning("Concern was extracted but triage did not complete.")
            else:
                st.warning("No concern extracted — triage never ran.")

            # ── PHI summary from ingest ──
            if phi_found:
                ft = ingest.get("finding_types", [])
                st.error(
                    f"**{phi_found} PHI finding(s) stripped from raw log** — "
                    f"types: `{', '.join(ft)}`  \n"
                    "These would have been exposed if pasted directly into Claude."
                )

            st.markdown("---")
            st.markdown("#### Turn-by-turn trace")
            st.caption("Each user turn shows what DLP found, what the agent pipeline extracted, and where state changed.")

            # ── Turn trace ──
            for turn in result.get("trace", []):
                role = turn.get("role", "user")
                text = turn.get("text", "")
                i    = turn.get("turn", 0)

                if role != "user":
                    with st.expander(f"Turn {i} — **Agent:** {text[:70]}{'...' if len(text) > 70 else ''}"):
                        st.markdown(f"> {text}")
                    continue

                dlp      = turn.get("dlp", {})
                hits     = dlp.get("regex_hits", 0) + dlp.get("semantic_hits", 0)
                has_info = bool(turn.get("patient_lookup") or turn.get("triage"))

                if hits:
                    label = f"🔴 Turn {i} — **Patient** — {hits} PHI finding(s)"
                elif has_info:
                    label = f"🟢 Turn {i} — **Patient** — clean + state update"
                else:
                    label = f"Turn {i} — **Patient** — clean"

                with st.expander(label, expanded=(hits > 0 or has_info)):
                    # Redacted text
                    st.markdown(f"**Redacted message sent to LLM:**")
                    st.code(text, language=None)

                    # DLP findings
                    if hits:
                        st.error(
                            f"DLP caught {hits} finding(s): "
                            f"`{', '.join(dlp.get('finding_types', []))}`"
                        )
                    else:
                        st.success("DLP: clean")

                    detail_col1, detail_col2 = st.columns(2)

                    # Patient info extracted
                    with detail_col1:
                        info = {
                            k: v for k, v in (turn.get("patient_info_so_far") or {}).items()
                            if v and v not in ("null", None, "")
                        }
                        if info:
                            st.markdown("**Patient info so far:**")
                            for k, v in info.items():
                                st.markdown(f"- `{k}`: {v}")

                    # Lookup + triage events
                    with detail_col2:
                        lookup = turn.get("patient_lookup")
                        if lookup:
                            if lookup.get("found_in_db"):
                                st.success(f"Found in DB: **{lookup['queried_name']}**")
                                record = lookup.get("record", {})
                                if record.get("conditions"):
                                    st.caption(f"Known conditions: {', '.join(record['conditions'])}")
                            else:
                                st.info(f"New patient: **{lookup['queried_name']}**")

                        t = turn.get("triage")
                        if t:
                            st.success(
                                f"Triage → **{t['specialist_name']}**  \n"
                                f"*{t['specialty']}*"
                            )

            # ── Summary text ──
            summary = result.get("summary", "")
            if summary:
                st.markdown("---")
                st.markdown("#### Replay summary")
                st.markdown(summary)

        else:
            # Placeholder before first run
            st.markdown("")
            st.info(
                "Select a scenario and click **Ingest + Replay** to see the debug trace.  \n\n"
                "The raw payload (with PHI) stays on your machine. "
                "Only the redacted version is replayed through the pipeline."
            )
            st.markdown("")
            st.markdown("**Available scenarios:**")
            for key, s in MOCK_SCENARIOS.items():
                badge_color = s["badge_color"]
                st.markdown(f"- :{badge_color}[**{s['badge']}**] {key.split('—')[1].strip()}")

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
        sev   = entry["severity"]
        color = "red" if sev == "high" else "orange" if sev == "medium" else "green"
        types = ", ".join(entry.get("finding_types", [])) or "none"
        st.markdown(
            f"`{entry['timestamp']}` &nbsp;|&nbsp; user: `{entry['user_id']}` &nbsp;|&nbsp; "
            f"severity: :{color}[**{sev}**] &nbsp;|&nbsp; findings: `{entry['findings_count']}` &nbsp;|&nbsp; "
            f"types: `{types}` &nbsp;|&nbsp; safe: `{entry['safe_to_send']}`"
        )
except FileNotFoundError:
    st.caption("No scans yet.")
