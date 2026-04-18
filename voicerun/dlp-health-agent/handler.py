"""
Primary Care Onboarding & Triage Agent — Voicerun handler.

Two flows:
  Returning patient  →  identify by name → skip re-collection → ask concern → triage → recommend specialist
  New patient        →  collect name, DOB, phone → ask concern → triage → recommend specialist → save to DB

DLP scans every patient message before it touches the LLM.
Specialist triage is powered by Claude semantic matching against a mocked doctor database.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from primfunctions.events import (
    Event, StartEvent, TextEvent, StopEvent,
    TextToSpeechEvent, TimeoutEvent, DebugEvent,
)
from primfunctions.context import Context
from primfunctions.completions import (
    ConversationHistory, SystemMessage, UserMessage,
    configure_provider, deserialize_conversation, generate_chat_completion_stream,
)
from datetime import date

from tools import (
    scan_and_clean,
    extract_patient_info,
    lookup_patient,
    save_patient,
    triage_specialist,
)

PROVIDER = "openai"
MODEL = "gpt-4o"
VOICE = "alloy"
TEMPERATURE = 0.7
MAX_TOKENS = 300
TIMEOUT = 30.0
TIMEOUT_MAX_COUNT = 9

ERROR_MESSAGE = "Sorry, I ran into an issue. Could you repeat that?"
TIMEOUT_MESSAGE = "Are you still there? Take your time."
TIMEOUT_GOODBYE = "It seems like you stepped away. Feel free to call back anytime."
GOODBYE_MESSAGE = "Thanks for calling Maple Grove Medical. Take care!"


def _build_system_prompt(
    patient_info: dict,
    is_returning: bool | None,
    db_patient: dict | None,
    triage_result: dict | None,
) -> str:
    today = date.today().strftime("%Y-%m-%d (%A)")
    prompt = (
        "You are a warm, efficient primary care receptionist at Maple Grove Medical Clinic. "
        "Your mission: onboard patients and triage them directly to the right specialist — "
        "so no one has to book a GP appointment just to ask for a referral. "
        "All patient messages have been pre-scanned by our HIPAA DLP layer before reaching you. "
        "This is a voice call — keep every response to 1–2 sentences, warm and natural.\n\n"
        f"Today is {today}.\n\n"
    )

    # --- State: who are we talking to? ---
    if is_returning is None:
        prompt += (
            "STEP: Identify the patient.\n"
            "You haven't looked them up yet. Ask for their name.\n"
        )

    elif is_returning:
        assert db_patient is not None
        conds = db_patient.get("conditions", [])
        cond_str = ", ".join(conds) if conds else "none on file"
        prompt += (
            "RETURNING PATIENT — INFO ALREADY ON FILE:\n"
            f"  Name:             {db_patient['name']}\n"
            f"  DOB:              {db_patient.get('dob', 'unknown')}\n"
            f"  Known conditions: {cond_str}\n"
            f"  Last visit:       {db_patient.get('last_visit', 'unknown')}\n"
            f"  Notes:            {db_patient.get('notes', '—')}\n"
            "DO NOT ask for DOB, phone, or insurance — it's already saved. "
            "Welcome them back warmly and ask what brings them in today.\n"
        )

    else:
        # New patient — show progress
        collected = {k: v for k, v in patient_info.items() if v and v not in (None, "null", "")}
        prompt += "NEW PATIENT — collecting basic info before triage.\n"
        if collected:
            prompt += f"  Collected so far: {collected}\n"
        needed = []
        if not collected.get("patient_name"):
            needed.append("full name")
        if not collected.get("dob"):
            needed.append("date of birth")
        if not collected.get("phone"):
            needed.append("callback phone number")
        if not collected.get("reason"):
            needed.append("primary concern / reason for visit")
        if needed:
            prompt += f"  Still need: {', '.join(needed)}\n"
            prompt += "  Ask for ONE item at a time — keep it conversational.\n"
        else:
            prompt += "  All basic info collected — triage is in progress.\n"

    # --- Triage result ---
    if triage_result:
        prompt += (
            "\nTRIAGE COMPLETE — RECOMMENDED SPECIALIST:\n"
            f"  {triage_result['specialist_name']} ({triage_result['specialty']})\n"
            f"  Available: {triage_result.get('availability', 'call for availability')}\n"
            f"  Why: {triage_result['reason']}\n"
            "Tell the patient which specialist to see and why — in one warm sentence. "
            "Mention this saves them from needing a separate GP visit just for a referral. "
            "Let them know the clinic team will follow up to schedule the appointment.\n"
        )
    elif patient_info.get("reason") and is_returning is not None:
        prompt += "\nPatient's concern is noted — triage is being determined, keep the conversation going.\n"

    prompt += (
        "\nRules:\n"
        "- If you see [REDACTED:...] tokens, acknowledge the info was protected by our privacy system.\n"
        "- Never ask for SSNs or full medical record numbers.\n"
        "- Max 2 sentences per response.\n"
    )
    return prompt


async def handler(event: Event, context: Context):

    if isinstance(event, StartEvent):
        configure_provider(PROVIDER, voicerun_managed=True)

        # Voicerun injects secrets via context.variables, not os.environ/.env
        for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "BASETEN_API_KEY", "BASETEN_MODEL"):
            val = context.variables.get(key)
            if val:
                os.environ[key] = val

        context.set_data("patient_info", {})
        context.set_data("is_returning", None)   # None = not yet checked
        context.set_data("db_patient", None)
        context.set_data("triage_done", False)
        context.set_data("triage_result", None)
        yield TextToSpeechEvent(
            text=(
                "Thank you for calling Maple Grove Medical Clinic. "
                "I'm your care assistant — I can get you to the right specialist without any paperwork or unnecessary appointments. "
                "Can I start by getting your name?"
            ),
            voice=VOICE,
        )

    if isinstance(event, TextEvent):
        raw_message = event.data.get("text", "")
        session_id = getattr(context, "session_id", "voicerun-session")

        # --- 1. DLP scan — raw speech never reaches the LLM ---
        dlp_result = scan_and_clean(raw_message, user_id=session_id)
        yield DebugEvent(
            event_name="dlp_scan",
            event_data={
                "safe_to_send":      dlp_result["safe_to_send"],
                "regex_hits":        len(dlp_result["regex_findings"]),
                "semantic_hits":     len(dlp_result["semantic_findings"]),
                "baseten_escalated": dlp_result.get("baseten_escalated"),
                "finding_types":     [f["type"] for f in dlp_result["regex_findings"]] +
                                     [f["type"] for f in dlp_result["semantic_findings"]],
            },
            direction="output",
            context={},
        )

        clean_message = dlp_result["clean"]
        messages: ConversationHistory = deserialize_conversation(
            context.get_completion_messages()
        )
        messages.append(UserMessage(content=clean_message))

        # --- 2. Extract structured patient fields ---
        # raw_hint lets Claude recover fields (DOB, phone) that were redacted in the transcript
        raw_msgs = [
            {
                "role": "user" if isinstance(m, UserMessage) else "assistant",
                "content": m.content if isinstance(m.content, str) else "",
            }
            for m in messages
        ]
        new_info = extract_patient_info(raw_msgs, raw_hint=raw_message)

        # Merge: accumulate across turns, don't overwrite with null
        current_info = context.get_data("patient_info") or {}
        merged_info = {**current_info}
        for k, v in new_info.items():
            if v and v not in ("null", None, ""):
                merged_info[k] = v
        context.set_data("patient_info", merged_info)

        yield DebugEvent(
            event_name="patient_info",
            event_data=merged_info,
            direction="output",
            context={},
        )

        # --- 3. Patient lookup (fires once, as soon as we have a name) ---
        is_returning = context.get_data("is_returning")
        patient_name = merged_info.get("patient_name")

        if patient_name and is_returning is None:
            db_patient = lookup_patient(patient_name)
            if db_patient:
                context.set_data("is_returning", True)
                context.set_data("db_patient", db_patient)
                # Fill any missing collected fields from DB record
                merged_info = {**merged_info, **{
                    k: v for k, v in db_patient.items()
                    if k not in merged_info or not merged_info[k]
                }}
                context.set_data("patient_info", merged_info)
            else:
                context.set_data("is_returning", False)
                context.set_data("db_patient", None)

            yield DebugEvent(
                event_name="patient_lookup",
                event_data={"queried_name": patient_name, "found": db_patient is not None},
                direction="output",
                context={},
            )

        # Refresh after potential update
        is_returning = context.get_data("is_returning")
        db_patient = context.get_data("db_patient")

        # --- 4. Triage (fires once, as soon as we have a concern) ---
        triage_done = context.get_data("triage_done") or False
        reason = merged_info.get("reason")

        if reason and not triage_done and is_returning is not None:
            result = triage_specialist(reason)
            if result:
                context.set_data("triage_done", True)
                context.set_data("triage_result", result)
                yield DebugEvent(
                    event_name="triage_result",
                    event_data=result,
                    direction="output",
                    context={},
                )

            # Save new patients after triage (we now have enough info)
            if not is_returning:
                save_patient({
                    "name":         merged_info.get("patient_name", ""),
                    "dob":          merged_info.get("dob", ""),
                    "phone":        merged_info.get("phone", ""),
                    "insurance_id": merged_info.get("insurance_id", ""),
                    "conditions":   [reason] if reason else [],
                    "last_visit":   date.today().isoformat(),
                })

        triage_result = context.get_data("triage_result")

        # --- 5. LLM responds with full context ---
        try:
            stream = await generate_chat_completion_stream(
                request={
                    "provider":    PROVIDER,
                    "model":       MODEL,
                    "messages":    [
                        SystemMessage(content=_build_system_prompt(
                            patient_info=merged_info,
                            is_returning=is_returning,
                            db_patient=db_patient,
                            triage_result=triage_result,
                        )),
                        *messages,
                    ],
                    "temperature": TEMPERATURE,
                    "max_tokens":  MAX_TOKENS,
                    "timeout":     TIMEOUT,
                },
                stream_options={"stream_sentences": True, "clean_sentences": True},
            )

            async for chunk in stream:
                if chunk.type == "content_sentence":
                    yield TextToSpeechEvent(text=chunk.sentence, voice=VOICE)
                elif chunk.type == "response":
                    messages.append(chunk.response.message)

            context.set_completion_messages(messages)

        except Exception:
            yield TextToSpeechEvent(text=ERROR_MESSAGE, voice=VOICE)

    if isinstance(event, TimeoutEvent):
        count = event.data.get("count", 0)
        if count >= TIMEOUT_MAX_COUNT:
            yield StopEvent(closing_speech=TIMEOUT_GOODBYE, voice=VOICE)
        elif count % 3 == 0:
            yield TextToSpeechEvent(text=TIMEOUT_MESSAGE, voice=VOICE)

    if isinstance(event, StopEvent):
        yield TextToSpeechEvent(text=GOODBYE_MESSAGE, voice=VOICE)
