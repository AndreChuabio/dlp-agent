"""
DLP Health Agent — Voicerun handler.
Patient onboarding via voice. DLP scans every message before it reaches the LLM.
You.com searches insurance coverage using only the insurance ID — never raw PHI.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from primfunctions.events import (
    Event,
    StartEvent,
    TextEvent,
    StopEvent,
    TextToSpeechEvent,
    TimeoutEvent,
    DebugEvent,
)
from primfunctions.context import Context
from primfunctions.completions import (
    ConversationHistory,
    SystemMessage,
    UserMessage,
    configure_provider,
    deserialize_conversation,
    generate_chat_completion_stream,
)
from datetime import date

from agent.tools import scan_and_clean, extract_patient_info, search_insurance_coverage

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
GOODBYE_MESSAGE = "Thank you for calling MediGuard AI. Have a great day."


def _build_system_prompt(patient_info: dict, coverage: dict | None) -> str:
    today = date.today().strftime("%Y-%m-%d (%A)")
    base = (
        "You are MediGuard AI, a HIPAA-compliant patient onboarding assistant on a phone call. "
        "Your job is to collect patient information conversationally — no forms, no paperwork. "
        "All patient messages are pre-scanned and redacted by a DLP layer. You never see raw PHI. "
        "Keep responses brief and natural — this is a voice call.\n\n"
        "Onboarding flow:\n"
        "1. Ask for their name and reason for visit.\n"
        "2. Ask for their insurance ID number.\n"
        "3. Once you have the insurance ID, let them know you're checking their coverage.\n"
        "4. Confirm their date of birth and a callback phone number.\n"
        "5. Summarize what you collected and let them know the clinic will follow up.\n\n"
        "Rules:\n"
        "- Ask for one piece of information at a time.\n"
        "- If a message has [REDACTED:...] tokens, acknowledge the info was protected for privacy.\n"
        "- Never ask patients to spell out SSNs or full medical record numbers — insurance ID only.\n"
        "- Be warm, empathetic, and conversational.\n"
        f"- Today's date is {today}.\n"
    )

    if patient_info:
        collected = {k: v for k, v in patient_info.items() if v and v != "null"}
        if collected:
            base += f"\nCollected so far: {collected}\n"

    if coverage and coverage.get("results"):
        snippets = " | ".join(r["snippet"] for r in coverage["results"][:2] if r.get("snippet"))
        base += f"\nInsurance coverage info found: {snippets}\n"

    return base


async def handler(event: Event, context: Context):

    if isinstance(event, StartEvent):
        configure_provider(PROVIDER, voicerun_managed=True)
        context.set_data("patient_info", {})
        context.set_data("coverage", None)
        yield TextToSpeechEvent(
            text="Hi, you've reached MediGuard AI, your HIPAA-compliant health assistant. I can help get you onboarded today without any paperwork. What's your name and what brings you in?",
            voice=VOICE,
        )

    if isinstance(event, TextEvent):
        raw_message = event.data.get("text", "")
        session_id = getattr(context, "session_id", "voicerun-session")

        # Step 1 — DLP scan, raw speech never reaches LLM
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

        # Step 2 — extract structured patient info from conversation
        raw_msgs = [{"role": "user" if isinstance(m, UserMessage) else "assistant",
                     "content": m.content if isinstance(m.content, str) else ""}
                    for m in messages]
        patient_info = extract_patient_info(raw_msgs)
        if patient_info:
            context.set_data("patient_info", patient_info)

        yield DebugEvent(
            event_name="patient_info",
            event_data=patient_info,
            direction="output",
            context={},
        )

        # Step 3 — if we have an insurance ID and haven't searched yet, hit You.com
        coverage = context.get_data("coverage")
        insurance_id = patient_info.get("insurance_id")
        if insurance_id and insurance_id != "null" and not coverage:
            coverage = search_insurance_coverage(
                insurance_id=insurance_id,
                reason=patient_info.get("reason", ""),
            )
            context.set_data("coverage", coverage)
            yield DebugEvent(
                event_name="coverage_search",
                event_data=coverage,
                direction="output",
                context={},
            )

        # Step 4 — LLM responds with full context but never raw PHI
        try:
            stream = await generate_chat_completion_stream(
                request={
                    "provider": PROVIDER,
                    "model": MODEL,
                    "messages": [
                        SystemMessage(content=_build_system_prompt(patient_info, coverage)),
                        *messages,
                    ],
                    "temperature": TEMPERATURE,
                    "max_tokens": MAX_TOKENS,
                    "timeout": TIMEOUT,
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
