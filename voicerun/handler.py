import json
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

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
from config import (
    PROVIDER,
    MODEL,
    VOICE,
    TEMPERATURE,
    MAX_TOKENS,
    TIMEOUT,
    ERROR_MESSAGE,
    TIMEOUT_MESSAGE,
    TIMEOUT_GOODBYE,
    GOODBYE_MESSAGE,
    TIMEOUT_MAX_COUNT,
    build_system_prompt,
    build_greeting,
)

# Import DLP pipeline from parent project
from agent.tools import scan_and_clean


def _get_llm_config(context: Context):
    return {
        "provider": PROVIDER,
        "model": MODEL,
    }


def _build_dlp_debug_event(context: Context, dlp_result: dict) -> DebugEvent:
    """Emit DLP scan result as a debug event — visible in Voicerun debugger."""
    return DebugEvent(
        event_name="dlp_scan",
        event_data={
            "safe_to_send":       dlp_result["safe_to_send"],
            "regex_findings":     len(dlp_result["regex_findings"]),
            "semantic_findings":  len(dlp_result["semantic_findings"]),
            "baseten_escalated":  dlp_result.get("baseten_escalated"),
            "finding_types":      [f["type"] for f in dlp_result["regex_findings"]] +
                                  [f["type"] for f in dlp_result["semantic_findings"]],
        },
        direction="output",
        context={},
    )


async def _run_completion(context: Context, messages: ConversationHistory):
    """Streaming LLM completion loop."""
    sentences = []
    system_prompt = build_system_prompt()

    stream = await generate_chat_completion_stream(
        request={
            **_get_llm_config(context),
            "messages": [SystemMessage(content=system_prompt), *messages],
            "temperature": TEMPERATURE,
            "max_tokens": MAX_TOKENS,
            "timeout": TIMEOUT,
        },
        stream_options={
            "stream_sentences": True,
            "clean_sentences": True,
        },
    )

    async for chunk in stream:
        if chunk.type == "content_sentence":
            sentences.append(chunk.sentence)
        elif chunk.type == "response":
            messages.append(chunk.response.message)

    return sentences, messages


async def handler(event: Event, context: Context):
    if isinstance(event, StartEvent):
        configure_provider(PROVIDER, voicerun_managed=True)
        yield TextToSpeechEvent(text=build_greeting(), voice=VOICE)

    if isinstance(event, TextEvent):
        raw_message = event.data.get("text", "")
        session_id = getattr(context, "session_id", "voicerun-session")

        # --- DLP SCAN — intercept before LLM ---
        dlp_result = scan_and_clean(raw_message, user_id=session_id)

        yield _build_dlp_debug_event(context, dlp_result)

        if not dlp_result["safe_to_send"]:
            finding_types = (
                [f["type"] for f in dlp_result["regex_findings"]] +
                [f["type"] for f in dlp_result["semantic_findings"]]
            )
            yield DebugEvent(
                event_name="dlp_blocked",
                event_data={"reason": "PHI detected", "types": finding_types},
                direction="output",
                context={},
            )

        # Pass redacted message to LLM — never the raw input
        clean_message = dlp_result["clean"]

        messages: ConversationHistory = deserialize_conversation(
            context.get_completion_messages()
        )
        messages.append(UserMessage(content=clean_message))

        try:
            sentences, messages = await _run_completion(context, messages)

            for sentence in sentences:
                yield TextToSpeechEvent(text=sentence, voice=VOICE)

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
