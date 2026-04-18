"""Main agent loop — accepts input, runs DLP pipeline, returns result."""

import logging
from agent.tools import scan_and_clean, transcribe_audio

logger = logging.getLogger(__name__)


def run(text: str = None, audio_source=None, user_id: str = "anonymous") -> dict:
    """
    Entry point for the DLP agent.
    Accepts either raw text or audio (transcribed via Voicerun).
    Returns full scan result dict.
    """
    if audio_source is not None:
        logger.info("Audio input detected — transcribing via Voicerun.")
        text = transcribe_audio(audio_source)

    if not text:
        raise ValueError("No input provided — pass text or audio_source.")

    logger.info(f"Running DLP scan for user: {user_id}")
    return scan_and_clean(text, user_id=user_id)
