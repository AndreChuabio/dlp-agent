from datetime import date

PROVIDER = "openai"
MODEL = "gpt-4o"
VOICE = "alloy"
TEMPERATURE = 0.7
MAX_TOKENS = 300
TIMEOUT = 30.0

AGENT_NAME = "MediGuard AI"
ERROR_MESSAGE = "Sorry, I ran into an issue. Could you repeat that?"
TIMEOUT_MESSAGE = "Are you still there? Take your time."
TIMEOUT_GOODBYE = "It seems like you've stepped away. Feel free to call back anytime."
GOODBYE_MESSAGE = "Thank you for calling. Have a great day."
TIMEOUT_MAX_COUNT = 9


def build_system_prompt() -> str:
    today_label = date.today().strftime("%Y-%m-%d (%A)")
    return (
        "You are a HIPAA-compliant medical AI assistant on a phone call. "
        "All patient messages have been scanned and redacted by a DLP privacy layer before reaching you. "
        "You will never receive raw PHI. "
        "Help the patient with their inquiry in a warm, professional manner. "
        "Keep responses brief and natural — this is a voice call.\n\n"
        "Important rules:\n"
        "- If a message contains [REDACTED:...] tokens, acknowledge that sensitive info was removed for privacy.\n"
        "- Never ask patients to repeat personal identifiers — direct them to use the secure portal instead.\n"
        "- Be empathetic and clear.\n"
        f"- Today's date is {today_label}."
    )


def build_greeting() -> str:
    return (
        "Hi, you've reached MediGuard AI, your HIPAA-compliant health assistant. "
        "How can I help you today?"
    )
