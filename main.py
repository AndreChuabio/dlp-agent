"""CLI entry point for the DLP agent.

The DLP scan result no longer includes the raw input text by default --
the caller already has it, and including it in the result object made
accidental logging trivially easy. Set DLP_DEBUG=true in the environment
to display the original side-by-side with the redacted version.
"""

import json
import os
import sys
from agent.orchestrator import run


def main():
    if len(sys.argv) > 1:
        text = " ".join(sys.argv[1:])
    else:
        print("Paste patient message (Ctrl+D when done):")
        text = sys.stdin.read()

    result = run(text=text, user_id="cli-user")

    if os.getenv("DLP_DEBUG", "false").lower() == "true":
        print("\n--- ORIGINAL (DLP_DEBUG) ---")
        print(text)
    print("\n--- REDACTED ---")
    print(result["clean"])
    print("\n--- FINDINGS ---")
    print(f"Regex:    {len(result['regex_findings'])} hit(s)")
    print(f"Semantic: {len(result['semantic_findings'])} hit(s)")
    print(f"Safe to send: {result['safe_to_send']}")
    print(f"Baseten escalated: {result['baseten_escalated']}")
    if result.get("openai_confirmed") is not None:
        print(f"OpenAI confirmed: {result['openai_confirmed']}")
    print("\n--- FULL RESULT ---")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
