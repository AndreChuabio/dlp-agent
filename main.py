"""CLI entry point for the DLP agent."""

import json
import sys
from agent.orchestrator import run


def main():
    if len(sys.argv) > 1:
        text = " ".join(sys.argv[1:])
    else:
        print("Paste patient message (Ctrl+D when done):")
        text = sys.stdin.read()

    result = run(text=text, user_id="cli-user")

    print("\n--- ORIGINAL ---")
    print(result["original"])
    print("\n--- REDACTED ---")
    print(result["clean"])
    print("\n--- FINDINGS ---")
    print(f"Regex:    {len(result['regex_findings'])} hit(s)")
    print(f"Semantic: {len(result['semantic_findings'])} hit(s)")
    print(f"Safe to send: {result['safe_to_send']}")
    print(f"Baseten escalated: {result['baseten_escalated']}")
    if result["openai_confirmed"] is not None:
        print(f"OpenAI confirmed: {result['openai_confirmed']}")
    print("\n--- FULL RESULT ---")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
