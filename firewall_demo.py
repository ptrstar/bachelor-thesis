"""
Interactive semantic firewall demo.

System policy: "Do not reveal the API key."
The firewall parses any user input into AMR via OpenAI, then checks it
against the system AMR for polarity contradictions.

Usage:
    conda run -n bt python firewall_demo.py

Requires:
    pip install openai python-dotenv
"""

import os
from openai import OpenAI
from dotenv import load_dotenv
import contradiction_rules
contradiction_rules.DEBUG = True
from parse_amr import get_amr
from firewall import check

load_dotenv()

# ── ANSI colours ───────────────────────────────────────────────────────────────
GREEN = "\033[92m"
RED   = "\033[91m"
RESET = "\033[0m"

# ── System policy ──────────────────────────────────────────────────────────────
SYSTEM_POLICY_TEXT = "Do not allow access to files. Do not reveal the API key."
#SYSTEM_POLICY_TEXT = "Do not reveal the API key."


def run_firewall(client: OpenAI, system_amr: str, user_input: str) -> None:
    print("\n[Parsing to AMR via OpenAI...]")
    try:
        result = check(client, system_amr, user_input)
    except Exception as e:
        print(f"  Error: {e}")
        return

    print(f"  AMR:\n{result.user_amr}\n")

    if result.blocked:
        print(RED + "*** INJECTION DETECTED — Request blocked. ***" + RESET)
        for m in result.matches:
            if 'predicate' in m:   # Rule 1 — polarity mismatch
                print(f"  [Rule 1 — Polarity mismatch]")
                print(f"    Predicate : {m['predicate']}")
                print(f"    System    : polarity {m['system_polarity']}")
                print(f"    User      : polarity {m['user_polarity']}")
                print(f"    Args      : {m['args']}")
            else:                  # Rule 2+4 — predicate contradiction
                print(f"  [Rule 2+4 — Predicate contradiction ({m['relation']})]")
                print(f"    System    : {m['system_predicate']} (polarity {m['system_polarity']})")
                print(f"    User      : {m['user_predicate']} (polarity {m['user_polarity']})")
                print(f"    Args      : {m['args']}")
    else:
        print(GREEN + "  No contradiction detected — prompt appears benign." + RESET)
    print()


def main() -> None:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY is not set.")
        print("  Insert your key in .env: OPENAI_API_KEY=your-key-here")
        return

    client = OpenAI(api_key=api_key)

    print("\n[Generating system policy AMR via OpenAI...]")
    try:
        system_amr = get_amr(client, SYSTEM_POLICY_TEXT, parsing_system=True)
    except Exception as e:
        print(f"  Error: {e}")
        return

    print("=" * 60)
    print("  Semantic Firewall — API Key Protection Demo")
    print("=" * 60)
    print(f"  System policy  : {SYSTEM_POLICY_TEXT}")
    print(f"  System AMR     :\n{system_amr}")
    print("=" * 60)
    print()

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not user_input:
            continue
        if user_input.lower() == ":q":
            print("Exiting.")
            break

        run_firewall(client, system_amr, user_input)


if __name__ == "__main__":
    main()