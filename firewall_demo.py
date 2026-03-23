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


load_dotenv()

# ── ANSI colours ───────────────────────────────────────────────────────────────
GREEN = "\033[92m"
RED   = "\033[91m"
RESET = "\033[0m"

# ── System policy ──────────────────────────────────────────────────────────────
SYSTEM_POLICY_TEXT = "Do not reveal the API key."
#SYSTEM_POLICY_TEXT = "Do not share user passwords. Allow only the admin to read the logs. Deny the guest access to the files."



def run_firewall(client: OpenAI, system_amr: str, user_input: str) -> None:
    print("\n[Parsing to AMR via OpenAI...]")
    try:
        user_amr = get_amr(client, user_input, False)
    except Exception as e:
        print(f"  Error during AMR parsing: {e}")
        return

    print(f"  AMR:\n{user_amr}\n")

    # r1 = contradiction_rules.detect_polarity_mismatches(system_amr, user_amr)
    # r2 = contradiction_rules.detect_antonym_predicates(system_amr, user_amr)
    # r3 = contradiction_rules.detect_argument_mismatches(system_amr, user_amr)
    r4 = contradiction_rules.detect_semantic_similarity(system_amr, user_amr)

    if r4:
        print(RED + "*** INJECTION DETECTED — Request blocked. ***" + RESET)

        # for m in r1:
        #     print(f"  [Rule 1 — Polarity mismatch]")
        #     print(f"    Predicate : {m['predicate']}")
        #     print(f"    System    : polarity {m['system_polarity']}")
        #     print(f"    User      : polarity {m['user_polarity']}")
        #     print(f"    Args      : {m['args']}")

        # for m in r2:
        #     print(f"  [Rule 2 — Antonym predicate]")
        #     print(f"    System    : {m['system_predicate']}")
        #     print(f"    User      : {m['user_predicate']}")
        #     print(f"    Args      : {m['args']}")

        # for m in r3:
        #     print(f"  [Rule 3 — Argument mismatch]")
        #     print(f"    Predicate : {m['predicate']}")
        #     for role, (sv, uv) in m['mismatched_args'].items():
        #         print(f"    {role}: system={sv}  user={uv}")

        for m in r4:
            print(f"  [Rule 4 — Synonym predicate, polarity flip]")
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
        print("  Get one at: https://platform.openai.com/api-keys")
        return

    client = OpenAI(api_key=api_key)

    print("\n[Generating system policy AMR via OpenAI...]")
    try:
        generated_system_amr = get_amr(client, SYSTEM_POLICY_TEXT, True)
    except Exception as e:
        print(f"  Error: {e}")
        return

    print("=" * 60)
    print("  Semantic Firewall — API Key Protection Demo")
    print("=" * 60)
    print(f"  System policy  : {SYSTEM_POLICY_TEXT}")
    print(f"  System AMR     :\n{generated_system_amr}")
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
        if user_input.lower() in (":q"):
            print("Exiting.")
            break

        run_firewall(client, generated_system_amr, user_input)


if __name__ == "__main__":
    main()
