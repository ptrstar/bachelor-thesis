"""
Test runner — python tests.py
"""

import sys
from dotenv import load_dotenv
load_dotenv()

from tests._runner import print_suite
import tests.helpers     as helpers
import tests.classify    as classify
import tests.llm_helpers as llm_helpers
import tests.parser      as parser

# ── register suites here ──────────────────────────────────────────────────────
SUITES = [
    helpers,
    classify,
    llm_helpers,
    parser,
]
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    total_failures = 0
    for suite in SUITES:
        results = suite.run()
        total_failures += print_suite(suite.NAME, results)

    print(f"\n{'─' * 60}")
    if total_failures == 0:
        print("  \033[92mAll tests passed.\033[0m")
    else:
        print(f"  \033[91m{total_failures} test(s) failed.\033[0m")
        sys.exit(1)