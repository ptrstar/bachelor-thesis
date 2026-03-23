"""
Manual test script — run with:  python tests.py
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
load_dotenv()

import contradiction_rules as cr
cr.DEBUG = False

# (word1, word2, expected_relation)
CASES = [
    ("allow", "permit", "synonym"),
    ("show",  "reveal", "synonym"),
    ("show",  "tell",   "synonym"),
    ("show",  "deny",   "antonym"),
    ("swim",  "want",   "none"),
]


def _test_classify(word1, word2, expected):
    result = cr._classify_relation_llm(word1, word2)
    assert result.relation == expected, \
        f"({word1!r}, {word2!r}): expected {expected!r}, got {result.relation!r} (score={result.score})"
    return word1, word2, result


with ThreadPoolExecutor(max_workers=len(CASES)) as pool:
    futures = {pool.submit(_test_classify, *case): case for case in CASES}
    for future in as_completed(futures):
        w1, w2, result = future.result()   # re-raises AssertionError on failure
        print(f"OK  ({w1!r}, {w2!r}) → {result.relation!r}  score={result.score}")
