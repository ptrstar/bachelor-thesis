"""
Test suite for _classify_relation_llm.
Add new cases to CASES — everything else is handled by the runner.
"""

import contradiction_rules as cr
from tests._runner import run_suite

NAME = "_classify_relation_llm"

# (label, word1, word2, expected_relation)
CASES = [
    ("allow / permit → synonym", "allow", "permit", "synonym"),
    ("show  / reveal → synonym", "show",  "reveal", "synonym"),
    ("show  / tell   → synonym", "show",  "tell",   "synonym"),
    ("show  / deny   → antonym", "show",  "deny",   "antonym"),
    ("swim  / want   → none",    "swim",  "want",   "none"),

]


def _check(word1, word2, expected):
    result = cr._classify_relation_llm(word1, word2)
    assert result.relation == expected, \
        f"expected {expected!r}, got {result.relation!r}"
    return f"score={result.score}"


def run():
    cases = [(label, lambda w1=w1, w2=w2, exp=exp: _check(w1, w2, exp))
             for label, w1, w2, exp in CASES]
    return run_suite(cases)