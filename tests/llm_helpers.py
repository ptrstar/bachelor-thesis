"""
Test suite for _classify_relation_llm used as antonym/synonym gate.
"""

import contradiction_rules as cr
from tests._runner import run_suite

NAME = "_classify_relation_llm (antonym/synonym gate)"

# (label, word1, word2, expected_relation, should_pass_threshold)
CASES = [
    ("allow / deny   → antonym, above threshold", "allow",  "deny",   "antonym", True),
    ("permit / forbid → antonym, above threshold","permit", "forbid", "antonym", True),
    ("allow / permit → synonym, above threshold", "allow",  "permit", "synonym", True),
    ("reveal / share → synonym, above threshold", "reveal", "share",  "synonym", True),
    ("allow / deny   → not synonym",              "allow",  "deny",   "synonym", False),
]


def _check(word1, word2, expected_relation, should_pass):
    r = cr._classify_relation_llm(word1, word2)
    matches = r.relation == expected_relation and r.score >= cr.SCORE_THRESHOLD
    assert matches == should_pass, \
        f"expected {'pass' if should_pass else 'fail'}, got relation={r.relation!r} score={r.score}"
    return f"relation={r.relation!r} score={r.score}"


def run():
    cases = [
        (label, lambda w1=w1, w2=w2, rel=rel, sp=sp: _check(w1, w2, rel, sp))
        for label, w1, w2, rel, sp in CASES
    ]
    return run_suite(cases)