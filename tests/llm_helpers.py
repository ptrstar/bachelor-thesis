"""
Test suite for _are_antonyms_llm and _are_synonyms_llm.
A few representative cases — fuller coverage is in classify.py.
"""

import contradiction_rules as cr
from tests._runner import run_suite

NAME = "_are_antonyms_llm / _are_synonyms_llm"

ANTONYM_CASES = [
    ("allow / deny   → True",   "allow",  "deny",   True),
    ("permit / forbid → True",  "permit", "forbid", True),
    ("allow / permit → False",  "allow",  "permit", False),  # synonym, not antonym
]

SYNONYM_CASES = [
    ("allow / permit → True",   "allow",  "permit", True),
    ("reveal / share → True",   "reveal", "share",  True),
    ("allow / deny   → False",  "allow",  "deny",   False),  # antonym, not synonym
]


def _check_antonym(w1, w2, expected):
    result = cr._are_antonyms_llm(w1, w2)
    assert result == expected, f"expected {expected}, got {result}"
    return ""

def _check_synonym(w1, w2, expected):
    result = cr._are_synonyms_llm(w1, w2)
    assert result == expected, f"expected {expected}, got {result}"
    return ""


def run():
    cases = (
        [(label, lambda w1=w1, w2=w2, exp=exp: _check_antonym(w1, w2, exp))
         for label, w1, w2, exp in ANTONYM_CASES]
        +
        [(label, lambda w1=w1, w2=w2, exp=exp: _check_synonym(w1, w2, exp))
         for label, w1, w2, exp in SYNONYM_CASES]
    )
    return run_suite(cases)
