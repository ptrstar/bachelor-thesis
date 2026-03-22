import unittest
from contradiction_rules import (
    detect_polarity_mismatches,
    detect_antonym_predicates,
    detect_argument_mismatches,
)

# ── AMR fixtures ──────────────────────────────────────────────────────────────

_ALLOW_USER_FILE = """
(a / allow-01
   :ARG0 (u / user)
   :ARG1 (f / file))
"""

_NOT_ALLOW_USER_FILE = """
(a / allow-01
   :polarity -
   :ARG0 (u / user)
   :ARG1 (f / file))
"""

_NOT_ALLOW_USER_DB = """
(a / allow-01
   :polarity -
   :ARG0 (u / user)
   :ARG1 (d / database))
"""

_NOT_ALLOW_ADMIN_FILE = """
(a / allow-01
   :polarity -
   :ARG0 (u / admin)
   :ARG1 (f / file))
"""

_ALLOW_ADMIN_FILE = """
(a / allow-01
   :ARG0 (u / admin)
   :ARG1 (f / file))
"""

_ALLOW_SIMPLE = "(a / allow-01 :ARG0 (u / user))"
_DENY_SIMPLE  = "(d / deny-01  :ARG0 (u / user))"


# ── Tests ─────────────────────────────────────────────────────────────────────

# Each entry: (system_amr, user_amr, expected_match_count, description, extra_assertions)
# extra_assertions: dict of keys to check on result[0], or None
CASES = [
    (
        _ALLOW_USER_FILE,
        _NOT_ALLOW_USER_FILE,
        1,
        "positive→negative polarity mismatch detected",
        {'predicate': 'allow-01', 'system_polarity': '+', 'user_polarity': '-',
         'args': {':ARG0': 'user', ':ARG1': 'file'}},
    ),
    (
        _ALLOW_USER_FILE,
        _ALLOW_USER_FILE,
        0,
        "same polarity → no mismatch",
        None,
    ),
    (
        _ALLOW_USER_FILE,
        _NOT_ALLOW_USER_DB,
        0,
        "opposite polarity but different ARG1 → no rule-1 match",
        None,
    ),
    (
        _NOT_ALLOW_ADMIN_FILE,
        _ALLOW_ADMIN_FILE,
        1,
        "negative→positive polarity mismatch detected",
        {'system_polarity': '-', 'user_polarity': '+'},
    ),
    (
        _ALLOW_SIMPLE,
        _DENY_SIMPLE,
        0,
        "completely different predicates → no rule-1 match",
        None,
    ),
]


class TestPolarityMismatch(unittest.TestCase):
    pass


def _make_test(sys_amr, user_amr, expected_count, description, assertions):
    def test(self):
        result = detect_polarity_mismatches(sys_amr, user_amr)
        self.assertEqual(len(result), expected_count, description)
        if assertions:
            m = result[0]
            for key, value in assertions.items():
                self.assertEqual(m[key], value)
    test.__doc__ = description
    return test


for i, (sys_amr, user_amr, count, desc, assertions) in enumerate(CASES):
    test_name = f"test_{i:02d}_{desc.replace(' ', '_').replace('→', 'to')}"
    setattr(TestPolarityMismatch, test_name, _make_test(sys_amr, user_amr, count, desc, assertions))


# ── Rule (2): antonym predicates ──────────────────────────────────────────────

# Deterministic stub — no API call needed in tests.
def _mock_antonyms(w1, w2):
    PAIRS = {frozenset({'allow', 'deny'}), frozenset({'permit', 'forbid'})}
    return frozenset({w1, w2}) in PAIRS


CASES_2 = [
    (
        _ALLOW_USER_FILE,
        _DENY_SIMPLE,
        0,
        "antonym predicates but different args → no match",
        None,
    ),
    (
        _ALLOW_USER_FILE,
        "(d / deny-01 :ARG0 (u / user) :ARG1 (f / file))",
        1,
        "allow vs deny with identical args → antonym match",
        {'system_predicate': 'allow-01', 'user_predicate': 'deny-01',
         'args': {':ARG0': 'user', ':ARG1': 'file'}},
    ),
    (
        _ALLOW_USER_FILE,
        _ALLOW_USER_FILE,
        0,
        "identical predicate → not an antonym pair",
        None,
    ),
    (
        _ALLOW_USER_FILE,
        _NOT_ALLOW_USER_FILE,
        0,
        "polarity negation of same predicate is rule-1, not rule-2",
        None,
    ),
]


class TestAntonymPredicates(unittest.TestCase):
    pass


def _make_test_2(sys_amr, user_amr, expected_count, description, assertions):
    def test(self):
        result = detect_antonym_predicates(sys_amr, user_amr, antonym_fn=_mock_antonyms)
        self.assertEqual(len(result), expected_count, description)
        if assertions:
            m = result[0]
            for key, value in assertions.items():
                self.assertEqual(m[key], value)
    test.__doc__ = description
    return test


for i, (sys_amr, user_amr, count, desc, assertions) in enumerate(CASES_2):
    test_name = f"test_{i:02d}_{desc.replace(' ', '_').replace('→', 'to')}"
    setattr(TestAntonymPredicates, test_name, _make_test_2(sys_amr, user_amr, count, desc, assertions))


# ── Rule (3): same predicate, mismatched arguments ────────────────────────────

_DENY_USER_A_FILE = """
(d / deny-01
   :ARG0 (a / admin)
   :ARG1 (u / user_a)
   :ARG2 (f / file))
"""

_DENY_USER_B_FILE = """
(d / deny-01
   :ARG0 (a / admin)
   :ARG1 (u / user_b)
   :ARG2 (f / file))
"""

_DENY_USER_A_DB = """
(d / deny-01
   :ARG0 (a / admin)
   :ARG1 (u / user_a)
   :ARG2 (db / database))
"""

CASES_3 = [
    (
        _DENY_USER_A_FILE,
        _DENY_USER_B_FILE,
        1,
        "same predicate, ARG1 differs → argument mismatch",
        {'predicate': 'deny-01',
         'mismatched_args': {':ARG1': ('user_a', 'user_b')}},
    ),
    (
        _DENY_USER_A_FILE,
        _DENY_USER_A_DB,
        1,
        "same predicate, ARG2 differs → argument mismatch",
        {'predicate': 'deny-01',
         'mismatched_args': {':ARG2': ('file', 'database')}},
    ),
    (
        _DENY_USER_A_FILE,
        _DENY_USER_A_FILE,
        0,
        "identical predicate and args → no mismatch",
        None,
    ),
    (
        _ALLOW_USER_FILE,
        _NOT_ALLOW_USER_DB,
        1,
        "allow-01: ARG1 file vs database → argument mismatch",
        {'predicate': 'allow-01',
         'mismatched_args': {':ARG1': ('file', 'database')}},
    ),
    (
        _ALLOW_USER_FILE,
        _DENY_SIMPLE,
        0,
        "different predicates → not rule-3",
        None,
    ),
]


class TestArgumentMismatches(unittest.TestCase):
    pass


def _make_test_3(sys_amr, user_amr, expected_count, description, assertions):
    def test(self):
        result = detect_argument_mismatches(sys_amr, user_amr)
        self.assertEqual(len(result), expected_count, description)
        if assertions:
            m = result[0]
            for key, value in assertions.items():
                self.assertEqual(m[key], value)
    test.__doc__ = description
    return test


for i, (sys_amr, user_amr, count, desc, assertions) in enumerate(CASES_3):
    test_name = f"test_{i:02d}_{desc.replace(' ', '_').replace('→', 'to')}"
    setattr(TestArgumentMismatches, test_name, _make_test_3(sys_amr, user_amr, count, desc, assertions))


if __name__ == '__main__':
    unittest.main()
