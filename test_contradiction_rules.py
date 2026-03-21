import unittest
from contradiction_rules import detect_polarity_mismatches

# ── AMR fixtures ──────────────────────────────────────────────────────────────

# System: "allow user to access file"
SYS_ALLOW = """
(a / allow-01
   :ARG0 (u / user)
   :ARG1 (f / file))
"""

# User: "do NOT allow user to access file"  →  polarity mismatch
USER_NOT_ALLOW = """
(a / allow-01
   :polarity -
   :ARG0 (u / user)
   :ARG1 (f / file))
"""

# User: "allow user to access file"  →  no mismatch
USER_ALLOW = """
(a / allow-01
   :ARG0 (u / user)
   :ARG1 (f / file))
"""

# User: "do NOT allow user to access database"  →  different ARG1, no rule-1 match
USER_NOT_ALLOW_DB = """
(a / allow-01
   :polarity -
   :ARG0 (u / user)
   :ARG1 (d / database))
"""

# System: "do NOT allow admin to access file"
SYS_NOT_ALLOW = """
(a / allow-01
   :polarity -
   :ARG0 (u / admin)
   :ARG1 (f / file))
"""

# User: "allow admin to access file"  →  polarity mismatch (negative → positive)
USER_ALLOW_ADMIN = """
(a / allow-01
   :ARG0 (u / admin)
   :ARG1 (f / file))
"""

# Completely different predicates — rule (2) territory, no rule-1 match
SYS_ALLOW_SIMPLE = "(a / allow-01 :ARG0 (u / user))"
USER_DENY_SIMPLE  = "(d / deny-01  :ARG0 (u / user))"


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestPolarityMismatch(unittest.TestCase):

    def test_positive_to_negative_detected(self):
        result = detect_polarity_mismatches(SYS_ALLOW, USER_NOT_ALLOW)
        self.assertEqual(len(result), 1)
        m = result[0]
        self.assertEqual(m['predicate'],       'allow-01')
        self.assertEqual(m['system_polarity'], '+')
        self.assertEqual(m['user_polarity'],   '-')
        self.assertEqual(m['args'], {':ARG0': 'user', ':ARG1': 'file'})

    def test_same_polarity_no_mismatch(self):
        result = detect_polarity_mismatches(SYS_ALLOW, USER_ALLOW)
        self.assertEqual(len(result), 0)

    def test_different_args_no_mismatch(self):
        # Same predicate + opposite polarity, but ARG1 differs → rule (3), not rule (1)
        result = detect_polarity_mismatches(SYS_ALLOW, USER_NOT_ALLOW_DB)
        self.assertEqual(len(result), 0)

    def test_negative_to_positive_detected(self):
        result = detect_polarity_mismatches(SYS_NOT_ALLOW, USER_ALLOW_ADMIN)
        self.assertEqual(len(result), 1)
        m = result[0]
        self.assertEqual(m['system_polarity'], '-')
        self.assertEqual(m['user_polarity'],   '+')

    def test_different_predicates_no_mismatch(self):
        result = detect_polarity_mismatches(SYS_ALLOW_SIMPLE, USER_DENY_SIMPLE)
        self.assertEqual(len(result), 0)


if __name__ == '__main__':
    unittest.main()
