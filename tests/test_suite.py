import unittest

from password_suite.auditor import audit_password, calculate_entropy_bits, check_patterns
from password_suite.hashing import pbkdf2_hash, verify_pbkdf2

class TestPasswordSuite(unittest.TestCase):
    def test_entropy_increases_with_length(self):
        e1 = calculate_entropy_bits("abcd1234")
        e2 = calculate_entropy_bits("abcd1234abcd1234")
        self.assertGreater(e2, e1)

    def test_patterns_detect_common_sequences(self):
        pats = check_patterns("qwerty123")
        self.assertTrue(any("keyboard" in p for p in pats) or any("keyboard pattern" == p for p in pats))

    def test_audit_returns_structured(self):
        r = audit_password("Correct-Horse-Battery-Staple-42")
        self.assertIn("metrics", r)
        self.assertIn("recommendations", r)
        self.assertIn("breakdown", r)
        self.assertIn("length", r["breakdown"])

    def test_pbkdf2_roundtrip(self):
        hr = pbkdf2_hash("test-password")
        self.assertTrue(verify_pbkdf2("test-password", hr.encoded))
        self.assertFalse(verify_pbkdf2("wrong", hr.encoded))

if __name__ == "__main__":
    unittest.main()
