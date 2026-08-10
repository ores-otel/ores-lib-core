import unittest
from ores_lib_core import REDACTED, Secret, redact_record, valid_correlation_id
class CoreTests(unittest.TestCase):
    def test_redaction(self): self.assertEqual(redact_record({"access_token":"x","ok":"y"}), {"access_token":REDACTED,"ok":"y"})
    def test_secret(self): self.assertEqual(str(Secret("x")), REDACTED)
    def test_correlation(self): self.assertTrue(valid_correlation_id("req-12345678")); self.assertFalse(valid_correlation_id("bad space"))
if __name__ == "__main__": unittest.main()
