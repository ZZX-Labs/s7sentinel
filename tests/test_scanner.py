import unittest

from s7sentinel.scanner import expand_targets


class ScannerSafetyTests(unittest.TestCase):
    def test_private_cidr_expands(self):
        self.assertEqual(
            expand_targets("192.168.1.0/30", allow_public=False, max_hosts=10),
            ["192.168.1.1", "192.168.1.2"],
        )

    def test_non_rfc1918_cidr_refused_even_when_public_flag_set(self):
        with self.assertRaises(ValueError):
            expand_targets("203.0.113.0/30", allow_public=True, max_hosts=10)

    def test_non_rfc1918_individual_requires_flag(self):
        with self.assertRaises(ValueError):
            expand_targets("203.0.113.5", allow_public=False, max_hosts=10)

    def test_non_rfc1918_individual_allowed_with_flag(self):
        self.assertEqual(
            expand_targets("203.0.113.5", allow_public=True, max_hosts=10),
            ["203.0.113.5"],
        )


if __name__ == "__main__":
    unittest.main()
