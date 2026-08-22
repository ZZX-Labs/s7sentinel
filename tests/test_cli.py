import unittest
from unittest.mock import patch

from s7sentinel.cli import main


class CLISafetyTests(unittest.TestCase):
    def test_scan_requires_authorization(self):
        with patch("sys.stderr"):
            rc = main(["scan", "--targets", "192.168.1.10"])
        self.assertEqual(rc, 2)

    def test_profile_command(self):
        with patch("builtins.print") as p:
            rc = main(["profile", "aa26-231a"])
        self.assertEqual(rc, 0)
        p.assert_called()


if __name__ == "__main__":
    unittest.main()
