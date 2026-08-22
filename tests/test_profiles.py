import json
import unittest

from s7sentinel.profiles import render_profile


class ProfileTests(unittest.TestCase):
    def test_profiles_render(self):
        data = json.loads(render_profile())
        self.assertIn("aa26-231a", data)
        self.assertIn("dream-agentic-2026", data)


if __name__ == "__main__":
    unittest.main()
