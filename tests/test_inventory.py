import tempfile
import unittest
from pathlib import Path

from s7sentinel.inventory import load_inventory


class InventoryTests(unittest.TestCase):
    def test_rejects_invalid_ip(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "inventory.csv"
            p.write_text("ip,model\nnot-an-ip,S7-1200\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_inventory(str(p))

    def test_rejects_duplicate_ip(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "inventory.csv"
            p.write_text("ip,model\n10.0.0.1,S7-1200\n10.0.0.1,S7-1500\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_inventory(str(p))


if __name__ == "__main__":
    unittest.main()
