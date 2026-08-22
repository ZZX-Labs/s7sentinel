import tempfile
import unittest
from pathlib import Path
from s7sentinel.hostcheck import scan_roots


class HostCheckTests(unittest.TestCase):
    def test_detects_snap7_source_reference(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "monitor.py"
            p.write_text("import snap7\n", encoding="utf-8")
            result = scan_roots([td], max_files=100)
            paths = [x.get("path", "") for x in result["artifacts"]]
            self.assertTrue(any(str(p) == x for x in paths))

    def test_does_not_execute_source(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "EXECUTED"
            p = Path(td) / "snap_tool.py"
            p.write_text(f"import snap7\nopen({str(marker)!r}, 'w').write('bad')\n", encoding="utf-8")
            scan_roots([td], max_files=100)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
