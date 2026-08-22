import tempfile
import unittest
from pathlib import Path
from s7sentinel.logcheck import analyze_csv


class LogCheckTests(unittest.TestCase):
    def test_detects_scan_and_unticketed_write(self):
        content = """timestamp,src_ip,dst_ip,dst_port,operation,authorized_source,change_ticket
2026-08-21T01:00:00+00:00,10.0.0.5,10.1.0.1,102,read,no,
2026-08-21T01:00:10+00:00,10.0.0.5,10.1.0.2,102,read,no,
2026-08-21T01:00:20+00:00,10.0.0.5,10.1.0.3,102,read,no,
2026-08-21T01:00:30+00:00,10.0.0.5,10.1.0.4,102,write,no,
"""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.csv"
            p.write_text(content, encoding="utf-8")
            result = analyze_csv(str(p))
            codes = {f["code"] for f in result["findings"]}
            self.assertIn("SEQUENTIAL_S7_SCAN_PATTERN", codes)
            self.assertIn("S7_WRITE_WITHOUT_CHANGE_TICKET", codes)
            self.assertIn("UNAUTHORIZED_S7_SOURCE", codes)


if __name__ == "__main__":
    unittest.main()
