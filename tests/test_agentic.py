import tempfile
import unittest
from pathlib import Path

from s7sentinel.agentic import analyze_agentic_csv, bayesian_priority, scan_agent_workspaces


class AgenticTests(unittest.TestCase):
    def test_bayesian_priority_increases_with_evidence(self):
        low = bayesian_priority(0.02, [3.0])
        high = bayesian_priority(0.02, [3.0, 8.0])
        self.assertGreater(high, low)

    def test_agent_workspace_scan_does_not_execute_source(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".openclaw").mkdir()
            marker = root / "EXECUTED"
            src = root / "hermes_notes.py"
            src.write_text(
                f"open({str(marker)!r}, 'w').write('bad')\n# learning cycle\n# posterior probability\n",
                encoding="utf-8",
            )
            result = scan_agent_workspaces([td], max_files=100, hash_matches=True)
            self.assertFalse(marker.exists())
            codes = {f["code"] for f in result["findings"]}
            self.assertIn("AGENTIC_WORKSPACE_DIRECTORY", codes)
            self.assertIn("AGENTIC_FILE_ARTIFACT", codes)

    def test_agent_log_detects_correlated_patterns(self):
        rows = [
            "timestamp,src_ip,user,system,event,endpoint,status,auth_result,auth_method,jwt_alg,bytes_out,file_name,user_agent,authorized,sensitive,change_ticket"
        ]
        # Eight failed logins -> spray pattern.
        for i in range(8):
            rows.append(
                f"2026-07-01T00:00:{i:02d}+00:00,10.9.0.5,user{i},portal,login,/login,401,failed,password,,100,,ua,no,no,"
            )
        # JWT none accepted + unauthenticated sensitive endpoint.
        rows.append(
            "2026-07-01T00:01:00+00:00,10.9.0.5,alice,api,api_request,/personnel,200,success,none,none,20000000,,ua,no,yes,"
        )
        # Server-side upload.
        rows.append(
            "2026-07-01T00:01:01+00:00,10.9.0.5,alice,web,file_upload,/upload,201,success,session,RS256,20,tool.aspx,ua,no,no,"
        )
        # SSO pivot across three systems.
        for i, system in enumerate(("oa", "hr", "assets"), start=2):
            rows.append(
                f"2026-07-01T00:01:{i:02d}+00:00,10.9.0.5,alice,{system},login,/sso,200,success,sso,RS256,100,,ua,no,no,"
            )
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.csv"
            p.write_text("\n".join(rows) + "\n", encoding="utf-8")
            result = analyze_agentic_csv(str(p), recon_endpoints=3, burst_events=10)
            codes = {f["code"] for f in result["findings"]}
            self.assertIn("PASSWORD_SPRAY_PATTERN", codes)
            self.assertIn("JWT_NONE_ALGORITHM_OBSERVED", codes)
            self.assertIn("UNAUTHENTICATED_SENSITIVE_API_SUCCESS", codes)
            self.assertIn("SERVER_SIDE_FILE_UPLOAD", codes)
            self.assertIn("CROSS_SYSTEM_SSO_PIVOT_PATTERN", codes)
            self.assertTrue(result["source_scores"])

    def test_agent_log_rejects_invalid_schema(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.csv"
            p.write_text("timestamp,event\n2026-01-01T00:00:00+00:00,login\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                analyze_agentic_csv(str(p))


if __name__ == "__main__":
    unittest.main()
