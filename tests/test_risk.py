import unittest
from s7sentinel.models import Asset, PortResult
from s7sentinel.risk import assess


class RiskTests(unittest.TestCase):
    def test_open_s7_private_is_high(self):
        a = Asset(ip="10.0.0.10", model="S7-1200 CPU 1214C", firmware="4.5", patch_status="current")
        r = assess(a, [PortResult(port=102, open=True)])
        self.assertEqual(r.risk_level, "HIGH")
        self.assertTrue(any(f.code == "S7COMM_REACHABLE" for f in r.findings))
        self.assertTrue(any("D3-NI" in f.d3fend_ids for f in r.findings if f.code == "S7COMM_REACHABLE"))

    def test_missing_firmware_flag(self):
        a = Asset(ip="10.0.0.11", model="S7-300 CPU 315", patch_status="current")
        r = assess(a, [PortResult(port=102, open=False)])
        self.assertTrue(any(f.code == "FIRMWARE_UNKNOWN" for f in r.findings))

    def test_remote_without_mfa(self):
        a = Asset(ip="10.0.0.12", model="S7-1500", remote_access="yes", mfa="no", patch_status="current")
        r = assess(a, [PortResult(port=102, open=False)])
        self.assertTrue(any(f.code == "REMOTE_ACCESS_WITHOUT_MFA" for f in r.findings))

    def test_explicit_control_failures(self):
        a = Asset(
            ip="10.0.0.13",
            model="S7-1200 CPU 1214C",
            firmware="4.5",
            patch_status="unpatched",
            engineering_access_restricted="no",
            plc_password="no",
            logging_enabled="no",
            logic_integrity_verified="no",
        )
        r = assess(a, [])
        codes = {f.code for f in r.findings}
        self.assertIn("PATCH_STATUS_NOT_CURRENT", codes)
        self.assertIn("ENGINEERING_ACCESS_NOT_RESTRICTED", codes)
        self.assertIn("PLC_PASSWORD_NOT_ENABLED", codes)
        self.assertIn("S7_MONITORING_NOT_ENABLED", codes)
        self.assertIn("LOGIC_INTEGRITY_NOT_VERIFIED", codes)
        self.assertEqual(r.risk_level, "HIGH")


if __name__ == "__main__":
    unittest.main()
