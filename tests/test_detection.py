import unittest
import sys
from pathlib import Path

sys.path.insert(0, r"C:\Users\moham\ai-soc-incident-response")

from backend.app.database import SessionLocal
from backend.app.models import User, SecurityIncident
from backend.app.detection_engine import process_login_attempt
from backend.app.auth import validate_password_policy, commit_new_password, verify_password
from fastapi import HTTPException

class TestSOCPlatform(unittest.TestCase):
    def setUp(self):
        self.db = SessionLocal()
        # Reset john.doe
        self.user = self.db.query(User).filter(User.username == "john.doe").first()
        if self.user:
            self.user.is_locked = False
            self.user.must_reset_password = False
            self.user.failed_login_count = 0
            self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_01_human_login_friction_no_lock(self):
        """Verify 3 typos do not lock account."""
        for i in range(1, 4):
            res = process_login_attempt(self.db, "john.doe", "192.168.1.50", "Mozilla/5.0", False)
            self.assertFalse(res.get("locked", False))
            self.assertEqual(res["status"], "HUMAN_FRICTION")

        res_ok = process_login_attempt(self.db, "john.doe", "192.168.1.50", "Mozilla/5.0", True)
        self.assertEqual(res_ok["status"], "SUCCESS")

        self.db.refresh(self.user)
        self.assertFalse(self.user.is_locked)
        print("PASS: Human typing friction tolerated without lockout.")

    def test_02_rapid_malware_burst_quarantines_account(self):
        """Verify 6 rapid attempts in seconds lock account and trigger CRITICAL incident."""
        final_res = None
        for i in range(1, 7):
            res = process_login_attempt(self.db, "john.doe", "10.0.0.99", "HydraBot/1.0", False)
            final_res = res

        self.assertEqual(final_res["status"], "MALWARE_BURST_DETECTED")
        self.assertTrue(final_res["locked"])
        self.assertTrue(final_res["must_reset_password"])

        self.db.refresh(self.user)
        self.assertTrue(self.user.is_locked)
        print(f"PASS: High-velocity brute force burst detected: {final_res['incident_number']}.")

    def test_03_password_history_policy(self):
        """Verify 3-password history rejects old passwords."""
        # Active password rejection
        with self.assertRaises(HTTPException):
            validate_password_policy("Password123!", self.user, self.db)

        # Set a novel password
        new_pw = "UltraSecure2027#Key"
        validate_password_policy(new_pw, self.user, self.db)
        commit_new_password(self.db, self.user, new_pw)

        self.db.refresh(self.user)
        self.assertFalse(self.user.is_locked)
        self.assertFalse(self.user.must_reset_password)
        self.assertTrue(verify_password(new_pw, self.user.password_hash))
        print("PASS: 3-Password history exclusion verified and quarantine lifted.")

    def test_04_rbac_soc_access_control(self):
        """Verify only Admin and SOC analysts have is_soc flag."""
        admin = self.db.query(User).filter(User.username == "admin").first()
        sarah = self.db.query(User).filter(User.username == "sarah.connor").first()
        john = self.db.query(User).filter(User.username == "john.doe").first()

        self.assertIsNotNone(admin)
        self.assertTrue(admin.is_admin)
        self.assertTrue(admin.is_soc)

        self.assertIsNotNone(sarah)
        self.assertFalse(sarah.is_admin)
        self.assertTrue(sarah.is_soc)

        self.assertIsNotNone(john)
        self.assertFalse(john.is_admin)
        self.assertFalse(john.is_soc)
        print("PASS: RBAC clearance correctly isolates Admin & SOC team from regular employees.")

if __name__ == "__main__":
    unittest.main()
