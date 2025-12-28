"""Tests for audit immutability (append-only enforcement + tamper evidence)."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from wazumation.core.audit import AuditChain, AuditResult


class TestAuditImmutability(unittest.TestCase):
    """Test that the audit log is append-only and tamper-evident."""

    def test_append_only_enforced(self):
        """DB should reject UPDATE/DELETE operations against audit_log."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "audit.db"
            chain = AuditChain(db_path)

            entry = chain.append(
                user="testuser",
                action="test_action",
                module="test_module",
                result=AuditResult.SUCCESS,
                details={"k": "v"},
            )

            conn = sqlite3.connect(db_path)
            cur = conn.cursor()

            with self.assertRaises(sqlite3.DatabaseError):
                cur.execute(
                    "UPDATE audit_log SET details=? WHERE entry_id=?",
                    ("{}", entry.entry_id),
                )
                conn.commit()

            with self.assertRaises(sqlite3.DatabaseError):
                cur.execute("DELETE FROM audit_log WHERE entry_id=?", (entry.entry_id,))
                conn.commit()

            conn.close()

    def test_verify_fails_if_triggers_missing(self):
        """verify_chain should fail if immutability triggers are missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "audit.db"
            chain = AuditChain(db_path)
            chain.append(user="u", action="a", module="m", result=AuditResult.SUCCESS)

            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("DROP TRIGGER audit_log_no_update")
            conn.commit()
            conn.close()

            ok, errors = chain.verify_chain()
            self.assertFalse(ok)
            self.assertTrue(any("triggers missing" in e.lower() for e in errors))

    def test_verify_fails_if_hash_tampered(self):
        """verify_chain should fail if stored hashes are modified."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "audit.db"
            chain = AuditChain(db_path)
            entry = chain.append(user="u", action="a", module="m", result=AuditResult.SUCCESS)

            # Simulate tampering: attacker bypasses immutability and updates stored hash.
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("DROP TRIGGER audit_log_no_update")
            cur.execute(
                "UPDATE audit_log SET current_hash=? WHERE entry_id=?",
                ("0" * 64, entry.entry_id),
            )
            conn.commit()
            conn.close()

            ok, errors = chain.verify_chain()
            self.assertFalse(ok)
            self.assertTrue(any("hash" in e.lower() for e in errors))


if __name__ == "__main__":
    unittest.main()


