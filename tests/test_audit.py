"""Tests for audit chain."""

import unittest
import tempfile
from pathlib import Path
from datetime import datetime
from wazumation.core.audit import AuditChain, AuditResult


class TestAuditChain(unittest.TestCase):
    """Test audit chain functionality."""

    def test_audit_chain_creation(self):
        """Test creating an audit chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "audit.db"
            chain = AuditChain(db_path)
            self.assertTrue(db_path.exists())

    def test_audit_chain_append(self):
        """Test appending entries to audit chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "audit.db"
            chain = AuditChain(db_path)

            entry = chain.append(
                user="testuser",
                action="test_action",
                module="test_module",
                result=AuditResult.SUCCESS,
            )

            self.assertIsNotNone(entry.entry_id)
            self.assertEqual(entry.user, "testuser")
            self.assertEqual(entry.action, "test_action")
            self.assertEqual(entry.module, "test_module")
            self.assertEqual(entry.result, AuditResult.SUCCESS)

    def test_audit_chain_verification(self):
        """Test audit chain verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "audit.db"
            chain = AuditChain(db_path)

            # Add some entries
            chain.append(
                user="testuser",
                action="action1",
                module="module1",
                result=AuditResult.SUCCESS,
            )
            chain.append(
                user="testuser",
                action="action2",
                module="module2",
                result=AuditResult.FAILURE,
            )

            # Verify chain
            is_valid, errors = chain.verify_chain()
            self.assertTrue(is_valid)
            self.assertEqual(len(errors), 0)

    def test_audit_chain_query(self):
        """Test querying audit chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "audit.db"
            chain = AuditChain(db_path)

            chain.append(
                user="user1",
                action="action1",
                module="module1",
                result=AuditResult.SUCCESS,
            )
            chain.append(
                user="user2",
                action="action2",
                module="module2",
                result=AuditResult.FAILURE,
            )

            # Query by module
            entries = chain.query(module="module1")
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].module, "module1")

            # Query by user
            entries = chain.query(user="user2")
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].user, "user2")

            # Query by result
            entries = chain.query(result=AuditResult.SUCCESS)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].result, AuditResult.SUCCESS)


if __name__ == "__main__":
    unittest.main()

