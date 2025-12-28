"""Tests for diff engine."""

import unittest
from datetime import datetime, timezone
from wazumation.core.change_plan import ChangePlan, FileChange, ChangeType
from wazumation.core.diff import DiffEngine


class TestDiffEngine(unittest.TestCase):
    """Test diff engine functionality."""

    def test_file_diff_create(self):
        """Test diff for file creation."""
        change = FileChange(
            path="/test/file",
            change_type=ChangeType.CREATE,
            new_content="line1\nline2\n",
        )
        diff = DiffEngine.generate_file_diff(change)
        self.assertIn("file", diff.lower())
        self.assertTrue("line1" in diff or "+line1" in diff)

    def test_file_diff_update(self):
        """Test diff for file update."""
        change = FileChange(
            path="/test/file",
            change_type=ChangeType.UPDATE,
            old_content="old1\nold2\n",
            new_content="new1\nnew2\n",
        )
        diff = DiffEngine.generate_file_diff(change)
        self.assertTrue(diff)  # Should produce some diff output

    def test_plan_diff(self):
        """Test plan diff generation."""
        plan = ChangePlan(
            plan_id="test123",
            created_at=datetime.now(timezone.utc),
            description="Test plan",
        )

        change = FileChange(
            path="/test/file",
            change_type=ChangeType.UPDATE,
            old_content="old",
            new_content="new",
        )
        plan.add_file_change(change)

        diff = DiffEngine.generate_plan_diff(plan)
        self.assertIn("Test plan", diff)
        self.assertIn("test123", diff)
        self.assertIn("/test/file", diff)

    def test_change_summary(self):
        """Test change summary."""
        plan = ChangePlan(
            plan_id="test123",
            created_at=datetime.now(timezone.utc),
            description="Test plan",
        )

        plan.add_file_change(
            FileChange(
                path="/test/file1",
                change_type=ChangeType.UPDATE,
                old_content="old",
                new_content="new",
            )
        )
        plan.add_file_change(
            FileChange(
                path="/test/file2",
                change_type=ChangeType.UPDATE,
                old_content="old",
                new_content="new",
            )
        )

        files, services, total = DiffEngine.get_change_summary(plan)
        self.assertEqual(files, 2)
        self.assertEqual(services, 0)
        self.assertEqual(total, 2)


if __name__ == "__main__":
    unittest.main()

