"""Tests for change plan."""

import unittest
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from wazumation.core.change_plan import ChangePlan, FileChange, ServiceChange, ChangeType


class TestChangePlan(unittest.TestCase):
    """Test change plan functionality."""

    def test_change_plan_creation(self):
        """Test creating a change plan."""
        plan = ChangePlan(
            plan_id="test123",
            created_at=datetime.now(timezone.utc),
            description="Test plan",
        )
        self.assertEqual(plan.plan_id, "test123")
        self.assertTrue(plan.is_empty())

    def test_file_change(self):
        """Test file change creation."""
        change = FileChange(
            path="/test/path",
            change_type=ChangeType.UPDATE,
            old_content="old",
            new_content="new",
        )
        self.assertEqual(change.path, "/test/path")
        self.assertEqual(change.change_type, ChangeType.UPDATE)

    def test_service_change(self):
        """Test service change creation."""
        change = ServiceChange(
            service_name="wazuh-manager",
            change_type=ChangeType.SERVICE_RESTART,
            reason="Test restart",
        )
        self.assertEqual(change.service_name, "wazuh-manager")
        self.assertEqual(change.change_type, ChangeType.SERVICE_RESTART)

    def test_plan_with_changes(self):
        """Test plan with file and service changes."""
        plan = ChangePlan(
            plan_id="test123",
            created_at=datetime.now(timezone.utc),
            description="Test plan",
        )

        file_change = FileChange(
            path="/test/path",
            change_type=ChangeType.UPDATE,
            old_content="old",
            new_content="new",
        )
        plan.add_file_change(file_change)

        service_change = ServiceChange(
            service_name="wazuh-manager",
            change_type=ChangeType.SERVICE_RESTART,
            reason="Test",
        )
        plan.add_service_change(service_change)

        self.assertFalse(plan.is_empty())
        self.assertEqual(len(plan.file_changes), 1)
        self.assertEqual(len(plan.service_changes), 1)
        self.assertTrue(plan.requires_sudo)

    def test_plan_serialization(self):
        """Test plan JSON serialization."""
        plan = ChangePlan(
            plan_id="test123",
            created_at=datetime.now(timezone.utc),
            description="Test plan",
        )
        plan.add_file_change(
            FileChange(
                path="/test/path",
                change_type=ChangeType.UPDATE,
                old_content="old",
                new_content="new",
            )
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            plan_file = Path(tmpdir) / "plan.json"
            plan.to_json(plan_file)
            self.assertTrue(plan_file.exists())

            # Load back
            loaded_plan = ChangePlan.from_json(plan_file)
            self.assertEqual(loaded_plan.plan_id, plan.plan_id)
            self.assertEqual(len(loaded_plan.file_changes), 1)
            self.assertEqual(loaded_plan.file_changes[0].path, "/test/path")


if __name__ == "__main__":
    unittest.main()

