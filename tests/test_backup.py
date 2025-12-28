"""Tests for backup manager."""

import unittest
import tempfile
from pathlib import Path
from wazumation.core.backup import BackupManager, RollbackManager


class TestBackupManager(unittest.TestCase):
    """Test backup manager functionality."""

    def test_backup_creation(self):
        """Test creating a backup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_manager = BackupManager(backup_dir)

            # Create a test file
            test_file = Path(tmpdir) / "test.conf"
            test_file.write_text("test content")

            # Create backup
            backup_path = backup_manager.create_backup(test_file)
            self.assertTrue(backup_path.exists())
            self.assertEqual(backup_path.read_text(), "test content")

    def test_list_backups(self):
        """Test listing backups."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_manager = BackupManager(backup_dir)

            # Create test file and backups
            test_file = Path(tmpdir) / "test.conf"
            test_file.write_text("content1")
            backup1 = backup_manager.create_backup(test_file)

            test_file.write_text("content2")
            backup2 = backup_manager.create_backup(test_file)

            # List backups
            backups = backup_manager.list_backups("test.conf")
            self.assertEqual(len(backups), 2)

    def test_rollback(self):
        """Test rollback functionality."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_manager = BackupManager(backup_dir)
            rollback_manager = RollbackManager(backup_manager)

            # Create original file
            test_file = Path(tmpdir) / "test.conf"
            test_file.write_text("original")

            # Create backup
            backup_path = backup_manager.create_backup(test_file)

            # Modify file
            test_file.write_text("modified")

            # Rollback
            rollback_manager.rollback(test_file, backup_path)
            self.assertEqual(test_file.read_text(), "original")


if __name__ == "__main__":
    unittest.main()

