"""Backup and rollback management."""

import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List
import hashlib


class BackupManager:
    """Manages configuration file backups."""

    def __init__(self, backup_dir: Path):
        """Initialize backup manager."""
        self.backup_dir = backup_dir
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def create_backup(self, file_path: Path, metadata: Optional[Dict] = None) -> Path:
        """Create a timestamped backup of a file."""
        if not file_path.exists():
            raise FileNotFoundError(f"Cannot backup non-existent file: {file_path}")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        file_hash = self._compute_file_hash(file_path)
        backup_name = f"{file_path.name}.{timestamp}.{file_hash[:8]}.bak"
        backup_path = self.backup_dir / backup_name

        shutil.copy2(file_path, backup_path)

        # Store metadata
        if metadata:
            metadata_path = backup_path.with_suffix(".bak.meta")
            import json
            with open(metadata_path, "w") as f:
                json.dump(metadata, f)

        return backup_path

    def _compute_file_hash(self, file_path: Path) -> str:
        """Compute SHA256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def list_backups(self, file_name: Optional[str] = None) -> List[Path]:
        """List all backups, optionally filtered by original file name."""
        backups = []
        for backup_file in self.backup_dir.glob("*.bak"):
            if file_name is None or backup_file.name.startswith(file_name + "."):
                backups.append(backup_file)
        return sorted(backups, reverse=True)  # Newest first

    def get_latest_backup(self, file_name: str) -> Optional[Path]:
        """Get the most recent backup for a file."""
        backups = self.list_backups(file_name)
        return backups[0] if backups else None


class RollbackManager:
    """Manages rollback operations."""

    def __init__(self, backup_manager: BackupManager):
        """Initialize rollback manager."""
        self.backup_manager = backup_manager

    def rollback(self, file_path: Path, backup_path: Optional[Path] = None) -> Path:
        """Rollback a file to a previous backup."""
        if backup_path is None:
            backup_path = self.backup_manager.get_latest_backup(file_path.name)
            if backup_path is None:
                raise ValueError(f"No backup found for {file_path.name}")

        if not backup_path.exists():
            raise FileNotFoundError(f"Backup file not found: {backup_path}")

        # Create backup of current state before rollback
        if file_path.exists():
            self.backup_manager.create_backup(file_path, metadata={"rollback_source": str(backup_path)})

        # Restore from backup
        shutil.copy2(backup_path, file_path)
        return file_path

    def list_rollback_points(self, file_name: str) -> List[Dict]:
        """List available rollback points for a file."""
        backups = self.backup_manager.list_backups(file_name)
        rollback_points = []
        for backup in backups:
            metadata_path = backup.with_suffix(".bak.meta")
            metadata = {}
            if metadata_path.exists():
                import json
                with open(metadata_path, "r") as f:
                    metadata = json.load(f)
            rollback_points.append(
                {
                    "backup_path": backup,
                    "timestamp": backup.stem.split(".")[1] if "." in backup.stem else "unknown",
                    "metadata": metadata,
                }
            )
        return rollback_points

