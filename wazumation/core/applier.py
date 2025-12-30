"""Safe application of change plans."""

import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Tuple, List, Optional
from wazumation.core.change_plan import ChangePlan, FileChange, ServiceChange, ChangeType
from wazumation.core.backup import BackupManager
from wazumation.core.validator import ConfigValidator, ValidationError
from wazumation.core.audit import AuditLogger, AuditResult


class ApplyError(Exception):
    """Raised when apply fails."""

    pass


class PlanApplier:
    """Safely applies change plans with validation and rollback."""

    def __init__(
        self,
        backup_manager: BackupManager,
        validator: ConfigValidator,
        audit_logger: AuditLogger,
        dry_run: bool = False,
    ):
        """Initialize plan applier."""
        self.backup_manager = backup_manager
        self.validator = validator
        self.audit_logger = audit_logger
        self.dry_run = dry_run

    def check_sudo(self) -> bool:
        """Check if sudo is available and prompt if needed."""
        if os.name == "nt":
            # Windows - check for admin privileges
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False

        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return True  # Already root

        try:
            result = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def request_sudo(self) -> bool:
        """Request sudo privileges. Returns True if granted."""
        if os.name == "nt":
            # Windows - check for admin privileges
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False

        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return True

        try:
            result = subprocess.run(
                ["sudo", "-v"],
                capture_output=True,
                timeout=30,
            )
            if result.returncode == 0:
                self.audit_logger.log(
                    action="sudo_elevation",
                    module="applier",
                    result=AuditResult.SUCCESS,
                    details={"user": os.getenv("USER", "unknown")},
                )
                return True
            return False
        except Exception as e:
            self.audit_logger.log(
                action="sudo_elevation",
                module="applier",
                result=AuditResult.FAILURE,
                details={"error": str(e)},
            )
            return False

    def _atomic_write(self, file_path: Path, content: str) -> None:
        """Atomically write file: temp → fsync → rename."""
        file_path.parent.mkdir(parents=True, exist_ok=True)
        temp_fd, temp_path = tempfile.mkstemp(
            dir=str(file_path.parent),
            prefix=f".{file_path.name}.tmp.",
            suffix="",
        )
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp_path, file_path)
        except Exception:
            os.unlink(temp_path)
            raise

    def _apply_file_change(self, change: FileChange) -> None:
        """Apply a single file change."""
        file_path = Path(change.path)

        if self.dry_run:
            self.audit_logger.log(
                action="dry_run_file_change",
                module="applier",
                result=AuditResult.APPROVED,
                details={
                    "path": change.path,
                    "type": change.change_type.value,
                },
            )
            return

        # Create backup before any change (skip in dry-run)
        if not self.dry_run and file_path.exists() and change.change_type != ChangeType.CREATE:
            backup_path = self.backup_manager.create_backup(
                file_path, metadata={"plan_id": change.metadata.get("plan_id")}
            )
            change.backup_path = str(backup_path)

        # Apply change
        if change.change_type == ChangeType.CREATE:
            self._atomic_write(file_path, change.new_content)
        elif change.change_type == ChangeType.UPDATE:
            self._atomic_write(file_path, change.new_content)
        elif change.change_type == ChangeType.DELETE:
            if file_path.exists():
                file_path.unlink()

    def _apply_service_change(self, change: ServiceChange) -> None:
        """Apply a service change."""
        if self.dry_run:
            self.audit_logger.log(
                action="dry_run_service_change",
                module="applier",
                result=AuditResult.APPROVED,
                details={
                    "service": change.service_name,
                    "operation": change.change_type.value,
                },
            )
            return

        # Only restart services on Linux with systemctl
        if os.name != "posix":
            self.audit_logger.log(
                action="service_change_skipped",
                module="applier",
                result=AuditResult.SUCCESS,
                details={
                    "service": change.service_name,
                    "operation": change.change_type.value,
                    "reason": "Not on Linux system",
                },
            )
            return

        # Check if systemctl is available
        if shutil.which("systemctl") is None:
            self.audit_logger.log(
                action="service_change_skipped",
                module="applier",
                result=AuditResult.SUCCESS,
                details={
                    "service": change.service_name,
                    "operation": change.change_type.value,
                    "reason": "systemctl not available",
                },
            )
            return

        # Allowed services (security: only restart known safe services)
        allowed_services = ["wazuh-manager"]
        if change.service_name not in allowed_services:
            self.audit_logger.log(
                action="service_change_rejected",
                module="applier",
                result=AuditResult.REJECTED,
                details={
                    "service": change.service_name,
                    "operation": change.change_type.value,
                    "reason": "Service not in allowlist",
                },
            )
            raise ApplyError(f"Service {change.service_name} not in allowlist: {allowed_services}")

        # Apply service change
        try:
            if change.change_type == ChangeType.SERVICE_RESTART:
                subprocess.run(["systemctl", "restart", change.service_name], check=True, timeout=30)
            elif change.change_type == ChangeType.SERVICE_START:
                subprocess.run(["systemctl", "start", change.service_name], check=True, timeout=30)
            elif change.change_type == ChangeType.SERVICE_STOP:
                subprocess.run(["systemctl", "stop", change.service_name], check=True, timeout=30)
        except subprocess.TimeoutExpired:
            raise ApplyError(f"Service operation timed out: {change.service_name}")
        except subprocess.CalledProcessError as e:
            raise ApplyError(f"Service operation failed: {change.service_name} - {e}")

    def apply(self, plan: ChangePlan, require_approval: bool = True) -> Tuple[bool, List[str]]:
        """Apply a change plan with validation and rollback."""
        errors = []

        # Validate plan
        is_valid, validation_errors = self.validator.validate_plan(plan)
        if not is_valid:
            self.audit_logger.log(
                action="plan_validation",
                module="applier",
                result=AuditResult.VALIDATION_FAILED,
                plan_id=plan.plan_id,
                details={"errors": validation_errors},
            )
            return False, validation_errors

        # Check sudo if needed (skip in dry-run)
        if not self.dry_run and plan.requires_sudo and not self.check_sudo():
            if not self.request_sudo():
                errors.append("Sudo privileges required but not granted")
                self.audit_logger.log(
                    action="apply_plan",
                    module="applier",
                    result=AuditResult.REJECTED,
                    plan_id=plan.plan_id,
                    details={"reason": "sudo_denied"},
                )
                return False, errors

        # Log approval
        if require_approval and not self.dry_run:
            self.audit_logger.log(
                action="plan_approved",
                module="applier",
                result=AuditResult.APPROVED,
                plan_id=plan.plan_id,
                requires_sudo=plan.requires_sudo,
            )

        # Apply file changes
        applied_changes = []
        try:
            for file_change in plan.file_changes:
                try:
                    self._apply_file_change(file_change)
                    applied_changes.append(file_change)
                except Exception as e:
                    errors.append(f"Failed to apply {file_change.path}: {str(e)}")
                    # Rollback applied changes
                    self._rollback_changes(applied_changes)
                    raise ApplyError(f"Apply failed: {errors}")

            # Validate final state BEFORE any service operations (safety gate).
            if not self.dry_run:
                for file_change in plan.file_changes:
                    if file_change.path.endswith("ossec.conf") and Path(file_change.path).exists():
                        is_valid, validation_errors = self.validator.validate_ossec_conf(Path(file_change.path))
                        if not is_valid:
                            errors.extend(validation_errors)
                            self._rollback_changes(applied_changes)
                            raise ApplyError(f"Pre-service validation failed: {errors}")

            # Apply service changes
            for service_change in plan.service_changes:
                try:
                    self._apply_service_change(service_change)
                except Exception as e:
                    errors.append(
                        f"Failed to {service_change.change_type.value} {service_change.service_name}: {str(e)}"
                    )
                    # Rollback file changes
                    self._rollback_changes(applied_changes)
                    raise ApplyError(f"Service operation failed: {errors}")
            # Post-apply validation is now implicit: config is validated before service ops.

            # Log success
            self.audit_logger.log(
                action="apply_plan",
                module="applier",
                result=AuditResult.SUCCESS,
                plan_id=plan.plan_id,
                details={
                    "files_changed": len(plan.file_changes),
                    "services_changed": len(plan.service_changes),
                },
                requires_sudo=plan.requires_sudo,
            )

            return True, []

        except ApplyError:
            self.audit_logger.log(
                action="apply_plan",
                module="applier",
                result=AuditResult.FAILURE,
                plan_id=plan.plan_id,
                details={"errors": errors},
            )
            return False, errors

    def _rollback_changes(self, changes: List[FileChange]) -> None:
        """Rollback applied file changes."""
        from wazumation.core.backup import RollbackManager

        rollback_manager = RollbackManager(self.backup_manager)
        for change in reversed(changes):  # Reverse order
            if change.backup_path:
                try:
                    rollback_manager.rollback(Path(change.path), Path(change.backup_path))
                    self.audit_logger.log(
                        action="rollback_file",
                        module="applier",
                        result=AuditResult.ROLLBACK,
                        details={"path": change.path, "backup": change.backup_path},
                    )
                except Exception as e:
                    self.audit_logger.log(
                        action="rollback_file",
                        module="applier",
                        result=AuditResult.FAILURE,
                        details={"path": change.path, "error": str(e)},
                    )

