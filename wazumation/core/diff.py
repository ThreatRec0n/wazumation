"""Diff generation and preview for configuration changes."""

import difflib
from typing import List, Tuple, Optional
from wazumation.core.change_plan import ChangePlan, FileChange


class DiffEngine:
    """Generate human-readable diffs for change plans."""

    @staticmethod
    def generate_file_diff(change: FileChange, context_lines: int = 3) -> str:
        """Generate unified diff for a file change."""
        if change.change_type.value == "create":
            old_lines = []
            new_lines = change.new_content.splitlines(keepends=True) if change.new_content else []
            fromfile = f"/dev/null"
            tofile = change.path
        elif change.change_type.value == "delete":
            old_lines = change.old_content.splitlines(keepends=True) if change.old_content else []
            new_lines = []
            fromfile = change.path
            tofile = "/dev/null"
        else:  # update
            old_lines = (
                change.old_content.splitlines(keepends=True) if change.old_content else []
            )
            new_lines = (
                change.new_content.splitlines(keepends=True) if change.new_content else []
            )
            fromfile = change.path
            tofile = change.path

        diff = difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=fromfile,
            tofile=tofile,
            lineterm="",
            n=context_lines,
        )
        return "\n".join(diff)

    @staticmethod
    def generate_plan_diff(plan: ChangePlan) -> str:
        """Generate complete diff preview for a change plan."""
        lines = []
        lines.append(f"=== Change Plan: {plan.description} ===")
        lines.append(f"Plan ID: {plan.plan_id}")
        lines.append(f"Created: {plan.created_at.isoformat()}")
        lines.append("")

        if plan.file_changes:
            lines.append("--- File Changes ---")
            for i, change in enumerate(plan.file_changes, 1):
                lines.append(f"\n[{i}] {change.change_type.value.upper()}: {change.path}")
                if change.metadata:
                    for key, value in change.metadata.items():
                        lines.append(f"    {key}: {value}")
                diff_output = DiffEngine.generate_file_diff(change)
                if diff_output:
                    lines.append(diff_output)
                lines.append("")

        if plan.service_changes:
            lines.append("--- Service Operations ---")
            for i, change in enumerate(plan.service_changes, 1):
                lines.append(
                    f"[{i}] {change.change_type.value.upper()}: {change.service_name}"
                )
                lines.append(f"    Reason: {change.reason}")
                if change.metadata:
                    for key, value in change.metadata.items():
                        lines.append(f"    {key}: {value}")
                lines.append("")

        if plan.is_empty():
            lines.append("(No changes planned)")

        return "\n".join(lines)

    @staticmethod
    def get_change_summary(plan: ChangePlan) -> Tuple[int, int, int]:
        """Get summary counts: files changed, services affected, total operations."""
        return (
            len(plan.file_changes),
            len(plan.service_changes),
            len(plan.file_changes) + len(plan.service_changes),
        )


