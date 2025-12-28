"""Immutable audit logging with hash chain verification."""

import hashlib
import json
import sqlite3
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
import os


class AuditResult(Enum):
    """Result of an audited operation."""

    SUCCESS = "success"
    FAILURE = "failure"
    ROLLBACK = "rollback"
    VALIDATION_FAILED = "validation_failed"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass
class AuditEntry:
    """Single audit log entry."""

    timestamp: datetime
    entry_id: str
    previous_hash: str
    current_hash: str
    user: str
    action: str
    module: str
    result: AuditResult
    plan_id: Optional[str] = None
    details: Dict[str, Any] = None
    requires_sudo: bool = False

    def __post_init__(self):
        """Initialize details if None."""
        if self.details is None:
            self.details = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["result"] = self.result.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEntry":
        """Create from dictionary."""
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        data["result"] = AuditResult(data["result"])
        return cls(**data)


class AuditChain:
    """Manages the immutable audit log with hash chain."""

    def __init__(self, db_path: Path):
        """Initialize audit chain database."""
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize SQLite database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # Durability and safety defaults (best-effort across platforms)
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=FULL")
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                entry_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                current_hash TEXT NOT NULL,
                user TEXT NOT NULL,
                action TEXT NOT NULL,
                module TEXT NOT NULL,
                result TEXT NOT NULL,
                plan_id TEXT,
                details TEXT NOT NULL,
                requires_sudo INTEGER NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp)
            """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_module ON audit_log(module)
            """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_result ON audit_log(result)
            """
        )

        # Enforce append-only behavior at the database layer (defense in depth).
        cursor.execute(
            """
            CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
            BEFORE DELETE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit_log is append-only (DELETE not allowed)');
            END;
            """
        )
        cursor.execute(
            """
            CREATE TRIGGER IF NOT EXISTS audit_log_no_update
            BEFORE UPDATE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit_log is append-only (UPDATE not allowed)');
            END;
            """
        )
        conn.commit()
        conn.close()

    def _get_last_hash(self) -> str:
        """Get the hash of the last entry in the chain."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT current_hash FROM audit_log ORDER BY timestamp DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else "0" * 64  # Genesis hash

    def _compute_hash(self, previous_hash: str, entry_payload: str) -> str:
        """Compute hash of entry."""
        combined = f"{previous_hash}:{entry_payload}"
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()

    def append(
        self,
        user: str,
        action: str,
        module: str,
        result: AuditResult,
        plan_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        requires_sudo: bool = False,
    ) -> AuditEntry:
        """Append a new entry to the audit chain."""
        if details is None:
            details = {}

        previous_hash = self._get_last_hash()
        timestamp = datetime.now(timezone.utc)
        entry_id = hashlib.sha256(
            f"{timestamp.isoformat()}:{user}:{action}".encode()
        ).hexdigest()[:16]

        # Create payload for hashing (exclude hash fields)
        payload_dict = {
            "entry_id": entry_id,
            "timestamp": timestamp.isoformat(),
            "user": user,
            "action": action,
            "module": module,
            "result": result.value,
            "plan_id": plan_id,
            "details": details,
            "requires_sudo": requires_sudo,
        }
        entry_payload = json.dumps(payload_dict, sort_keys=True)
        current_hash = self._compute_hash(previous_hash, entry_payload)

        entry = AuditEntry(
            timestamp=timestamp,
            entry_id=entry_id,
            previous_hash=previous_hash,
            current_hash=current_hash,
            user=user,
            action=action,
            module=module,
            result=result,
            plan_id=plan_id,
            details=details,
            requires_sudo=requires_sudo,
        )

        # Insert into database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_log 
            (entry_id, timestamp, previous_hash, current_hash, user, action, module, result, plan_id, details, requires_sudo)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.entry_id,
                entry.timestamp.isoformat(),
                entry.previous_hash,
                entry.current_hash,
                entry.user,
                entry.action,
                entry.module,
                entry.result.value,
                entry.plan_id,
                json.dumps(entry.details),
                1 if entry.requires_sudo else 0,
            ),
        )
        conn.commit()
        conn.close()

        return entry

    def verify_chain(self) -> Tuple[bool, List[str]]:
        """Verify integrity of the audit chain. Returns (is_valid, errors)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        errors: List[str] = []

        # Verify DB-layer immutability triggers exist.
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit_log'"
        )
        trigger_names = {row[0] for row in cursor.fetchall()}
        required = {"audit_log_no_delete", "audit_log_no_update"}
        missing = sorted(required - trigger_names)
        if missing:
            errors.append(f"Audit immutability triggers missing: {', '.join(missing)}")

        cursor.execute(
            "SELECT previous_hash, current_hash, entry_id, timestamp, user, action, module, result, plan_id, details, requires_sudo FROM audit_log ORDER BY timestamp ASC"
        )
        rows = cursor.fetchall()
        conn.close()

        previous_hash = "0" * 64  # Genesis hash

        for row in rows:
            (
                stored_prev_hash,
                stored_curr_hash,
                entry_id,
                timestamp,
                user,
                action,
                module,
                result,
                plan_id,
                details_json,
                requires_sudo,
            ) = row

            if stored_prev_hash != previous_hash:
                errors.append(
                    f"Hash chain broken at entry {entry_id}: expected previous_hash {previous_hash}, got {stored_prev_hash}"
                )

            payload_dict = {
                "entry_id": entry_id,
                "timestamp": timestamp,
                "user": user,
                "action": action,
                "module": module,
                "result": result,
                "plan_id": plan_id,
                "details": json.loads(details_json),
                "requires_sudo": bool(requires_sudo),
            }
            entry_payload = json.dumps(payload_dict, sort_keys=True)
            computed_hash = self._compute_hash(previous_hash, entry_payload)

            if stored_curr_hash != computed_hash:
                errors.append(
                    f"Hash mismatch at entry {entry_id}: expected {computed_hash}, got {stored_curr_hash}"
                )

            previous_hash = stored_curr_hash

        return len(errors) == 0, errors

    def query(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        module: Optional[str] = None,
        result: Optional[AuditResult] = None,
        user: Optional[str] = None,
        limit: int = 1000,
    ) -> List[AuditEntry]:
        """Query audit log with filters."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        conditions = []
        params = []

        if start_date:
            conditions.append("timestamp >= ?")
            params.append(start_date.isoformat())
        if end_date:
            conditions.append("timestamp <= ?")
            params.append(end_date.isoformat())
        if module:
            conditions.append("module = ?")
            params.append(module)
        if result:
            conditions.append("result = ?")
            params.append(result.value)
        if user:
            conditions.append("user = ?")
            params.append(user)

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        params.append(limit)

        cursor.execute(
            f"""
            SELECT entry_id, timestamp, previous_hash, current_hash, user, action, module, result, plan_id, details, requires_sudo
            FROM audit_log
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            params,
        )

        rows = cursor.fetchall()
        conn.close()

        entries = []
        for row in rows:
            (
                entry_id,
                timestamp,
                prev_hash,
                curr_hash,
                user,
                action,
                module,
                result,
                plan_id,
                details_json,
                requires_sudo,
            ) = row
            entries.append(
                AuditEntry(
                    timestamp=datetime.fromisoformat(timestamp),
                    entry_id=entry_id,
                    previous_hash=prev_hash,
                    current_hash=curr_hash,
                    user=user,
                    action=action,
                    module=module,
                    result=AuditResult(result),
                    plan_id=plan_id,
                    details=json.loads(details_json),
                    requires_sudo=bool(requires_sudo),
                )
            )

        return entries

    def export_jsonl(self, output_path: Path, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None) -> None:
        """Export audit log to JSONL format."""
        entries = self.query(start_date=start_date, end_date=end_date)
        with open(output_path, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(json.dumps(entry.to_dict()) + "\n")


class AuditLogger:
    """Convenience wrapper for audit logging."""

    def __init__(self, audit_chain: AuditChain, user: Optional[str] = None):
        """Initialize audit logger."""
        self.audit_chain = audit_chain
        self.user = user or os.getenv("USER", "unknown")

    def log(
        self,
        action: str,
        module: str,
        result: AuditResult,
        plan_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        requires_sudo: bool = False,
    ) -> AuditEntry:
        """Log an audit entry."""
        return self.audit_chain.append(
            user=self.user,
            action=action,
            module=module,
            result=result,
            plan_id=plan_id,
            details=details or {},
            requires_sudo=requires_sudo,
        )

