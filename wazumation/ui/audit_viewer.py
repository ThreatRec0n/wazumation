"""Audit log viewer widget."""

from datetime import datetime
from pathlib import Path
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QLabel,
    QGroupBox,
    QDateEdit,
    QComboBox,
    QLineEdit,
    QFileDialog,
    QMessageBox,
)
from PySide6.QtCore import Qt, QDate
from wazumation.core.audit import AuditChain, AuditResult


class AuditViewerWidget(QWidget):
    """Widget for viewing audit logs."""

    def __init__(self, audit_chain: AuditChain):
        """Initialize audit viewer."""
        super().__init__()
        self.audit_chain = audit_chain
        self._setup_ui()
        self.refresh_logs()

    def _setup_ui(self):
        """Setup audit viewer UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Filters
        filter_group = QGroupBox("Filters")
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Module:"))
        self.module_filter = QComboBox()
        self.module_filter.setEditable(True)
        self.module_filter.addItem("All")
        filter_layout.addWidget(self.module_filter)

        filter_layout.addWidget(QLabel("Result:"))
        self.result_filter = QComboBox()
        self.result_filter.addItem("All")
        for result in AuditResult:
            self.result_filter.addItem(result.value)
        filter_layout.addWidget(self.result_filter)

        filter_layout.addWidget(QLabel("User:"))
        self.user_filter = QLineEdit()
        self.user_filter.setPlaceholderText("Filter by user...")
        filter_layout.addWidget(self.user_filter)

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_logs)
        filter_layout.addWidget(self.refresh_button)

        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)

        # Export button
        export_layout = QHBoxLayout()
        self.export_button = QPushButton("Export to JSONL")
        self.export_button.clicked.connect(self.export_logs)
        export_layout.addWidget(self.export_button)
        export_layout.addStretch()
        layout.addLayout(export_layout)

        # Audit log table
        table_group = QGroupBox("Audit Log (Immutable - Delete Not Allowed)")
        table_layout = QVBoxLayout()
        self.audit_table = QTableWidget()
        self.audit_table.setColumnCount(7)
        self.audit_table.setHorizontalHeaderLabels(
            ["Timestamp", "Entry ID", "User", "Action", "Module", "Result", "Details"]
        )
        self.audit_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.audit_table.horizontalHeader().setStretchLastSection(True)
        table_layout.addWidget(self.audit_table)
        table_group.setLayout(table_layout)
        layout.addWidget(table_group, 1)

        # Chain verification
        verify_layout = QHBoxLayout()
        self.verify_button = QPushButton("Verify Chain Integrity")
        self.verify_button.clicked.connect(self.verify_chain)
        self.verify_label = QLabel("")
        verify_layout.addWidget(self.verify_button)
        verify_layout.addWidget(self.verify_label)
        verify_layout.addStretch()
        layout.addLayout(verify_layout)

    def refresh_logs(self):
        """Refresh audit log display."""
        # Get filters
        module = (
            self.module_filter.currentText() if self.module_filter.currentText() != "All" else None
        )
        result_str = (
            self.result_filter.currentText()
            if self.result_filter.currentText() != "All"
            else None
        )
        result = AuditResult(result_str) if result_str else None
        user = self.user_filter.text() if self.user_filter.text() else None

        # Query logs
        entries = self.audit_chain.query(module=module, result=result, user=user, limit=1000)

        # Populate table
        self.audit_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            self.audit_table.setItem(row, 0, QTableWidgetItem(entry.timestamp.isoformat()))
            self.audit_table.setItem(row, 1, QTableWidgetItem(entry.entry_id))
            self.audit_table.setItem(row, 2, QTableWidgetItem(entry.user))
            self.audit_table.setItem(row, 3, QTableWidgetItem(entry.action))
            self.audit_table.setItem(row, 4, QTableWidgetItem(entry.module))
            self.audit_table.setItem(row, 5, QTableWidgetItem(entry.result.value))
            details_str = str(entry.details)[:100]  # Truncate long details
            self.audit_table.setItem(row, 6, QTableWidgetItem(details_str))

        self.audit_table.resizeColumnsToContents()

    def export_logs(self):
        """Export audit logs to JSONL file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Audit Log", "audit_export.jsonl", "JSONL Files (*.jsonl)"
        )
        if file_path:
            try:
                self.audit_chain.export_jsonl(Path(file_path))
                QMessageBox.information(self, "Export Complete", f"Audit log exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", f"Failed to export: {str(e)}")

    def verify_chain(self):
        """Verify audit chain integrity."""
        is_valid, errors = self.audit_chain.verify_chain()
        if is_valid:
            self.verify_label.setText("✓ Chain integrity verified")
            self.verify_label.setStyleSheet("color: green;")
        else:
            error_msg = "\n".join(errors[:5])  # Show first 5 errors
            self.verify_label.setText(f"✗ Chain integrity failed: {error_msg}")
            self.verify_label.setStyleSheet("color: red;")
            QMessageBox.warning(self, "Chain Verification Failed", "\n".join(errors))


