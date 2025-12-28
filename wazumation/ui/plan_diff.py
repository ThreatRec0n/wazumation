"""Plan and diff viewer widget."""

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTextEdit,
    QPushButton,
    QLabel,
    QGroupBox,
    QMessageBox,
)
from PySide6.QtCore import Qt
from wazumation.core.change_plan import ChangePlan
from wazumation.core.diff import DiffEngine


class PlanDiffWidget(QWidget):
    """Widget for viewing change plans and diffs."""

    def __init__(self, on_approved_callback, on_rejected_callback):
        """Initialize plan diff widget."""
        super().__init__()
        self.on_approved = on_approved_callback
        self.on_rejected = on_rejected_callback
        self.current_plan = None
        self._setup_ui()

    def _setup_ui(self):
        """Setup plan diff UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Plan summary
        summary_group = QGroupBox("Plan Summary")
        summary_layout = QVBoxLayout()
        self.summary_label = QLabel("No plan loaded")
        self.summary_label.setWordWrap(True)
        summary_layout.addWidget(self.summary_label)
        summary_group.setLayout(summary_layout)
        layout.addWidget(summary_group)

        # Diff display
        diff_group = QGroupBox("Changes Preview")
        diff_layout = QVBoxLayout()
        self.diff_text = QTextEdit()
        self.diff_text.setReadOnly(True)
        self.diff_text.setFontFamily("Courier")
        self.diff_text.setFontPointSize(9)
        diff_layout.addWidget(self.diff_text)
        diff_group.setLayout(diff_layout)
        layout.addWidget(diff_group, 1)

        # Action buttons
        button_layout = QHBoxLayout()
        self.approve_button = QPushButton("Approve & Apply")
        self.approve_button.setStyleSheet("background-color: green; color: white; font-weight: bold;")
        self.approve_button.clicked.connect(self.on_approve_clicked)
        self.approve_button.setEnabled(False)

        self.reject_button = QPushButton("Reject")
        self.reject_button.setStyleSheet("background-color: red; color: white;")
        self.reject_button.clicked.connect(self.on_reject_clicked)
        self.reject_button.setEnabled(False)

        button_layout.addWidget(self.approve_button)
        button_layout.addWidget(self.reject_button)
        button_layout.addStretch()
        layout.addLayout(button_layout)

    def set_plan(self, plan: ChangePlan):
        """Set the current plan to display."""
        self.current_plan = plan
        self.summary_label.setText(plan.get_summary())

        # Generate diff
        diff_output = DiffEngine.generate_plan_diff(plan)
        self.diff_text.setPlainText(diff_output)

        # Enable buttons
        self.approve_button.setEnabled(True)
        self.reject_button.setEnabled(True)

    def clear_plan(self):
        """Clear current plan."""
        self.current_plan = None
        self.summary_label.setText("No plan loaded")
        self.diff_text.clear()
        self.approve_button.setEnabled(False)
        self.reject_button.setEnabled(False)

    def on_approve_clicked(self):
        """Handle approve button click."""
        if not self.current_plan:
            return

        reply = QMessageBox.question(
            self,
            "Confirm Approval",
            f"Are you sure you want to apply plan {self.current_plan.plan_id}?\n\n"
            "This will modify Wazuh configuration files and may restart services.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            self.on_approved()

    def on_reject_clicked(self):
        """Handle reject button click."""
        if self.current_plan:
            self.on_rejected()


