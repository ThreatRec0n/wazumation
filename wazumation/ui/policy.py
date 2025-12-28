"""Policy configuration widget."""

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGroupBox,
    QFormLayout,
    QSpinBox,
    QCheckBox,
    QLabel,
    QPushButton,
    QListWidget,
    QLineEdit,
    QMessageBox,
)
from PySide6.QtCore import Qt


class PolicyWidget(QWidget):
    """Widget for configuring Wazumation policies."""

    def __init__(self):
        """Initialize policy widget."""
        super().__init__()
        self._setup_ui()

    def _setup_ui(self):
        """Setup policy UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(20)

        # Audit retention
        retention_group = QGroupBox("Audit Retention")
        retention_layout = QFormLayout()
        self.retention_days = QSpinBox()
        self.retention_days.setMinimum(1)
        self.retention_days.setMaximum(365)
        self.retention_days.setValue(30)
        retention_layout.addRow("Retention (days):", self.retention_days)
        retention_group.setLayout(retention_layout)
        layout.addWidget(retention_group)

        # Approval workflow
        approval_group = QGroupBox("Approval Workflow")
        approval_layout = QVBoxLayout()
        self.require_approval = QCheckBox("Require explicit approval before applying changes")
        self.require_approval.setChecked(True)
        approval_layout.addWidget(self.require_approval)
        approval_group.setLayout(approval_layout)
        layout.addWidget(approval_group)

        # Read-only mode
        readonly_group = QGroupBox("Write Mode")
        readonly_layout = QVBoxLayout()
        self.read_only_mode = QCheckBox("Read-only mode (disable all writes)")
        self.read_only_mode.setChecked(False)
        readonly_layout.addWidget(self.read_only_mode)
        readonly_group.setLayout(readonly_layout)
        layout.addWidget(readonly_group)

        # Module allowlist/denylist
        modules_group = QGroupBox("Module Policy")
        modules_layout = QVBoxLayout()
        modules_layout.addWidget(QLabel("Allowed Modules (empty = all allowed):"))
        self.allowed_modules = QListWidget()
        modules_layout.addWidget(self.allowed_modules)

        add_module_layout = QHBoxLayout()
        self.module_input = QLineEdit()
        self.module_input.setPlaceholderText("Module name...")
        add_module_button = QPushButton("Add")
        add_module_button.clicked.connect(self.add_allowed_module)
        add_module_layout.addWidget(self.module_input)
        add_module_layout.addWidget(add_module_button)
        modules_layout.addLayout(add_module_layout)

        remove_module_button = QPushButton("Remove Selected")
        remove_module_button.clicked.connect(self.remove_allowed_module)
        modules_layout.addWidget(remove_module_button)

        modules_group.setLayout(modules_layout)
        layout.addWidget(modules_group)

        # Save button
        save_layout = QHBoxLayout()
        save_button = QPushButton("Save Policy")
        save_button.clicked.connect(self.save_policy)
        save_layout.addWidget(save_button)
        save_layout.addStretch()
        layout.addLayout(save_layout)

        layout.addStretch()

    def add_allowed_module(self):
        """Add module to allowlist."""
        module_name = self.module_input.text().strip()
        if module_name:
            self.allowed_modules.addItem(module_name)
            self.module_input.clear()

    def remove_allowed_module(self):
        """Remove selected module from allowlist."""
        current_item = self.allowed_modules.currentItem()
        if current_item:
            self.allowed_modules.takeItem(self.allowed_modules.row(current_item))

    def save_policy(self):
        """Save policy settings."""
        # In real implementation, this would save to a config file
        QMessageBox.information(
            self,
            "Policy Saved",
            "Policy settings saved. (Note: This is a placeholder - full persistence not yet implemented)",
        )


