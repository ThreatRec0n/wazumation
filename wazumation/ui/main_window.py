"""Main application window."""

import os
from pathlib import Path

try:
    from PySide6.QtWidgets import (
        QMainWindow,
        QWidget,
        QVBoxLayout,
        QHBoxLayout,
        QTabWidget,
        QLabel,
        QPushButton,
        QMessageBox,
        QStatusBar,
    )
    from PySide6.QtCore import Qt, QTimer
except ImportError:
    raise ImportError("PySide6 is required for GUI. Install with: pip install PySide6")
from wazumation.ui.dashboard import DashboardWidget
from wazumation.ui.modules import ModulesWidget
from wazumation.ui.plan_diff import PlanDiffWidget
from wazumation.ui.audit_viewer import AuditViewerWidget
from wazumation.ui.policy import PolicyWidget
from wazumation.core.audit import AuditChain, AuditLogger, AuditResult
from wazumation.core.backup import BackupManager
from wazumation.core.validator import ConfigValidator
from wazumation.core.applier import PlanApplier
from wazumation.wazuh.plugin import PluginRegistry
from wazumation.wazuh.plugins import register_all_plugins


class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(self):
        """Initialize main window."""
        super().__init__()
        self.setWindowTitle("Wazumation - Wazuh Configuration Automation")
        self.setMinimumSize(1200, 800)

        # Initialize core components
        self.data_dir = Path.home() / ".wazumation"
        self.data_dir.mkdir(exist_ok=True)

        self.audit_chain = AuditChain(self.data_dir / "audit.db")
        self.audit_logger = AuditLogger(self.audit_chain)
        self.backup_manager = BackupManager(self.data_dir / "backups")
        self.validator = ConfigValidator()
        self.applier = PlanApplier(
            self.backup_manager, self.validator, self.audit_logger, dry_run=False
        )

        # Initialize plugin registry
        self.plugin_registry = PluginRegistry()
        register_all_plugins(self.plugin_registry)

        # Detect Wazuh installation
        self.wazuh_manager_path = Path("/var/ossec")
        self.wazuh_config_path = self.wazuh_manager_path / "etc" / "ossec.conf"
        self.is_manager = self.wazuh_config_path.exists()

        # Current change plan
        self.current_plan = None

        # Setup UI
        self._setup_ui()
        self._setup_status_bar()

        # Update status periodically
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self._update_status)
        self.status_timer.start(5000)  # Every 5 seconds

    def _setup_ui(self):
        """Setup user interface."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(10, 10, 10, 10)

        # Header
        header = QLabel("Wazumation")
        header.setStyleSheet("font-size: 24px; font-weight: bold; padding: 10px;")
        layout.addWidget(header)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.North)

        # Dashboard tab
        self.dashboard = DashboardWidget(
            self.wazuh_manager_path, self.wazuh_config_path, self.is_manager
        )
        self.tabs.addTab(self.dashboard, "Dashboard")

        # Modules tab
        self.modules = ModulesWidget(
            self.plugin_registry,
            self.wazuh_config_path,
            self.is_manager,
            self.on_plan_created,
        )
        self.tabs.addTab(self.modules, "Modules")

        # Plan & Diff tab
        self.plan_diff = PlanDiffWidget(self.on_plan_approved, self.on_plan_rejected)
        self.tabs.addTab(self.plan_diff, "Plan & Diff")

        # Audit Viewer tab
        self.audit_viewer = AuditViewerWidget(self.audit_chain)
        self.tabs.addTab(self.audit_viewer, "Audit Log")

        # Policy tab
        self.policy = PolicyWidget()
        self.tabs.addTab(self.policy, "Policy")

        layout.addWidget(self.tabs)

        # Read-only mode indicator
        self.read_only_label = QLabel("🔒 Read-Only Mode")
        self.read_only_label.setStyleSheet("color: orange; font-weight: bold; padding: 5px;")
        layout.addWidget(self.read_only_label)

    def _setup_status_bar(self):
        """Setup status bar."""
        self.statusBar().showMessage("Ready")

    def _update_status(self):
        """Update status bar."""
        if self.is_manager:
            status = "Wazuh Manager detected"
        else:
            status = "Wazuh Manager not detected (read-only mode)"
        self.statusBar().showMessage(status)

    def on_plan_created(self, plan):
        """Handle plan creation from modules."""
        self.current_plan = plan
        self.plan_diff.set_plan(plan)
        self.tabs.setCurrentIndex(2)  # Switch to Plan & Diff tab

    def on_plan_approved(self):
        """Handle plan approval."""
        if not self.current_plan:
            QMessageBox.warning(self, "No Plan", "No plan to apply.")
            return

        # Apply plan
        success, errors = self.applier.apply(self.current_plan, require_approval=True)
        if success:
            QMessageBox.information(
                self,
                "Plan Applied",
                f"Plan {self.current_plan.plan_id} applied successfully.",
            )
            # Refresh modules view
            self.modules.read_current_config()
        else:
            QMessageBox.critical(
                self,
                "Apply Failed",
                f"Failed to apply plan:\n\n" + "\n".join(errors),
            )

        self.current_plan = None
        self.plan_diff.clear_plan()

    def on_plan_rejected(self):
        """Handle plan rejection."""
        if self.current_plan:
            self.audit_logger.log(
                action="plan_rejected",
                module="gui",
                result=AuditResult.REJECTED,
                plan_id=self.current_plan.plan_id,
            )
        self.current_plan = None
        self.plan_diff.clear_plan()

