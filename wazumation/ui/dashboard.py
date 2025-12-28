"""Dashboard widget."""

import subprocess
from pathlib import Path
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QGroupBox,
    QGridLayout,
)
from PySide6.QtCore import Qt


class DashboardWidget(QWidget):
    """Dashboard showing environment status."""

    def __init__(self, wazuh_manager_path: Path, wazuh_config_path: Path, is_manager: bool):
        """Initialize dashboard."""
        super().__init__()
        self.wazuh_manager_path = wazuh_manager_path
        self.wazuh_config_path = wazuh_config_path
        self.is_manager = is_manager
        self._setup_ui()

    def _setup_ui(self):
        """Setup dashboard UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(20)

        # Environment detection
        env_group = QGroupBox("Environment Detection")
        env_layout = QGridLayout()
        env_layout.addWidget(QLabel("Type:"), 0, 0)
        env_type = QLabel("Manager" if self.is_manager else "Agent/Unknown")
        env_type.setStyleSheet("font-weight: bold;")
        env_layout.addWidget(env_type, 0, 1)
        env_layout.addWidget(QLabel("Config Path:"), 1, 0)
        env_layout.addWidget(QLabel(str(self.wazuh_config_path)), 1, 1)
        env_layout.addWidget(QLabel("Manager Path:"), 2, 0)
        env_layout.addWidget(QLabel(str(self.wazuh_manager_path)), 2, 1)
        env_group.setLayout(env_layout)
        layout.addWidget(env_group)

        # Version info
        version_group = QGroupBox("Version Information")
        version_layout = QVBoxLayout()
        version_label = QLabel(self._get_version_info())
        version_label.setWordWrap(True)
        version_layout.addWidget(version_label)
        version_group.setLayout(version_layout)
        layout.addWidget(version_group)

        # Service status
        status_group = QGroupBox("Service Status")
        status_layout = QVBoxLayout()
        status_label = QLabel(self._get_service_status())
        status_label.setWordWrap(True)
        status_layout.addWidget(status_label)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)

        layout.addStretch()

    def _get_version_info(self) -> str:
        """Get Wazuh version information."""
        if not self.is_manager:
            return "Wazuh manager not detected. Running in read-only mode."

        try:
            result = subprocess.run(
                ["/var/ossec/bin/wazuh-control", "info"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout
            return "Unable to get version info"
        except Exception as e:
            return f"Error getting version: {str(e)}"

    def _get_service_status(self) -> str:
        """Get service status."""
        if not self.is_manager:
            return "Service status unavailable (not running on manager)"

        status_lines = []
        services = ["wazuh-manager", "wazuh-api"]
        for service in services:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", service],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                status = result.stdout.strip()
                status_lines.append(f"{service}: {status}")
            except Exception:
                status_lines.append(f"{service}: unknown")

        return "\n".join(status_lines) if status_lines else "Unable to get service status"


