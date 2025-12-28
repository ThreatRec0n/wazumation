"""Modules configuration widget."""

from pathlib import Path
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QLabel,
    QGroupBox,
    QFormLayout,
    QLineEdit,
    QComboBox,
    QCheckBox,
    QMessageBox,
    QScrollArea,
)
from PySide6.QtCore import Qt
from wazumation.wazuh.plugin import PluginRegistry
from wazumation.wazuh.xml_parser import WazuhXMLParser
from wazumation.core.change_plan import ChangePlan


class ModulesWidget(QWidget):
    """Widget for configuring Wazuh modules."""

    def __init__(
        self,
        plugin_registry: PluginRegistry,
        config_path: Path,
        is_manager: bool,
        on_plan_created_callback,
    ):
        """Initialize modules widget."""
        super().__init__()
        self.plugin_registry = plugin_registry
        self.config_path = config_path
        self.is_manager = is_manager
        self.on_plan_created = on_plan_created_callback
        self.current_plugin = None
        self._setup_ui()

    def _setup_ui(self):
        """Setup modules UI."""
        layout = QHBoxLayout(self)
        layout.setSpacing(10)

        # Plugin list
        plugin_list_group = QGroupBox("Available Modules")
        plugin_list_layout = QVBoxLayout()
        self.plugin_list = QListWidget()
        self.plugin_list.itemClicked.connect(self.on_plugin_selected)
        plugin_list_layout.addWidget(self.plugin_list)

        # Populate plugin list
        for plugin in self.plugin_registry.list_all():
            if self.is_manager or "agent" in plugin.applies_to:
                item = QListWidgetItem(plugin.name)
                item.setData(Qt.UserRole, plugin.name)
                self.plugin_list.addItem(item)

        plugin_list_group.setLayout(plugin_list_layout)
        layout.addWidget(plugin_list_group, 1)

        # Configuration panel
        config_group = QGroupBox("Configuration")
        config_layout = QVBoxLayout()
        self.config_scroll = QScrollArea()
        self.config_widget = QWidget()
        self.config_layout = QFormLayout(self.config_widget)
        self.config_scroll.setWidget(self.config_widget)
        self.config_scroll.setWidgetResizable(True)
        config_layout.addWidget(self.config_scroll)

        # Buttons
        button_layout = QHBoxLayout()
        self.read_button = QPushButton("Read Current")
        self.read_button.clicked.connect(self.read_current_config)
        self.plan_button = QPushButton("Create Plan")
        self.plan_button.clicked.connect(self.create_plan)
        self.plan_button.setEnabled(False)
        button_layout.addWidget(self.read_button)
        button_layout.addWidget(self.plan_button)
        config_layout.addLayout(button_layout)

        config_group.setLayout(config_layout)
        layout.addWidget(config_group, 2)

        # Status label
        self.status_label = QLabel("Select a module to configure")
        layout.addWidget(self.status_label)

    def on_plugin_selected(self, item):
        """Handle plugin selection."""
        plugin_name = item.data(Qt.UserRole)
        self.current_plugin = self.plugin_registry.get(plugin_name)
        if self.current_plugin:
            self._setup_config_form()
            self.read_current_config()

    def _setup_config_form(self):
        """Setup configuration form for current plugin."""
        # Clear existing form
        while self.config_layout.count():
            child = self.config_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        if not self.current_plugin:
            return

        self.form_widgets = {}
        default_state = self.current_plugin.get_default_state()

        # Create form fields based on default state
        if isinstance(default_state, dict):
            self._create_form_fields(default_state, self.config_layout)

        self.plan_button.setEnabled(True)

    def _create_form_fields(self, state: dict, layout: QFormLayout, prefix: str = ""):
        """Recursively create form fields from state dictionary."""
        for key, value in state.items():
            if key == "attributes" and isinstance(value, dict):
                for attr_key, attr_value in value.items():
                    field_name = f"{prefix}{attr_key}" if prefix else attr_key
                    widget = QLineEdit(str(attr_value))
                    layout.addRow(f"{attr_key}:", widget)
                    self.form_widgets[field_name] = widget
            elif key == "children" and isinstance(value, dict):
                self._create_form_fields(value, layout, prefix)
            elif isinstance(value, dict) and "text" in value:
                field_name = f"{prefix}{key}" if prefix else key
                widget = QLineEdit(str(value["text"]))
                layout.addRow(f"{key}:", widget)
                self.form_widgets[field_name] = widget
            elif isinstance(value, str):
                field_name = f"{prefix}{key}" if prefix else key
                widget = QLineEdit(value)
                layout.addRow(f"{key}:", widget)
                self.form_widgets[field_name] = widget

    def read_current_config(self):
        """Read current configuration from file."""
        if not self.current_plugin:
            return

        if not self.config_path.exists():
            QMessageBox.warning(
                self, "File Not Found", f"Configuration file not found: {self.config_path}"
            )
            return

        try:
            current_state = self.current_plugin.read(self.config_path)
            self._populate_form(current_state)
            self.status_label.setText(f"Read configuration for {self.current_plugin.name}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read configuration: {str(e)}")

    def _populate_form(self, state: dict):
        """Populate form fields from state."""
        # This is a simplified version - would need proper traversal
        for key, widget in self.form_widgets.items():
            if key in state:
                if isinstance(state[key], dict) and "text" in state[key]:
                    widget.setText(str(state[key]["text"]))
                elif isinstance(state[key], str):
                    widget.setText(state[key])

    def create_plan(self):
        """Create change plan from form data."""
        if not self.current_plugin:
            return

        # Get current state
        try:
            current_state = self.current_plugin.read(self.config_path)
        except Exception:
            current_state = self.current_plugin.get_default_state()

        # Get desired state from form
        desired_state = self._get_form_state()

        # Validate
        is_valid, errors = self.current_plugin.validate(desired_state)
        if not is_valid:
            QMessageBox.warning(self, "Validation Failed", "\n".join(errors))
            return

        # Create plan
        try:
            plan = self.current_plugin.plan(self.config_path, current_state, desired_state)
            self.on_plan_created(plan)
            self.status_label.setText(f"Plan created: {plan.plan_id}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create plan: {str(e)}")

    def _get_form_state(self) -> dict:
        """Get state from form widgets."""
        state = {}
        for key, widget in self.form_widgets.items():
            if isinstance(widget, QLineEdit):
                value = widget.text()
                # Try to reconstruct the nested structure
                if "." in key:
                    parts = key.split(".")
                    current = state
                    for part in parts[:-1]:
                        if part not in current:
                            current[part] = {}
                        current = current[part]
                    current[parts[-1]] = value
                else:
                    state[key] = value
        return state


