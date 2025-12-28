"""Main GUI application entry point."""

import sys
from pathlib import Path

try:
    from PySide6.QtWidgets import QApplication
    from wazumation.ui.main_window import MainWindow
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False


def main():
    """Launch GUI application."""
    if not GUI_AVAILABLE:
        print("Error: PySide6 is required for GUI mode. Install it with: pip install PySide6", file=sys.stderr)
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setApplicationName("Wazumation")
    app.setOrganizationName("Wazumation")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()

