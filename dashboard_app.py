"""
Desktop SOC-style dashboard for the Windows Service & Process Monitoring Agent.

Run from the repository root (Windows recommended for WMI/service data):

    pip install -r requirements.txt
    python dashboard_app.py

The UI runs live scans via ``gui/scan_engine.py`` and watches ``logs/`` for new
``alerts_*.json`` files written by the CLI or the GUI.
"""

from __future__ import annotations

import sys

from PyQt6.QtWidgets import QApplication

from gui.main_window import MainWindow
from gui.styles import APP_STYLESHEET


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("Windows Monitoring Agent")
    app.setStyle("Fusion")
    app.setStyleSheet(APP_STYLESHEET)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
