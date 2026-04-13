"""Background scan worker so the GUI stays responsive."""

from __future__ import annotations

from PyQt6.QtCore import QThread, pyqtSignal

from gui.scan_engine import ScanSnapshot, run_full_scan


class ScanWorker(QThread):
    """Runs ``run_full_scan`` off the UI thread."""

    finished_ok = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, *, persist: bool = True, simulate: bool = False) -> None:
        super().__init__()
        self._persist = persist
        self._simulate = simulate

    def run(self) -> None:  # noqa: D102
        try:
            snap = run_full_scan(persist=self._persist, simulate=self._simulate)
            if snap.error:
                self.failed.emit(snap.error)
            else:
                self.finished_ok.emit(snap)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
