"""
Main PyQt window: light SaaS-style dashboard with cards, charts, and tables.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
from typing import Any, Dict, List, Optional, Set

import psutil
from path_utils import ensure_alert_path_field, is_suspicious_path, resolve_alert_path, truncate_path_display
from PyQt6.QtCore import QFileSystemWatcher, QPointF, Qt, QTimer, QUrl
from PyQt6.QtGui import QColor, QDesktopServices, QFont, QLinearGradient, QPainter, QPen, QPolygonF
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

import config
from gui.components import ChartCard, HealthBadge, SummaryCard
from gui.scan_engine import ScanSnapshot, latest_alerts_json_path, load_alerts_json
from gui.scan_worker import ScanWorker


def _alert_fingerprint(alert: Dict[str, Any]) -> str:
    raw = "|".join(
        str(alert.get(k, ""))
        for k in (
            "type",
            "severity",
            "timestamp",
            "description",
            "reason",
            "pid",
            "child_pid",
            "service_name",
            "path",
        )
    )
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


# Severity indicator colors (dots / icons) — align with design brief
SEVERITY_ACCENT: Dict[str, QColor] = {
    "CRITICAL": QColor(0xE7, 0x4C, 0x3C),
    "HIGH": QColor(0xF5, 0xA6, 0x23),
    "MEDIUM": QColor(0xF1, 0xC4, 0x0F),
    "LOW": QColor(0x4A, 0x90, 0xE2),
    "INFO": QColor(0xA0, 0xAE, 0xC0),
}

SEVERITY_GLYPH: Dict[str, str] = {
    "CRITICAL": "●",
    "HIGH": "●",
    "MEDIUM": "●",
    "LOW": "●",
    "INFO": "●",
}

# Alerts table: icon | time | entity | path | severity | type | reason
_ALERT_COL_PATH = 3
_PATH_DATA_ROLE = Qt.ItemDataRole.UserRole
_PID_DATA_ROLE = Qt.ItemDataRole.UserRole + 1


class SeverityBarChart(QWidget):
    """Light-themed severity distribution bars."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._stats: Dict[str, int] = {}
        self.setMinimumHeight(200)

    def set_statistics(self, stats: Dict[str, Any]) -> None:
        if not stats:
            self._stats = {}
            self.update()
            return
        if "critical" in stats:
            self._stats = {
                "CRITICAL": int(stats.get("critical", 0)),
                "HIGH": int(stats.get("high", 0)),
                "MEDIUM": int(stats.get("medium", 0)),
                "LOW": int(stats.get("low", 0)),
                "INFO": int(stats.get("info", 0)),
            }
        else:
            bd = stats if isinstance(stats, dict) else {}
            self._stats = {str(k).upper(): int(v) for k, v in bd.items() if isinstance(v, (int, float))}
        self.update()

    def paintEvent(self, event) -> None:  # noqa: ANN001
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(12, 8, -12, -8)
        painter.setPen(QPen(QColor("#E2E8F0")))
        painter.setBrush(QColor("#FFFFFF"))
        painter.drawRoundedRect(rect, 10, 10)

        inner = rect.adjusted(16, 28, -16, -20)
        painter.setPen(Qt.PenStyle.NoPen)
        keys = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        vals = [self._stats.get(k, 0) for k in keys]
        m = max(vals + [1])
        n = len(keys)
        gap = 12
        bar_w = max(28, (inner.width() - gap * (n - 1)) // n)
        base_y = inner.bottom() - 8
        colors = ["#E74C3C", "#F5A623", "#F1C40F", "#4A90E2", "#A0AEC0"]
        painter.setFont(QFont("Segoe UI", 9))
        for i, key in enumerate(keys):
            v = vals[i]
            bh = int((inner.height() - 36) * (v / m))
            x = inner.left() + i * (bar_w + gap)
            y = base_y - bh
            grad = QLinearGradient(0, y, 0, base_y)
            c = QColor(colors[i])
            grad.setColorAt(0, c.lighter(108))
            grad.setColorAt(1, c)
            painter.setBrush(grad)
            painter.drawRoundedRect(x, y, bar_w, bh, 6, 6)
            painter.setPen(QColor("#718096"))
            painter.drawText(x - 4, base_y + 6, bar_w + 8, 20, Qt.AlignmentFlag.AlignCenter, key[:3])
            painter.drawText(x - 4, y - 18, bar_w + 8, 16, Qt.AlignmentFlag.AlignCenter, str(v))


class TrendSparkline(QWidget):
    """Light-themed alerts-over-time area chart."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._series: List[int] = []
        self.setMinimumHeight(200)

    def push(self, total: int, max_points: int = 28) -> None:
        self._series.append(int(total))
        self._series = self._series[-max_points:]
        self.update()

    def paintEvent(self, event) -> None:  # noqa: ANN001
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(12, 8, -12, -8)
        painter.setPen(QPen(QColor("#E2E8F0")))
        painter.setBrush(QColor("#FFFFFF"))
        painter.drawRoundedRect(rect, 10, 10)

        inner = rect.adjusted(18, 22, -18, -16)
        painter.setPen(QColor("#CBD5E0"))
        painter.drawLine(inner.left(), inner.bottom(), inner.right(), inner.bottom())

        if len(self._series) < 2:
            painter.setPen(QColor("#A0AEC0"))
            painter.setFont(QFont("Segoe UI", 10))
            painter.drawText(inner, Qt.AlignmentFlag.AlignCenter, "Run scans or enable auto-refresh to build trend.")
            return

        w, h = inner.width(), inner.height()
        pad_y = 8
        mx = max(self._series + [1])
        pts: List[QPointF] = []
        for i, v in enumerate(self._series):
            xi = inner.left() + i * w / (len(self._series) - 1)
            yi = inner.bottom() - pad_y - (h - pad_y * 2) * (v / mx)
            pts.append(QPointF(xi, yi))

        poly = QPolygonF(pts + [QPointF(pts[-1].x(), inner.bottom()), QPointF(pts[0].x(), inner.bottom())])
        fill_grad = QLinearGradient(0, inner.top(), 0, inner.bottom())
        fill_grad.setColorAt(0, QColor(74, 144, 226, 55))
        fill_grad.setColorAt(1, QColor(74, 144, 226, 8))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(fill_grad)
        painter.drawPolygon(poly)

        painter.setPen(QPen(QColor("#4A90E2"), 2.5))
        for i in range(len(pts) - 1):
            painter.drawLine(pts[i], pts[i + 1])

        painter.setFont(QFont("Segoe UI", 9))
        painter.setPen(QColor("#718096"))
        painter.drawText(inner.left(), inner.top() - 2, inner.width(), 16, Qt.AlignmentFlag.AlignLeft, "Total alerts")


class MainWindow(QMainWindow):
    """Primary dashboard window (light theme)."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Windows Monitoring Agent")
        self.resize(1320, 840)

        self._last_snapshot: Optional[ScanSnapshot] = None
        self._current_alerts: List[Dict[str, Any]] = []
        self._all_processes: List[Dict[str, Any]] = []
        self._known_critical: Set[str] = set()
        self._critical_baseline_done = False
        self._worker: Optional[ScanWorker] = None
        self._last_log_hash: Optional[str] = None

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(20, 12, 20, 16)
        root.setSpacing(0)

        self._build_toolbar()
        root.addWidget(self.tool_bar)

        body = QWidget()
        body_lay = QVBoxLayout(body)
        body_lay.setContentsMargins(0, 16, 0, 0)
        body_lay.setSpacing(0)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)
        body_lay.addWidget(self.tabs, 1)

        self._build_tabs()
        root.addWidget(body, 1)

        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._status.showMessage("Ready.")

        self._wire_file_watcher()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_auto_refresh)
        self._timer.start(self.spin_interval.value() * 1000)

    def _build_toolbar(self) -> None:
        self.tool_bar = QToolBar("Main")
        self.tool_bar.setMovable(False)
        self.addToolBar(self.tool_bar)

        self.btn_scan = QPushButton("Run scan")
        self.btn_scan.setToolTip("Run live process & service analysis")
        self.btn_scan.clicked.connect(self._start_scan)
        self.tool_bar.addWidget(self.btn_scan)

        self.btn_reload = QPushButton("Reload logs")
        self.btn_reload.setObjectName("secondary")
        self.btn_reload.clicked.connect(lambda: self._reload_from_disk(silent=False))
        self.tool_bar.addWidget(self.btn_reload)

        self.btn_export = QPushButton("Export…")
        self.btn_export.setObjectName("secondary")
        self.btn_export.clicked.connect(self._export_data)
        self.tool_bar.addWidget(self.btn_export)

        self.tool_bar.addSeparator()
        self.chk_simulate = QCheckBox("Demo alerts")
        self.tool_bar.addWidget(self.chk_simulate)
        self.chk_save = QCheckBox("Save reports")
        self.chk_save.setChecked(True)
        self.tool_bar.addWidget(self.chk_save)

        self.tool_bar.addSeparator()
        self.chk_auto = QCheckBox("Auto-refresh")
        self.chk_auto.setChecked(True)
        self.tool_bar.addWidget(self.chk_auto)
        self.tool_bar.addWidget(QLabel("Interval"))
        self.spin_interval = QSpinBox()
        self.spin_interval.setRange(5, 600)
        self.spin_interval.setValue(15)
        self.spin_interval.setSuffix(" s")
        self.spin_interval.valueChanged.connect(self._reset_timer)
        self.tool_bar.addWidget(self.spin_interval)

    def _build_tabs(self) -> None:
        # --- Dashboard -----------------------------------------------------
        self.tab_overview = QWidget()
        ov = QVBoxLayout(self.tab_overview)
        ov.setSpacing(18)

        header = QHBoxLayout()
        title = QLabel("Dashboard")
        title.setObjectName("pageTitle")
        header.addWidget(title)
        header.addStretch()
        self.health_badge = HealthBadge()
        header.addWidget(self.health_badge, 0, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        ov.addLayout(header)

        cards = QHBoxLayout()
        cards.setSpacing(14)
        self.card_process = SummaryCard("🖥", "Total processes", "—")
        self.card_alerts = SummaryCard("🔔", "Total alerts", "0")
        self.card_crit = SummaryCard("⛔", "Critical", "0")
        self.card_high = SummaryCard("⚡", "High", "0")
        self.card_med = SummaryCard("📌", "Medium", "0")
        for c in (self.card_process, self.card_alerts, self.card_crit, self.card_high, self.card_med):
            cards.addWidget(c, 1)
        ov.addLayout(cards)

        self.chart = SeverityBarChart()
        self.spark = TrendSparkline()
        chart_left = ChartCard("Severity distribution", self.chart)
        chart_right = ChartCard("Alerts over time", self.spark)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(chart_left)
        split.addWidget(chart_right)
        split.setSizes([640, 640])
        ov.addWidget(split, 1)

        self.tabs.addTab(self.tab_overview, "Dashboard")

        # --- Alerts --------------------------------------------------------
        self.tab_alerts = QWidget()
        al = QVBoxLayout(self.tab_alerts)
        al.setSpacing(12)
        filt = QHBoxLayout()
        filt.setSpacing(12)
        self.edit_alert_search = QLineEdit()
        self.edit_alert_search.setPlaceholderText("Search alerts (reason, type, entity…)")
        self.edit_alert_search.setClearButtonEnabled(True)
        self.edit_alert_search.textChanged.connect(lambda _t: self._apply_alert_filter())
        filt.addWidget(self.edit_alert_search, 2)
        filt.addWidget(QLabel("Severity"))
        self.combo_sev = QComboBox()
        self.combo_sev.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.combo_sev.currentTextChanged.connect(lambda _t: self._apply_alert_filter())
        filt.addWidget(self.combo_sev, 0)
        al.addLayout(filt)

        filt2 = QHBoxLayout()
        filt2.setSpacing(12)
        self.chk_alert_suspicious = QCheckBox("Suspicious paths only")
        self.chk_alert_suspicious.setToolTip("Temp, AppData, Downloads, Public, Startup, …")
        self.chk_alert_suspicious.toggled.connect(lambda _c: self._apply_alert_filter())
        filt2.addWidget(self.chk_alert_suspicious)
        filt2.addStretch()
        self.btn_open_loc = QPushButton("Open folder…")
        self.btn_open_loc.setObjectName("secondary")
        self.btn_open_loc.setToolTip("Open File Explorer at the binary’s folder")
        self.btn_open_loc.clicked.connect(self._open_alert_path)
        self.btn_kill = QPushButton("End process…")
        self.btn_kill.setObjectName("secondary")
        self.btn_kill.setToolTip("Terminate the process for this row (requires permissions)")
        self.btn_kill.clicked.connect(self._kill_alert_process)
        filt2.addWidget(self.btn_open_loc)
        filt2.addWidget(self.btn_kill)
        al.addLayout(filt2)

        self.table_alerts = QTableWidget(0, 7)
        self.table_alerts.setHorizontalHeaderLabels(
            ["", "Timestamp", "Entity", "Path", "Severity", "Type", "Reason"]
        )
        self.table_alerts.verticalHeader().setVisible(False)
        hdr = self.table_alerts.horizontalHeader()
        hdr.setStretchLastSection(True)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table_alerts.setColumnWidth(0, 44)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table_alerts.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_alerts.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table_alerts.setAlternatingRowColors(True)
        self.table_alerts.setShowGrid(False)
        self.table_alerts.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table_alerts.setSortingEnabled(True)
        self.table_alerts.itemSelectionChanged.connect(self._sync_alert_action_buttons)
        al.addWidget(self.table_alerts)
        self.tabs.addTab(self.tab_alerts, "Alerts")

        # --- Processes -----------------------------------------------------
        self.tab_procs = QWidget()
        pl = QVBoxLayout(self.tab_procs)
        pl.setSpacing(12)
        prow = QHBoxLayout()
        prow.setSpacing(12)
        self.edit_proc_search = QLineEdit()
        self.edit_proc_search.setPlaceholderText("Search by name, path, or PID…")
        self.edit_proc_search.setClearButtonEnabled(True)
        self.edit_proc_search.textChanged.connect(lambda _t: self._apply_proc_filter())
        prow.addWidget(self.edit_proc_search, 2)
        prow.addWidget(QLabel("Filter"))
        self.combo_proc = QComboBox()
        self.combo_proc.addItem("All processes", "all")
        self.combo_proc.addItem("Paths under Temp / AppData", "staging")
        self.combo_proc.addItem("High memory (≥ 200 MB)", "mem")
        self.combo_proc.currentIndexChanged.connect(lambda _i: self._apply_proc_filter())
        prow.addWidget(self.combo_proc, 0)
        pl.addLayout(prow)

        self.table_procs = QTableWidget(0, 5)
        self.table_procs.setHorizontalHeaderLabels(["PID", "Process", "Path", "CPU %", "Memory (MB)"])
        self.table_procs.verticalHeader().setVisible(False)
        self.table_procs.horizontalHeader().setStretchLastSection(True)
        self.table_procs.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_procs.setAlternatingRowColors(True)
        self.table_procs.setShowGrid(False)
        self.table_procs.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table_procs.setSortingEnabled(True)
        pl.addWidget(self.table_procs)
        self.tabs.addTab(self.tab_procs, "Processes")

        # --- Services ------------------------------------------------------
        self.tab_svc = QWidget()
        sl = QVBoxLayout(self.tab_svc)
        self.table_svc = QTableWidget(0, 7)
        self.table_svc.setHorizontalHeaderLabels(
            ["", "Name", "Display name", "Status", "Start", "Path", "Flag"]
        )
        self.table_svc.verticalHeader().setVisible(False)
        self.table_svc.setColumnWidth(0, 40)
        self.table_svc.horizontalHeader().setStretchLastSection(True)
        self.table_svc.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_svc.setAlternatingRowColors(True)
        self.table_svc.setShowGrid(False)
        self.table_svc.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table_svc.setSortingEnabled(True)
        sl.addWidget(self.table_svc)
        self.tabs.addTab(self.tab_svc, "Services")

    def _repolish(self, w: QWidget) -> None:
        app = QApplication.instance()
        if app is not None:
            st = app.style()
            st.unpolish(w)
            st.polish(w)

    def _wire_file_watcher(self) -> None:
        self._watcher = QFileSystemWatcher(self)
        log_dir = os.path.abspath(config.LOG_DIRECTORY)
        os.makedirs(log_dir, exist_ok=True)
        self._watcher.addPath(log_dir)
        self._watcher.directoryChanged.connect(lambda _=None: self._reload_from_disk(silent=True))

    def _reset_timer(self) -> None:
        self._timer.setInterval(max(5, self.spin_interval.value()) * 1000)

    def _on_auto_refresh(self) -> None:
        if not self.chk_auto.isChecked():
            return
        self._reload_from_disk(silent=True)

    def _start_scan(self) -> None:
        if self._worker and self._worker.isRunning():
            return
        self.btn_scan.setEnabled(False)
        self._status.showMessage("Scan running…")
        self._worker = ScanWorker(
            persist=self.chk_save.isChecked(),
            simulate=self.chk_simulate.isChecked(),
        )
        self._worker.finished_ok.connect(self._on_scan_finished)
        self._worker.failed.connect(self._on_scan_failed)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.start()

    def _on_scan_finished(self, snap: object) -> None:
        self.btn_scan.setEnabled(True)
        if not isinstance(snap, ScanSnapshot):
            return
        if snap.error:
            self._on_scan_failed(snap.error)
            return
        self._last_snapshot = snap
        self._ingest_alerts(snap.alerts, snap.statistics, process_count=len(snap.processes))
        self._fill_process_table(snap.processes)
        self._fill_service_table(snap.services)
        self._status.showMessage(
            f"Scan complete — {len(snap.alerts)} alerts — {snap.alert_file or 'not persisted'}"
        )

    def _on_scan_failed(self, msg: str) -> None:
        self.btn_scan.setEnabled(True)
        self._status.showMessage("Scan failed.")
        QMessageBox.critical(self, "Scan failed", msg)

    def _ingest_alerts(
        self,
        alerts: List[Dict[str, Any]],
        stats: Dict[str, Any],
        *,
        process_count: Optional[int] = None,
    ) -> None:
        self._current_alerts = [ensure_alert_path_field(dict(a)) for a in alerts]
        self._update_overview(stats, process_count=process_count)
        self._apply_alert_filter()
        self.chart.set_statistics(stats)
        total = int(stats.get("total_alerts", len(alerts)))
        self.spark.push(total)
        self._maybe_popup_critical(alerts)

    def _update_overview(self, stats: Dict[str, Any], *, process_count: Optional[int] = None) -> None:
        if process_count is None and self._last_snapshot:
            process_count = len(self._last_snapshot.processes)
        proc_text = str(process_count) if process_count is not None else "—"
        self.card_process.set_value(proc_text)
        self.card_alerts.set_value(str(stats.get("total_alerts", 0)))
        self.card_crit.set_value(str(stats.get("critical", 0)))
        self.card_high.set_value(str(stats.get("high", 0)))
        self.card_med.set_value(str(stats.get("medium", 0)))

        crit = int(stats.get("critical", 0))
        high = int(stats.get("high", 0))
        if crit > 0:
            self.health_badge.set_state("bad")
        elif high > 0:
            self.health_badge.set_state("warn")
        else:
            self.health_badge.set_state("ok")
        self._repolish(self.health_badge)

    def _maybe_popup_critical(self, alerts: List[Dict[str, Any]]) -> None:
        crit_fps = {_alert_fingerprint(a) for a in alerts if str(a.get("severity")).upper() == "CRITICAL"}
        if not self._critical_baseline_done:
            self._known_critical |= crit_fps
            self._critical_baseline_done = True
            return
        new_fps = crit_fps - self._known_critical
        if new_fps:
            titles = [
                (a.get("type"), (a.get("reason") or a.get("description", ""))[:200])
                for a in alerts
                if str(a.get("severity")).upper() == "CRITICAL" and _alert_fingerprint(a) in new_fps
            ][:5]
            body = "\n".join(f"• {t[0]}: {t[1]}" for t in titles)
            QMessageBox.warning(
                self,
                "Critical threat detected",
                "New CRITICAL alert(s) detected:\n\n" + body,
            )
        self._known_critical |= crit_fps

    def _apply_alert_filter(self) -> None:
        filt = self.combo_sev.currentText()
        needle = self.edit_alert_search.text().strip().lower()
        sus_only = self.chk_alert_suspicious.isChecked()
        rows: List[Dict[str, Any]] = []
        for a in self._current_alerts:
            sev = str(a.get("severity", "")).upper()
            if filt != "All" and sev != filt:
                continue
            full_path = resolve_alert_path(a)
            if sus_only and not is_suspicious_path(full_path):
                continue
            who = str(
                a.get("process_name")
                or a.get("child_name")
                or a.get("service_name")
                or a.get("type", "")
            )
            blob = " ".join(
                str(x).lower()
                for x in (
                    who,
                    a.get("type"),
                    a.get("reason"),
                    a.get("description"),
                    a.get("severity"),
                    a.get("timestamp"),
                    full_path,
                )
            )
            if needle and needle not in blob:
                continue
            rows.append(a)

        self.table_alerts.setSortingEnabled(False)
        self.table_alerts.setRowCount(0)
        self.table_alerts.setRowCount(len(rows))
        base_flags = Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled
        white = QColor("#FFFFFF")
        alt = QColor("#FAFBFC")
        for r, a in enumerate(rows):
            ts = str(a.get("timestamp", ""))
            who = str(
                a.get("process_name")
                or a.get("child_name")
                or a.get("service_name")
                or a.get("type", "")
            )
            sev = str(a.get("severity", "")).upper()
            typ = str(a.get("type", ""))
            reason = str(a.get("reason") or a.get("description", ""))
            full_path = resolve_alert_path(a)
            path_disp = truncate_path_display(full_path, 80) if full_path else "—"
            pid_raw = a.get("child_pid") if a.get("child_pid") is not None else a.get("pid")
            try:
                pid_val = int(pid_raw) if pid_raw is not None and str(pid_raw).strip() != "" else 0
            except (TypeError, ValueError):
                pid_val = 0

            su = sev.upper()
            dot_txt = SEVERITY_GLYPH.get(su, "●")
            if is_suspicious_path(full_path):
                dot_txt = "⚠"
            dot = QTableWidgetItem(dot_txt)
            dot.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            dot.setForeground(SEVERITY_ACCENT.get(su, QColor("#A0AEC0")))
            dot.setFlags(base_flags)
            dot.setToolTip("Severity indicator (⚠ when path looks like staging/user-writable).")

            row_bg = white if r % 2 == 0 else alt
            self.table_alerts.setItem(r, 0, dot)

            for col, val in ((1, ts), (2, who), (4, sev), (5, typ), (6, reason)):
                cell = QTableWidgetItem(val)
                cell.setFlags(base_flags)
                cell.setBackground(row_bg)
                cell.setForeground(QColor("#2D3748"))
                self.table_alerts.setItem(r, col, cell)

            path_it = QTableWidgetItem(path_disp)
            path_it.setToolTip(full_path or "No path recorded for this alert.")
            path_it.setData(_PATH_DATA_ROLE, full_path)
            path_it.setData(_PID_DATA_ROLE, pid_val if pid_val else None)
            path_it.setFlags(base_flags)
            path_it.setBackground(row_bg)
            if is_suspicious_path(full_path):
                path_it.setForeground(QColor("#C0392B"))
                path_it.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
            else:
                path_it.setForeground(QColor("#2D3748"))
                path_it.setFont(QFont("Consolas", 9))
            self.table_alerts.setItem(r, _ALERT_COL_PATH, path_it)

        self.table_alerts.setSortingEnabled(True)
        self._sync_alert_action_buttons()

    def _sync_alert_action_buttons(self) -> None:
        row = self.table_alerts.currentRow()
        if row < 0:
            self.btn_open_loc.setEnabled(False)
            self.btn_kill.setEnabled(False)
            return
        it = self.table_alerts.item(row, _ALERT_COL_PATH)
        full = str(it.data(_PATH_DATA_ROLE) or "").strip() if it else ""
        pid = it.data(_PID_DATA_ROLE) if it else None
        self.btn_open_loc.setEnabled(bool(full))
        try:
            pid_int = int(pid) if pid is not None and str(pid).strip() != "" else 0
        except (TypeError, ValueError):
            pid_int = 0
        self.btn_kill.setEnabled(pid_int > 0)

    def _open_alert_path(self) -> None:
        row = self.table_alerts.currentRow()
        if row < 0:
            return
        it = self.table_alerts.item(row, _ALERT_COL_PATH)
        if not it:
            return
        full = str(it.data(_PATH_DATA_ROLE) or "").strip()
        if not full or full == "—":
            QMessageBox.information(self, "Open folder", "No executable path on this alert.")
            return
        p = os.path.abspath(full)
        if os.path.isfile(p):
            folder = os.path.dirname(p)
        elif os.path.isdir(p):
            folder = p
        else:
            folder = os.path.dirname(p)
        if folder and os.path.isdir(folder):
            QDesktopServices.openUrl(QUrl.fromLocalFile(folder))
            self._status.showMessage(f"Opened: {folder}")
        else:
            QMessageBox.warning(self, "Open folder", "Could not resolve a folder to open.")

    def _kill_alert_process(self) -> None:
        row = self.table_alerts.currentRow()
        if row < 0:
            return
        it = self.table_alerts.item(row, _ALERT_COL_PATH)
        if not it:
            return
        try:
            pid = int(it.data(_PID_DATA_ROLE))
        except (TypeError, ValueError):
            QMessageBox.information(self, "End process", "No valid PID for this row.")
            return
        if pid <= 0:
            QMessageBox.information(self, "End process", "No process ID (e.g. service-only alert).")
            return
        ans = QMessageBox.question(
            self,
            "End process",
            f"Terminate PID {pid}? This can destabilize the system if the process is required.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if ans != QMessageBox.StandardButton.Yes:
            return
        try:
            psutil.Process(pid).terminate()
            self._status.showMessage(f"Sent terminate to PID {pid}.")
            QMessageBox.information(self, "End process", f"Terminate signal sent to PID {pid}.")
        except psutil.AccessDenied:
            QMessageBox.warning(self, "End process", "Access denied — try running the dashboard elevated.")
        except psutil.NoSuchProcess:
            QMessageBox.information(self, "End process", "Process already exited.")
        except psutil.Error as exc:
            QMessageBox.warning(self, "End process", str(exc))

    def _fill_process_table(self, processes: List[Dict[str, Any]]) -> None:
        self._all_processes = processes
        self._apply_proc_filter()

    def _apply_proc_filter(self) -> None:
        q = self.edit_proc_search.text().strip().lower()
        mode = self.combo_proc.currentData()
        if mode is None:
            mode = "all"
        data = list(self._all_processes)
        if q:
            data = [
                p
                for p in data
                if q in str(p.get("pid")).lower()
                or q in str(p.get("name", "")).lower()
                or q in str(p.get("path", "")).lower()
            ]
        if mode == "staging":
            keys = ("temp", "appdata", "downloads", "startup")
            data = [p for p in data if any(k in str(p.get("path", "")).lower() for k in keys)]
        elif mode == "mem":
            data = [p for p in data if float(p.get("memory_mb") or 0) >= 200.0]

        self.table_procs.setSortingEnabled(False)
        self.table_procs.setRowCount(0)
        self.table_procs.setRowCount(len(data))
        white = QColor("#FFFFFF")
        alt = QColor("#FAFBFC")
        for r, p in enumerate(sorted(data, key=lambda x: int(x.get("pid", 0)))):
            vals = [
                str(p.get("pid", "")),
                str(p.get("name", "")),
                str(p.get("path", "")),
                str(p.get("cpu", "")),
                str(p.get("memory_mb", "")),
            ]
            row_bg = white if r % 2 == 0 else alt
            for c, val in enumerate(vals):
                it = QTableWidgetItem(val)
                it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                it.setBackground(row_bg)
                it.setForeground(QColor("#2D3748"))
                self.table_procs.setItem(r, c, it)
        self.table_procs.setSortingEnabled(True)

    def _fill_service_table(self, services: List[Dict[str, Any]]) -> None:
        self.table_svc.setSortingEnabled(False)
        self.table_svc.setRowCount(0)
        self.table_svc.setRowCount(len(services))
        white = QColor("#FFFFFF")
        alt = QColor("#FAFBFC")
        for r, s in enumerate(services):
            susp = bool(s.get("suspicious"))
            row_bg = white if r % 2 == 0 else alt
            dot = QTableWidgetItem("●" if susp else "")
            dot.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if susp:
                dot.setForeground(QColor("#E74C3C"))
            else:
                dot.setForeground(QColor("#CBD5E0"))
            dot.setFlags(dot.flags() & ~Qt.ItemFlag.ItemIsEditable)
            dot.setBackground(row_bg)
            self.table_svc.setItem(r, 0, dot)

            vals = [
                str(s.get("name", "")),
                str(s.get("display_name", "")),
                str(s.get("status", "")),
                str(s.get("start_type", "")),
                str(s.get("path", "")),
                "Review" if susp else "",
            ]
            for c, val in enumerate(vals, start=1):
                it = QTableWidgetItem(val)
                it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                it.setBackground(row_bg)
                it.setForeground(QColor("#2D3748"))
                if susp and c == 5:
                    it.setForeground(QColor("#C0392B"))
                    it.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
                self.table_svc.setItem(r, c, it)
        self.table_svc.setSortingEnabled(True)

    def _reload_from_disk(self, *, silent: bool = False) -> None:
        path = latest_alerts_json_path()
        if not path:
            if not silent:
                QMessageBox.information(self, "Logs", "No alerts JSON found yet. Run a scan first.")
            return
        digest = f"{path}|{os.path.getmtime(path)}"
        if digest == self._last_log_hash and silent:
            return
        self._last_log_hash = digest
        payload = load_alerts_json(path)
        if not payload:
            if not silent:
                QMessageBox.warning(self, "Logs", "Could not parse alerts file.")
            return
        alerts = payload.get("alerts") or []
        bd = payload.get("severity_breakdown") or {}
        stats = {
            "total_alerts": int(payload.get("total_alerts", len(alerts))),
            "critical": int(bd.get("CRITICAL", 0)),
            "high": int(bd.get("HIGH", 0)),
            "medium": int(bd.get("MEDIUM", 0)),
            "low": int(bd.get("LOW", 0)),
            "info": int(bd.get("INFO", 0)),
        }
        pc = len(self._last_snapshot.processes) if self._last_snapshot else None
        self._ingest_alerts(alerts, stats, process_count=pc)
        if not silent:
            self._status.showMessage(f"Loaded log: {path}")
        else:
            self._status.showMessage(f"Synced: {os.path.basename(path)}")

    def _export_data(self) -> None:
        path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export alerts",
            "alerts_export.json",
            "JSON (*.json);;CSV (*.csv)",
        )
        if not path:
            return
        lower = path.lower()
        if selected_filter.startswith("CSV") or lower.endswith(".csv"):
            if not lower.endswith(".csv"):
                path += ".csv"
            with open(path, "w", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                w.writerow(
                    ["timestamp", "process_or_service", "path", "severity", "type", "reason"]
                )
                for a in self._current_alerts:
                    who = (
                        a.get("process_name")
                        or a.get("child_name")
                        or a.get("service_name")
                        or ""
                    )
                    w.writerow(
                        [
                            a.get("timestamp"),
                            who,
                            resolve_alert_path(a),
                            a.get("severity"),
                            a.get("type"),
                            a.get("reason") or a.get("description"),
                        ]
                    )
        else:
            if not lower.endswith(".json"):
                path += ".json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"alerts": self._current_alerts}, f, indent=2)
        QMessageBox.information(self, "Export", f"Saved:\n{path}")

    def showEvent(self, event) -> None:  # noqa: ANN001
        super().showEvent(event)
        self._reload_from_disk(silent=True)
