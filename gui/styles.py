"""
Qt stylesheets for the monitoring dashboard.

``LIGHT_THEME_QSS`` — modern SaaS-style light UI (default for ``dashboard_app``).
``DARK_THEME_QSS`` — legacy dark theme (optional).
"""

# --- Light theme (primary) -------------------------------------------------
LIGHT_THEME_QSS = """
/* Global */
QWidget {
    background-color: #F5F7FA;
    color: #2D3748;
    font-size: 13px;
    font-family: "Segoe UI", "SF Pro Text", Roboto, system-ui, sans-serif;
}
QMainWindow, QDialog {
    background-color: #F5F7FA;
}

/* Top toolbar */
QToolBar {
    background-color: #FFFFFF;
    border: none;
    border-bottom: 1px solid #E2E8F0;
    padding: 8px 12px;
    spacing: 10px;
}
QToolBar QLabel {
    color: #718096;
    font-size: 12px;
}

/* Tabs — underline active (web-style) */
QTabWidget::pane {
    border: none;
    background-color: #F5F7FA;
    top: 0px;
}
QTabBar::tab {
    background: transparent;
    color: #718096;
    padding: 12px 20px;
    margin-right: 4px;
    border: none;
    border-bottom: 3px solid transparent;
    font-weight: 500;
    min-width: 72px;
}
QTabBar::tab:selected {
    color: #4A90E2;
    font-weight: 600;
    border-bottom: 3px solid #4A90E2;
}
QTabBar::tab:hover:!selected {
    color: #4A5568;
    background-color: #EDF2F7;
    border-radius: 6px 6px 0 0;
}

/* Form controls */
QLineEdit, QComboBox, QSpinBox {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 8px;
    padding: 8px 12px;
    min-height: 18px;
    selection-background-color: #4A90E2;
    selection-color: #FFFFFF;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid #4A90E2;
}
QComboBox::drop-down {
    border: none;
    width: 28px;
}
QComboBox QAbstractItemView {
    background: #FFFFFF;
    border: 1px solid #E2E8F0;
    selection-background-color: #EBF4FC;
    selection-color: #2D3748;
}

QCheckBox {
    spacing: 8px;
    color: #4A5568;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 1px solid #CBD5E0;
    background: #FFFFFF;
}
QCheckBox::indicator:checked {
    background-color: #4A90E2;
    border-color: #4A90E2;
}

/* Buttons */
QPushButton {
    background-color: #4A90E2;
    color: #FFFFFF;
    border: none;
    border-radius: 8px;
    padding: 9px 18px;
    font-weight: 600;
    min-height: 20px;
}
QPushButton:hover {
    background-color: #3B7BC8;
}
QPushButton:pressed {
    background-color: #2F6AB0;
}
QPushButton:disabled {
    background-color: #CBD5E0;
    color: #F7FAFC;
}
QPushButton#secondary {
    background-color: #EDF2F7;
    color: #4A5568;
    border: 1px solid #E2E8F0;
}
QPushButton#secondary:hover {
    background-color: #E2E8F0;
    color: #2D3748;
}
QPushButton#secondary:pressed {
    background-color: #CBD5E0;
}

/* Typography */
QLabel#pageTitle {
    font-size: 22px;
    font-weight: 700;
    color: #1A202C;
    letter-spacing: -0.3px;
}
QLabel#sectionTitle {
    font-size: 14px;
    font-weight: 600;
    color: #4A5568;
}
QLabel#muted {
    color: #718096;
    font-size: 12px;
}
QLabel#metricValue {
    font-size: 28px;
    font-weight: 700;
    color: #1A202C;
    letter-spacing: -0.5px;
}
QLabel#metricCaption {
    font-size: 11px;
    font-weight: 600;
    color: #718096;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
QLabel#cardIcon {
    font-size: 22px;
    color: #4A90E2;
}

/* Summary / chart cards */
QFrame#summaryCard {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 12px;
}
QFrame#chartCard {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 12px;
}

/* Health badge (pill) */
QFrame#healthBadgeOk {
    background-color: #E8F8EF;
    border: 1px solid #2ECC71;
    border-radius: 20px;
}
QFrame#healthBadgeWarn {
    background-color: #FFF8EB;
    border: 1px solid #F5A623;
    border-radius: 20px;
}
QFrame#healthBadgeBad {
    background-color: #FDECEA;
    border: 1px solid #E74C3C;
    border-radius: 20px;
}
QLabel#healthBadgeText {
    font-weight: 600;
    font-size: 12px;
    padding: 2px 4px;
    background: transparent;
    border: none;
}
QFrame#healthBadgeOk QLabel#healthBadgeText { color: #1E7F4A; }
QFrame#healthBadgeWarn QLabel#healthBadgeText { color: #B7791F; }
QFrame#healthBadgeBad QLabel#healthBadgeText { color: #C0392B; }

/* Tables */
QTableWidget {
    gridline-color: #EDF2F7;
    background-color: #FFFFFF;
    alternate-background-color: #FAFBFC;
    border: 1px solid #E2E8F0;
    border-radius: 10px;
    selection-background-color: #EBF4FC;
    selection-color: #1A202C;
}
QTableWidget::item {
    padding: 8px 6px;
    border: none;
}
QTableWidget::item:hover {
    background-color: #F0F4F8;
}
QTableWidget::item:selected {
    background-color: #EBF4FC;
    color: #1A202C;
}
QHeaderView::section {
    background-color: #F7FAFC;
    color: #4A5568;
    padding: 10px 8px;
    border: none;
    border-bottom: 1px solid #E2E8F0;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.4px;
}

QStatusBar {
    background-color: #FFFFFF;
    color: #718096;
    border-top: 1px solid #E2E8F0;
    padding: 4px 8px;
}

QSplitter::handle {
    background: #E2E8F0;
    width: 2px;
}
QScrollBar:vertical {
    background: #F7FAFC;
    width: 10px;
    margin: 0;
    border-radius: 5px;
}
QScrollBar::handle:vertical {
    background: #CBD5E0;
    min-height: 24px;
    border-radius: 5px;
}
QScrollBar::handle:vertical:hover {
    background: #A0AEC0;
}
"""

# Default export for dashboard_app
APP_STYLESHEET = LIGHT_THEME_QSS

# Legacy dark theme (optional)
DARK_THEME_QSS = """
QWidget {
    background-color: #12141a;
    color: #e6e8ef;
    font-size: 13px;
    font-family: "Segoe UI", "SF Pro Text", Roboto, sans-serif;
}
QMainWindow, QDialog { background-color: #12141a; }
QTabWidget::pane { border: 1px solid #2a2f3a; border-radius: 6px; top: -1px; }
QTabBar::tab {
    background: #1b1f28; color: #aeb4c5; padding: 10px 18px;
    border-top-left-radius: 6px; border-top-right-radius: 6px;
}
QTabBar::tab:selected { background: #252a36; color: #f2f4f8; font-weight: 600; }
QTableWidget {
    gridline-color: #2a2f3a; background-color: #161a22;
    alternate-background-color: #1b1f28;
    selection-background-color: #2d6cdf; selection-color: #ffffff;
    border: 1px solid #2a2f3a; border-radius: 4px;
}
QHeaderView::section {
    background-color: #1f2430; color: #cfd6e6; padding: 8px;
    border: none; border-bottom: 2px solid #2d6cdf; font-weight: 600;
}
QLineEdit, QComboBox, QSpinBox {
    background-color: #1b1f28; border: 1px solid #2a2f3a; border-radius: 4px;
    padding: 6px 10px; selection-background-color: #2d6cdf;
}
QPushButton {
    background-color: #2d6cdf; color: #ffffff; border: none;
    border-radius: 4px; padding: 8px 16px; font-weight: 600;
}
QPushButton:hover { background-color: #3a7bf0; }
QPushButton#secondary { background-color: #2a3140; color: #e6e8ef; }
QToolBar { background: #161a22; border-bottom: 1px solid #2a2f3a; spacing: 8px; padding: 4px; }
QStatusBar { background: #161a22; color: #8b93a8; border-top: 1px solid #2a2f3a; }
"""
