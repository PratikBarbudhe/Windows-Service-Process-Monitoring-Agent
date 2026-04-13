"""
Reusable light-theme UI building blocks (cards, chart shells, health badge).
"""

from __future__ import annotations

from typing import Literal, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QApplication, QFrame, QGraphicsDropShadowEffect, QHBoxLayout, QLabel, QVBoxLayout, QWidget


def _soft_shadow(target: QWidget, blur: int = 22, y_off: int = 3, alpha: int = 38) -> None:
    """Lightweight elevation shadow (SaaS-style card)."""
    fx = QGraphicsDropShadowEffect(target)
    fx.setBlurRadius(blur)
    fx.setOffset(0, y_off)
    fx.setColor(QColor(15, 23, 42, alpha))
    target.setGraphicsEffect(fx)


class SummaryCard(QFrame):
    """
    Metric card: optional icon glyph, large value, caption.
    Styled like a SaaS dashboard tile (white, rounded, subtle border).
    """

    def __init__(
        self,
        icon_text: str,
        caption: str,
        initial_value: str = "—",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("summaryCard")
        self.setMinimumHeight(108)
        self.setMinimumWidth(140)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(18, 16, 18, 16)
        outer.setSpacing(14)

        self._icon = QLabel(icon_text)
        self._icon.setObjectName("cardIcon")
        self._icon.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        outer.addWidget(self._icon, 0, Qt.AlignmentFlag.AlignTop)

        text_col = QVBoxLayout()
        text_col.setSpacing(4)
        self._caption = QLabel(caption)
        self._caption.setObjectName("metricCaption")
        self._value = QLabel(initial_value)
        self._value.setObjectName("metricValue")
        text_col.addWidget(self._caption)
        text_col.addWidget(self._value)
        text_col.addStretch()
        outer.addLayout(text_col, 1)
        _soft_shadow(self)

    def set_value(self, text: str) -> None:
        self._value.setText(text)


class ChartCard(QFrame):
    """White card wrapper with a section title and inner content widget."""

    def __init__(self, title: str, inner: QWidget, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("chartCard")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 16)
        lay.setSpacing(10)
        ttl = QLabel(title)
        ttl.setObjectName("sectionTitle")
        lay.addWidget(ttl)
        lay.addWidget(inner, 1)
        _soft_shadow(self, blur=26, y_off=4, alpha=32)


class HealthBadge(QFrame):
    """Compact pill: Safe / Warning / Critical."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._text = QLabel("Safe")
        self._text.setObjectName("healthBadgeText")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 6, 14, 6)
        lay.setSpacing(0)
        lay.addWidget(self._text)
        self.set_state("ok")

    def set_state(self, state: Literal["ok", "warn", "bad"]) -> None:
        if state == "ok":
            self.setObjectName("healthBadgeOk")
            self._text.setText("Safe")
        elif state == "warn":
            self.setObjectName("healthBadgeWarn")
            self._text.setText("Warning")
        else:
            self.setObjectName("healthBadgeBad")
            self._text.setText("Critical")
        app = QApplication.instance()
        if app is not None:
            st = app.style()
            st.unpolish(self)
            st.polish(self)
