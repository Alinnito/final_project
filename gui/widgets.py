from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

class MetricCard(QFrame):
    """Информационная карточка метрики безопасности для дашборда"""
    def __init__(self, title: str, value: str, subtext: str = "", accent_color: str = "#00b4d8"):
        super().__init__()
        self.accent_color = accent_color
        self.setStyleSheet(f"""
            QFrame {{
                background-color: #252830;
                border: 1px solid #383e4a;
                border-left: 5px solid {accent_color};
                border-radius: 6px;
                padding: 10px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        layout.setContentsMargins(10, 8, 10, 8)

        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("color: #8c9ba5; font-size: 11px; font-weight: bold; text-transform: uppercase;")
        layout.addWidget(lbl_title)

        self.lbl_value = QLabel(value)
        self.lbl_value.setStyleSheet(f"color: #ffffff; font-size: 22px; font-weight: bold;")
        layout.addWidget(self.lbl_value)

        if subtext:
            self.lbl_sub = QLabel(subtext)
            self.lbl_sub.setStyleSheet("color: #6c7a89; font-size: 10px;")
            layout.addWidget(self.lbl_sub)
