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

    def update_value(self, new_val: str):
        self.lbl_value.setText(new_val)

class RiskIndicator(QFrame):
    """Индикатор уровня риска с цветовой дифференциацией"""
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.pbar = QProgressBar()
        self.pbar.setRange(0, 100)
        self.pbar.setValue(0)
        self.pbar.setTextVisible(True)
        self.pbar.setFixedHeight(24)
        layout.addWidget(self.pbar)
        self.set_risk(0)

    def set_risk(self, score: int):
        self.pbar.setValue(score)
        if score < 30:
            color = "#2a9d8f"  # Зеленый
            status = f"Низкий риск ({score}/100) - Безопасно"
        elif score < 60:
            color = "#e9c46a"  # Желтый
            status = f"Умеренный риск ({score}/100) - Предупреждение"
        elif score < 80:
            color = "#f4a261"  # Оранжевый
            status = f"Высокий риск ({score}/100) - Требует внимания"
        else:
            color = "#e63946"  # Красный
            status = f"КРИТИЧЕСКИЙ РИСК ({score}/100) - АТАКА!"

        self.pbar.setFormat(status)
        self.pbar.setStyleSheet(f"""
            QProgressBar {{
                background-color: #1e1e24;
                border: 1px solid #383e4a;
                border-radius: 4px;
                text-align: center;
                color: #ffffff;
                font-weight: bold;
                font-size: 11px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 3px;
            }}
        """)
