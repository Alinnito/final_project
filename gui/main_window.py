"""
Главное окно графического интерфейса пользователя
"""
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QTabWidget,
    QPushButton, QTextEdit, QLineEdit, QComboBox, QTableWidget,
    QHeaderView, QGroupBox
)
from PySide6.QtCore import Qt

from core.crypto_engine import CryptoEngine
from core.sqli_detector import SQLiDetector
from core.audit_logger import AuditLogger
from core.rbac_manager import RBACManager
from core.db_connector import DBConnector

DARK_STYLE = """
QMainWindow {
    background-color: #191b1f;
}
QWidget {
    color: #e0e6ed;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 13px;
}
QTabWidget::pane {
    border: 1px solid #333942;
    background-color: #1f232a;
    border-radius: 4px;
}
QTabBar::tab {
    background-color: #252a33;
    color: #a0aec0;
    padding: 8px 16px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}
QTabBar::tab:selected {
    background-color: #1f232a;
    color: #00b4d8;
    font-weight: bold;
    border-bottom: 2px solid #00b4d8;
}
QPushButton {
    background-color: #007acc;
    color: white;
    border: none;
    border-radius: 4px;
    padding: 7px 15px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #0098ff;
}
QPushButton:pressed {
    background-color: #005999;
}
QPushButton#btn_danger {
    background-color: #e63946;
}
QPushButton#btn_danger:hover {
    background-color: #ff4d5e;
}
QPushButton#btn_success {
    background-color: #2a9d8f;
}
QPushButton#btn_success:hover {
    background-color: #38b2a3;
}
QLineEdit, QTextEdit, QComboBox {
    background-color: #14171c;
    border: 1px solid #333942;
    border-radius: 4px;
    color: #ffffff;
    padding: 6px;
}
QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
    border: 1px solid #00b4d8;
}
QTableWidget {
    background-color: #191b1f;
    border: 1px solid #333942;
    gridline-color: #2d333b;
    border-radius: 4px;
}
QHeaderView::section {
    background-color: #252a33;
    color: #e0e6ed;
    padding: 6px;
    border: 1px solid #333942;
    font-weight: bold;
}
QGroupBox {
    border: 1px solid #333942;
    border-radius: 6px;
    margin-top: 10px;
    font-weight: bold;
    color: #00b4d8;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
}
"""

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DBSecGuard — Комплексная система защиты баз данных PostgreSQL")
        self.resize(1150, 750)
        self.setStyleSheet(DARK_STYLE)

        # Инициализация подсистем
        self.crypto = CryptoEngine()
        self.sqli = SQLiDetector()
        self.audit = AuditLogger(self.crypto)
        self.rbac = RBACManager()
        self.db = DBConnector(crypto=self.crypto)

        # Текущая активная сессия
        self.current_user = self.rbac.create_session("admin_root", "admin", "192.168.1.100")

        self.init_ui()
        self.preload_demo_logs()
        self.update_dashboard_metrics()