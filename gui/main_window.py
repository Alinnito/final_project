"""
Главное окно графического интерфейса пользователя
"""
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QLabel, QPushButton, QTextEdit, QLineEdit, QComboBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QMessageBox, QGroupBox, QSplitter
)
from PySide6.QtCore import Qt

from core.crypto_engine import CryptoEngine
from core.sqli_detector import SQLiDetector
from core.audit_logger import AuditLogger
from core.rbac_manager import RBACManager
from core.db_connector import DBConnector
from gui.widgets import MetricCard

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

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)

        # Верхняя панель статуса
        top_bar = QHBoxLayout()
        lbl_brand = QLabel("🛡️ DBSecGuard Enterprise")
        lbl_brand.setStyleSheet("font-size: 16px; font-weight: bold; color: #00b4d8;")
        top_bar.addWidget(lbl_brand)

        top_bar.addStretch()

        self.lbl_status = QLabel(f"СУБД: {self.db.mode}")
        self.lbl_status.setStyleSheet("color: #a0aec0; font-size: 12px; background: #252a33; padding: 4px 10px; border-radius: 4px;")
        top_bar.addWidget(self.lbl_status)

        lbl_user = QLabel("Оператор:")
        top_bar.addWidget(lbl_user)

        self.combo_user_role = QComboBox()
        self.combo_user_role.addItems(["Admin (Полный доступ)", "Security_Officer (Офицер ИБ)", "Department_Operator (Оператор)", "Guest (Гость)"])
        self.combo_user_role.currentIndexChanged.connect(self.on_role_changed)
        top_bar.addWidget(self.combo_user_role)

        main_layout.addLayout(top_bar)

        # Вкладки
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self.tab_dash = QWidget()
        self.tab_inspector = QWidget()
        self.tab_audit = QWidget()
        self.tab_masking = QWidget()
        self.tab_rbac = QWidget()

        self.tabs.addTab(self.tab_dash, "📊 Дашборд безопасности")
        self.tabs.addTab(self.tab_inspector, "🔍 Инспектор запросов и WAF")
        self.tabs.addTab(self.tab_audit, "📋 Журнал аудита и инциденты")
        self.tabs.addTab(self.tab_masking, "🔒 Маскирование и шифрование")
        self.tabs.addTab(self.tab_rbac, "👥 Политики доступа RBAC")

        self.setup_dash_tab()

    def setup_dash_tab(self):
        layout = QVBoxLayout(self.tab_dash)
        layout.setSpacing(12)

        # Карточки метрик
        cards_layout = QHBoxLayout()
        self.card_total = MetricCard("Всего запросов", "0", "обработано шлюзом", "#00b4d8")
        self.card_threats = MetricCard("Отражено атак", "0", "SQLi и инъекции", "#e63946")
        self.card_incidents = MetricCard("Инцидентов ИБ", "0", "высокой важности", "#f4a261")
        self.card_integrity = MetricCard("Целостность логов", "100%", "HMAC-SHA256 подпись", "#2a9d8f")

        cards_layout.addWidget(self.card_total)
        cards_layout.addWidget(self.card_threats)
        cards_layout.addWidget(self.card_incidents)
        cards_layout.addWidget(self.card_integrity)
        layout.addLayout(cards_layout)

        # Блок описания состояния безопасности
        gb_state = QGroupBox("Текущий статус подсистемы информационной безопасности")
        gb_layout = QVBoxLayout(gb_state)
        lbl_info = QLabel(
            "• Механизм фильтрации запросов (DB Firewall): АКТИВЕН (сигнатурный и эвристический анализ)\n"
            "• Динамическое маскирование персональных данных (DDM): ВКЛЮЧЕНО для номеров телефонов, email, паспортов\n"
            "• Криптографическая защита конфиденциальных полей: AES-128 Fernet с ключом из защищенного хранилища\n"
            "• Неизменяемый аудит транзакций: АКТИВЕН с расчетом цифровой контрольной суммы HMAC для каждой записи\n"
            "• Политики разграничения доступа: Ролевая модель RBAC с контролем доступа к строкам и атрибутам"
        )
        lbl_info.setStyleSheet("color: #cbd5e1; line-height: 150%; font-size: 13px;")
        gb_layout.addWidget(lbl_info)
        layout.addWidget(gb_state)

        # Быстрые действия
        act_box = QGroupBox("Быстрые операции управления безопасностью")
        act_layout = QHBoxLayout(act_box)
        btn_verify = QPushButton("🛡️ Полная проверка целостности аудита (HMAC)")
        btn_verify.clicked.connect(self.verify_audit_integrity)
        act_layout.addWidget(btn_verify)

        layout.addWidget(act_box)
        layout.addStretch()

    # --- Обработчики событий ---

    def on_role_changed(self, idx):
        roles_map = {
            0: ("admin_root", "admin"),
            1: ("sec_officer", "security_officer"),
            2: ("operator_dept", "department_operator"),
            3: ("guest_user", "guest")
        }
        username, role_str = roles_map.get(idx, ("guest_user", "guest"))
        self.current_user = self.rbac.create_session(username, role_str, "192.168.1.100")
        QMessageBox.information(self, "Смена сессии", f"Активная роль переключена на: {role_str.upper()}.\nПолномочия обновлены.")

    def verify_audit_integrity(self):
        corrupted = self.audit.verify_all_records()
        if not corrupted:
            QMessageBox.information(
                self, "Проверка целостности",
                "УСПЕШНО!\nВсе записи журнала аудита проверены с использованием имитовставки HMAC-SHA256.\nПризнаков модификации, подмены или удаления не обнаружено."
            )
        else:
            QMessageBox.critical(
                self, "НАРУШЕНИЕ ЦЕЛОСТНОСТИ!",
                f"Обнаружена подделка или модификация записей журнала аудита! Поврежденные ID: {corrupted}"
            )
