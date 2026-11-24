"""
Главное окно графического интерфейса пользователя
"""
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QLabel, QPushButton, QTextEdit, QLineEdit, QComboBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QMessageBox, QGroupBox, QSplitter
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

from core.crypto_engine import CryptoEngine
from core.sqli_detector import SQLiDetector
from core.audit_logger import AuditLogger
from core.rbac_manager import RBACManager
from core.db_connector import DBConnector
from gui.widgets import MetricCard, RiskIndicator

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
        lbl_brand = QLabel("🛡️ DBSecGuard")
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
        self.setup_inspector_tab()
        self.setup_audit_tab()
        self.setup_masking_tab()
        self.setup_rbac_tab()

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

    def setup_inspector_tab(self):
        layout = QVBoxLayout(self.tab_inspector)

        splitter = QSplitter(Qt.Vertical)

        # Верхняя панель: ввод запроса и выбор пресета
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)

        preset_layout = QHBoxLayout()
        preset_layout.addWidget(QLabel("Выбрать тестовый шаблон запроса:"))
        self.combo_presets = QComboBox()
        self.combo_presets.addItem("--- Пользовательский ввод ---", "")
        self.combo_presets.addItem("Легитимный: Выборка студентов кафедры", "SELECT id, full_name, group_name FROM students WHERE group_name = 'БИБ-21';")
        self.combo_presets.addItem("Легитимный: Запрос данных сотрудника", "SELECT id, full_name, phone, email FROM employees WHERE id = 1;")
        self.combo_presets.addItem("Атака SQLi 1: Логическое тождество (Tautology Bypass)", "SELECT * FROM users WHERE username = 'admin' OR '1'='1' -- AND pass = 'pwd';")
        self.combo_presets.addItem("Атака SQLi 2: Внедрение UNION SELECT для кражи данных", "SELECT full_name FROM students UNION SELECT passport_encrypted FROM employees; --")
        self.combo_presets.addItem("Атака SQLi 3: Составной запрос (Stacked Query / DROP)", "SELECT id FROM employees; DROP TABLE students; --")
        self.combo_presets.addItem("Атака SQLi 4: Слепая инъекция по времени (Time-Based)", "SELECT * FROM employees WHERE id = 1 AND pg_sleep(5);")
        self.combo_presets.addItem("Атака SQLi 5: Попытка чтения системного каталога", "SELECT table_name FROM information_schema.tables WHERE table_schema='public';")
        self.combo_presets.currentIndexChanged.connect(self.on_preset_selected)
        preset_layout.addWidget(self.combo_presets)
        top_layout.addLayout(preset_layout)

        top_layout.addWidget(QLabel("SQL-запрос к СУБД:"))
        self.txt_query = QTextEdit()
        self.txt_query.setPlaceholderText("Введите SQL-запрос для проверки и выполнения...")
        self.txt_query.setMinimumHeight(80)
        top_layout.addWidget(self.txt_query)

        # Индикатор риска
        top_layout.addWidget(QLabel("Оценка угрозы безопасности:"))
        self.risk_indicator = RiskIndicator()
        top_layout.addWidget(self.risk_indicator)

        self.lbl_verdict = QLabel("Готов к проверке запроса")
        self.lbl_verdict.setStyleSheet("color: #a0aec0; font-style: italic;")
        top_layout.addWidget(self.lbl_verdict)

        btn_row = QHBoxLayout()
        self.btn_inspect = QPushButton("🔍 Анализировать угрозу (WAF / SQLi Inspector)")
        self.btn_inspect.clicked.connect(self.inspect_current_query)
        btn_row.addWidget(self.btn_inspect)

        self.btn_execute = QPushButton("⚡ Пропустить через защитный шлюз и выполнить")
        self.btn_execute.setObjectName("btn_success")
        self.btn_execute.clicked.connect(self.execute_secure_query)
        btn_row.addWidget(self.btn_execute)

        top_layout.addLayout(btn_row)
        splitter.addWidget(top_widget)

        # Нижняя панель: результат выполнения
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.addWidget(QLabel("Результат выполнения запроса (с применением маскирования):"))
        self.table_results = QTableWidget()
        bottom_layout.addWidget(self.table_results)
        splitter.addWidget(bottom_widget)

        layout.addWidget(splitter)

    def setup_audit_tab(self):
        layout = QVBoxLayout(self.tab_audit)

        filter_bar = QHBoxLayout()
        filter_bar.addWidget(QLabel("Фильтр:"))
        self.btn_filter_all = QPushButton("Все события")
        self.btn_filter_all.clicked.connect(lambda: self.load_audit_table(only_incidents=False))
        filter_bar.addWidget(self.btn_filter_all)

        self.btn_filter_inc = QPushButton("Только инциденты ИБ")
        self.btn_filter_inc.setObjectName("btn_danger")
        self.btn_filter_inc.clicked.connect(lambda: self.load_audit_table(only_incidents=True))
        filter_bar.addWidget(self.btn_filter_inc)

        filter_bar.addStretch()
        btn_verify = QPushButton("Проверить целостность (HMAC)")
        btn_verify.clicked.connect(self.verify_audit_integrity)
        filter_bar.addWidget(btn_verify)

        layout.addLayout(filter_bar)

        self.table_audit = QTableWidget()
        self.table_audit.setColumnCount(8)
        self.table_audit.setHorizontalHeaderLabels([
            "ID", "Время", "Пользователь", "IP-адрес", "Операция", "Уровень риска", "Статус", "Запрос"
        ])
        self.table_audit.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table_audit.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch)
        layout.addWidget(self.table_audit)

    def setup_masking_tab(self):
        layout = QVBoxLayout(self.tab_masking)

        gb_demo = QGroupBox("Интерактивный стенд проверки динамического маскирования (DDM)")
        demo_layout = QVBoxLayout(gb_demo)

        h1 = QHBoxLayout()
        h1.addWidget(QLabel("Номер телефона:"))
        self.input_phone = QLineEdit("+7 (916) 123-45-67")
        h1.addWidget(self.input_phone)
        self.lbl_masked_phone = QLabel("Результат маскирования:")
        h1.addWidget(self.lbl_masked_phone)
        demo_layout.addLayout(h1)

        h2 = QHBoxLayout()
        h2.addWidget(QLabel("Электронная почта:"))
        self.input_email = QLineEdit("student.ivanov@university.ru")
        h2.addWidget(self.input_email)
        self.lbl_masked_email = QLabel("Результат маскирования:")
        h2.addWidget(self.lbl_masked_email)
        demo_layout.addLayout(h2)

        h3 = QHBoxLayout()
        h3.addWidget(QLabel("Паспорт РФ:"))
        self.input_passport = QLineEdit("4510 987654")
        h3.addWidget(self.input_passport)
        self.lbl_masked_passport = QLabel("Результат маскирования:")
        h3.addWidget(self.lbl_masked_passport)
        demo_layout.addLayout(h3)

        btn_mask_test = QPushButton("Применить алгоритмы маскирования")
        btn_mask_test.clicked.connect(self.test_masking_fields)
        demo_layout.addWidget(btn_mask_test)

        layout.addWidget(gb_demo)

        # Таблица защищенных данных из базы
        gb_db_data = QGroupBox("Таблица сотрудников (данные с динамическим маскированием)")
        db_layout = QVBoxLayout(gb_db_data)
        self.table_employees = QTableWidget()
        db_layout.addWidget(self.table_employees)
        btn_refresh_emp = QPushButton("Загрузить данные из базы")
        btn_refresh_emp.clicked.connect(self.load_employees_table)
        db_layout.addWidget(btn_refresh_emp)
        layout.addWidget(gb_db_data)

    def setup_rbac_tab(self):
        layout = QVBoxLayout(self.tab_rbac)

        gb_roles = QGroupBox("Матрица разграничения доступа (RBAC Matrix)")
        roles_layout = QVBoxLayout(gb_roles)

        tbl = QTableWidget()
        tbl.setColumnCount(6)
        tbl.setHorizontalHeaderLabels([
            "Роль", "Чтение публичных", "Чтение чувствительных (ПДн)", "Запись данных", "Конфигурация ИБ", "Просмотр аудита"
        ])
        tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        matrix = [
            ("Admin (DBA)", "✅ Да", "✅ Да (полный)", "✅ Да", "✅ Да", "✅ Да"),
            ("Security Officer (Офицер ИБ)", "✅ Да", "❌ Нет (маскировано)", "❌ Нет", "✅ Да", "✅ Да"),
            ("Department Operator (Оператор)", "✅ Да", "❌ Нет (маскировано)", "✅ Да", "❌ Нет", "❌ Нет"),
            ("Analyst (Аналитик)", "✅ Да", "❌ Нет (маскировано)", "❌ Нет", "❌ Нет", "✅ Да"),
            ("Guest (Гость)", "✅ Да (ограничено)", "❌ Нет", "❌ Нет", "❌ Нет", "❌ Нет")
        ]
        tbl.setRowCount(len(matrix))
        for row_idx, row_data in enumerate(matrix):
            for col_idx, val in enumerate(row_data):
                item = QTableWidgetItem(val)
                item.setTextAlignment(Qt.AlignCenter)
                tbl.setItem(row_idx, col_idx, item)

        roles_layout.addWidget(tbl)
        layout.addWidget(gb_roles)

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

    def test_masking_fields(self):
        phone = self.input_phone.text()
        email = self.input_email.text()
        passport = self.input_passport.text()

        self.lbl_masked_phone.setText(f"Результат: {self.crypto.mask_phone(phone)}")
        self.lbl_masked_email.setText(f"Результат: {self.crypto.mask_email(email)}")
        self.lbl_masked_passport.setText(f"Результат: {self.crypto.mask_passport(passport)}")

    def load_employees_table(self):
        cols, rows = self.db.execute_raw_query("SELECT id, full_name, phone, email, salary_encrypted FROM employees")
        self.table_employees.setColumnCount(len(cols))
        self.table_employees.setRowCount(len(rows))
        self.table_employees.setHorizontalHeaderLabels(cols)

    def on_preset_selected(self, idx):
        query = self.combo_presets.currentData()
        if query:
            self.txt_query.setPlainText(query)
            self.inspect_current_query()

    def inspect_current_query(self):
        query = self.txt_query.toPlainText().strip()
        result = self.sqli.inspect_query(query)
        self.risk_indicator.set_risk(result.risk_score)
        self.lbl_verdict.setText(f"Вердикт: {result.explanation}")
        return result

    def execute_secure_query(self):
        query = self.txt_query.toPlainText().strip()
        if not query:
            QMessageBox.warning(self, "Предупреждение", "Введите текст SQL-запроса!")
            return

    def load_audit_table(self, only_incidents=False):
        records = self.audit.get_incidents() if only_incidents else self.audit.records
        self.table_audit.setRowCount(len(records))

        for idx, r in enumerate(reversed(records)):
            self.table_audit.setItem(idx, 0, QTableWidgetItem(str(r.record_id)))
            self.table_audit.setItem(idx, 1, QTableWidgetItem(r.timestamp))
            self.table_audit.setItem(idx, 2, QTableWidgetItem(r.username))
            self.table_audit.setItem(idx, 3, QTableWidgetItem(r.client_ip))
            self.table_audit.setItem(idx, 4, QTableWidgetItem(r.operation))

            item_risk = QTableWidgetItem(f"{r.risk_score}/100")
            if r.risk_score >= 70:
                item_risk.setBackground(QColor("#781c24"))
                item_risk.setForeground(QColor("#ffffff"))
            elif r.risk_score >= 40:
                item_risk.setBackground(QColor("#664d03"))
                item_risk.setForeground(QColor("#ffffff"))
            else:
                item_risk.setBackground(QColor("#0f5132"))
                item_risk.setForeground(QColor("#ffffff"))
            self.table_audit.setItem(idx, 5, item_risk)

            status_str = "🛑 ЗАБЛОКИРОВАН" if r.is_blocked else "✅ Разрешен"
            self.table_audit.setItem(idx, 6, QTableWidgetItem(status_str))
            self.table_audit.setItem(idx, 7, QTableWidgetItem(r.query_text))