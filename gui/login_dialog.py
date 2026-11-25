"""
Диалоговое окно аутентификации пользователя
"""
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox
)
from PySide6.QtCore import Qt
import hashlib

DEMO_USERS = {
    "sa":    (hashlib.sha256(b"1234").hexdigest(),    "admin", 1),
    "sec_officer":   (hashlib.sha256(b"SecOfficer2026!").hexdigest(),   "security_officer", 1),
    "operator_dept": (hashlib.sha256(b"Operator2026!").hexdigest(),     "department_operator", 2),
    "guest_user":    (hashlib.sha256(b"Guest2026!").hexdigest(),        "guest", 1),
}

class LoginDialog(QDialog):
    """Диалог входа: логин, пароль, IP-адрес клиента"""

    def __init__(self, rbac_manager, parent=None):
        super().__init__(parent)
        self.rbac = rbac_manager
        self.session = None

        self.setWindowTitle("DBSecGuard — Вход в систему")
        self.setFixedSize(420, 320)
        self.setStyleSheet("""
            QDialog { background-color: #191b1f; }
            QLabel { color: #e0e6ed; font-size: 13px; }
            QLineEdit {
                background-color: #14171c; border: 1px solid #333942;
                border-radius: 4px; color: #ffffff; padding: 6px;
            }
            QLineEdit:focus { border: 1px solid #00b4d8; }
            QPushButton {
                background-color: #007acc; color: white; border: none;
                border-radius: 4px; padding: 8px 15px; font-weight: bold;
            }
            QPushButton:hover { background-color: #0098ff; }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        title = QLabel("🛡️ DBSecGuard")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #00b4d8;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("Аутентификация пользователя")
        subtitle.setStyleSheet("color: #a0aec0; font-size: 12px;")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)

        layout.addWidget(QLabel("Имя пользователя:"))
        self.txt_username = QLineEdit()
        self.txt_username.setPlaceholderText("user")
        layout.addWidget(self.txt_username)

        layout.addWidget(QLabel("Пароль:"))
        self.txt_password = QLineEdit()
        self.txt_password.setEchoMode(QLineEdit.Password)
        self.txt_password.setPlaceholderText("введите пароль")
        self.txt_password.returnPressed.connect(self.try_login)
        layout.addWidget(self.txt_password)

        layout.addWidget(QLabel("IP-адрес клиента:"))
        self.txt_ip = QLineEdit("192.168.1.100")
        layout.addWidget(self.txt_ip)

        btn_layout = QHBoxLayout()
        self.btn_login = QPushButton("Войти")
        self.btn_login.clicked.connect(self.try_login)
        btn_layout.addWidget(self.btn_login)

        self.btn_cancel = QPushButton("Отмена")
        self.btn_cancel.setStyleSheet("background-color: #444;")
        self.btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(self.btn_cancel)

        layout.addLayout(btn_layout)

    def try_login(self):
        username = self.txt_username.text().strip()
        password = self.txt_password.text()
        ip = self.txt_ip.text().strip() or "127.0.0.1"

        if not username or not password:
            QMessageBox.warning(self, "Ошибка", "Введите имя пользователя и пароль.")
            return

        user_entry = DEMO_USERS.get(username)
        if not user_entry:
            QMessageBox.critical(self, "Отказ", "Пользователь не найден.")
            return

        stored_hash, role_str, dept_id = user_entry
        if hashlib.sha256(password.encode("utf-8")).hexdigest() != stored_hash:
            QMessageBox.critical(self, "Отказ", "Неверный пароль.")
            return

        self.session = self.rbac.create_session(username, role_str, ip, dept_id)
        self.accept()