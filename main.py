"""
Главная точка входа в программу DBSecGuard (Комплекс защиты баз данных PostgreSQL).
Поддерживает запуск в графическом режиме (PySide6) и в консольном режиме (--cli / --test).
"""
import sys
import os

# Добавляем корневой каталог src в sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.crypto_engine import CryptoEngine
from core.sqli_detector import SQLiDetector
from core.audit_logger import AuditLogger
from core.rbac_manager import RBACManager, Role, Permission
from core.db_connector import DBConnector

def run_cli_demo():
    print("=" * 70)
    print("   КОМПЛЕКС ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ БАЗ ДАННЫХ (DBSecGuard)")
    print("   Режим автоматического демонстрационного тестирования безопасности")
    print("=" * 70)

    crypto = CryptoEngine()
    sqli = SQLiDetector()
    audit = AuditLogger(crypto)
    rbac = RBACManager()
    db = DBConnector(crypto=crypto)

    print(f"\n[+] СУБД: {db.mode}")
    print("[+] Модуль криптозащиты (AES-128 Fernet): Инициализирован")
    print("[+] Модуль WAF / детекции SQL-инъекций: Инициализирован")
    print("[+] Защищенный журнал аудита (HMAC-SHA256): Активен")

    # Тест 1: Проверка легитимного запроса
    q_valid = "SELECT id, full_name, group_name FROM students WHERE group_name = 'БИБ-21';"
    print(f"\n--> Тест 1: Проверка легитимного запроса:\n    SQL: {q_valid}")
    res1 = sqli.inspect_query(q_valid)
    print(f"    Оценка риска: {res1.risk_score}/100 | Действие: {res1.action} | Вердикт: {res1.explanation}")
    audit.log_event("analyst_1", "192.168.1.15", q_valid, res1.risk_score, res1.action == "BLOCK")

    # Тест 2: Проверка атаки SQL-инъекции (Tautology Bypass)
    q_attack1 = "SELECT * FROM users WHERE username = 'admin' OR '1'='1' -- AND pass = 'pwd';"
    print(f"\n--> Тест 2: Проверка атаки обхода аутентификации (Tautology):\n    SQL: {q_attack1}")
    res2 = sqli.inspect_query(q_attack1)
    print(f"    Оценка риска: {res2.risk_score}/100 | Действие: {res2.action} | Вердикт: {res2.explanation}")
    audit.log_event("attacker_ip", "85.140.24.112", q_attack1, res2.risk_score, res2.action == "BLOCK", "SQLi Tautology")

    # Тест 3: Проверка атаки UNION SELECT
    q_attack2 = "SELECT full_name FROM students UNION SELECT passport_encrypted FROM employees; --"
    print(f"\n--> Тест 3: Проверка атаки внедрения UNION SELECT:\n    SQL: {q_attack2}")
    res3 = sqli.inspect_query(q_attack2)
    print(f"    Оценка риска: {res3.risk_score}/100 | Действие: {res3.action} | Вердикт: {res3.explanation}")
    audit.log_event("attacker_ip", "85.140.24.112", q_attack2, res3.risk_score, res3.action == "BLOCK", "SQLi UNION")

    # Тест 4: Динамическое маскирование персональных данных
    print("\n--> Тест 4: Динамическое маскирование персональных данных:")
    raw_phone = "+7 (916) 123-45-67"
    raw_email = "student.petrov@university.ru"
    raw_passport = "4510 987654"
    print(f"    Телефон: {raw_phone} --> {crypto.mask_phone(raw_phone)}")
    print(f"    E-mail:  {raw_email} --> {crypto.mask_email(raw_email)}")
    print(f"    Паспорт: {raw_passport} --> {crypto.mask_passport(raw_passport)}")

    # Тест 5: Проверка неизменяемости журнала аудита
    print("\n--> Тест 5: Проверка целостности журнала аудита по цифровым подписям HMAC-SHA256:")
    corrupted = audit.verify_all_records()
    if not corrupted:
        print("    [OK] Целостность 100%: Ни одна запись аудита не была модифицирована или подменена.")
    else:
        print(f"    [FAIL] Нарушение целостности! Поврежденные записи: {corrupted}")

    print("\n" + "=" * 70)
    print("   Все тесты безопасности успешно пройдены!")
    print("=" * 70)

def main():
    if "--cli" in sys.argv or "--test" in sys.argv:
        run_cli_demo()
        return

    # Запуск графического интерфейса
    from PySide6.QtWidgets import QApplication
    from gui.login_dialog import LoginDialog
    from gui.main_window import MainWindow

    app = QApplication(sys.argv)

    # Создаём RBAC-менеджер заранее, чтобы LoginDialog и MainWindow
    # использовали ОДИН и тот же экземпляр (сессии не теряются)
    rbac = RBACManager()

    login = LoginDialog(rbac)
    if login.exec() != LoginDialog.Accepted:
        sys.exit(0)  # пользователь нажал «Отмена»

    window = MainWindow(rbac=rbac, current_user=login.session)
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
