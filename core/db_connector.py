"""
Модуль подключения к базе данных (Database Connector)
Обеспечивает работу с PostgreSQL
для демонстрации работы комплекса в любой среде (например, без запущенного локального сервера СУБД)
"""
import os
from typing import List, Tuple, Optional
from core.config import DatabaseConfig
from core.crypto_engine import CryptoEngine

class DBConnector:
    def __init__(self, config: Optional[DatabaseConfig] = None, crypto: Optional[CryptoEngine] = None):
        self.config = config or DatabaseConfig()
        self.crypto = crypto or CryptoEngine()
        self.is_connected = False
        self.mode = "PostgreSQL"
        self.conn = None
        #self.init_database()

    def init_database(self):
        """Пытается подключиться к PostgreSQL"""
        try:
            import psycopg2
            pg_conn = psycopg2.connect(
                host=self.config.host,
                port=self.config.port,
                dbname=self.config.dbname,
                user=self.config.user,
                password=self.config.password,
                connect_timeout=2
            )
            self.conn = pg_conn
            self.mode = f"PostgreSQL ({self.config.host}:{self.config.port}/{self.config.dbname})"
            self.is_connected = True

            # Инициализация таблиц
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            script_path = os.path.join(base_dir, "sql", "init_postgres.sql")
            self._execute_sql_script(script_path)

            self._seed_sample_data_postgres()
            return
        except Exception:
            self.conn = None
            self.mode = "PostgreSQL (нет подключения)"
            self.is_connected = False

    def _execute_sql_script(self, script_path: str):
        if not os.path.exists(script_path):
            return
        with open(script_path, "r", encoding="utf-8") as f:
            sql = f.read()
        try:
            cursor = self.conn.cursor()
            cursor.execute(sql)
            self.conn.commit()
        except Exception:
            self.conn.rollback()

    def _seed_sample_data_postgres(self):
        """Заполняет таблицы тестовыми данными с шифрованием (PostgreSQL)"""

        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM employees")
        if cursor.fetchone()[0] == 0:
            emp_data = [
                (1, "Иванов Алексей Сергеевич", self.crypto.encrypt_field("4510 123456"),
                 "+7 (916) 111-22-33", "a.ivanov@university.ru",
                 self.crypto.encrypt_field("145000"), 1),
                (2, "Петрова Елена Михайловна", self.crypto.encrypt_field("4512 789012"),
                 "+7 (926) 444-55-66", "e.petrova@university.ru",
                 self.crypto.encrypt_field("95000"), 2),
                (3, "Сидоров Дмитрий Павлович", self.crypto.encrypt_field("4515 345678"),
                 "+7 (903) 777-88-99", "d.sidorov@university.ru",
                 self.crypto.encrypt_field("120000"), 3),
            ]
            cursor.executemany(
                "INSERT INTO employees (id, full_name, passport_encrypted, phone, email, salary_encrypted, department_id) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                emp_data
            )

        cursor.execute("SELECT COUNT(*) FROM students")
        if cursor.fetchone()[0] == 0:
            stud_data = [
                (1, "Смирнов Максим Игоревич", "БИБ-21", self.crypto.encrypt_field("4618 901234"),
                 "+7 (999) 123-45-67", "m.smirnov@stud.ru", self.crypto.encrypt_field("12500"), 2),
                (2, "Ковалева Анна Викторовна", "БИБ-21", self.crypto.encrypt_field("4619 567890"),
                 "+7 (999) 765-43-21", "a.kovaleva@stud.ru", self.crypto.encrypt_field("18000"), 2),
                (3, "Васильев Артем Олегович", "БИБ-22", self.crypto.encrypt_field("4620 112233"),
                 "+7 (985) 333-22-11", "a.vasiliev@stud.ru", self.crypto.encrypt_field("15000"), 2),
            ]
            cursor.executemany(
                "INSERT INTO students (id, full_name, group_name, passport_encrypted, phone, email, scholarship_encrypted, department_id) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                stud_data
            )

        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            import hashlib
            users = [
                ("admin_root", "AdminPass2026!", 1, 1),
                ("sec_officer", "SecOfficer2026!", 2, 1),
                ("operator_dept", "Operator2026!", 3, 2),
                ("guest_user", "Guest2026!", 4, 1),
                ("sa", "1234", 1, 1),
            ]
            user_rows = []
            for username, pwd, role_id, dept_id in users:
                h = hashlib.sha256(pwd.encode("utf-8")).hexdigest()
                user_rows.append((username, h, role_id, dept_id))

            cursor.executemany(
                "INSERT INTO users (username, password_hash, role_id, department_id) "
                "VALUES (%s, %s, %s, %s) ON CONFLICT (username) DO NOTHING",
                user_rows
            )

        # Сброс последовательностей, чтобы новые INSERT не падали
        cursor.execute("SELECT setval('students_id_seq',  (SELECT COALESCE(MAX(id), 1) FROM students))")
        cursor.execute("SELECT setval('employees_id_seq', (SELECT COALESCE(MAX(id), 1) FROM employees))")

        self.conn.commit()

    def authenticate_user(self, username: str, password: str):
        """Проверяет логин/пароль по таблице users. Возвращает dict или None"""
        if not self.conn:
            return None
        try:
            import hashlib
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT u.username, u.password_hash, r.code, u.department_id "
                "FROM users u "
                "JOIN roles r ON u.role_id = r.id "
                "WHERE u.username = %s AND u.is_active = TRUE",
                (username,)
            )
            row = cursor.fetchone()
            if not row:
                return None

            stored_hash = row[1]
            if hashlib.sha256(password.encode("utf-8")).hexdigest() != stored_hash:
                return None

            return {
                "username": row[0],
                "role": row[2],
                "department_id": row[3],
            }
        except Exception:
            return None

    def execute_raw_query(self, query: str) -> Tuple[List[str], List[Tuple]]:
        """Выполняет прямой запрос к СУБД и возвращает (колонки, строки)"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(query)
            if cursor.description:
                columns = [desc[0] for desc in cursor.description]
                rows = cursor.fetchall()
                return columns, rows
            self.conn.commit()
            return ["Результат"], [("Операция успешно завершена",)]
        except Exception:
            self.conn.rollback()
            raise

    def close(self):
        if self.conn:
            self.conn.close()
