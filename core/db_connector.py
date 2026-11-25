"""
Модуль подключения к базе данных (Database Connector)
Обеспечивает работу с PostgreSQL, а также автономный режим на встроенной SQLite
для демонстрации работы комплекса в любой среде (например, без запущенного локального сервера СУБД)
"""
import sqlite3
import os
from typing import List, Tuple, Optional
from core.config import DatabaseConfig
from core.crypto_engine import CryptoEngine

class DBConnector:
    def __init__(self, config: Optional[DatabaseConfig] = None, crypto: Optional[CryptoEngine] = None):
        self.config = config or DatabaseConfig()
        self.crypto = crypto or CryptoEngine()
        self.is_connected = False
        self.mode = "SQLite (Автономный демонстрационный режим)"
        self.conn = None
        self._init_database()

    def _init_database(self):
        """Пытается подключиться к PostgreSQL; при недоступности инициализирует локальную БД SQLite"""
        # Проверяем PostgreSQL
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
            pass

        # Инициализация SQLite
        db_path = self.config.sqlite_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.mode = "SQLite (Локальный демонстрационный контур)"
        self.is_connected = True
        self._seed_sample_data()

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
        if cursor.fetchone()[0] > 0:
            return

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

        # Сброс последовательностей, чтобы новые INSERT не падали
        cursor.execute("SELECT setval('employees_id_seq', (SELECT COALESCE(MAX(id), 1) FROM employees))")
        cursor.execute("SELECT setval('students_id_seq',  (SELECT COALESCE(MAX(id), 1) FROM students))")

        self.conn.commit()

    def _seed_sample_data(self):
        """Создает демонстрационные таблицы и наполняет их тестовыми данными с шифрованием (SQLIte)"""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS departments (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                code TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS employees (
                id INTEGER PRIMARY KEY,
                full_name TEXT NOT NULL,
                passport_encrypted TEXT NOT NULL,
                phone TEXT NOT NULL,
                email TEXT NOT NULL,
                salary_encrypted TEXT NOT NULL,
                department_id INTEGER
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY,
                full_name TEXT NOT NULL,
                group_name TEXT NOT NULL,
                passport_encrypted TEXT NOT NULL,
                phone TEXT NOT NULL,
                email TEXT NOT NULL,
                scholarship_encrypted TEXT NOT NULL
            )
        """)

        # Проверим, есть ли уже данные
        cursor.execute("SELECT COUNT(*) FROM employees")
        if cursor.fetchone()[0] == 0:
            # Заполняем департаменты
            cursor.executemany("INSERT INTO departments VALUES (?, ?, ?)", [
                (1, "Управление информационной безопасности", "CISO"),
                (2, "Кафедра кибербезопасности", "KIB"),
                (3, "Бухгалтерия и отдел кадров", "HR_FIN")
            ])
            # Заполняем сотрудников (шифруем чувствительные поля)
            emp_data = [
                (1, "Иванов Алексей Сергеевич", self.crypto.encrypt_field("4510 123456"), "+7 (916) 111-22-33", "a.ivanov@university.ru", self.crypto.encrypt_field("145000"), 1),
                (2, "Петрова Елена Михайловна", self.crypto.encrypt_field("4512 789012"), "+7 (926) 444-55-66", "e.petrova@university.ru", self.crypto.encrypt_field("95000"), 2),
                (3, "Сидоров Дмитрий Павлович", self.crypto.encrypt_field("4515 345678"), "+7 (903) 777-88-99", "d.sidorov@university.ru", self.crypto.encrypt_field("120000"), 3),
            ]
            cursor.executemany("INSERT INTO employees VALUES (?, ?, ?, ?, ?, ?, ?)", emp_data)

            # Заполняем студентов
            stud_data = [
                (1, "Смирнов Максим Игоревич", "БИБ-21", self.crypto.encrypt_field("4618 901234"), "+7 (999) 123-45-67", "m.smirnov@stud.ru", self.crypto.encrypt_field("12500")),
                (2, "Ковалева Анна Викторовна", "БИБ-21", self.crypto.encrypt_field("4619 567890"), "+7 (999) 765-43-21", "a.kovaleva@stud.ru", self.crypto.encrypt_field("18000")),
                (3, "Васильев Артем Олегович", "БИБ-22", self.crypto.encrypt_field("4620 112233"), "+7 (985) 333-22-11", "a.vasiliev@stud.ru", self.crypto.encrypt_field("15000")),
            ]
            cursor.executemany("INSERT INTO students VALUES (?, ?, ?, ?, ?, ?, ?)", stud_data)

            self.conn.commit()

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
