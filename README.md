# DBSecGuard — Комплексная система защиты баз данных

## Возможности

* WAF на уровне приложения — сигнатурный и эвристический анализ SQL-запросов с расчётом Risk Score (0–100) и блокировкой при риске ≥ 70.
* RBAC — ролевая модель доступа, аутентификация по логину/паролю, контроль доступа к атрибутам через маскирование.
* Динамическое маскирование (DDM) — телефоны, email, паспорта, банковские карты, оклады/стипендии для ролей без READ_SENSITIVE.
* Шифрование полей — Fernet (AES-128-CBC + HMAC-SHA256) для конфиденциальных колонок.
* Tamper-Evident аудит — HMAC-SHA256 для каждой записи, сохранение в БД, проверка целостности в один клик.
* GUI на PySide6 — дашборд, инспектор запросов, журнал аудита, стенд маскирования, матрица RBAC.
* Fallback на SQLite — автономный демонстрационный режим при недоступности PostgreSQL.

## Подсистемы

| Подсистема | Модуль | Назначение |
|---|---|---|
|SQL Inspector / WAF Engine|core/sqli_detector.py|Сигнатурный и эвристический анализ SQL|
|RBAC Manager|core/rbac_manager.py|Роли, разрешения, сессии|
|Crypto & DDM Module| core/crypto_engine.py|Шифрование Fernet, маскирование|
|Tamper-Evident Audit Logger| core/audit_logger.py|HMAC-SHA256, журнал в БД|
|DB Connector| core/db_connector.py|PostgreSQL + SQLite fallback|

## Установка зависимостей

```bash
pip install -r requirements.txt
```

## Настройка PostgreSQL (опционально)

Если PostgreSQL недоступен, приложение автоматически перейдёт на SQLite. Для работы с PostgreSQL:
1. Создайте БД и пользователя (или используйте существующие).
2. Настройте параметры в core/config.py:
```bash
host: ("DB_HOST", "localhost")
port: ("DB_PORT", "5432")
dbname: ("DB_NAME", "postgres")
user: ("DB_USER", "postgres")
password: ("DB_PASS", "1234")
```
3. SQL-скрипт sql/init_postgres.sql выполнится автоматически при подключении (создаст таблицы и заполнит departments).
