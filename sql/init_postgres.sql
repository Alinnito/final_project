CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS departments (
    id SERIAL PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    code VARCHAR(32) NOT NULL UNIQUE,
    confidentiality_level INT DEFAULT 1
);

CREATE TABLE IF NOT EXISTS employees (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(128) NOT NULL,
    passport_encrypted TEXT NOT NULL,
    phone VARCHAR(32) NOT NULL,
    email VARCHAR(64) NOT NULL,
    salary_encrypted TEXT NOT NULL,
    department_id INT REFERENCES departments(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS students (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(128) NOT NULL,
    group_name VARCHAR(32) NOT NULL,
    passport_encrypted TEXT NOT NULL,
    phone VARCHAR(32) NOT NULL,
    email VARCHAR(64) NOT NULL,
    scholarship_encrypted TEXT NOT NULL,
    department_id INT REFERENCES departments(id)
);

INSERT INTO departments (id, name, code, confidentiality_level) VALUES
    (1, 'Управление информационной безопасности', 'CISO', 3),
    (2, 'Кафедра кибербезопасности', 'KIB', 2),
    (3, 'Бухгалтерия и отдел кадров', 'HR_FIN', 3)
ON CONFLICT (id) DO NOTHING;

SELECT setval('departments_id_seq', (SELECT COALESCE(MAX(id), 1) FROM departments));