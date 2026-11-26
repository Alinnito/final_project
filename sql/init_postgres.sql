-- 1. Подразделения
CREATE TABLE IF NOT EXISTS departments (
    id SERIAL PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    code VARCHAR(32) NOT NULL UNIQUE,
    confidentiality_level INT DEFAULT 1
);

-- 2. Сотрудники
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

-- 3. Студенты
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

-- 4. Должности
CREATE TABLE IF NOT EXISTS positions (
    id SERIAL PRIMARY KEY,
    title VARCHAR(128) NOT NULL,
    grade VARCHAR(16),
    description TEXT
);

-- 5. Связь сотрудник - должность
CREATE TABLE IF NOT EXISTS employee_positions (
    id SERIAL PRIMARY KEY,
    employee_id INT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    position_id INT NOT NULL REFERENCES positions(id) ON DELETE RESTRICT,
    appointed_at DATE NOT NULL DEFAULT CURRENT_DATE,
    dismissed_at DATE,
    is_current BOOLEAN DEFAULT TRUE,
    CONSTRAINT uq_employee_current_position UNIQUE (employee_id, is_current)
        DEFERRABLE INITIALLY DEFERRED
);

-- 6. Кабинеты
CREATE TABLE IF NOT EXISTS classrooms (
    id SERIAL PRIMARY KEY,
    number VARCHAR(16) NOT NULL UNIQUE,
    building VARCHAR(64),
    capacity INT,
    has_projector BOOLEAN DEFAULT FALSE
);

-- 7. Типы занятий
CREATE TABLE IF NOT EXISTS lesson_types (
    id SERIAL PRIMARY KEY,
    code VARCHAR(16) NOT NULL UNIQUE,
    name VARCHAR(64) NOT NULL,
    default_duration_min INT DEFAULT 90
);

-- 8. Занятия
CREATE TABLE IF NOT EXISTS lessons (
    id SERIAL PRIMARY KEY,
    subject VARCHAR(128) NOT NULL,
    teacher_id INT NOT NULL REFERENCES employees(id) ON DELETE RESTRICT,
    group_id INT NOT NULL REFERENCES student_groups(id) ON DELETE CASCADE,
    classroom_id INT NOT NULL REFERENCES classrooms(id) ON DELETE RESTRICT,
    lesson_date DATE NOT NULL,
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    lesson_type VARCHAR(16) DEFAULT 'lecture',
    CONSTRAINT chk_lesson_time CHECK (end_time > start_time)
);

-- 9. Оценки
CREATE TABLE IF NOT EXISTS grades (
    id SERIAL PRIMARY KEY,
    student_id INT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    lesson_id INT NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
    grade_value INT NOT NULL CHECK (grade_value BETWEEN 1 AND 5),
    graded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    comment TEXT,
    CONSTRAINT uq_student_lesson_grade UNIQUE (student_id, lesson_id)
);

-- 10. Аудит логов
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    username VARCHAR(64) NOT NULL,
    client_ip VARCHAR(45) NOT NULL,
    query_text TEXT NOT NULL,
    operation_type VARCHAR(16) NOT NULL,
    risk_score INT DEFAULT 0,
    is_blocked BOOLEAN DEFAULT FALSE,
    incident_type VARCHAR(64),
    integrity_hmac VARCHAR(64) NOT NULL
);

INSERT INTO departments (id, name, code, confidentiality_level) VALUES
    (1, 'Управление информационной безопасности', 'CISO', 3),
    (2, 'Кафедра кибербезопасности', 'KIB', 2),
    (3, 'Бухгалтерия и отдел кадров', 'HR_FIN', 3)
ON CONFLICT (id) DO NOTHING;

SELECT setval('audit_logs_id_seq', (SELECT COALESCE(MAX(id), 1) FROM audit_logs));