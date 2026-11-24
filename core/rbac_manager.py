"""
Модуль управления доступом на основе ролей (Role-Based Access Control - RBAC)
Определяет роли, матрицу полномочий, валидацию сессий пользователей
"""
from enum import Enum

class Permission(Enum):
    READ_PUBLIC = "read_public"
    READ_SENSITIVE = "read_sensitive"
    WRITE_DATA = "write_data"
    EXECUTE_DDL = "execute_ddl"
    CONFIGURE_SECURITY = "configure_security"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    EXPORT_INCIDENTS = "export_incidents"

class Role(Enum):
    ADMIN = "admin"
    SECURITY_OFFICER = "security_officer"
    DEPARTMENT_OPERATOR = "department_operator"
    ANALYST = "analyst"
    GUEST = "guest"