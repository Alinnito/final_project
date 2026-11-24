"""
Модуль управления доступом на основе ролей (Role-Based Access Control - RBAC)
Определяет роли, матрицу полномочий, валидацию сессий пользователей
"""
from enum import Enum
from typing import Dict, Set

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

# Матрица прав доступа
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: {
        Permission.READ_PUBLIC,
        Permission.READ_SENSITIVE,
        Permission.WRITE_DATA,
        Permission.EXECUTE_DDL,
        Permission.CONFIGURE_SECURITY,
        Permission.VIEW_AUDIT_LOGS,
        Permission.EXPORT_INCIDENTS
    },
    Role.SECURITY_OFFICER: {
        Permission.READ_PUBLIC,
        Permission.CONFIGURE_SECURITY,
        Permission.VIEW_AUDIT_LOGS,
        Permission.EXPORT_INCIDENTS
    },
    Role.DEPARTMENT_OPERATOR: {
        Permission.READ_PUBLIC,
        Permission.WRITE_DATA
    },
    Role.ANALYST: {
        Permission.READ_PUBLIC,
        Permission.VIEW_AUDIT_LOGS
    },
    Role.GUEST: {
        Permission.READ_PUBLIC
    }
}

class UserSession:
    def __init__(self, username: str, role: Role, ip_address: str, department_id: int = 1):
        self.username = username
        self.role = role
        self.ip_address = ip_address
        self.department_id = department_id

    def has_permission(self, perm: Permission) -> bool:
        allowed = ROLE_PERMISSIONS.get(self.role, set())
        return perm in allowed

    def can_view_sensitive(self) -> bool:
        return self.has_permission(Permission.READ_SENSITIVE)