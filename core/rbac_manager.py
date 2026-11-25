"""
Модуль управления доступом на основе ролей (Role-Based Access Control - RBAC)
Определяет роли, матрицу полномочий, валидацию сессий пользователей
"""
from enum import Enum
from typing import Dict, Set, Optional

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

class RBACManager:
    def __init__(self):
        self.active_sessions: Dict[str, UserSession] = {}

    def create_session(self, username: str, role_str: str, ip: str, dept_id: int = 1) -> UserSession:
        try:
            role = Role(role_str.lower())
        except ValueError:
            role = Role.GUEST
        session = UserSession(username, role, ip, dept_id)
        self.active_sessions[username] = session
        return session

    def get_session(self, username: str) -> Optional[UserSession]:
        return self.active_sessions.get(username)

    def check_access(self, username: str, permission: Permission) -> bool:
        session = self.get_session(username)
        if not session:
            return False
        return session.has_permission(permission)