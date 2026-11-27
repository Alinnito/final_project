"""
Главная точка входа в программу DBSecGuard (Комплекс защиты баз данных PostgreSQL)
"""
import sys
from core.rbac_manager import RBACManager
from core.db_connector import DBConnector

def main():
    # Запуск графического интерфейса
    from PySide6.QtWidgets import QApplication
    from gui.login_dialog import LoginDialog
    from gui.main_window import MainWindow

    app = QApplication(sys.argv)

    db = DBConnector()
    rbac = RBACManager()

    login = LoginDialog(rbac, db_connector = db)
    if login.exec() != LoginDialog.Accepted:
        sys.exit(0)  # пользователь нажал «Отмена»

    window = MainWindow(rbac=rbac, current_user=login.session, db_connector=db)
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
