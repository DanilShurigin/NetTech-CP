import logging
import sqlite3
import os


class UserDatabase:
    """
    База данных пользователей.
    """

    def __init__(self, db_path: str = "users.db") -> None:
        """
        Инициализация базы данных пользователей.

        Args:
            db_path: Путь к файлу БД.
        """
        self._db_path = db_path
        self.logger = logging.getLogger("server.users_db")
        self._init_db()
        self.logger.info("User database started", extra={"db_file", db_path})

    def _init_db(self) -> None:
        """
        Создать таблицу пользователей, если её нет.
        """
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        login TEXT PRIMARY KEY,
                        salt TINYBLOB NOT NULL,
                        passwd_hash BLOB NOT NULL
                    )
                    """
                )
            self.logger.debug("Database table 'users' created or already exists")
        except sqlite3.Error as sql_error:
            self.logger.error("Failed to initialize users database", exc_info=True)
            exit(1) # TODO: Заменить на аккуратное завершение работы.

    def add_user(self, login: str, salt: str, passwd_hash: str) -> bool:
        """
        Добавить запись о новом пользователе.

        Args:
            login: Логин (имя) пользователя.
            salt: Соль для хэширования пароля.
            passwd_hash: Хэш пароля.

        Returns:
            `True` - пользователь добавлен.
            `False` - пользователь не добавлен.
        """
        try:
            # Если пользователь уже существует в БД, его не нужно создавать.
            if self.user_exists(login):
                self.logger.warning("User '%s' already exists", login)
                return False
            # Иначе создаём пользователя
            with sqlite3.connect(self._db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO users (login, salt, passwd_hash)
                    VALUE (?, ?, ?)
                    """,
                    (login, salt, passwd_hash),
                )
            self.logger.info("User '%s' added.", login)
            return True
        except sqlite3.Error as sql_error:
            self.logger.error("Failed to add user", {"login": login}, exc_info=True)
            return False

    def user_exists(self, login: str) -> bool:
        """
        Проверить, существует ли в БД запись для указанного логина.

        Args:
            login: Логин пользователя.

        Returns:
            `True` - В таблице есть запись с таким логином.
            `False` - В таблице нет записи с таким логином
            или в ходе проверки возникла ошибка.
        """
        is_exists = False
        try:
            with sqlite3.connect(self._db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT 1 FROM users WHERE login = ?
                    """,
                    (login,),
                )
                is_exists = cursor.fetchone() is not None

            self.logger.debug("User '%s' checked for existance", login)
            return is_exists
        except sqlite3.Error as sql_error:
            self.logger.error("Failed to check user existace", {"login": login}, exc_info=True)
            return False
    
    def get_user_salt(self, login: str) -> str | None:
        """
        Получить соль для хэширования пароля по логину пользователя.

        Args:
            login: Логин пользователя.
        
        Returns:
            salt: Соль для хэширования пароля.
            None: Если пользователь не найден или произошла ошибка.
        """
        try:
            salt = None
            # Если пользователя нет, то и соли тоже нет.
            if not self.user_exists(login):
                self.logger.warning("Cannot select salt for user '%s' because user does not exist", login)
                return None

            with sqlite3.connect(self._db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT salt FROM users WHERE login = ?
                    """,
                    (login,),
                )
                row = cursor.fetchone()
                salt = row[0] if row else None

            self.logger.debug("Salt selected for user '%s'", login)
            return salt
        except sqlite3.Error as sql_error:
            self.logger.error("Failed to select salt", {"login": login}, exc_info=True)
            return None

    def get_user_password_hash(self, login: str) -> str | None:
        """
        Получить хэш пароля по логину пользователя.

        Args:
            login: Логин пользователя.
        
        Returns:
            passwd_hash: Хэш пароля.
            None: Если пользователь не найден или произошла ошибка.
        """
        try:
            passwd_hash = None
            # Если пользователя нет, то и хэша тоже нет.
            if not self.user_exists(login):
                self.logger.warning("Cannot select password hash for user '%s' because user does not exist", login)
                return None

            with sqlite3.connect(self._db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT passwd_hash FROM users WHERE login = ?
                    """,
                    (login,),
                )
                row = cursor.fetchone()
                passwd_hash = row[0] if row else None

            self.logger.debug("Password hash selected for user '%s'", login)
            return passwd_hash
        except sqlite3.Error as sql_error:
            self.logger.error("Failed to select password hash", {"login": login}, exc_info=True)
            return None


_user_db_instance = None


def get_user_database(db_path: str = None) -> UserDatabase:
    """
    Вернуть объект базы данных пользователей.

    Args:
        db_path (str): Путь к файлу БД.

    Returns:
        UserDatabase: База данных пользователей
    """
    if _user_db_instance is None and db_path is not None:
        _user_db_instance = UserDatabase(db_path)
    elif _user_db_instance is None and db_path is None:
        raise RuntimeError("UserDatabase yet not initialized")
    
    return _user_db_instance
