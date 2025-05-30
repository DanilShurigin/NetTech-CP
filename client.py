import cmd
import hashlib
import socket
import os

from client_src.config import load_config
from client_src.logger import setup_logger
from client_src.connection_handler import ConnectionHandler
from lib.protocol import BadMessageType


class ClientUI(cmd.Cmd):
    """Интерактивная оболочка клиента с поддержкой команд."""

    prompt = "client> "

    def __init__(self):
        """
        Инициализирует клиентский интерфейс.
        """
        super().__init__()

    def do_download(self, arg: str) -> None:
        """
        Скачивает файл с сервера.

        Использование: download filename [save_as]
        """
        args = arg.split()
        if not args:
            error_msg = "Error: Empty filename"
            logger.error(error_msg)
            print(error_msg)
            return

        filename = args[0]
        save_as = args[1] if len(args) > 1 else filename

        logger.info(f"File downloading request: {filename} -> {save_as}")

        try:
            handler.perform_file_download(filename, save_as)
            abs_path = os.path.abspath(save_as)
            print(f"File \033]8;;file://{abs_path}\033\\{abs_path}\033]8;;\033\\ downloaded")
        except Exception as e:
            logger.error(f"Downloading error", exc_info=True)
            print(f"Error: {str(e)}")

        print()  # Новая строка после прогресс-бара

    def do_register(self, arg: str) -> None:
        """
        Регистрирует нового пользователя.

        Использование: register
        """
        logger.info("Registration")

        try:
            # Запрашиваем логин и пароль у пользователя
            login = input("Login: ")
            password = input("Password: ")

            status = handler.perform_registration(login, password)
            
            if status:
                logger.info("Registered as '%s'", login)
                print(f"Registered as {login}")
            else:
                logger.info(f"Not registered")
                print("Not registered")

        except Exception as e:
            logger.exception(f"Failed to register: {str(e)}")
            print(f"Error: {str(e)}")

    def do_auth(self, arg: str) -> None:
        """
        Аутентифицирует пользователя.

        Использование: auth
        """
        logger.info("Authentication")

        try:
            # Запрашиваем логин и пароль у пользователя
            login = input("Login: ")
            password = input("Password: ")

            status = handler.perform_authentication(login, password)
            
            if status:
                logger.info("Authenticated as '%s'", login)
                print(f"Authenticated as {login}")
            else:
                logger.info(f"Not authenticated")
                print("Not authenticated")
            

        except Exception as e:
            logger.exception(f"Failed to authenticate: {str(e)}")
            print(f"Error: {str(e)}")

    def do_exit(self, arg: str) -> bool:
        """
        Завершить работу клиента.

        Использование: exit
        """
        logger.info("Client stopping")
        return True


if __name__ == "__main__":
    # Получение параметров запуска из ком. строки
    config = load_config()
    # Начальная настройка логгера
    logger = setup_logger(log_file=config.log, log_level=config.log_level)

    # Запуск основного цикла клиента
    try:
        # Создаём сокет
        cl_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Подключаемся к серверу
        cl_socket.connect((config.remote_host, config.remote_port))
        logger.info("Connected to server", extra={"srv_addr": (config.remote_host, config.remote_port)})
        # Создаем экзмепляр обработчика подключения
        handler = ConnectionHandler(cl_socket)
        # Запускаем интерактивную оболочку
        cli = ClientUI()
        cli.cmdloop()
    except KeyboardInterrupt:
        logger.info("Client shutdown initiated by keyboard interrupt")
        print("\n\n")
    except Exception as err:
        logger.critical("Client fatal error", exc_info=True)
        print(f"Critical error: {err.args[0]}")

    # Завершение работы
    if "cl_socket" in locals():
        cl_socket.close()
        logger.info("Server connection closed")
    logger.info("Client has been gracefully stopped")
