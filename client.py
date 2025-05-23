import cmd
import hashlib
import socket

from client_src.config import load_config
from client_src.logger import setup_logger
from client_src.connection_handler import ConnectionHandler


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
            error_msg = "Ошибка: укажите имя файла"
            self.logger.error(error_msg)
            print(error_msg)
            return

        filename = args[0]
        save_as = args[1] if len(args) > 1 else filename

        self.logger.info(f"Запрос на скачивание файла: {filename} -> {save_as}")

        try:
            handler.perform_file_download(filename, save_as)
        except Exception as e:
            logger.exception(f"Ошибка при выполнении команды download: {str(e)}")
            print(f"Ошибка: {str(e)}")

        print()  # Новая строка после прогресс-бара

    def do_register(self, arg: str) -> None:
        """
        Регистрирует нового пользователя.

        Использование: register
        """
        self.logger.info("Registration")

        try:
            # Запрашиваем логин и пароль у пользователя
            login = input("Login: ")
            password = input("Password: ")

            status = handler.perform_registration(login, password)
            
            if status:
                self.logger.info("Registered as '%s'", login)
                print(f"Registered as {login}")
            else:
                self.logger.info(f"Not registered")
                print("Not registered")

        except Exception as e:
            self.logger.exception(f"Failed to register: {str(e)}")
            print(f"Error: {str(e)}")

    def do_auth(self, arg: str) -> None:
        """
        Аутентифицирует пользователя.

        Использование: auth
        """
        self.logger.info("Authentication")

        try:
            # Запрашиваем логин и пароль у пользователя
            login = input("Login: ")
            password = input("Password: ")

            status = handler.perform_registration(login, password)
            
            if status:
                self.logger.info("Authenticated as '%s'", login)
                print(f"Authenticated as {login}")
            else:
                self.logger.info(f"Not authenticated")
                print("Not authenticated")
            

        except Exception as e:
            self.logger.exception(f"Failed to authenticate: {str(e)}")
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
    except:
        logger.critical("Client fatal error", exc_info=True)

    # Завершение работы
    if "cl_socket" in locals():
        cl_socket.close()
        logger.info("Server connection closed")
    logger.info("Client has been gracefully stopped")
