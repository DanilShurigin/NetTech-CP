import sys
import threading

from server_src.config import load_config
from server_src.logger import setup_logger
from server_src.db import get_user_database
from server_src.filesystem import get_filesystem
from server_src.ui import get_server_ui
from server_src.listener import SrvWorkSocket
from server_src.server_exceptions import ServerException
from server_src.connection_handler import ConnectionHandler


def main() -> None:
    # Выводим базовый интерфейс
    print()
    get_server_ui().print()
    # sys.stdout.write('\x1b[1A') # Перемещаем курсор на 1 строку вверх

    interface_thread = threading.Thread(
        target=get_server_ui().run,
        args=(1,),
        daemon=True,
    )
    interface_thread.start()

    while True:
        try:
            # Ждём и принимаем соединение
            client_conn, client_addr = srv_socket.accept()

            # Создаём обработчик клиента
            handler = ConnectionHandler(client_conn, client_addr)

            # Обрабатываем клиента в отдельном потоке
            handler.start()

        except ServerException:
            logger.error("Client connection closed with errors", exc_info=True)


if __name__ == "__main__":
    # Получение параметров запуска из ком. строки
    config = load_config()
    # Начальная настройка логгера
    logger = setup_logger(log_file=config.log, log_level=config.log_level)
    # Инициализация компонентов сервера
    users_db = get_user_database(config.db)
    srv_filesystem = get_filesystem(config.shared_folder)
    srv_ui = get_server_ui()
    srv_socket = SrvWorkSocket("127.0.0.1", config.local_port)

    logger.info("Server initialized")

    # Запуск основного цикла сервера
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Server shutdown initiated by keyboard interrupt")
        print("\n\n\n")
    except:
        logger.critical("Server fatal error", exc_info=True)

    # Завершение работы
    srv_socket.close()
