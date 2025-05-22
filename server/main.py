from src.config import load_config
from src.logger import setup_logger
from src.db import get_user_database
from src.filesystem import get_filesystem
from src.listener import SrvWorkSocket
from src.server_exceptions import ServerException
from src.connection_handler import ConnectionHandler


def main() -> None:
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
    srv_socket = SrvWorkSocket("127.0.0.1", config.local_port)

    logger.info("Server initialized")

    # Запуск основного цикла сервера
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Server shutdown initiated by keyboard interrupt")
    except:
        logger.critical("Server fatal error", exc_info=True)

    # Завершение работы
    srv_socket.close()
