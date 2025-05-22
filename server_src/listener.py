import logging
import socket

logger = logging.getLogger("server.socket")


class SrvWorkSocket(socket.socket):
    """
    Рабочий сокет сервера.
    """

    def __init__(self, host: str, port: int):
        super().__init__(family=socket.AF_INET, type=socket.SOCK_STREAM)
        # Привязка сокета к порту
        self._host = host
        self._port = port

        self.bind((host, port))
        # Запуск прослушивания входящих соединений
        self.listen()

    def listen(self) -> None:
        """
        Запустить прослушивание порта на наличие входящих соединений.
        """
        super().listen()

        logger.info(
            "Server starts listening on port %d",
            self._port,
            extra={"host": self._host, "port": self._port},
        )

    def accept(self) -> tuple[socket.socket, tuple[str, int]]:
        """
        Принять входящий запрос на соединение.
        """
        accepted_conn, conn_addr = super().accept()

        logger.info("New connection accepted", extra={"addr": conn_addr})

        return accepted_conn, conn_addr

    def close(self) -> None:
        """
        Отвязать сокет от порта.
        """
        super().close()

        logger.info("Work socket closed", extra={})
