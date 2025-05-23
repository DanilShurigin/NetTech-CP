import socket
import logging
import hashlib
import os
import sys

from lib.protocol import Protocol, Message, MessageType, ProtocolException
from lib.protocol import (
    read_connection_msg,
    read_info_msg,
    read_register_msg,
    read_authentication_msg,
    read_download_msg,
    send_connection_msg,
    send_success_info_msg,
    send_error_info_msg,
    send_register_msg,
    send_authentication_msg,
    send_download_msg,
)


logger = logging.getLogger("client.conn_handler")


class ConnectionHandler:
    """
    Обработчик подключения к серверу.
    """

    def __init__(self, cl_socket: socket.socket):
        self._socket = cl_socket
        self._conn_id = b""
        self._perform_handshake()

    def _perform_handshake(self):
        # Отправляем первое сообщение для получения conn_id
        send_connection_msg(
            sock=self._socket,
            conn_id=b"\x00" * 16,
            flags=0x00,
            payload=b"",
        )

        # Получаем от сервера идентификатор соединения
        message = read_connection_msg(self._socket)
        if not message.conn_id or message.msg_type == MessageType.ERROR:
            error_msg = "Не удалось получить conn_id"
            logger.error(error_msg)
            raise ProtocolException(error_msg)

        self.conn_id = message._conn_id

    def perform_registration(self, login: str, password: str) -> bool:
        """
        Зарегистрировать пользователя на сервере.

        Args:
            login (str): Логин пользователя
            password (str): Пароль пользователя

        Returns:
            bool: `True` - успех, `False` - неудача.
        """
        # Отправляем имя пользователя
        send_register_msg(self._socket, self._conn_id, 0x00, login.encode())
        logger.debug("Sent user login")

        # Получаем соль
        message = read_register_msg(self._socket)
        salt = message.payload

        # Формируем хэш из пароля и соли и отправляем на сервер
        send_register_msg(
            self._socket,
            self._conn_id,
            0x00,
            hashlib.sha256(salt + password.encode()).digest(),
        )

        # Получаем статус клиента
        message = read_info_msg(self._socket)
        if message.msg_type == MessageType.SUCCESS:
            return True
        return False

    def perform_authentication(self, login: str, password: str) -> bool:
        """
        Аутентифицировать пользователя на сервере.

        Args:
            login (str): Логин пользователя
            password (str): Пароль пользователя

        Returns:
            bool: `True` - успех, `False` - неудача.
        """
        # Отправляем имя пользователя
        send_register_msg(self._socket, self._conn_id, 0x00, login.encode())
        logger.debug("Sent user login")

        # Получаем соль
        message = read_register_msg(self._socket)
        salt = message.payload

        # Формируем хэш из пароля и соли и отправляем на сервер
        send_register_msg(
            self._socket,
            self._conn_id,
            0x00,
            hashlib.sha256(salt + password.encode()).digest(),
        )

        # Получаем статус клиента
        message = read_info_msg(self._socket)
        if message.msg_type == MessageType.SUCCESS:
            return True
        return False

    def perform_file_download(self, filepath: str, save_as: str) -> bool:
        """
        Скачать файл с сервера.

        Args:
            filepath (str): Путь к файлу на сервере

        Returns:
            bool: `True` - успех, `False` - неудача.
        """
        # Отправляем путь к файлу
        send_download_msg(self._socket, self._conn_id, 0x00, filepath.encode())

        # Получаем размер файла
        message = read_download_msg(self._socket)

        # Проверяем, хватит ли места
        file_size = int(message.payload.decode())
        stat = os.statvfs("./")
        if (stat.f_bavail * stat.f_frsize) <= file_size:
            send_download_msg(self._socket, self._conn_id, 0x00, b"ERR")
            logger.error(
                "Not enough free space on disk",
                extra={"avail": stat.f_bavail * stat.f_frsize, "file_size": file_size},
            )
            return False
        
        # Отправляем сообщение о готовности
        send_download_msg(self._socket, self._conn_id, 0x00, b"OK")

        print_progress(filepath, 0.0)

        # Принимаем файл частями
        sha256 = hashlib.sha256()
        received_bytes = 0
        with open(save_as, "wb") as f:
            while received_bytes < file_size:
                message = read_download_msg(self._socket)
                # Прекратить, если нет флага
                if message.flags & 0x10:
                    break
                # Если флаг есть
                chunk = message.payload
                f.write(chunk)
                sha256.update(chunk)
                received_bytes += len(chunk)
                print_progress(filepath, received_bytes/file_size)
        
        # Проверяем хэш файла
        remote_file_hash = message.payload
        if sha256.digest() != remote_file_hash:
            logger.error("File is corrupted")
            os.remove(filepath)
            return False
        
        logger.info("File received")
        return True


PROGRESS_BAR_SYMBOLS = "░▒▓█"


def _progress_repr(percents: float) -> str:
    """
    Создать полосу загрузки по количеству процентов.

    Args:
        percents (float): Процент загрузки

    Returns:
        str: Полоса загрузки
    """
    percents = percents*100
    return (
        PROGRESS_BAR_SYMBOLS[-1] * int(percents // 4)
        + PROGRESS_BAR_SYMBOLS[round(percents % 4) if percents < 100 else -1]
    )

def print_progress(filename: str, progress: float) -> None:
    """Вывести текущее состояние загрузки"""
    status = f"{filename if len(filename)<=20 else '...'+filename[-17:]:<20} |{_progress_repr(progress):21}| {round(progress*100):>3}%\n"
    # Очистить предыдущий вывод
    sys.stdout.write('\x1b[1A\x1b[2K\x1b[0G')
    # Вывести новые данные
    sys.stdout.write(status)
    sys.stdout.flush()
