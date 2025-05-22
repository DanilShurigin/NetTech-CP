import struct
import uuid
import socket
import logging
from enum import IntEnum


logger = logging.getLogger("protocol")


class ProtocolException(Exception):
    """
    Исключение в работе протокола.
    """

    pass


class MessageType(IntEnum):
    """
    Типы сообщений.
    """

    CONN = 0x01  # Установление соединения
    SUCCESS = 0x02  # Успех
    ERROR = 0x03  # Ошибка
    REGISTER = 0x04  # Регистрация
    AUTH = 0x05  # Аутентификация
    DOWNLOAD = 0x06  # Скачивание файла


class Message:
    """
    Сообщение, передаваемое протоколом.
    """

    def __init__(
        self, conn_id: uuid.UUID, msg_type: MessageType, flags: int, payload: bytes
    ):
        """
        Инициализировать сообщение протокола.

        Args:
            conn_id (uuid.UUID): Идентификатор соединения
            msg_type (MessageType): Тип
            flags (int): Управляющие биты
            payload (bytes): Полезная нагрузка
        """
        self._conn_id = conn_id
        self._msg_type = msg_type
        self._flags = flags
        self._payload = payload

    @property
    def conn_id(self) -> uuid.UUID:
        """
        Вернуть идентификатор соединения.
        """
        return self._conn_id

    @property
    def msg_type(self) -> MessageType:
        """
        Вернуть тип сообщения.
        """
        return self._msg_type

    @property
    def flags(self) -> int:
        """Вернуть управляющие биты в десятичной системе"""
        return self._flags

    @property
    def payload(self) -> bytes:
        """
        Вернуть полезную нагрузку
        """
        return self._payload

    def __repr__(self) -> str:
        return f"Message(conn_id={self._conn_id}, msg_type={self._msg_type}, flags={bin(self._flags)[2:].zfill(8)}, payload={self._payload})"


class Protocol:
    # Формат заголовка: payload_length (4), conn_id (16), msg_type (1), flags (1)
    HEADER_FORMAT = "<I16sBB"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    @staticmethod
    def pack_message(msg: Message) -> bytes:
        """
        Упаковать сообщение в двоичный формат.

        Args:
            msg (Message): Сообщение

        Returns:
            bytes: Сообщение в виде потока байт
        """
        header = struct.pack(
            Protocol.HEADER_FORMAT,
            len(msg.payload),
            msg.conn_id.bytes,
            msg.msg_type,
            msg.flags,
        )

        return header + msg.payload

    @staticmethod
    def unpack_header(header_data: bytes) -> tuple[int, bytes, int, int]:
        """
        Распаковать заголовок сообщения.

        Args:
            header_data (bytes): Заголовок сообщения в виде потока байт.

        Returns:
            header (tuple[int, bytes, int, int]): Поля заголовка.
        """
        payload_length, conn_id, msg_type, flags = struct.unpack(
            Protocol.HEADER_FORMAT,
            header_data,
        )

        return payload_length, conn_id, msg_type, flags

    @staticmethod
    def read(sock: socket.socket) -> Message:
        """
        Прочитать сообщение из сокета.

        Args:
            sock (socket.socket): Сокет соединения.

        Returns:
            msg (Message): Поля сообщения.

        Raises:
            ProtocolException: Не удалось прочитать сообщение.
        """
        try:
            # Читаем из сокета заголовок сообщения
            header_data = sock.recv(Protocol.HEADER_SIZE)
            if not header_data:
                raise IOError("Unable to read header")
            # Разделяем заголовок на поля
            payload_length, conn_id, msg_type, flags = Protocol.unpack_header(
                header_data
            )
            payload = b""
            # Читаем из сокета полезную нагрузку, если такая есть
            if payload_length > 0:
                payload = sock.recv(payload_length)
                if len(payload) != payload_length:
                    raise IOError("Unable to read payload")
            # Формируем сообщение
            msg = Message(conn_id, msg_type, flags, payload)

            logger.debug("Message readed from socket", extra={"message": msg.__repr__()})
            
            return msg
        
        except (struct.error, IOError) as err:
            logger.error("Message read error", exc_info=True)
            raise ProtocolException("Message read error: %e", err)

    @staticmethod
    def send(sock: socket.socket, msg: Message) -> None:
        """
        Отправить сообщение в сокет.

        Args:
            sock (socket.socket): Сокет соединения.
            msg (Message): Сообщение

        Raise:
            ProtocolException: Не удалось отправить сообщение.
        """
        try:
            logger.debug("Sending message to socket", extra={"message": msg.__repr__()})
            # Формируем поток байт из полей сообщения
            message = Protocol.pack_message(msg)
            # Отправляем сообщение в сокет
            sock.sendall(message)
        except (struct.error, IOError) as err:
            logger.error("Message send error", exc_info=True)
            raise ProtocolException("Message write error: %e", err)


# Методы-сокращения


def read_connection_msg(sock: socket.socket) -> Message:
    """
    Прочитать из сокета сообщение типа CONN.

    Args:
        sock (socket.socket): Сокет соединения

    Returns:
        Message: Прочитанное сообщение
    """
    logger.info("Reading CONN message from socket", extra={"socket": sock.__repr__()})
    # Получаем сообщение
    msg = Protocol.read(sock=sock)
    # Проверяем тип в заголовке
    if msg.msg_type != MessageType.CONN:
        logger.error(
            "Readed message contains wrong type",
            extra={"socket": sock.__repr__(), "msg_type": msg.msg_type},
        )
        raise ProtocolException("Bad message type")

    return msg


def send_connection_msg(
    sock: socket.socket, conn_id: uuid.UUID, flags: int, payload: bytes
) -> None:
    """
    Отправить в сокет сообщение типа CONN.

    Args:
        sock (socket.socket): Сокет соединения
        conn_id (uuid.UUID): Идентификатор соединения
        flags (int): Управляющие биты
        payload (bytes): Полезная нагрузка
    """
    logger.info("Sending CONN message to socket", extra={"socket": sock.__repr__()})
    # Создаём сообщение
    msg = Message(
        conn_id=conn_id, msg_type=MessageType.CONN, flags=flags, payload=payload
    )
    # Отправляем сообщение
    Protocol.send(sock=sock, msg=msg)


def read_info_msg(sock: socket.socket) -> Message:
    """
    Прочитать из сокета сообщение типа ERROR или SUCCESS.

    Args:
        sock (socket.socket): Сокет соединения

    Returns:
        Message: Прочитанное сообщение
    """
    logger.info(
        "Reading ERROR|SUCCESS message from socket", extra={"socket": sock.__repr__()}
    )
    # Получаем сообщение
    msg = Protocol.read(sock=sock)
    # Проверяем тип в заголовке
    if msg.msg_type not in [MessageType.SUCCESS, MessageType.ERROR]:
        logger.error(
            "Readed message contains wrong type",
            extra={"socket": sock.__repr__(), "msg_type": msg.msg_type},
        )
        raise ProtocolException("Bad message type")

    return msg


def send_success_info_msg(
    sock: socket.socket, conn_id: uuid.UUID, flags: int, payload: bytes
) -> None:
    """
    Отправить в сокет сообщение типа SUCCESS.

    Args:
        sock (socket.socket): Сокет соединения
        conn_id (uuid.UUID): Идентификатор соединения
        flags (int): Управляющие биты
        payload (bytes): Полезная нагрузка
    """
    logger.info("Sending SUCCESS message to socket", extra={"socket": sock.__repr__()})
    # Создаём сообщение
    msg = Message(
        conn_id=conn_id, msg_type=MessageType.SUCCESS, flags=flags, payload=payload
    )
    # Отправляем сообщение
    Protocol.send(sock=sock, msg=msg)


def send_error_info_msg(
    sock: socket.socket, conn_id: uuid.UUID, flags: int, payload: bytes
) -> None:
    """
    Отправить в сокет сообщение типа ERROR.

    Args:
        sock (socket.socket): Сокет соединения
        conn_id (uuid.UUID): Идентификатор соединения
        flags (int): Управляющие биты
        payload (bytes): Полезная нагрузка
    """
    logger.info("Sending ERROR message to socket", extra={"socket": sock.__repr__()})
    # Создаём сообщение
    msg = Message(
        conn_id=conn_id, msg_type=MessageType.ERROR, flags=flags, payload=payload
    )
    # Отправляем сообщение
    Protocol.send(sock=sock, msg=msg)


def read_register_msg(sock: socket.socket) -> Message:
    """
    Прочитать из сокета сообщение типа REGISTER.

    Args:
        sock (socket.socket): Сокет соединения

    Returns:
        Message: Прочитанное сообщение
    """
    logger.info(
        "Reading REGISTER message from socket", extra={"socket": sock.__repr__()}
    )
    # Получаем сообщение
    msg = Protocol.read(sock=sock)
    # Проверяем тип в заголовке
    if msg.msg_type != MessageType.REGISTER:
        logger.error(
            "Readed message contains wrong type",
            extra={"socket": sock.__repr__(), "msg_type": msg.msg_type},
        )
        raise ProtocolException("Bad message type")

    return msg


def send_register_msg(
    sock: socket.socket, conn_id: uuid.UUID, flags: int, payload: bytes
) -> None:
    """
    Отправить в сокет сообщение типа REGISTER.

    Args:
        sock (socket.socket): Сокет соединения
        conn_id (uuid.UUID): Идентификатор соединения
        flags (int): Управляющие биты
        payload (bytes): Полезная нагрузка
    """
    logger.info("Sending REGISTER message to socket", extra={"socket": sock.__repr__()})
    # Создаём сообщение
    msg = Message(
        conn_id=conn_id, msg_type=MessageType.REGISTER, flags=flags, payload=payload
    )
    # Отправляем сообщение
    Protocol.send(sock=sock, msg=msg)


def read_authentication_msg(sock: socket.socket) -> Message:
    """
    Прочитать из сокета сообщение типа AUTH.

    Args:
        sock (socket.socket): Сокет соединения

    Returns:
        Message: Прочитанное сообщение
    """
    logger.debug("Reading AUTH message from socket", extra={"socket": sock.__repr__()})
    # Получаем сообщение
    msg = Protocol.read(sock=sock)
    # Проверяем тип в заголовке
    if msg.msg_type != MessageType.AUTH:
        logger.error(
            "Readed message contains wrong type",
            extra={"socket": sock.__repr__(), "msg_type": msg.msg_type},
        )
        raise ProtocolException("Bad message type")

    return msg


def send_authentication_msg(
    sock: socket.socket, conn_id: uuid.UUID, flags: int, payload: bytes
) -> None:
    """
    Отправить в сокет сообщение типа AUTH.

    Args:
        sock (socket.socket): Сокет соединения
        conn_id (uuid.UUID): Идентификатор соединения
        flags (int): Управляющие биты
        payload (bytes): Полезная нагрузка
    """
    logger.info("Sending AUTH message to socket", extra={"socket": sock.__repr__()})
    # Создаём сообщение
    msg = Message(
        conn_id=conn_id, msg_type=MessageType.AUTH, flags=flags, payload=payload
    )
    # Отправляем сообщение
    Protocol.send(sock=sock, msg=msg)


def read_download_msg(sock: socket.socket) -> Message:
    """
    Прочитать из сокета сообщение типа DOWNLOAD.

    Args:
        sock (socket.socket): Сокет соединения

    Returns:
        Message: Прочитанное сообщение
    """
    logger.debug(
        "Reading DOWNLOAD message from socket", extra={"socket": sock.__repr__()}
    )
    # Получаем сообщение
    msg = Protocol.read(sock=sock)
    # Проверяем тип в заголовке
    if msg.msg_type != MessageType.DOWNLOAD:
        logger.error(
            "Readed message contains wrong type",
            extra={"socket": sock.__repr__(), "msg_type": msg.msg_type},
        )
        raise ProtocolException("Bad message type")

    return msg


def send_download_msg(
    sock: socket.socket, conn_id: uuid.UUID, flags: int, payload: bytes
) -> None:
    """
    Отправить в сокет сообщение типа DOWNLOAD.

    Args:
        sock (socket.socket): Сокет соединения
        conn_id (uuid.UUID): Идентификатор соединения
        flags (int): Управляющие биты
        payload (bytes): Полезная нагрузка
    """
    logger.info("Sending DOWNLOAD message to socket", extra={"socket": sock.__repr__()})
    # Создаём сообщение
    msg = Message(
        conn_id=conn_id, msg_type=MessageType.DOWNLOAD, flags=flags, payload=payload
    )
    # Отправляем сообщение
    Protocol.send(sock=sock, msg=msg)
