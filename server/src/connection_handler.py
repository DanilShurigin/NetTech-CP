import socket
import threading
import logging
import uuid
import atomics
import os

from db import get_user_database
from filesystem import get_filesystem
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


logger = logging.getLogger("server.conn_handler")

# Размер блока передаваемого файла
FILE_CHUNK_SIZE = 4096
# Максимальное количество одновременных подключений
MAX_THREADS = 3
# Счётчик активных подключений
threads_counter = atomics.atomic(width=4, atype=atomics.INT)


class ConnectionHandler(threading.Thread):
    """
    Обработчик входящего подключения.
    """

    def __init__(
        self, conn_socket: socket.socket, conn_addr: socket._RetAddress
    ) -> None:
        """
        Инициализировать обработчик.

        Args:
            conn_socket (socket.socket): Сокет, через который установлено соединение с клиентом.
            conn_addr (socket._RetAddress): Удаленный адрес клиента
        """
        # Инициализация потока
        super().__init__()

        self._conn_socket = conn_socket
        self._conn_addr = conn_addr
        self._is_declined = (
            threads_counter.load() >= MAX_THREADS
        )  # Нужно ли закрыть соединение из-за ограничений
        # по макс. кол-ву одновременно поддерживаемых соединений
        self._id = uuid.uuid4()  # Уникальный ID этого подключения
        self._is_authenticated = False  # Аутентифицирован ли клиент в этом подключении

        threads_counter.inc()

        logger.debug(
            "Connection handler initialized",
            extra={
                "UUID": self._id,
                "remote_addr": conn_addr,
                "thread_name": self._name,
                "is_declined": self._is_declined,
            },
        )

        logger.debug(
            "Threads stats (in-use / total): %d / %d",
            threads_counter.load(),
            MAX_THREADS,
        )

    def start(self) -> None:
        """
        Запустить обработку подключения в отдельном потоке.
        """
        logger.info(
            "Processing connection in separated thread",
            extra={"UUID": self._id, "remote_addr": self._conn_addr},
        )

        return super().start()

    def run(self) -> None:
        """
        Запустить обработку потока.
        """
        try:
            # Ожидаем получение сообщения CONN с нулевым полем conn_id
            message = None
            try:
                message = read_connection_msg(self._conn_socket)
            except ProtocolException:
                logger.info(
                    "Client does not send initial message", extra={"UUID": self._id}
                )
                raise

            # Проверяем, что conn_id действительно нулевой, иначе завершаем соединение ошибкой.
            if message.conn_id != b"\x00" * 16:
                send_error_info_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0b00000001,
                    payload="Wrong initial message format".encode(),
                )
                logger.info(
                    "Client send wrong formatted initial message",
                    extra={"UUID": self._id},
                )
                return

            # Отправляем сообщение о невозможности подключения, если `is_declined`
            if self._is_declined:
                send_error_info_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0b00000001,
                    payload="Server is busy".encode(),
                )
                logger.info(
                    "Connection declined due to server business",
                    extra={"UUID": self._id},
                )
                return

            # Отправляем клиенту идентификатор соединения
            send_connection_msg(
                sock=self._conn_socket,
                conn_id=self._id,
                flags=0b00000001,
                payload="".encode(),
            )

            # Обрабатываем диалог после установления соединения на уровне протокола
            while True:
                # Читаем сообщение из сокета и закрываем соединение,
                # если клиент больше не присылает сообщения.
                try:
                    message = Protocol.read(sock=self._conn_socket)
                except ProtocolException:
                    logger.error(
                        "Unable to handle incoming operation message",
                        extra={"UUID": self._id},
                        exc_info=True,
                    )
                    raise

                # Проверяем соответствие conn_id в запросе с id соединения
                if message.conn_id != self._id.bytes:
                    logger.info(
                        "Wrong conn_id in received message", extra={"UUID": self._id}
                    )
                    send_error_info_msg(
                        sock=self._conn_socket,
                        conn_id=self._id,
                        flags=0b00000001,
                        payload="Wrong conn_id for this connection".encode(),
                    )
                    return

                # Обрабатываем запрос
                if message.msg_type == MessageType.REGISTER:
                    logger.info("Processing REGISTER request", extra={"UUID": self._id})
                    self.register_client(message=message)
                elif message.msg_type == MessageType.AUTH:
                    logger.info("Processing AUTH request", extra={"UUID": self._id})
                    self.authenticate_client(message=message)
                elif message.msg_type == MessageType.DOWNLOAD:
                    logger.info("Processing DOWNLOAD request", extra={"UUID": self._id})
                    self.upload_file(message=message)
                else:
                    logger.info(
                        "Unknown message type received",
                        extra={"UUID": self._id, "msg_type": message.msg_type},
                    )
                    send_error_info_msg(
                        sock=self._conn_socket,
                        conn_id=self._id,
                        flags=0b00000001,
                        payload="Unknown operation".encode(),
                    )

        except ProtocolException:
            logger.error(
                "Connection processing error", extra={"UUID": self._id}, exc_info=True
            )
            send_error_info_msg(
                sock=self._conn_socket,
                conn_id=self._id,
                flags=0b00000001,
                payload="Internal error".encode(),
            )

        finally:
            # Avoid a refcycle if the thread is running a function with
            # an argument that has a member that points to the thread.
            del self._target, self._args, self._kwargs

            self._conn_socket.close()
            threads_counter.dec()

            logger.info("Connection closed", extra={"UUID": self._id})

    def register_client(self, message: Message) -> None:
        """
        Провести регистрацию клиента.

        Args:
            message (Message): Сообщение от клиента.
        """
        try:
            # Получаем имя пользователя из сообщения
            login = message.payload.decode()
            logger.info(
                "User '%s' requested registration", login, extra={"UUID": self._id}
            )

            # Проверяем пользователя на наличие записи в БД.
            # Если запись есть, повторная регистрация запрещена
            if get_user_database().user_exists(login):
                logger.info(
                    "User '%s' already exists in users DB",
                    login,
                    extra={"UUID": self._id},
                )
                send_error_info_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0b00000001,
                    payload="Already exists".encode(),
                )
                return

            # Генерируем соль и отправляем её клиенту.
            salt = os.urandom(32)
            send_register_msg(
                sock=self._conn_socket,
                conn_id=self._id,
                flags=0b00000001,
                payload=salt,
            )
            logger.debug("SALT sended to client", extra={"UUID": self._id})

            # Получаем от клиента "посоленный" хэш пароля
            message = read_register_msg(sock=self._conn_socket)
            passwd_hash = message.payload
            logger.debug(
                "Received password hash for user '%s'", login, extra={"UUID": self._id}
            )

            # Сохраняем нового пользователя в БД
            if not get_user_database().add_user(login, salt, passwd_hash):
                send_error_info_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0b00000001,
                    payload="Not registered".encode(),
                )
                logger.error("Registration failed", extra={"UUID": self._id})
                return

            self._is_authenticated = True
            send_success_info_msg(
                sock=self._conn_socket,
                conn_id=self._id,
                flags=0b00000001,
                payload="Registered".encode(),
            )
            logger.info("User '%s' successfully registered", extra={"UUID": self._id})

        except ProtocolException as err:
            logger.error(
                "Unable to register client", extra={"UUID": self._id}, exc_info=True
            )
            return

    def authenticate_client(self, message: Message) -> None:
        """
        Провести аутентификацию клиента.

        Args:
            message (Message): Сообщение от клиента.
        """
        try:
            # Получаем имя пользователя из сообщения
            login = message.payload.decode()
            logger.info(
                "User '%s' requested authentication", login, extra={"UUID": self._id}
            )

            # Проверяем пользователя на наличие записи в БД.
            # Если записи нет, аутентификация запрещена без регистрации
            if not get_user_database().user_exists(login):
                logger.info(
                    "User '%s' does not exist in users DB",
                    login,
                    extra={"UUID": self._id},
                )
                send_error_info_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0b00000001,
                    payload="Does not exists".encode(),
                )
                return

            # Достаем из БД соль
            salt = get_user_database().get_user_salt(login)
            if salt is None:
                logger.error(
                    "Failed to retrive SALT from users DB", extra={"UUID": self._id}
                )
                send_error_info_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0b00000001,
                    payload="Not authenticated".encode(),
                )
                return

            # Отправляем соль клиенту
            send_register_msg(
                sock=self._conn_socket,
                conn_id=self._id,
                flags=0b00000001,
                payload=salt,
            )
            logger.debug("SALT sended to client", extra={"UUID": self._id})

            # Получаем от клиента "посоленный" хэш пароля
            message = read_register_msg(sock=self._conn_socket)
            passwd_hash = message.payload
            logger.debug(
                "Received password hash for user '%s'", login, extra={"UUID": self._id}
            )

            # Получаем из БД хэшированный пароль клиента
            stored_passwd_hash = get_user_database().get_user_password_hash(login)
            if stored_passwd_hash is None:
                logger.error(
                    "Failed to retrive PASSWORD from users DB", extra={"UUID": self._id}
                )
                send_error_info_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0b00000001,
                    payload="Not authenticated".encode(),
                )
                return

            # Проверяем совпадение двух хэшей
            if stored_passwd_hash != passwd_hash:
                send_error_info_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0b00000001,
                    payload="Not authenticated".encode(),
                )
                logger.error("Authentication failed", extra={"UUID": self._id})
                return

            self._is_authenticated = True
            send_success_info_msg(
                sock=self._conn_socket,
                conn_id=self._id,
                flags=0b00000001,
                payload="Authenticated".encode(),
            )
            logger.info(
                "User '%s' successfully authenticated", extra={"UUID": self._id}
            )

        except ProtocolException as err:
            logger.error(
                "Unable to authenticate client", extra={"UUID": self._id}, exc_info=True
            )
            return

    def upload_file(self, message: Message) -> None:
        """
        Отправить клиенту запрощенный файл.

        Args:
            message (Message): Сообщение от клиента.
        """
        try:
            # Получаем путь к файлу из сообщения
            filepath = message.payload.decode()
            logger.info(
                "Client requested file uploading",
                extra={"UUID": self._id, "filepath": filepath},
            )

            # Проверяем правильность пути к файлу
            if filepath != get_filesystem().clear_filepath(filepath):
                logger.info(
                    "Received filepath counted as dangerous", extra={"UUID": self._id}
                )
                send_error_info_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0b00000001,
                    payload="Dangerous filepath".encode(),
                )
                return

            # Получаем размер файла
            try:
                file_size = get_filesystem().get_file_size(filepath)
                logger.debug(
                    "Requested file stats",
                    extra={"UUID": self._id, "filepath": filepath, "size": file_size},
                )
            except FileNotFoundError:
                logger.error(
                    "Requested file does not exist",
                    extra={"UUID": self._id},
                    exc_info=True,
                )
                send_error_info_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0b00000001,
                    payload="File does not exists".encode(),
                )
                return
            
            # Отправляем клиенту размер файла
            send_download_msg(
                sock=self._conn_socket,
                conn_id=self._id,
                flags=0b00000001,
                payload=str(file_size).encode(),
            )
            logger.debug("File size sended to client", extra={"UUID": self._id})

            # Ждём сообщения о готовности принимать файл
            message = read_download_msg(sock=self._conn_socket)
            if message.payload.decode() != "OK":
                logger.info(
                    "Client is not ready",
                    extra={"UUID": self._id, "reply": message.payload},
                )
                return

            # Отправляем файл частями и хэш файла в конце
            try:
                sent_bytes = 0
                for chunk in get_filesystem().read_file_in_chunks(filepath, FILE_CHUNK_SIZE):
                    send_download_msg(
                        sock=self._conn_socket,
                        conn_id=self._id,
                        flags=0b00010001,
                        payload=chunk,
                    )
                    logger.debug("File chunk sended", extra={"UUID": self._id})
                
                # Отправляем хэш файла
                file_hash = get_filesystem().calc_file_hash(filepath)
                send_download_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0b00010001,
                    payload=file_hash,
                )
                logger.debug("File hash sended", extra={"UUID": self._id, "hash": file_hash.hex()})

            except IOError as io_err:
                logger.error(
                    "Unable to interact with file",
                    extra={"UUID": self._id},
                    exc_info=True,
                )
                send_error_info_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0b00000001,
                    payload="Unable to interact with file".encode(),
                )
                raise ProtocolException("Unable to interact with file")
            
            logger.info("File transfer completed", extra={"UUID": self._id})

        except ProtocolException as err:
            logger.error(
                "Unable to upload file to client",
                extra={"UUID": self._id},
                exc_info=True,
            )
            return
