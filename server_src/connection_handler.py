import socket
import threading
import logging
import uuid
import atomics
import os

from .db import get_user_database
from .filesystem import get_filesystem
from .ui import get_server_ui

from lib.protocol import (
    Protocol,
    Message,
    MessageType,
    ProtocolException,
    BadMessageType,
)
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

    def __init__(self, conn_socket: socket.socket, conn_addr: tuple[str, int]) -> None:
        """
        Инициализировать обработчик.

        Args:
            conn_socket (socket.socket): Сокет, через который установлено соединение с клиентом.
            conn_addr (tuple[str, int]): Удаленный адрес клиента
        """
        # Инициализация потока
        super().__init__(daemon=True)

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
            # Добавляем клиента в таблицу
            get_server_ui().add_client(self._id.bytes, self._conn_addr, "anonymous")

            # Устанавливаем соединение. Если не удалось, закрываем канал.
            if not self.connect_client():
                return
            message = None

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

        except ConnectionError:
            logger.error(
                "Critical connection error", extra={"UUID": self._id}, exc_info=True
            )
        except:
            logger.error(
                "Connection processing error", extra={"UUID": self._id}, exc_info=True
            )
            try:
                send_error_info_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0b00000001,
                    payload="Internal error".encode(),
                )
            except:
                pass

        finally:
            # Avoid a refcycle if the thread is running a function with
            # an argument that has a member that points to the thread.
            del self._target, self._args, self._kwargs

            self._conn_socket.close()
            get_server_ui().remove_client(self._id.bytes)
            threads_counter.dec()

            logger.info("Connection closed", extra={"UUID": self._id})

    def connect_client(self) -> bool:
        """
        Установить соединение с клиентом.
        """
        # Ожидаем получение сообщения CONN с нулевым полем conn_id
        message = None
        try:
            message = read_connection_msg(self._conn_socket)

        except BadMessageType:
            logger.info(
                "Client sent wrong typed initial message",
                extra={"UUID": self._id},
                exc_info=True,
            )
            return False

        except ProtocolException:
            logger.info(
                "Client does not send initial message", extra={"UUID": self._id}
            )
            raise ConnectionError()

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
            return False

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
            return False

        # Отправляем клиенту идентификатор соединения
        send_connection_msg(
            sock=self._conn_socket,
            conn_id=self._id,
            flags=0b00000001,
            payload="".encode(),
        )

        return True

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

            # Запрещена регистрация для пользователей с именем anonymous
            if login == "anonymous":
                logger.info(
                    "User cannot use this name",
                    extra={"UUID": self._id},
                )
                send_error_info_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0b00000001,
                    payload="Reserved name".encode(),
                )
                return

            # Если пользователь уже аутентифицирован, отправляем успех
            if self._is_authenticated:
                logger.info("User already authenticated", extra={"UUID": self._id})
                send_success_info_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0x01,
                    payload="Authenticated",
                )
                return

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
            logger.debug("SALT sent to client", extra={"UUID": self._id})

            # Получаем от клиента "посоленный" хэш пароля
            message = read_register_msg(sock=self._conn_socket)
            passwd_hash = message.payload
            logger.debug(
                "Password hash received for user '%s'", login, extra={"UUID": self._id}
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
                payload="Authenticated".encode(),
            )
            get_server_ui().update_client(self._id.bytes, user=login)
            logger.info("User '%s' successfully registered", extra={"UUID": self._id})

        except BadMessageType:
            logger.info(
                "Client sent wrong typed message",
                extra={"UUID": self._id},
                exc_info=True,
            )
            send_error_info_msg(self._conn_socket, self._id, 0x01, b"Bad message type")
            return

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

            # Запрещена аутентификация для пользователей с именем anonymous
            if login == "anonymous":
                logger.info(
                    "User cannot use this name",
                    login,
                    extra={"UUID": self._id},
                )
                send_error_info_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0b00000001,
                    payload="Reserved name".encode(),
                )
                return
            
            # Если пользователь уже аутентифицирован, отправляем успех
            if self._is_authenticated:
                logger.info("User already authenticated", extra={"UUID": self._id})
                send_success_info_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0x01,
                    payload="Authenticated",
                )
                return

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
            logger.debug("SALT sent to client", extra={"UUID": self._id})

            # Получаем от клиента "посоленный" хэш пароля
            message = read_register_msg(sock=self._conn_socket)
            passwd_hash = message.payload
            logger.debug(
                "Password hash received for user '%s'", login, extra={"UUID": self._id}
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
                logger.error("Not authenticated", extra={"UUID": self._id})
                return

            self._is_authenticated = True
            send_success_info_msg(
                sock=self._conn_socket,
                conn_id=self._id,
                flags=0b00000001,
                payload="Authenticated".encode(),
            )
            get_server_ui().update_client(self._id.bytes, user=login)
            logger.info(
                "User '%s' successfully authenticated", extra={"UUID": self._id}
            )
        
        except BadMessageType:
            logger.info(
                "Client sent wrong typed message",
                extra={"UUID": self._id},
                exc_info=True,
            )
            send_error_info_msg(self._conn_socket, self._id, 0x01, b"Bad message type")
            return
        
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
            # Нельзя работать с файлами, если не пройдена аутентификация
            if not self._is_authenticated:
                logger.info(
                    "Client is not authenticated yet",
                    extra={"UUID": self._id},
                )
                send_error_info_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0b00000001,
                    payload="Not authorized".encode(),
                )
                return
            
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
                    payload="Not exists".encode(),
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

            get_server_ui().update_client(
                self._id.bytes, filepath=filepath, progress=0.0
            )

            # Отправляем файл частями и хэш файла в конце
            try:
                sent_bytes = 0
                for chunk in get_filesystem().read_file_in_chunks(
                    filepath, FILE_CHUNK_SIZE
                ):
                    send_download_msg(
                        sock=self._conn_socket,
                        conn_id=self._id,
                        flags=0b00010001,
                        payload=chunk,
                    )
                    sent_bytes += len(chunk)
                    get_server_ui().update_client(
                        self._id.bytes, progress=(sent_bytes / file_size)
                    )
                    logger.debug("File chunk sended", extra={"UUID": self._id, "progress": (sent_bytes / file_size)})

                # Отправляем хэш файла
                file_hash = get_filesystem().calc_file_hash(filepath)
                send_download_msg(
                    sock=self._conn_socket,
                    conn_id=self._id,
                    flags=0b00000001,
                    payload=file_hash,
                )
                logger.debug(
                    "File hash sended",
                    extra={"UUID": self._id, "hash": file_hash.hex()},
                )

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

        except BadMessageType:
            logger.info(
                "Client sent wrong typed message",
                extra={"UUID": self._id},
                exc_info=True,
            )
            send_error_info_msg(self._conn_socket, self._id, 0x01, b"Bad message type")
            return
        
        except ProtocolException as err:
            logger.error(
                "Unable to upload file to client",
                extra={"UUID": self._id},
                exc_info=True,
            )
            return
