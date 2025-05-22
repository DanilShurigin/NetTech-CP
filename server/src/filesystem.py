import os
import logging
import hashlib
from pathlib import Path


logger = logging.getLogger("server.filesystem")


class FileSystem:
    """
    Файловая система сервера.
    """

    def __init__(self, files_dir: str = "server_files") -> None:
        """
        Инициалировать клиент файловой системы сервера.

        Args:
            files_dir (str, optional): Путь к папке с файлами, из которой файлы будут
                                       раздаваться клиентам (по умолчанию "./server_files").
        """
        self._dir = files_dir
        # Создаём папку, если такой ещё нет.
        os.makedirs(files_dir, exist_ok=True)
        logger.info("Files dir established", extra={"dir": files_dir})
    
    @staticmethod
    def clear_filepath(filepath: str) -> str:
        """
        Очистить путь к файлу от вредных частей.

        Удаляет `.` и/или `/` из начала пути.

        Args:
            filepath (str): Путь к файлу

        Returns:
            str: Чистый путь к файлу
        """
        path = Path(filepath)
        parts = []
        for part in path.parts:
            if part in ('.', '..', '/'):
                continue
            parts.append(part)
        
        return str(Path(*parts).as_posix())

    def calc_file_hash(self, filepath: str) -> bytes:
        """
        Вычислить SHA-256 хэш файла в папке раздачи.

        Args:
            filepath (str): Путь к файлу

        Returns:
            bytes: SHA-256 хэш файла в виде потока байт
        
        Raises:
            IOError: Не удалось вычислить хэш для файла
        """
        filepath = self.clear_filepath(filepath)

        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                # Читаем из файла блок
                # Добавляем его к хэшу
                while chunk := f.read(8192):
                    sha256.update(chunk)
            # Получаем полный хэш от файла
            file_hash = sha256.digest()
            logger.debug("Hash calculated", extra={"filepath": filepath, "hash": file_hash})

            return file_hash
        
        except IOError as err:
            logger.error("Failed to calculate file hash", extra={"filepath": filepath}, exc_info=True)
            raise
    
    def get_file_size(self, filepath: str) -> int:
        """
        Получить размер файла.

        Args:
            filepath (str): Путь к файлу

        Returns:
            int: Размер файла в байтах
        """
        filepath = self.clear_filepath(filepath)

        return Path(filepath).stat().st_size

    def read_file_in_chunks(self, filepath: str, chunk_size: int = 1024):
        """
        Читать файл блоками по `chunk_size` байт.

        Args:
            filepath (str): Путь к файлу
            chunk_size (int, optional): Размер блока в байтах (1024 по умолчанию).

        Returns:
            bytes: Прочитанный блок
        
        Rises:
            IOError: Не удалось прочитать файл
        """
        filepath = self.clear_filepath(filepath)

        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(chunk_size):
                    yield chunk
        
        except IOError as err:
            logger.error("Failed to read file", extra={"filepath": filepath}, exc_info=True)
            raise   

_filesystem_instance = None

def get_filesystem(files_dir: str = None) -> FileSystem:
    """
    Вернуть объект файловой системы сервера.

    Args:
        files_dir (str): Путь к папке с файлами, из которой файлы будут
                         раздаваться клиентам (по умолчанию "server_fil

    Returns:
        UserDatabase: База данных пользователей
    """
    if _filesystem_instance is None and files_dir is not None:
        _filesystem_instance = FileSystem(files_dir)
    elif _filesystem_instance is None and files_dir is None:
        _filesystem_instance = FileSystem()
    
    return _filesystem_instance
