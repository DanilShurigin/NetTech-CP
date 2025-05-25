import logging
import os
import threading
import sys
import time

logger = logging.getLogger("server.ui")

PROGRESS_BAR_SYMBOLS = "_▁▂▃▄▅▆▇█"
MIN_CONSOLE_WIDTH = 85

class ServerUI:
    """
    Пользовательский интерфейс сервера.
    """

    def __init__(self) -> None:
        self.title = "FILE TRANSFER MANAGER"
        self.clients = {}
        self.lock = threading.Lock()
        self.table_height = 0

    @staticmethod
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
            PROGRESS_BAR_SYMBOLS[-1] * (round(percents) // 9)
            + PROGRESS_BAR_SYMBOLS[(round(percents) % 9) if percents < 100 else -1]
        )

    @staticmethod
    def _ip_out(ip_addr: str) -> str:
        """Вернуть поле `Address` таблицы"""
        return f" {ip_addr:<15} "

    @staticmethod
    def _port_out(port: int) -> str:
        """Вернуть поле `Port` таблицы"""
        return f" {port:^8} "

    @staticmethod
    def _user_out(name: str) -> str:
        """Вернуть поле `Name` таблицы"""
        return f" {name if len(name)<=10 else name[:7]+'...':^10} "

    @staticmethod
    def _file_out(filename: str, progress: float) -> str:
        """Вернуть поле `File Transfer` таблицы"""
        return f" {filename if len(filename)<=18 else '...'+filename[-15:]:<18} |{ServerUI._progress_repr(progress):<12}| {round(progress*100):>3}% "

    def _create_output(self, clients: list) -> str:
        """
        Создать текстовое представление интерфейса.

        Returns:
            str: Текст, который нужно вывести в консоль,
                 чтобы увидеть интерфейс.
        """
        terminal_columns = os.get_terminal_size().columns
        # Нельзя вывести таблицу если терминал уже MIN_CONSOLE_WIDTH
        if terminal_columns < MIN_CONSOLE_WIDTH:
            return f"Please, resize console window!\n└ Width: {terminal_columns}/{MIN_CONSOLE_WIDTH}"
        
        return (
            f"╔{'═'*65}╦{'═'*16}╗\n"
          + f"║{self.title:^65}║ Connected: {len(clients)}/3 ║\n"
          + f"╠{'═'*17}╦{'═'*10}╦{'═'*12}╦{'═'*23}╩{'═'*16}╣\n"
          + f"║{'Address':^17}║{'Port':^10}║{'User':^12}║{'File Transfer':^40}║\n"
          + f"╠{'═'*17}╬{'═'*10}╬{'═'*12}╬{'═'*40}╣\n"
          + f"╟{'╌'*17}╫{'╌'*10}╫{'╌'*12}╫{'╌'*40}╢\n".join([f"║{ServerUI._ip_out(client['address']):^17}║{ServerUI._port_out(client['port']):^10}║{ServerUI._user_out(client['user']):^12}║{ServerUI._file_out(client['file'], client["progress"]) if client['file'] else ' No active transitions':<40}║\n" for client in clients])
          + f"╚{'═'*17}╩{'═'*10}╩{'═'*12}╩{'═'*40}╝\n"
        )
    
    def _clear_previous_output(self) -> None:
        """Очистить предыдущий вывод в консоли."""
        # Очищаем строки с таблицей
        sys.stdout.write('\x1b[1A\x1b[2K'*self.table_height)
        # Переставляем курсор в начало строки
        sys.stdout.write('\x1b[0G')
        # Применяем
        sys.stdout.flush()
    
    def print(self) -> None:
        """Вывести интерфейс в консоль"""
        with self.lock:
            clients = self.clients.copy()
        
        self._clear_previous_output()
        # Пересчитываем высоту таблицы
        self.table_height = 6 + ((2 * len(clients) - 1) if len(clients) > 0 else 0)
        # Выводим новую таблицу
        sys.stdout.write(self._create_output(clients.values()))
        sys.stdout.flush()
    
    def run(self, pause_time: int) -> None:
        """Обновлять таблицу"""
        while True:
            self.print()
            time.sleep(pause_time)
    
    def add_client(self, conn_id: bytes, addr: tuple[str, int], user: str) -> None:
        """Добавить клиента в таблицу"""
        with self.lock:
            self.clients[conn_id] = {
                "address": addr[0],
                "port": addr[1],
                "user": user,
                "file": None,
                "progress": 0.0,
            }
    
    def remove_client(self, conn_id: bytes) -> None:
        """Удалить клиента из таблицы"""
        with self.lock:
            self.clients.pop(conn_id, None)

    def update_client(self, conn_id: bytes, user: str = None, filepath: str = None, progress: float = 0.0) -> None:
        """Обновить данные клиента в таблице"""
        with self.lock:
            self.clients[conn_id]["user"] = user or self.clients[conn_id]["user"]
            self.clients[conn_id]["file"] = filepath or self.clients[conn_id]["file"]
            self.clients[conn_id]["progress"] = progress or self.clients[conn_id]["progress"]


_server_ui_instance = None


def get_server_ui() -> ServerUI:
    """Получить объект интерфейса сервера"""
    global _server_ui_instance
    if _server_ui_instance is None:
        _server_ui_instance = ServerUI()
    
    return _server_ui_instance
