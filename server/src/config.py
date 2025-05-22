import argparse

class CmdLineParser(argparse.ArgumentParser):
    """
    Прасер параметров командной строки.
    """
    def __init__(self, ):
        super().__init__(description="Серверное приложение для аутентификации и передачи файлов")

        # Объявляем параметры
        self.add_argument(
            "-p",
            "--local-port",
            type=int,
            default=33333,
            help="Локальный порт для запуска сервера (по умолчанию: 33333)",
        )

        self.add_argument(
            "--db",
            type=str,
            required=True,
            help="Путь к файлу БД с аутентификационными данными пользователей",
        )

        self.add_argument(
            "--shared-folder",
            type=str,
            required=True,
            help="Путь к каталогу с файлами для раздачи",
        )

        self.add_argument(
            "--log",
            type=str,
            required=True,
            help="Путь к файлу для записи логов",
        )

        self.add_argument(
            "--log-level",
            type=str,
            default="info",
            choices=["debug", "info", "warning", "error", "critical"],
            help="Уровень логирования (по умолчанию: info)",
        )


def load_config() -> argparse.Namespace:
    """
    Получить конфигурацию для сервера.

    Returns:
        dict: Параметры конфигурации {"параметр": "значение"}.
    """
    parser = CmdLineParser()

    cmd_params = parser.parse_args()
    
    return cmd_params
