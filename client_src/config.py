import argparse

class CmdLineParser(argparse.ArgumentParser):
    """
    Прасер параметров командной строки.
    """
    def __init__(self, ):
        super().__init__(description="Клиентское приложение для аутентификации и передачи файлов")

        # Объявляем параметры
        self.add_argument(
            "-p",
            "--local-port",
            type=int,
            default=33332,
            help="Локальный порт для запуска клиента (по умолчанию: 33332)",
        )

        self.add_argument(
            "-H",
            "--remote-host",
            type=str,
            required=True,
            help="Хост сервера.",
        )

        self.add_argument(
            "-P",
            "--remote-port",
            type=int,
            required=True,
            help="Порт сервера.",
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
    Получить конфигурацию для клиента.

    Returns:
        dict: Параметры конфигурации {"параметр": "значение"}.
    """
    parser = CmdLineParser()

    cmd_params = parser.parse_args()
    
    return cmd_params
