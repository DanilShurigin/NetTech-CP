import logging
import logging.config


def setup_logger(log_file: str, log_level: str = "info") -> logging.Logger:
    """
    Настраивает и возвращает логгер с выводом в файл и консоль.

    Args:
        log_file (str): Путь к файлу для записи логов
        log_level (str): Уровень логирования (debug, info, warning, error, critical)

    Returns:
        logging.Logger: Настроенный логгер
    """
    LOGGING_CONFIG = {
        "version": 1,
        "loggers": {
            "": {  # root logger
                "level": log_level.upper(),
                "handlers": ["file"],
            },
            "client.conn_handler": {
                "level": log_level.upper(),
            },
            "protocol": {
                "level": log_level.upper(),
            },
        },
        "handlers": {
            "console": {
                "level": "DEBUG",
                "formatter": "json",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            },
            "file": {
                "level": "INFO",
                "formatter": "json",
                "class": "logging.FileHandler",
                "mode": "a",
                "filename": log_file,
            },
        },
        "formatters": {
            "json": {
                "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
                "format": """
                    asctime: %(asctime)s
                    name: %(name)s
                    module: %(module)s
                    levelname: %(levelname)s
                    message: %(message)s
                    exc_info: %(exc_info)s
                """,
            },
        },
    }

    logging.config.dictConfig(LOGGING_CONFIG)
    return logging.getLogger()
