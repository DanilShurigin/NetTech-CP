import logging


def setup_logger(log_file: str, log_level: str = "info") -> logging.Logger:
    """
    Настраивает и возвращает логгер с выводом в файл и консоль.
    
    Args:
        log_file: Путь к файлу для записи логов
        log_level: Уровень логирования (debug, info, warning, error, critical)
    
    Returns:
        Настроенный логгер
    """
    LOGGING_CONFIG = {
        "version": 1,
        "loggers": {
            "": {  # root logger
                "level": log_level.upper(),
                "handlers": ["file"],
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
    logger = logging.getLogger("server")
    logger.info("Logger initialized", extra={"log_file": log_file, "log_level": log_level})
    return logger
