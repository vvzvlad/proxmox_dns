import logging

from colorama import Fore, Style, init

from src.settings import settings

init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.ERROR:
            record.msg = f"{Fore.RED}{record.msg}{Style.RESET_ALL}"
        elif record.levelno == logging.WARNING:
            record.msg = f"{Fore.YELLOW}{record.msg}{Style.RESET_ALL}"
        elif record.levelno == logging.INFO:
            record.msg = f"{Fore.GREEN}{record.msg}{Style.RESET_ALL}"
        return super().format(record)


def setup_logger() -> logging.Logger:
    logger_t = logging.getLogger("mdns_proxy")
    logger_t.setLevel(logging.getLevelName(settings.log_level.upper()))
    console_handler = logging.StreamHandler()
    # Let the logger level (from LOG_LEVEL) be the single gate; do not cap the handler,
    # otherwise LOG_LEVEL=DEBUG would still be filtered out here.
    console_handler.setFormatter(
        ColoredFormatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )
    logger_t.addHandler(console_handler)
    return logger_t


logger = setup_logger()
