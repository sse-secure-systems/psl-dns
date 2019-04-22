import logging

LOG_LEVELS = {0: logging.WARNING,
              1: logging.INFO,
              2: logging.DEBUG,}


class PSLBase():
    def __init__(self, *args, **kwargs):
        log_level = kwargs.pop('log_level', None)
        log_level = LOG_LEVELS.get(log_level) or LOG_LEVELS[0]
        logging.basicConfig(level=log_level)

        self.logger = logging.getLogger('psl')