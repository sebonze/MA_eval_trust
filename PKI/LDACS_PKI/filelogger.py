import logging
import time
import datetime as dt
import os
from logging import Logger
from parameters import LOGGING_FILENAME


class MicrosecondFormatter(logging.Formatter):
    """
    This class is necessary to be able to format microseconds. Apparently, the normal `datefmt` of the
    logging class does not take the `%f` that usually does the job.
    """
    converter = dt.datetime.fromtimestamp

    def formatTime(self, record, datefmt=None):
        ct = self.converter(record.created)
        if datefmt:
            s = ct.strftime(datefmt)
        else:
            t = ct.strftime("%Y-%m-%d %H:%M:%S")
            s = "%s,%03d" % (t, record.msecs)
        return s


class FileLogger(object):
    logger: Logger
    verbose: bool

    def __init__(self, filename=LOGGING_FILENAME, verbose=False):
        # create folder if it doesn't exist
        folder = '/'.join(filename.split('/')[:-1])
        if not os.path.exists(folder):
            os.makedirs(folder)
        self.logger = self.create_logger(filename)
        self.verbose = verbose
        self.info(f"[filelogger] I just got created. Now I can do your logging, which I will write to {filename}. Am I "
                  f"verbose? Answer: {self.verbose}.")

    def info(self, m: str):
        if self.verbose:
            print(f"{time.strftime(f'%Y-%m-%d %H:%M:%S')} INFO {m}")
        self.logger.info(m)

    def debug(self, m: str):
        if self.verbose:
            print(f"{time.strftime(f'%Y-%m-%d %H:%M:%S')} DEBUG {m}")
        self.logger.debug(m)

    def warning(self, m: str):
        if self.verbose:
            print(f"{time.strftime(f'%Y-%m-%d %H:%M:%S')} WARNING {m}")
        self.logger.warning(m)

    def error(self, m: str):
        if self.verbose:
            print(f"{time.strftime(f'%Y-%m-%d %H:%M:%S')} ERROR {m}")
        self.logger.error(m)

    def critical(self, m: str):
        if self.verbose:
            print(f"{time.strftime(f'%Y-%m-%d %H:%M:%S')} CRITICAL {m}")
        self.logger.critical(m)

    @staticmethod
    def create_logger(filename: str = LOGGING_FILENAME):
        """
        Creates a file logger that logs everything to `filename`.
        :param filename: file where all the logs are written.
        :return: logger that logs everything.
        """
        # Create Logger
        logger: Logger = logging.getLogger()
        # Lowest level -> log everything
        logger.setLevel(logging.NOTSET)
        # Write to file
        handler = logging.FileHandler(filename=filename, mode="a", encoding="utf-8")
        logger.addHandler(handler)
        # Format such that we have microseconds
        formatter = MicrosecondFormatter(fmt='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S.%f')
        handler.setFormatter(formatter)
        return logger


if __name__ == "__main__":
    # Test the logging
    logger: FileLogger = FileLogger()
    logger.info("this is info")
    time.sleep(2)
    logger.debug("but were gonna fix the bug, aka debug")
    time.sleep(2)
    logger.warning("be cautious, this is your last warning")
    time.sleep(2)
    logger.error("I feel like we made a mistake, or was it an error?")
    time.sleep(2)
    logger.critical("Shit's going down, it's getting critical!")
