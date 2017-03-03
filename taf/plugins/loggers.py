# Copyright (c) 2011 - 2017, Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""``loggers.py``

`logging functionality for TAF`

"""

import errno
import inspect
import logging
import argparse
import os
import re
import sys
from threading import Thread


class NoErrArgumentParser(argparse.ArgumentParser):
    """ArgumentParser class that handle only predefined for an instance options.

    Note:
        The original ArgumentParser class raises an error if handle unknown option.
        But py.test have it's own options and it's own custom parser and if ArgumentParser find them it raises an error.
        Using this class allows not to define all possible options in each module that uses ArgumentParser.

    """

    def __init__(self, *args, **kwargs):
        """Initialize NoErrArgumentParser class.

        """
        self.valid_args_cre_list = []
        argparse.ArgumentParser.__init__(self, *args, **kwargs)

    def add_argument(self, *args, **kwargs):
        """Add arguments and save regexps of valid for the instance options in valid_args_cre_list.

        """
        self.valid_args_cre_list.append(re.compile("^{0}".format(args[0])))
        argparse.ArgumentParser.add_argument(self, *args, **kwargs)

    def parse_args(self, *args, **kwargs):
        """Filter out invalid options and parse only predefined ones for the instance.

        """
        if len(args) > 0:
            args_to_parse = args[0]
        else:
            args_to_parse = sys.argv[1:]
        new_args_to_parse = []

        short_arg = False
        for _a in args_to_parse:
            if short_arg:
                new_args_to_parse.append(_a)
                short_arg = False
                continue
            else:
                for cre in self.valid_args_cre_list:
                    if cre.match(_a):
                        new_args_to_parse.append(_a)
                        if _a[:2] != "--":
                            short_arg = True

        return argparse.ArgumentParser.parse_args(self, new_args_to_parse)


def parse_options():
    """Parse additional cli logging options.

    """
    parser = NoErrArgumentParser(usage=argparse.SUPPRESS, formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("--logdir", dest="logdir", default=None,
                      help="Directory path to store log files.")
    parser.add_argument("--loglevel", dest="loglevel", default="INFO",
                      help="Logging level (DEBUG, INFO, WARNING, ERROR, FATAL, CRITICAL).")
    parser.add_argument("--logprefix", dest="logprefix", default="main",
                      help="Log files prefix.")
    parser.add_argument("--silent", action="store_true", dest="silent", default=False,
                      help="Do not print logging to console.")
    parser.add_argument("-k", action="store", dest="keyword", default=None,
                      help="pytest kewords.")
    parser.add_argument("-m", action="store", dest="markexpr", default=None,
                      help="pytest markers expression.")

    opts = parser.parse_args()

    if opts.markexpr is None:
        opts.markexpr = ""
    if opts.keyword is None:
        opts.keyword = ""

    return opts


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


# Global loggers properties
_OPTS = parse_options()

LOG_PREFIX = _OPTS.logprefix
LOG_DIR = os.path.normpath(os.path.expandvars(os.path.expanduser(_OPTS.logdir))) if _OPTS.logdir is not None else None
# Create logdir if one
if LOG_DIR is not None:
    mkdir_p(LOG_DIR)

# Set file name of main log.
_SUFFIX = "-".join([_OPTS.markexpr.replace(" ", "_"),
                    _OPTS.keyword.replace(" ", "_")])
_SELF_PID = str(os.getpid())
_LOGNAME = ".".join([LOG_PREFIX, _SUFFIX, _SELF_PID, "log"])
LOG_FILENAME = os.path.normpath(os.path.join(LOG_DIR, _LOGNAME)) if LOG_DIR is not None else None

LOG_LEVEL = _OPTS.loglevel
LOG_STREAM = not _OPTS.silent

# Add additional log level.
logging.TRACE = 9
logging.addLevelName(logging.TRACE, "TRACE")

# Logging levels
# Obsolete style
levels = {'CRITICAL': logging.CRITICAL,
          'FATAL': logging.FATAL,
          'ERROR': logging.ERROR,
          'WARNING': logging.WARNING,
          'WARN': logging.WARN,
          'INFO': logging.INFO,
          'DEBUG': logging.DEBUG,
          'NOTSET': logging.NOTSET,
          "TRACE": logging.TRACE}

del _OPTS


class ClassLogger(object):
    """Class logger descriptor.

    """

    def __init__(self, log_level=LOG_LEVEL, log_file=LOG_FILENAME, log_stream=LOG_STREAM, for_exception=False, introspection=True):
        """Initialize instance of ClassLogger.

        Args:
            log_level (str): Log level value.
            log_file (str):  Path to log file.
            log_stream (bool):  Log stream value.
            for_exception (bool):  True for exception information.
            introspection (bool):  True for extended information.

        """
        self._logger = None
        self.for_exception = for_exception
        self.log_file = log_file
        self.log_level = log_level
        if introspection:
            if self.for_exception:
                self.log_formatter = \
                    logging.Formatter("%(asctime)s : %(threadName)s : %(levelname)s : [%(caller_module)s.%(caller_class)s%(caller_func)s] - %(message)s")
            else:
                self.log_formatter = logging.Formatter("%(asctime)s : %(threadName)s : %(levelname)s : [%(module)s.%(classname)s%(funcName)s] - %(message)s")
        else:
            self.log_formatter = logging.Formatter("%(asctime)s : %(threadName)s : %(levelname)s : [%(name)s] - %(message)s")
        self.log_stream = log_stream
        self._log_stream_handler = None
        self._log_file_handler = None
        self._logger_adapter = None

    def __get__(self, instance, owner):
        """This method is called from class.

        Args:
            owner (owner):  class instance.

        Returns:
             logging.LoggerAdapter:  logger adaptor.

        Note:
            In case using logger for module level use get() method. __get__() won't be called from module level.

        """
        if self.for_exception:
            caller_frame = inspect.stack()[2]
            module_name = inspect.getmodulename(caller_frame[1])
            func_name = caller_frame[3]
            try:
                class_name = caller_frame[0].f_locals["self"].__class__.__name__
            except KeyError:
                class_name = ""
            _logger_adaptor = self._get_logger(module_name, class_name, func_name)
        else:
            _logger_adaptor = self._get_logger(owner.__module__, owner.__name__)
        return _logger_adaptor

    def _get_logger(self, modulename, classname="", caller_func=""):
        """Configure and return loggerAdapter instance.

        Args:
            modulename (str):  module name.
            classname (str):  class name.
            caller_func (str):  function name.

        Returns:
            logging.LoggerAdapter: logger adaptor.

        """
        if classname:
            classname = "{0}.".format(classname)
        if self._logger is None or self._logger.name != modulename:
            self._logger = logging.getLogger(modulename)
            self._logger.setLevel(getattr(logging, self.log_level))
            if self.log_stream:
                present_stream_handlers = [_h for _h in self._logger.handlers if isinstance(_h, logging.StreamHandler)]
                if not present_stream_handlers:
                    self._log_stream_handler = logging.StreamHandler(sys.stdout)
                    self._log_stream_handler.setFormatter(self.log_formatter)
                    self._logger.addHandler(self._log_stream_handler)
            if self.log_file:
                present_file_handlers = [_h for _h in self._logger.handlers if isinstance(_h, logging.FileHandler)]
                if not present_file_handlers:
                    self._log_file_handler = logging.FileHandler(self.log_file)
                    self._log_file_handler.setFormatter(self.log_formatter)
                    self._logger.addHandler(self._log_file_handler)
            if self.for_exception:
                self._logger_adapter = logging.LoggerAdapter(self._logger, {'caller_module': modulename, 'caller_func': caller_func, 'caller_class': classname})
            else:
                self._logger_adapter = logging.LoggerAdapter(self._logger, {'classname': classname})
        return self._logger_adapter

    def get(self, modulename, classname=""):
        """Return logerAdapter instance for module level logging.

        Args:
            modulename (str):  module name.
            classname (str):  class name.

        Returns:
            logging.LoggerAdapter:  logger adaptor.

        """
        _logger_adaptor = self._get_logger(modulename, classname)
        return _logger_adaptor


class LoggerWrapper(Thread):
    """Read text message from a pipe and redirect them to a logger.

    Note:
        The object itself is able to supply a file descriptor to be used for writing.
        fdWrite ==> fdRead ==> pipeReader.

    """

    def __init__(self, logger, level):
        """Setup the object with a logger and a loglevel and start the thread.

        """
        # Initialize the superclass
        super(LoggerWrapper, self).__init__()
        # Make the thread a Daemon Thread (program will exit when only daemon threads are alive)
        self.daemon = True
        # Set the logger object where messages will be redirected
        self.logger = logger
        # Set the log level
        self.level = level
        # Create the pipe and store read and write file descriptors
        self.fd_read, self.fd_write = os.pipe()
        # Create a file-like wrapper around the read file descriptor of the pipe, this has been done to simplify read operations
        self.pipe_reader = os.fdopen(self.fd_read)
        # Start the thread
        self.start()

    def fileno(self):
        """Return the write file descriptor of the pipe.

        """
        return self.fd_write

    def run(self):
        """This is the method executed by the thread, it simply read from the pipe (using a file-like wrapper) and write the text to log.

        Note:
            NB the trailing newline character of the string read from the pipe is removed.

        """
        # Endless loop, the method will exit this loop only when the pipe is close that is when a call to self.pipeReader.readline() returns an empty string
        while True:
            # Read a line of text from the pipe
            message_from_pipe = self.pipe_reader.readline()
            # If the line read is empty the pipe has been closed, do a cleanup and exit
            if not message_from_pipe:
                self.pipe_reader.close()
                os.close(self.fd_read)
                return
            # Remove the trailing newline character from the string before sending it to the logger
            if message_from_pipe[-1] == os.linesep:
                message_to_log = message_from_pipe[:-1]
            else:
                message_to_log = message_from_pipe
            # Send the text to the logger
            self._write(message_to_log)
        # This message should not be printed in normal condition.
        print(">" * 50, "Redirection thread terminated.")

    def _write(self, message):
        """Utility method to send the message to the logger with the correct loglevel.

        """
        self.logger.log(self.level, message)


def module_logger(name="", clsname=""):
    """Return LoggerAdapter for module level logging.

    """
    return ClassLogger().get(name, clsname)


def pipe_loggers(name, log_file):
    """Return LoggerWrapper for pipe logging.

    """
    log_file = os.path.join(LOG_DIR, log_file) if LOG_DIR is not None else None
    logger = ClassLogger(log_file=log_file, introspection=False).get(name)
    log_wrap_out = LoggerWrapper(logger, logging.INFO)
    log_wrap_err = LoggerWrapper(logger, logging.ERROR)
    return log_wrap_out, log_wrap_err
