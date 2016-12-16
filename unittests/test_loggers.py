"""
@copyright Copyright (c) 2011 - 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file test_loggers.py

@summary Unittests for logging functionality in TAF.
"""

import os
import threading

import pytest

from testlib import loggers
from testlib import custom_exceptions


LOG_DIR = os.path.join("/".join(__file__.split("/")[:-1]) + "/test_logs_dir")
DATAFILE = os.path.join("/".join(LOG_DIR.split("/")) + "/test_log.log")


# skip unittest if not installed pytest-capturelog plugin
@pytest.fixture()
def skip_if_no_fixture(request):
    fm = request._fixturemanager
    if "caplog" not in fm._arg2fixturedefs:
        pytest.skip("Need to install pytest-capturelog plugin for run this test")


# helper function for closing logging handlers
def remove_logger(logger):
    while logger.logger.handlers:
        logger.logger.handlers[0].flush()
        logger.logger.handlers[0].close()
        logger.logger.removeHandler(logger.logger.handlers[0])


# fixture for opening log files
@pytest.fixture()
def log_file(request):
    test_file = open(DATAFILE, 'w+')
    return test_file


# initializing fixtures for logging
@pytest.fixture()
def simple_log(request):
    logger = loggers.ClassLogger()._get_logger(request.cls.__module__, request.cls.__name__)
    request.addfinalizer(lambda: remove_logger(logger))
    return logger


@pytest.fixture()
def file_log(request):
    logger = loggers.ClassLogger(log_file=DATAFILE)._get_logger(request.cls.__module__, request.cls.__name__)
    request.addfinalizer(lambda: remove_logger(logger))
    return logger


@pytest.fixture()
def exception_log(request):
    logger = loggers.ClassLogger(for_exception=True, log_file=DATAFILE)._get_logger("test_module", "test_class", "test_function")
    request.addfinalizer(lambda: remove_logger(logger))
    return logger


@pytest.fixture()
def introspection_log(request):
    logger = loggers.ClassLogger(introspection=False, log_file=DATAFILE)._get_logger(request.cls.__module__)
    request.addfinalizer(lambda: remove_logger(logger))
    return logger


@pytest.fixture()
def module_log(request):
    logger = loggers.module_logger(request.cls.__module__, request.cls.__name__)
    request.addfinalizer(lambda: remove_logger(logger))
    return logger


class TestLogger(object):

    @classmethod
    def teardown_class(cls):
        """ Removes all created files and directory on teardown of class"""
        if os.path.isfile(DATAFILE):
            os.remove(DATAFILE)
        if os.path.isdir(LOG_DIR):
            os.rmdir(LOG_DIR)

    def test_loggers_mkdir(self):
        """ Verify that method mkdir_p creates directory."""
        loggers.mkdir_p(LOG_DIR)
        assert os.path.isdir(LOG_DIR)

    def test_loggers_options_and_mkdir(self, request):
        """ Verify that dictionary of logging options contains correct values and method mkdir_p is not creates directory if it exists."""
        loggers.mkdir_p(LOG_DIR)
        opts = loggers.parse_options()
        markexpr = request.config.option.markexpr
        logdir = loggers.LOG_DIR
        loglevel = request.config.option.loglevel
        # don't test keyword since that can be changed by py.test invocation
        # used to select this unittest
        expected = {'silent': False, 'loglevel': loglevel, 'logdir': logdir,
                    'logprefix': 'main', 'markexpr': markexpr}
        # only test the subset of expected values
        for k, v in expected.items():
            assert getattr(opts, k) == v

    def test_info_log_message(self, skip_if_no_fixture, caplog, simple_log, request):
        """ Verify that log message for level INFO contains correct values."""
        simple_log.info("test message for info")
        if "." in request.module.__name__:
            mod_name = request.module.__name__.split(".", 1)[1]
        else:
            mod_name = request.module.__name__
        # captures and verifies log messages
        for records in caplog.records():
            assert records.message == "test message for info"
            assert records.levelname == "INFO"
            assert records.module == mod_name
            assert records.classname == "TestLogger."
            assert records.funcName == "test_info_log_message"
            thread_name = threading.current_thread().name
            assert records.threadName == thread_name

    def test_error_log_message(self, skip_if_no_fixture, caplog, simple_log, request):
        """ Verify that log message for level ERROR contains correct values."""
        simple_log.error("test message for error")
        if "." in request.module.__name__:
            mod_name = request.module.__name__.split(".", 1)[1]
        else:
            mod_name = request.module.__name__
        # captures and verifies log messages
        for records in caplog.records():
            assert records.message == "test message for error"
            assert records.levelname == "ERROR"
            assert records.module == mod_name
            assert records.classname == "TestLogger."
            assert records.funcName == "test_error_log_message"
            thread_name = threading.current_thread().name
            assert records.threadName == thread_name

    def test_debug_log_message(self, skip_if_no_fixture, caplog, simple_log, request):
        """ Verify that log message for level DEBUG contains correct values."""
        simple_log.logger.setLevel("DEBUG")
        simple_log.debug("test message for debug")
        if "." in request.module.__name__:
            mod_name = request.module.__name__.split(".", 1)[1]
        else:
            mod_name = request.module.__name__
        # captures and verifies log messages
        for records in caplog.records():
            assert records.message == "test message for debug"
            assert records.levelname == "DEBUG"
            assert records.module == mod_name
            assert records.classname == "TestLogger."
            assert records.funcName == "test_debug_log_message"
            thread_name = threading.current_thread().name
            assert records.threadName == thread_name

    def test_warning_log_message(self, skip_if_no_fixture, caplog, simple_log, request):
        """ Verify that log message for level WARNING contains correct values."""
        simple_log.warning("test message for warning")
        if "." in request.module.__name__:
            mod_name = request.module.__name__.split(".", 1)[1]
        else:
            mod_name = request.module.__name__
        # captures and verifies log messages
        for records in caplog.records():
            assert records.message == "test message for warning"
            assert records.levelname == "WARNING"
            assert records.module == mod_name
            assert records.classname == "TestLogger."
            assert records.funcName == "test_warning_log_message"
            thread_name = threading.current_thread().name
            assert records.threadName == thread_name

    def test_log_message_from_log_files(self, skip_if_no_fixture, caplog, file_log, request, log_file):
        """ Verify that log message from log files contains correct values."""
        file_log.info("test message")
        if "." in request.module.__name__:
            mod_name = request.module.__name__.split(".", 1)[1]
        else:
            mod_name = request.module.__name__
        # captures and verifies log messages
        for records in caplog.records():
            assert records.message == "test message"
            assert records.levelname == "INFO"
            assert records.module == mod_name
            assert records.classname == "TestLogger."
            assert records.funcName == "test_log_message_from_log_files"
            thread_name = threading.current_thread().name
            assert records.threadName == thread_name
            # compares log messages from log files
            log_string = "{0} : {1} : INFO : [{2}.TestLogger.test_log_message_from_log_files] - test message".format(records.asctime, thread_name, mod_name)
            lines = log_file.readlines()
            log_file.close()
            assert lines[0].split("\n")[0] == log_string

    def test_log_message_for_exception(self, skip_if_no_fixture, caplog, exception_log, request, log_file):
        """ Verify that  log message for exception from log files contains correct values."""
        exception_log.error("test message from exception")
        # captures and verifies log messages
        for records in caplog.records():
            assert records.message == "test message from exception"
            assert records.levelname == "ERROR"
            assert records.caller_module == "test_module"
            assert records.caller_class == "test_class."
            assert records.caller_func == "test_function"
            thread_name = threading.current_thread().name
            assert records.threadName == thread_name
            # compares log messages from log files
            log_string = "{0} : {1} : ERROR : [test_module.test_class.test_function] - test message from exception".format(records.asctime, thread_name)
            lines = log_file.readlines()
            log_file.close()
            assert lines[0].split("\n")[0] == log_string

    def test_module_log_message(self, skip_if_no_fixture, caplog, request, module_log):
        """ Verify that module level logging contains correct values."""
        if "." in request.module.__name__:
            mod_name = request.module.__name__.split(".", 1)[1]
        else:
            mod_name = request.module.__name__
        module_log.info("test message from module logger")
        # captures and verifies log messages
        for records in caplog.records():
            assert records.message == "test message from module logger"
            assert records.levelname == "INFO"
            assert records.module == mod_name
            assert records.classname == "TestLogger."
            assert records.funcName == "test_module_log_message"
            thread_name = threading.current_thread().name
            assert records.threadName == thread_name

    def test_log_message_for_introspection(self, skip_if_no_fixture, caplog, introspection_log, request, log_file):
        """ Verify that  log message for introspection from log files contains correct values."""
        introspection_log.info("test message")
        mod_name = request.module.__name__
        # captures and verifies log messages
        for records in caplog.records():
            assert records.name == mod_name
            assert records.levelname == "INFO"
            thread_name = threading.current_thread().name
            assert records.threadName == thread_name
            # compares log messages from log files
            log_string = "{0} : {1} : INFO : [{2}] - test message".format(records.asctime, thread_name, mod_name)
            lines = log_file.readlines()
            log_file.close()
            assert lines[0].split("\n")[0] == log_string

    def test_log_message_for_exception_with_trace(self, skip_if_no_fixture, caplog, request):
        """ Verify that log messages for exception with trace contains correct values."""
        error = custom_exceptions.CustomException("Test exception!", trace=True)
        assert error.__str__() == "'Test exception!'"
        if "." in request.module.__name__:
            mod_name = request.module.__name__.split(".", 1)[1]
        else:
            mod_name = request.module.__name__
        # captures and verifies log messages for exception
        record_exception = caplog.records()[0]
        assert record_exception.message == "Test exception!"
        assert record_exception.levelname == "ERROR"
        assert record_exception.caller_module == mod_name
        assert record_exception.caller_class == "TestLogger."
        assert record_exception.caller_func == "test_log_message_for_exception_with_trace"
        thread_name = threading.current_thread().name
        assert record_exception.threadName == thread_name
        # captures and verifies log messages for trace exceptions
        record_traceback = caplog.records()[1]
        assert record_traceback.message == "Traceback:\nNone\n"
        assert record_traceback.levelname == "ERROR"
        assert record_traceback.caller_module == mod_name
        assert record_traceback.caller_class == "TestLogger."
        assert record_traceback.caller_func == "test_log_message_for_exception_with_trace"
        thread_name = threading.current_thread().name
        assert record_traceback.threadName == thread_name

    def test_log_message_from_log_file_for_exception_with_trace(self, skip_if_no_fixture, caplog, request, log_file, exception_log, monkeypatch):
        """ Verify that log messages for exception with trace from log files contains correct values."""
        monkeypatch.setattr(custom_exceptions.CustomException, "class_logger", exception_log)
        custom_exceptions.CustomException("Test exception!", trace=True)
        # captures and verifies log messages for exception
        record_exception = caplog.records()[0]
        # captures and verifies log messages for trace exceptions
        record_traceback = caplog.records()[1]
        thread_name = threading.current_thread().name
        # compares log messages from log files
        log_string = "{0} : {1} : ERROR : [test_module.test_class.test_function] - Test exception!".format(record_exception.asctime, thread_name)
        log_string_trace = "{0} : {1} : ERROR : [test_module.test_class.test_function] - Traceback:".format(record_traceback.asctime, thread_name)
        lines = log_file.readlines()
        log_file.close()
        assert lines[0].split("\n")[0] == log_string
        assert lines[1].split("\n")[0] == log_string_trace
        assert lines[2].split("\n")[0] == "None"
