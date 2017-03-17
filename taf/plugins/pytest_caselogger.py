# Copyright (c) 2011 - 2017, Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""``pytest_caselogger.py``

`Plugin is getting logs for each test case`

"""

import time

import pytest

from .pytest_helpers import get_tcname
from .pytest_onsenv import setup_scope
from testlib import caselogger


def pytest_addoption(parser):
    """Describe plugin specified options.

    """
    group = parser.getgroup("log_enable", "plugin case logger")
    group.addoption("--log_enable", action="store", default="True",
                    choices=["False", "True"],
                    help="Enable/Disable log tool for test (False | True). '%default' by default.")
    group.addoption("--log_test", action="store", default="Failed",
                    choices=["Failed", "All"],
                    help="Choose test case result to store logs for (Failed | All). '%default' by default.")
    group.addoption("--log_storage", action="store", default="none",
                    choices=["None", "Host"],
                    help="Where to store logs (None | Host). '%default' by default.")
    group.addoption("--log_type", action="store", default="Single",
                    choices=["Single", "All"],
                    help="Store all logs or only for single test case (Single | All). '%default' by default.")


def pytest_configure(config):
    """Registering plugin.

    """
    if config.option.log_enable == "True":
        config.pluginmanager.register(CaseLoggerPlugin(), "_case_logger")


def pytest_unconfigure(config):
    """Unregistering plugin.

    """
    case_logger = getattr(config, "_case_logger", None)
    if case_logger == "True":
        del config._case_logger
        config.pluginmanager.unregister(case_logger)


class CaseLoggerExecutor(object):
    """Base class for TAF caselogger functionality.

    """

    def __init__(self, env):
        """Initialize CaseLoggerExecutor instance.

        Args:
            env(testlib.common3.Environment):  Environment instance from config

        """
        self.node = None
        self.env = env
        self.log_storage = env.opts.log_storage
        self.log_flag = env.opts.log_enable

    def case_setup(self):
        """Add message into device logs on test case setup.

        """
        self.log_timestamp = time.time()  # pylint: disable=attribute-defined-outside-init
        self.tc_name = get_tcname(self.node)  # pylint: disable=attribute-defined-outside-init

        # Make notice of test setup in log file.
        for switch in list(self.env.switch.values()):
            try:
                switch.ui.logs_add_message("Notice", "[QA] Test %s execution started at %s" % (self.tc_name, self.log_timestamp))
            except Exception as err:
                self.log_flag = "False"
                self.node.config.ctlogger.error("[Caselogger] Adding message to device logs failed: %s", err)

    def case_teardown(self):
        """Add message into device logs on test case teardown. Copy test case logs to the log host.

        """
        # Make notice of test teardown in log file.
        for switch in list(self.env.switch.values()):
            if switch.status:
                try:
                    switch.ui.logs_add_message("Notice", "[QA] Test teardown at %s" % (self.log_timestamp, ))
                except Exception as err:
                    self.node.config.ctlogger.error("[Caselogger] Adding message to device logs failed: %s", err)

        # Get test case logs
        if self.log_flag == "True":
            if self.log_storage == "Host":
                for switch in list(self.env.switch.values()):

                    case_logger = caselogger.CaseLogger(switch, self.node.config.ctlogger)
                    if self.env.opts.log_test == "Failed" and self.node.excinfo:
                        case_logger.get_test_case_logs(self.tc_name, self.log_timestamp, self.env.opts.log_type)
                    elif self.env.opts.log_test == "All":
                        case_logger.get_test_case_logs(self.tc_name, self.log_timestamp, self.env.opts.log_type)

    def suite_teardown(self):
        """Copy core logs to the log host on test suite teardown.

        """
        if self.log_flag == "True":
            if self.log_storage == "Host":
                for switch in list(self.env.switch.values()):
                    case_logger = caselogger.CaseLogger(switch, self.node.config.ctlogger)
                    # suit_name is defined below
                    case_logger.get_core_logs(self.suite_name)  # pylint: disable=no-member


class CaseLoggerPlugin(object):
    """Base class for caselogger plugin functionality.

    """

    @pytest.hookimpl(tryfirst=True, hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        """Add information about test case execution results.

        """
        # execute all other hooks to obtain the report object
        yield

        # Add info about test cases execution results
        if call.when == "call":
            item.excinfo = call.excinfo

    @pytest.fixture(autouse=True, scope=setup_scope())
    def suitelogger(self, request, env_main):
        """Call caselogger on test suite teardown.

        Args:
            request(pytest.request):  pytest request instance
            env_main (testlib.common3.Environment):  'env_main' pytest fixture from pytest_onsenv.py

        Returns:
            CaseLoggerExecutor: instance of CaseLoggerExecutor class

        """
        case_logger = CaseLoggerExecutor(env_main)
        request.addfinalizer(case_logger.suite_teardown)
        return case_logger

    @pytest.fixture(autouse=True)
    def caselogger(self, request, suitelogger, env):
        """Call caselogger on test case setup/teardown

        Args:
            request(pytest.request): pytest request instance
            suitelogger:  pytest fixture
            env(testlib.common3.Environment):  'env' pytest fixture from pytest_onsenv.py

        """
        suitelogger.node = request.node
        suitelogger.suite_name = request.node.module.__name__
        request.addfinalizer(suitelogger.case_teardown)
        suitelogger.case_setup()
