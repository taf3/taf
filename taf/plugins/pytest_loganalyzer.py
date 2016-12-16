# coding: utf-8
"""
@copyright Copyright (c) 2015 - 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  pytest_loganalyzer.py

@summary  Plugin is checking device's log after each test case is executed.
"""
import re
import os
import json
from itertools import tee
from collections import defaultdict

import pytest

from . import loggers
from .pytest_onsenv import setup_scope


def pytest_addoption(parser):
    """
    @brief  Describe plugin specified options.
    """
    group = parser.getgroup("log_analyzer", "plugin log analyzer")
    group.addoption(
        "--log_analyzer", action="store", default="True",
        choices=["False", "True"],
        help="Enable/Disable device log analyzer tool(False | True). '%default' by default.")


def pytest_configure(config):
    """
    @brief  Registering plugin.
    """
    if config.option.log_analyzer == "True":
        config.pluginmanager.register(LogAnalyzerPlugin(), "_log_analyzer")


def pytest_unconfigure(config):
    """
    @brief  Unregistering plugin.
    """
    log_analyzer = getattr(config, "_log_analyzer", None)
    if log_analyzer == "True":
        del config._log_analyzer
        config.pluginmanager.unregister(log_analyzer)


def pairwise(iterable):
    """s -> (s0,s1), (s1,s2), (s2, s3), ..."""
    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)


class LogAnalyzer(object):

    class_logger = loggers.ClassLogger()
    start_time = {}
    command = "date '+%Y-%m-%d %T'"
    runtest_setup_flag = {}

    # Error records with specific error level to show. E.g.: '3' means any error messages with
    # priorities 0, 1, 2, 3.
    error_priority = 3

    IGNORE_RES = [
        re.compile('^Runtime journal is using '),
    ]

    def __init__(self, switch):
        """
        @brief  Initialize LogAnalyzer instance
        @param  switch:  switch dictionary
        @type  switch:  dict{SwitchGeneral}
        """
        self.switch = switch
        self.item_skip_log_marker = None

    def ignore(self, entry):
        """
        Check if duplicate can be ignored

        @param entry: journalctl json decoded dict
        @type entry: dict
        @return: if we should ignore this message when checking duplicates
        @rtype: bool
        """
        # Ignore these duplicates.  First in a long line of forthcoming false positives
        # Jun 03 00:50:59 rr12or systemd-journal[338]: Runtime journal is using 8.0M (max allowed 399.0M, trying to leave 598.5M free of 3.8G available → current limit 399.0M).
        # Jun 03 00:50:59 rr12or systemd-journal[338]: Runtime journal is using 8.0M (max allowed 399.0M, trying to leave 598.5M free of 3.8G available → current limit 399.0M).
        return any(regexp.search(entry['MESSAGE']) for regexp in self.IGNORE_RES)

    def _check_log_duplicates(self, log_output):
        """
        @brief  Check if duplicated records are present in device log
        @param  log_output:  output of device log
        @type  log_output:  str
        """
        json_lines = (json.loads(x, encoding='utf-8') for x in log_output.splitlines())
        duplicates = defaultdict(list)
        for lineno, log_entry in enumerate(json_lines):
            # use the exact message, no need to lower or strip
            # message is unicode
            if not self.ignore(log_entry):
                duplicates[log_entry["MESSAGE"]].append(lineno)

        for duplicate, duplicated_indexes in duplicates.items():
            if len(duplicated_indexes) > 1:
                for a, b in pairwise(duplicated_indexes):
                    assert abs(a - b) > 1, "Log duplication found in journalctl:\n %s" % duplicate

    def _check_log_errors(self, log_output):
        """
        @brief  Check if errors with specific priority are present in device log
        @param  log_output:  output of device log
        @type  log_output:  str
        """
        # just count the newlines
        lines = log_output.count(os.linesep)
        assert lines <= 1, "%s error message(s) with priority in range 0..%s are present in " \
                           "journalctl: \n\n%s" % \
                           (lines - 1, self.error_priority, log_output)

    def setup(self):
        """
        @brief  Initialize start time of test run
        """
        for switch_id, switch in self.switch.items():
            switch.ssh.login()
            switch.ssh.open_shell()
            try:
                self.start_time[switch_id] = switch.ssh.exec_command(self.command, 5).stdout.strip()
                self.runtest_setup_flag[switch_id] = True
            except Exception as err:
                self.runtest_setup_flag[switch_id] = False
                self.class_logger.debug(
                    "Command %s was not executed successfully."
                    "Therefore loganalyzer plugin checks will not be executed for switch %s. "
                    "\n%s", self.command, switch_id, err)
            finally:
                switch.ssh.close_shell()

    def teardown(self):
        """
        @brief  Check for errors and duplicated records in device log (journalctl)
        """
        journalctl_all_cmd = "journalctl -o json --since '{0}' --until '{1}'"
        journalctl_priority_cmd = "journalctl --priority={0} --since '{1}' --until '{2}'"
        end_time = {}
        # item_skip_log_marker value should be set before teardown
        skip_flag = self.item_skip_log_marker is not None
        for switch_id, switch in self.switch.items():
            if self.runtest_setup_flag[switch_id]:
                switch.ssh.login()
                switch.ssh.open_shell()
                try:
                    try:
                        end_time[switch_id] = switch.ssh.exec_command(self.command,
                                                                      5).stdout.strip()
                        if not skip_flag:
                            output = switch.ssh.exec_command(
                                journalctl_all_cmd.format(self.start_time[switch_id],
                                                          end_time[switch_id]),
                                5).stdout
                            errors_output = switch.ssh.exec_command(
                                journalctl_priority_cmd.format(self.error_priority,
                                                               self.start_time[switch_id],
                                                               end_time[switch_id]),
                                5).stdout
                        self.start_time[switch_id] = end_time[switch_id]
                    except Exception as err:
                        self.class_logger.debug(
                            "Command was not executed successfully, therefore skipping "
                            "loganalyzer plugin... \n%s ", err)
                    else:
                        if not skip_flag:
                            try:
                                self._check_log_duplicates(output)
                                self._check_log_errors(errors_output)
                            except AssertionError as err:
                                # log errors are unicode, decode to string
                                pytest.fail(str(err).encode('utf-8'))
                finally:
                    switch.ssh.close_shell()


class LogAnalyzerPlugin(object):

    @pytest.fixture(scope=setup_scope(), autouse=True)
    def log_analyzer_setup(self, env_main):
        """
        @brief  Setup LogAnalyzer plugin after devices had been started
        @param  env_main:  pytest fixture
        @param  env_main:  common3.Env
        @rtype:  LogAnalyzer
        @return:  LogAnalyzer instance
        """
        log_wrapper = LogAnalyzer(env_main.switch)
        log_wrapper.setup()
        return log_wrapper

    @pytest.fixture(autouse=True)
    def log_analyzer(self, request, env, log_analyzer_setup):
        """
        @brief  Validate device's logs on test teardown
        @param  request:  pytest request
        @type  request:  pytest.request
        @param  log_analyzer_setup:  LogAnalyzer instance
        @type  log_analyzer_setup:  LogAnalyzer
        """
        # Set item_skip_log_marker for LogAnalyzer instance before teardown
        log_analyzer_setup.item_skip_log_marker = request.node.get_marker("skip_loganalyzer")
        request.addfinalizer(log_analyzer_setup.teardown)
