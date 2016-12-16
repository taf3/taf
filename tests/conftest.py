#! /usr/bin/env python
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

@file  conftest.py

@summary  Global configuration for test suites.
"""

import os
import sys
import time

import pytest

from testlib import common3
from testlib import loggers

pytest_plugins = ["plugins.pytest_returnvalues", ]


def pytest_addoption(parser):
    """
    @brief  TAF specific options
    """
    parser.addoption("--env", action="store", default=None,
                     help="Testing environment, '%default' by default.")
    parser.addoption("--setup_file", action="store", default="sim_lxc_simplified.json", dest="setup",
                     help="Environment setup, '%default' by default.")
    parser.addoption("--loglevel", action="store", default="INFO",
                     help="Logging level, '%default' by default.")
    parser.addoption("--logdir", action="store", default=None,
                     help="Logging directory path, %default by default.")
    parser.addoption("--silent", action="store_true", default=False,
                     help="Suppress stdout messages. %default by default.")
    parser.addoption("--get_only", action="store_true", default=False,
                     help="Do not start environment, only connect to exists one. %default by default.")
    parser.addoption("--leave_on", action="store_true", default=False,
                     help="Do not shutdown environment after the end of tests. %default by default.")
    parser.addoption("--setup_scope", action="store", default="module",
                     choices=["session", "module", "class", "function"],
                     help="Setup scope (session | module | class | function). '%default' by default.")
    parser.addoption("--call_check", action="store", default="fast",
                     choices=["none", "complete", "fast", "sanity_check_only"],
                     help="Check method for devices on test case call (none | complete | fast | sanity_check_only). '%default' by default.")
    parser.addoption("--teardown_check", action="store", default="sanity_check_only",
                     choices=["none", "complete", "fast", "sanity_check_only"],
                     help="Check method for devices on test case teardown (none | complete | fast | sanity_check_only). '%default' by default.")
    parser.addoption("--fail_ctrl", action="store", default="restart",
                     choices=["stop", "restart", "ignore"],
                     help="Action on device failure (stop | restart | ignore). '%default' by default.")
    parser.addoption("--use_parallel_init", action="store_true", default=False,
                     help="Use threads for simultaneous device processing. %default by default.")


def setup_scope():
    """
    @brief  Return setup_scope option value in global namespace.
    """
    try:
        _setup_scope = filter(lambda x: x.startswith("--setup_scope"), sys.argv)[0].split("=")[1]
    except IndexError:
        _setup_scope = "module"
    return _setup_scope


def pytest_configure(config):
    if config.option.logdir is not None:
        # Set file name of pytest log.
        if config.option.resultlog is None:
            log_suffix = "-".join([config.option.markexpr.replace(" ", "_"),
                                   config.option.keyword.replace(" ", "_")])
            self_pid = str(os.getpid())
            resultlog_name = ".".join(["pytest", log_suffix, self_pid, "log"])
            config.option.resultlog = os.path.join(os.path.expandvars(os.path.expanduser(config.option.logdir)),
                                                   resultlog_name)


def _get_entries_list(item, step, action):
    """
    @brief  Returns list of entries which need the action to be applied on step (runtest_call/teardown).
    """
    entries_dict = {}
    entries_list = []
    if step in item.keywords.keys():
        entries_dict = item.keywords[step]
        if action in entries_dict:
            entries_list = entries_dict[action]
    return entries_list


def pytest_runtest_call(item):
    item.config.ctlogger.debug("Entering pytest_runtest_call hook. Item: %s" % item.name)
    _start_time = time.time()
    # WORKAROUND:
    item.config.pytest_runtest_call_status = False
    # Clean up environment before new case
    if item.config.env.opts.call_check == "fast":
        item.config.env.cleanup(_get_entries_list(item, "runtest_call", "cleanup"))
    if item.config.env.opts.call_check == "complete":
        item.config.env.shutdown(_get_entries_list(item, "runtest_call", "reinit"))
        item.config.env.initialize(_get_entries_list(item, "runtest_call", "reinit"))
    if item.config.env.opts.call_check == "sanity_check_only":
        item.config.env.check(_get_entries_list(item, "runtest_call", "check"))

    _duration = time.time() - _start_time
    item.config.ctlogger.debug("PROFILING: pytest_runtest_call hook duration = %s. Item: %s" % (_duration, item.name))
    item.config.ctlogger.debug("Exit pytest_runtest_call hook. Item: %s" % item.name)
    # WORKAROUND:
    item.config.pytest_runtest_call_status = True


def pytest_runtest_teardown(item, nextitem):
    item.config.ctlogger.debug("Entering pytest_runtest_teardown hook. Item: %s" % item.name)
    _start_time = time.time()
    # Check environment
    if item.config.env.opts.teardown_check == "fast":
        item.config.env.cleanup(_get_entries_list(item, "runtest_teardown", "cleanup"))
    # WORKAROUND:
    if item.config.env.opts.teardown_check == "complete" or (hasattr(item.config, "pytest_runtest_call_status") and not item.config.pytest_runtest_call_status):
        item.config.env.shutdown(_get_entries_list(item, "runtest_teardown", "reinit"))
        item.config.env.initialize(_get_entries_list(item, "runtest_teardown", "reinit"))
    if item.config.env.opts.teardown_check == "sanity_check_only":
        item.config.env.check(_get_entries_list(item, "runtest_teardown", "check"))
    _duration = time.time() - _start_time
    item.config.ctlogger.info("PROFILING: pytest_runtest_teardown hook duration = %s. Item: %s" % (_duration, item.name))
    item.config.ctlogger.debug("Exit pytest_runtest_teardown hook. Item: %s" % item.name)


def pytest_sessionstart(session):
    # Check options
    session.config.ctlogger = loggers.module_logger("conftest")
    session.config.ctlogger.debug("Session start...")
    if not (session.config.option.setup_scope in ["session", "module", "class", "function"]):
        session.config.ctlogger.error("Incorrect --setup_scope option.")
        pytest.exit("Incorrect --setup_scope option.")
    if not (session.config.option.call_check in ["none", "complete", "fast", "sanity_check_only"]):
        session.config.ctlogger.error("Incorrect --call_check option.")
        pytest.exit("Incorrect --call_check option.")
    if not (session.config.option.teardown_check in ["none", "complete", "fast", "sanity_check_only"]):
        session.config.ctlogger.error("Incorrect --teardown_check option.")
        pytest.exit("Incorrect --teardown_check option.")
    if not (session.config.option.fail_ctrl in ["stop", "restart", "ignore"]):
        session.config.ctlogger.error("Incorrect --fail_ctrl option.")
        pytest.exit("Incorrect --fail_ctrl option.")
    # Define environment
    session.config.env = common3.Environment(session.config.option)
