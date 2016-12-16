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

@file  pytest_smartrerun.py

@summary  Plugin is collecting failed test cases from specific Test Plan in Jira and run them again.
"""
import pytest

from .pytest_helpers import get_tcname
from .pytest_onsenv import setup_scope


def pytest_addoption(parser):
    """
    @brief  Describe plugin specified options.
    """
    group = parser.getgroup("SM reporting", "plugin: smart rerun")
    group.addoption("--sm_rerun", action="store", default=None,
                    help="Rerun Test Cases with 'Failed' and  'Cant Test' status from custom Test Plan. "
                         "Use - 'platform:PLATFORMNAME' to run last Test Plan on specific platform")
    group.addoption("--sm_linked_defects", action="store_true", default=False,
                    help="When False (default) rerun only Test Cases without linked defects")


def pytest_configure(config):
    """
    @brief  Registering plugin.
    """
    if config.option.sm_rerun:
        config.pluginmanager.register(SmartRerun(config), "_smart_rerun")


def pytest_unconfigure(config):
    """
    @brief  Unregistering plugin.
    """
    smart_rerun = getattr(config, "_smart_rerun", None)
    if smart_rerun:
        del config._smart_rerun
        config.pluginmanager.unregister(smart_rerun)


class SmartRerun(object):
    """
    @description  Re-run failed test cases.
    """
    def __init__(self, config):
        self.config = config
        self.test_cases = None
        self.synapsert = None

    @pytest.fixture(scope=setup_scope(), autouse=True)
    def log_level(self, request, env_main):
        def teardown():
            self._set_switch_log_level(env_main, "Notice")
        # Set log level
        self._set_switch_log_level(env_main, "Debug")
        request.addfinalizer(teardown)

    def _set_switch_log_level(self, env, loglevel):
        """
        @brief  Change loglevel on switches
        @param  loglevel:  logging level
        @type loglevel:  str
        """
        if hasattr(env, 'switch'):
            for switch in env.switch.values():
                switch.set_app_log_level(loglevel)

    def pytest_collection_modifyitems(self, config, items):
        if config.option.tm_update and config.option.sm_rerun is not None:
            try:
                from .connectors.SYNAPSERT import SYNAPSERT
                self.synapsert = SYNAPSERT()
                tps = ""
                if config.option.sm_rerun.startswith("platform:"):
                    test_plan = self.synapsert.get_last_tp_by_platform(config.option.sm_rerun.lstrip("platform:"))
                    if test_plan:
                        tps = self.synapsert.get_summary(test_plan)
                    else:
                        raise Exception("Cannot find Test Plan by platform: %s" % (config.option.sm_rerun.lstrip("platform:"), ))
                else:
                    tps = config.option.sm_rerun
                # check if Test Plan exist
                _failed_issues = self.synapsert.get_last_failed_issues_from_tps(tps, config.option.sm_linked_defects)
            except ImportError:
                raise Exception("Cannot import SYNAPSERT from  connectors, maybe file doesn't exist")
            if _failed_issues is not None:
                for item in items[:]:
                    tcname = get_tcname(item)
                    if tcname not in _failed_issues:
                        items.remove(item)
            else:
                raise Exception("Cannot get last failed issues")

    def pytest_sessionfinish(self, session, exitstatus):
        if session.config.option.tm_update and session.config.option.sm_rerun:
            self.test_cases = []
            for item in session.items:
                self.test_cases.append(get_tcname(item))

    def pytest_terminal_summary(self, terminalreporter):
        if terminalreporter.config.option.tm_update and terminalreporter.config.option.sm_rerun and self.synapsert:
            tr = terminalreporter
            test_cases = {}
            for tcname in self.test_cases:
                test_cases[tcname] = self.synapsert.get_st_history(tcname, terminalreporter.config.option.sm_rerun)
            tr.write_sep("=", "Rerun statistic", bold=True)
            tr.write_line("%-8s%-8s%-10s %s" % ("Passed", "Failed", "CantTest", "Test Case Name"))
            for tcname in test_cases:
                tr.write_line("%-8s%-8s%-10s %s" % (test_cases[tcname]["Passed"],
                                                    test_cases[tcname]["Failed"],
                                                    test_cases[tcname]["Can't Test"],
                                                    tcname
                                                    ))
