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

"""``SYNAPSERT.py``

`SYNAPSERT class`

"""

import sys
import os

import loggers
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..', './')))
from pytest_helpers import get_failure_reason


class ReportingServerConfig(object):
    """Reporting Server configuration.

    """
    class_logger = loggers.ClassLogger()

    @staticmethod
    def _additional_option(parser):
        """Plugin specific options.

        """
        group = parser.getgroup("TM reporting", "plugin: tm updater")
        group.addoption("--tm_buildname", action="store", default=None,
                        help="Set Buildname for Test management system. %default by default.")
        group.addoption("--tm_update", action="store", default=None,
                        help="Set TM type and Update results in TM, %default by default.")
        group.addoption("--tm_appendtcs", action="store_true",
                        help="Create test case in TM DB. Default = %default")
        group.addoption("--tm_force_update", action="store_true",
                        help="Force update summary and description of test case in TM DB. Default = %default")
        group.addoption("--tm_prefix", action="store", default=None,
                        help="Add prefix custom prefix to Test Plan. Default = %default")

    @staticmethod
    def _sessionstart(log_class, item, name, buildname):
        """Tell to XMLRPC Server that we are going to interact with it.

        Args:
            item(pytest.Item): test case item
            name(str): name for current session
            buildname(str): buildname for current session

        """
        commands = []
        if item.config.option.tm_update:
            log_class.info("Enabling Test Management System update...")
            commands = [["reportadd", [name, item.config.option.tm_update]],
                        ["reportconfig", [name, item.config.option.tm_update, "options",
                                          [["append_tcs", item.config.option.tm_appendtcs],
                                           ["force_update", item.config.option.tm_force_update],
                                           ["prefix", item.config.option.tm_prefix]]]]]

        return commands

    @staticmethod
    def _configure(config):
        """Checking tm_update option.

        Args:
            config(bool):  get options

        """
        return (config.option.tm_update is not None) and not config.option.collectonly

    @staticmethod
    def _get_build_name(options):
        """Return spesified buildname.

        Args:
            options(str):  get options

        """
        if options.tm_buildname is not None:
            return options.tm_buildname
