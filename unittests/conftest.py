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

@summary  TAF unittests common options.
"""
import sys
import os
import time
import shutil

import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../taf')))

pytest_plugins = ["plugins.pytest_reportingserver", "pytester"]


def pytest_addoption(parser):
    parser.addoption("--loglevel", action="store", default="INFO",
                     help="Logging level, 'INFO' by default.")
    parser.addoption("--get_only", action="store_true", default=False,
                     help="Do not start environment, only connect to exists one. %default by default.")
    parser.addoption("--leave_on", action="store_true", default=False,
                     help="Do not shutdown environment after the end of tests. %default by default.")
    parser.addoption("--with_jira", action="store_true", default=False,
                     help="Run unittests related to JIRA, '%default' by default.")
    parser.addoption("--synapsert_config", action="store", default=None,
                     help="Path to the config folder, '%default' by default.")
    parser.addoption("--logdir", action="store", default="logs",
                     help="Logging directory path, %default by default.")
    parser.addoption("--ixia_clear_ownership", action="store_true", default=True,
                     help="Clear IXIA ports ownership on session start. %default by default.")

    # CLISSH options.
    parser.addoption("--ssh_ip", action="store", default="localhost",
                     help="IP address for CLISSH func testing, '%default' by default.")
    parser.addoption("--ssh_user", action="store", default="unittester",
                     help="Login user for CLISSH func testing, '%default' by default.")
    parser.addoption("--ssh_pass", action="store", default="unittester",
                     help="Login password for CLISSH func testing, '%default' by default.")
    parser.addoption("--cli_api", action="append", default=[],
                     help="Enumerate CLI APIs to test, '%default' by default.")


@pytest.fixture(scope="session", autouse=True)
def env_setup(request):

    class UnittestEnv(object):
        env_prop = {"switchppVersion": "Unittesting",
                    'chipName': ""}

    if request.config.option.xml_info is None:
        request.config.option.xml_info = "{'Tests change number': '', 'Time': '%s'}" % time.ctime()

    request.config.env = UnittestEnv()

    # Define temporary directory which is used in fixture 'testdir'
    test_dir = request.config._tmpdirhandler.getbasetemp().strpath
    # Remove temporary directory after tests execution
    def remove_test_dir():
        if os.path.isdir(test_dir):
            shutil.rmtree(test_dir)
    request.addfinalizer(remove_test_dir)
