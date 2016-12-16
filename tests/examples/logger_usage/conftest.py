#!/usr/bin/env python
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

@summary  Logger example suite related py.test hooks and fixtures.
"""

import pytest
import sys

from testlib import loggers
from testlib import fixtures


def setup_scope():
    """
    @brief  Return setup_scope option value in global namespace.
    """
    try:
        _setup_scope = filter(lambda x: x.startswith("--setup_scope"), sys.argv)[0].split("=")[1]
    except IndexError:
        _setup_scope = "module"
    return _setup_scope


class Env(object):
    """
    @brief  Class to represent main environment fixture.
    """
    def __init__(self, request):
        self.env = request.config.env
        self.option = request.config.option

    def create(self):
        self.env.initialize()
        # SSH auto-logging:
        for host in self.env.lhost.values():
            host.ssh.login()
        return self.env

    def destroy(self):
        # SSH auto-logout:
        for host in self.env.lhost.values():
            if host.ssh.login_status:
                host.ssh.close()
        self.env.shutdown()


@pytest.fixture(scope=setup_scope())
def env(request):
    """
    @brief  Main environment fixture.
    """
    env_wrapper = Env(request)
    request.addfinalizer(env_wrapper.destroy)
    request.config.env = env_wrapper.create()
    return request.config.env


@pytest.fixture(scope="class", autouse=True)
def autolog(request):
    """
    @brief  Inject logger object to test class.
    @note  You do not need to pass this fixture to test function.
    """
    return fixtures.autolog(request, "log")


@pytest.fixture(scope="function", autouse=True)
def sshlog(request):
    """
    @brief  Register additional file handler for ssh loggers per test case.
    @note  You don't need to pass this fixture to test case. The fixture will be automatically
           applied to any test case which has "env" fixture and "env" has linux_host entries.
    """
    # Check if env is used in TC and file logging is enabled
    if "env" not in request.fixturenames or loggers.LOG_DIR is None:
        return
    # Call sshlog fixture template
    fixtures.sshlog(request, "env")
