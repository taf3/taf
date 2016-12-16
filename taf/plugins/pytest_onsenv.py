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

@file  pytest_onsenv.py

@summary  Creates env fixture for ons test cases.
"""
import time
import sys

import pytest

from testlib import testenv
from testlib import common3
from testlib import switch_general
from testlib import dev_linux_host


# WORKAROUND: add fix from pytest 2.6 (fix issue498: https://bitbucket.org/hpk42/pytest/commits/6a5904c4816cebd3e146a4277c0ad5021b131753#chg-_pytest/python.py)
def finish(self):
    try:
        while self._finalizer:
            func = self._finalizer.pop()
            func()
    finally:
        if hasattr(self, "cached_result"):
            del self.cached_result


def _check_pytest_version(version, max_version):
    """
    @brief  Check if version is less or equal to the max_version
    @param  version:  product version
    @type  version:  str
    @param  max_version:  max product version
    @type  max_version:  str
    @rtype:  bool
    @return:  True/False
    """
    version_list = version.split('.')
    max_version_list = max_version.split('.')
    i = 0
    while i <= len(version_list):
        if len(version_list) == i:
            return True
        if len(max_version_list) == i:
            return False
        if int(max_version_list[i]) > int(version_list[i]):
            return True
        if int(max_version_list[i]) == int(version_list[i]):
            i += 1
            continue
        if int(max_version_list[i]) < int(version_list[i]):
            return False
    return False

if _check_pytest_version(pytest.__version__, '2.5.2'):
    from _pytest.python import FixtureDef
    FixtureDef.finish = finish

# WORKAROUND END

TESTENV_OPTIONS = ["none", "simplified2", "simplified3", "simplified4", "simplified5", "golden",
                   "diamond", "mixed"]


def pytest_addoption(parser):
    """
    @brief  TAF specific options
    """
    parser.addoption("--env", action="store", default=None,
                     help="Testing environment, '%default' by default.")
    parser.addoption("--setup_file", action="store", default=None, dest="setup",
                     help="Environment setup, '%default' by default.")
    parser.addoption("--build_path", action="store", default="/opt/simswitch",
                     help="Path to build, '%default' by default.")
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
    parser.addoption("--testenv", action="store", default="none",
                     choices=TESTENV_OPTIONS,
                     help=(
                     "Verify environment before starting tests ({}). '%default' by default.".format(
                         " | ".join(TESTENV_OPTIONS))))
    parser.addoption("--use_parallel_init", action="store_true", default=False,
                     help="Use threads for simultaneous switches processing. %default by default.")
    parser.addoption("--fail_ctrl", action="store", default="restart",
                     choices=["stop", "restart", "ignore"],
                     help="Action on device failure (stop | restart | ignore). '%default' by default.")
    parser.addoption("--ixia_clear_ownership", action="store_true", default=False,
                     help="Clear IXIA ports ownership on session start. %default by default.")
    # use --switch_ui also to support eventual migration away from --ui
    parser.addoption("--ui", "--switch_ui", action="store", default="ons_xmlrpc",
                     choices=list(switch_general.UI_MAP.keys()),
                     help="User Interface to configure switch ({}). '%default' by default.".format(
                         " | ".join(switch_general.UI_MAP)))
    parser.addoption("--lhost_ui", action="store", default="linux_bash",
                     choices=list(dev_linux_host.UI_MAP.keys()),
                     help="User Interface to configure lhost ({}). '%default' by default.".format(
                         " | ".join(dev_linux_host.UI_MAP)))


def setup_scope():
    """
    @brief  Return setup_scope option value in global namespace.
    """
    try:
        _setup_scope = [x for x in sys.argv if x.startswith("--setup_scope")][0].split("=")[1]
    except IndexError:
        _setup_scope = "module"
    return _setup_scope


def pytest_configure(config):
    """
    @brief  Registering plugin.
    """
    if config.option.setup:
        config.pluginmanager.register(OnsEnvPlugin(), "_onsenv")
    else:
        config.ctlogger.error("SETUP")
        pytest.exit("SETUP")


def pytest_unconfigure(config):
    """
    @brief  Unregistering plugin.
    """
    onsenv = getattr(config, "_onsenv", None)
    if onsenv:
        del config._onsenv
        config.pluginmanager.unregister(onsenv)


class Env(object):
    def __init__(self, request, env):
        self.env = env
        self.option = request.config.option

    def create(self):
        # self.request = request
        self.env.initialize()
        # Perform cross connection in case cross device isn't configured to do this at create step.
        if hasattr(self.env, "cross"):
            for cross in list(self.env.cross.values()):
                if not cross.autoconnect:
                    cross.cross_connect(cross.connections)

        # Read and store env properties
        self.env.env_prop = testenv.get_env_prop(self.env)

        if hasattr(self.env, "testenv_checkstatus"):
            testenv_checkstatus = self.env.testenv_checkstatus
        else:
            testenv_checkstatus = False

        # Testing environment if option is selected
        if self.option.testenv != "none" and not testenv_checkstatus:
            getattr(testenv.TestLinks(self.env), "test_links_{0}".format(self.option.testenv))()
            self.env.testenv_checkstatus = True

    def destroy(self):
        """
        @brief  destroy testing environment
        """
        self.env.shutdown()


class EnvTest(object):
    """
    @description  Cleanup/Check testing environment
    """

    def __init__(self, request, env):
        self.request = request
        self.env = env
        self.request.node.call_status = False

    def setup(self):
        """
        @brief  Cleanup/Check testing environment on test case setup
        """
        _start_time = time.time()
        # Clean up environment before new case
        if self.env.opts.call_check == "fast":
            self.env.cleanup()
        if self.env.opts.call_check == "complete":
            self.env.shutdown()
            self.env.initialize()
        if self.env.opts.call_check == "sanity_check_only":
            self.env.check()

        self.request.node.call_status = True

        _duration = time.time() - _start_time
        self.request.config.ctlogger.debug("PROFILING: env fixture setup duration = %s. Item: %s" % (_duration, self.request.node.name))
        self.request.config.ctlogger.debug("Exit env fixture setup. Item: %s" % self.request.node.name)

    def teardown(self):
        """
        @brief  Cleanup/Check testing environment on test case teardown
        """
        self.request.config.ctlogger.debug("Entering env fixture teardown. Item: %s" % self.request.node.name)
        _start_time = time.time()
        # Check environment
        if self.env.opts.teardown_check == "fast":
            self.env.cleanup()
        if self.env.opts.teardown_check == "complete" or not self.request.node.call_status:
            self.env.shutdown()
            self.env.initialize()
        if self.env.opts.teardown_check == "sanity_check_only":
            self.env.check()
        _duration = time.time() - _start_time
        self.request.config.ctlogger.info("PROFILING: env fixture teardown duration = %s. Item: %s" % (_duration, self.request.node.name))
        self.request.config.ctlogger.debug("Exit env fixture teardown hook. Item: %s" % self.request.node.name)


class OnsEnvPlugin(object):

    @pytest.fixture(scope='session')
    def env_init(self, request):
        """
        @brief  Validate command line options
        @param  request:  pytest request
        @param  request:  pytest.request
        @rtype:  testlib.common3.Environment
        @return:  Environment instance
        """
        if request.config.option.setup_scope not in {"session", "module", "class", "function"}:
            request.config.ctlogger.error("Incorrect --setup_scope option.")
            pytest.exit("Incorrect --setup_scope option.")
        if request.config.option.call_check not in {"none", "complete", "fast", "sanity_check_only"}:
            request.config.ctlogger.error("Incorrect --call_check option.")
            pytest.exit("Incorrect --call_check option.")
        if request.config.option.teardown_check not in {"none", "complete", "fast", "sanity_check_only"}:
            request.config.ctlogger.error("Incorrect --teardown_check option.")
            pytest.exit("Incorrect --teardown_check option.")
        if request.config.option.fail_ctrl not in {"stop", "restart", "ignore"}:
            request.config.ctlogger.error("Incorrect --fail_ctrl option.")
            pytest.exit("Incorrect --fail_ctrl option.")

        request.config.env.testenv_checkstatus = False
        return request.config.env

    @pytest.fixture(scope=setup_scope())
    def env_main(self, request, env_init):
        """
        @brief  Start/stop devices from environment
        @param  request:  pytest request
        @param  request:  pytest.request
        @rtype:  testlib.common3.Environment
        @return:  Environment instance
        """
        env_wrapper = Env(request, env_init)

        request.addfinalizer(env_wrapper.destroy)
        env_wrapper.create()

        return env_init

    @pytest.fixture
    def env(self, request, env_main):
        """
        @brief  Clear devices from environment
        @param  request:  pytest.request
        @param  env_main:  pytest fixture
        @rtype:  testlib.common3.Environment
        @return:  Environment instance
        """
        env = EnvTest(request, env_main)
        request.addfinalizer(env.teardown)
        env.setup()

        return env_main

    def pytest_sessionstart(self, session):
        session.config.ctlogger.debug("Session start...")
        # Define environment
        session.config.env = common3.Environment(session.config.option)
