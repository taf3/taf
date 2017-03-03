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

"""``pytest_pidchecker.py``

`Plugin is checking processes for being restarted`

"""

import pytest


def pytest_addoption(parser):
    """Describe plugin specified options.

    """
    group = parser.getgroup("pidchecker", "plugin pid checker")
    group.addoption("--pidcheck_disable", action="store_false", dest="pidchecker",
                    default=True,
                    help="Enable pidchecker plugin. %default by default.")


def pytest_configure(config):
    """Registering plugin.

    """
    if config.option.pidchecker:
        config.pluginmanager.register(PidCheckerPlugin(), "_pid_checker")


def pytest_unconfigure(config):
    """Unregistering plugin.

    """
    pid_checker = getattr(config, "_pid_checker", None)
    if pid_checker:
        del config._pid_checker
        config.pluginmanager.unregister(pid_checker)


class PidChecker(object):
    """Base class for TAF pidchecker functionality.

    """

    def __init__(self, env, flag, item):
        """Create PidChecker instance.

        Args:
            env (testlib.common3.Environment):  Environment instance from 'env' fixture.
            flag (bool):  Flag to know if plugin should skip process validation.
            item (pytest.Item):  Test case instance.

        """
        self.env = env
        self.processes = {}
        self.flag = flag
        self.item_name = item.name
        self.skip_details = item.get_marker("skip_pidchecker")
        if self.skip_details and self.skip_details.args != ():
            self.skip_prcheck = self.skip_details.args
        else:
            self.skip_prcheck = None

    def setup(self):
        """Get ONS processes PIDs on test case setup.

        """
        # Start function of processes checking.
        # pid_disable_keywords = ["reboot", "mgmtstatic", "part_graceful", "part_hard", "cli_enhancements_1_1__CliDo"]

        if self.skip_details and self.skip_details.args == ():
            self.flag = False

        if self.flag:
            for switch in list(self.env.switch.values()):
                self._check_processes_setup(switch, self.item_name)

    def teardown(self):
        """Get ONS processes PIDs on test case teardown.

        """
        if self.env.switch and self.flag:

            # Check processes were restarted:
            for switch in list(self.env.switch.values()):
                if switch.status:
                    restarted = self._check_processes_teardown(switch, self.item_name)
                    if isinstance(restarted, str):
                        pytest.fail("During test case %s run on %s device some processes were lost: %s" % (self.item_name, switch.name, restarted))
                    elif restarted != []:
                        pytest.fail("During test case %s run on %s devise some processes were restarted: %s" % (self.item_name, switch.name, restarted))

    def _check_processes_setup(self, switch, tc_name):
        """Check processes on setup.

        Args:
            switch (testlib.switch_general.SwitchGeneral):  switch instance from test environment.
            tc_name (str):  test case's name.

        """
        # Make global process-to-pid dictionary on SETUP hook.
        flag = True
        counter = 0
        while flag and counter <= 3:
            try:
                counter += 1
                flag = False
                switch.ssh.login()
                switch.ssh.open_shell()
            except Exception:
                flag = True
        self.processes[switch] = switch.get_processes(tc_name, skip_prcheck=self.skip_prcheck)

    def _check_processes_teardown(self, switch, tc_name):
        """Check process on teardown.

        Args:
            switch (testlib.switch_general.SwitchGeneral):  switch instance from test environment.
            tc_name (str):  test case's name.

        """
        # Make local process-to-pid dictionary on TEARDOWN hook
        # and return restarted processes.
        restarted = []
        processes = switch.get_processes(tc_name, skip_prcheck=self.skip_prcheck)

        # close ssh connection
        if hasattr(switch, 'ssh'):
            switch.ssh.close()

        for pname in list(self.processes[switch].keys()):
            try:
                if self.processes[switch][pname] != processes[pname]:
                    restarted.append(pname + " pid:" + str(processes[pname]))
            except Exception as err:
                restarted = Exception(err)
        return restarted


class PidCheckerPlugin(object):
    """PidCheckerPlugin implementation.

    """
    @pytest.fixture(autouse=True)
    def pidcheck(self, request, env):
        """Call ONS processes verification on test case setup/teardown.

        Args:
            request (pytest.request): pytest request instance.
            env (testlib.common3.Environment): 'env' pytest fixture from pytest_onsenv.py.

        """
        pidcheck_flag = request.config.option.pidchecker and hasattr(env, "switch") and hasattr(env.switch[1], "get_processes")
        pidchecker = PidChecker(env, pidcheck_flag, request.node)
        request.addfinalizer(pidchecker.teardown)
        pidchecker.setup()
