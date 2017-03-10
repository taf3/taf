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

"""``linux_app_host.py``

`Linux host with application implementation`

"""

from .clissh import CLISSH
from .custom_exceptions import CLIException


class LinuxAppHost(CLISSH):
    """Base class for linux host with started application.

    """

    def __init__(self, ipaddr, ssh_port, ssh_user, ssh_pass, prompt, app_name, app_prompt):
        """Initialize LinuxAppHost class.

        Args:
            ipaddr(str):  Linux host IP address
            ssh_port(int):  Linux host ssh port
            ssh_user(str):  Linux host user
            ssh_pass(str):  Linux host password
            prompt(str):  Linux host ssh prompt
            app_name(str):  Application name
            app_prompt(str):  Application prompt

        """
        super(LinuxAppHost, self).__init__(ipaddr, ssh_port, ssh_user, ssh_pass, prompt=prompt)
        self.ssh_prompt = prompt
        self.app_name = app_name
        self.app_prompt = app_prompt

    def connect(self):
        """SSH to linux host and start the application.

        """
        self.class_logger.debug("Login on switch with login: {0}".format(self.username, ))
        self.login(timeout=15)
        self.class_logger.debug("Create Shell")
        self.open_shell()
        self.class_logger.debug("Launch the application: {0}".format(self.app_name, ))
        self.prompt = self.app_prompt
        self.execute_command(self.app_name, timeout=60, return_code="")

    def execute_command(self, command, timeout=None, return_code="0"):
        """Execute command in started application.

        Args:
            command(str):  Command to be executed
            timeout(int):  Ttimeout for command execution
            return_code(str):  Expected return code

        Returns:
            str:  Command execution output

        """
        data, return_code = self.shell_command(command, timeout=timeout, expected_rc=return_code, ret_code=False)
        return data

    def disconnect(self, app_disconnect_command="quit"):
        """Close the application and disconnect from SSH session.

        Args:
            app_disconnect_command(str):  Application exit command to be executed

        """
        self.prompt = self.ssh_prompt
        self.execute_command(app_disconnect_command, timeout=15)
        self.close()


class TestPointApp(LinuxAppHost):
    """Class for linux host with started TestPointShared.

    """

    def __init__(self, ipaddr, ssh_port, ssh_user, ssh_pass, prompt):
        """Initialize LinuxAppHost class with TestPointShared application.

        Args:
            ipaddr(str):  Linux host IP address
            ssh_port(int):  Linux host ssh port
            ssh_user(str):  Linux host user
            ssh_pass(str):  Linux host password
            prompt(str):  Linux host ssh prompt

        """
        super(TestPointApp, self).__init__(ipaddr, ssh_port, ssh_user, ssh_pass, prompt, "TestPointShared", "<0>%")
        self.expert_mode_prompt = "<expert>%"
        self.expert_mode = False
        self.change_mode_command = "\x10"  # Ctrl-P to change mode

    def disconnect(self, app_disconnect_command="quit"):
        """Close the application and disconnect from SSH session.

        Args:
            app_disconnect_command(str):  Application exit command to be executed

        """
        self.leave_expert_mode()
        super(TestPointApp, self).disconnect(app_disconnect_command="quit")

    def enter_expert_mode(self):
        """Enter expert mode in TestPointShared.

        Raises:
            Exception:  error on switching to expert mode

        """
        if not self.expert_mode:
            try:
                self.prompt = self.expert_mode_prompt
                self.execute_command(self.change_mode_command)
                self.expert_mode = True
            except:
                self.prompt = self.app_prompt
                raise Exception("Could not switch to expert mode")

    def leave_expert_mode(self):
        """Leave expert mode in TestPointShared.

        Raises:
            Exception:  error on switching to regular mode

        """
        if self.expert_mode:
            try:
                self.prompt = self.app_prompt
                self.execute_command(self.change_mode_command)
                self.expert_mode = False
            except:
                self.prompt = self.expert_mode_prompt
                raise Exception("Could not switch to regular mode")


class SwitchdSharedApp(LinuxAppHost):
    """Class for linux host with started switchdShared.

    """

    def __init__(self, ipaddr, ssh_port, ssh_user, ssh_pass, prompt, app_name):
        """Initialize LinuxAppHost class with switchdShared application.

        Args:
            ipaddr(str):  Linux host IP address
            ssh_port(int):  Linux host ssh port
            ssh_user(str):  Linux host user
            ssh_pass(str):  Linux host password
            prompt(str):  Linux host ssh prompt
            app_name(str):  Application name

        """
        super(SwitchdSharedApp, self).__init__(ipaddr, ssh_port, ssh_user, ssh_pass, prompt, app_name, "")
        self.exit_command = "\x03"  # Ctrl-C to exit switchdShared

    def connect(self):
        """SSH to linux host and start the application.

        """
        self.class_logger.debug("Login on switch with login: {0}".format(self.username, ))
        self.login(timeout=15)
        self.class_logger.debug("Create Shell")
        self.open_shell()
        self.class_logger.debug("Launch the application: {0}".format(self.app_name, ))
        self.prompt = self.app_prompt
        try:
            self.execute_command(self.app_name, timeout=3, return_code="")
            self.class_logger.debug("{0} is not loaded".format(self.app_name))
        except CLIException:
            pass

    def disconnect(self, app_disconnect_command="quit"):
        """Close the application and disconnect from SSH session.

        Args:
            app_disconnect_command(str):  Application exit command to be executed

        """
        super(SwitchdSharedApp, self).disconnect(app_disconnect_command=self.exit_command)
