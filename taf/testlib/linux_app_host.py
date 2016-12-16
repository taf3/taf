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

@file  linux_app_host.py

@summary Linux host with application implementation.
"""

from .clissh import CLISSH
from .custom_exceptions import CLIException


class LinuxAppHost(CLISSH):
    """
    @description  Base class for linux host with started application
    """

    def __init__(self, ipaddr, ssh_port, ssh_user, ssh_pass, prompt, app_name, app_prompt):
        """
        @brief  Initialize LinuxAppHost class
        @param  ipaddr:  Linux host IP address
        @type  ipaddr:  str
        @param  ssh_port:  Linux host ssh port
        @type  ssh_port:  int
        @param  ssh_user:  Linux host user
        @type  ssh_user:  str
        @param  ssh_pass:  Linux host password
        @type  ssh_pass:  str
        @param  prompt:  Linux host ssh prompt
        @type  prompt:  str
        @param  app_name:  Application name
        @type  app_name:  str
        @param  app_prompt:  Application prompt
        @type  app_prompt:  str
        """
        super(LinuxAppHost, self).__init__(ipaddr, ssh_port, ssh_user, ssh_pass, prompt=prompt)
        self.ssh_prompt = prompt
        self.app_name = app_name
        self.app_prompt = app_prompt

    def connect(self):
        """
        @brief  SSH to linux host and start the application
        """
        self.class_logger.debug("Login on switch with login: {0}".format(self.username, ))
        self.login(timeout=15)
        self.class_logger.debug("Create Shell")
        self.open_shell()
        self.class_logger.debug("Launch the application: {0}".format(self.app_name, ))
        self.prompt = self.app_prompt
        self.execute_command(self.app_name, timeout=60, return_code="")

    def execute_command(self, command, timeout=None, return_code="0"):
        """
        @brief  Execute command in started application
        @param  command:  Command to be executed
        @type  command:  str
        @param  timeout:  Ttimeout for command execution
        @type  timeout:  int
        @param  return_code:  Expected return code
        @type  return_code:  str
        @rtype:  str
        @return:  Command execution output
        """
        data, return_code = self.shell_command(command, timeout=timeout, expected_rc=return_code, ret_code=False)
        return data

    def disconnect(self, app_disconnect_command="quit"):
        """
        @brief  Close the application and disconnect from SSH session
        @param  app_disconnect_command:  Application exit command to be executed
        @type  app_disconnect_command:  str
        """
        self.prompt = self.ssh_prompt
        self.execute_command(app_disconnect_command, timeout=15)
        self.close()


class TestPointApp(LinuxAppHost):
    """
    @description  Class for linux host with started TestPointShared
    """

    def __init__(self, ipaddr, ssh_port, ssh_user, ssh_pass, prompt):
        """
        @brief  Initialize LinuxAppHost class with TestPointShared application
        @param  ipaddr:  Linux host IP address
        @type  ipaddr:  str
        @param  ssh_port:  Linux host ssh port
        @type  ssh_port:  int
        @param  ssh_user:  Linux host user
        @type  ssh_user:  str
        @param  ssh_pass:  Linux host password
        @type  ssh_pass:  str
        @param  prompt:  Linux host ssh prompt
        @type  prompt:  str
        """
        super(TestPointApp, self).__init__(ipaddr, ssh_port, ssh_user, ssh_pass, prompt, "TestPointShared", "<0>%")
        self.expert_mode_prompt = "<expert>%"
        self.expert_mode = False
        self.change_mode_command = "\x10"  # Ctrl-P to change mode

    def disconnect(self, app_disconnect_command="quit"):
        """
        @copydoc  LinuxAppHost::disconnect()
        """
        self.leave_expert_mode()
        super(TestPointApp, self).disconnect(app_disconnect_command="quit")

    def enter_expert_mode(self):
        """
        @brief  Enter expert mode in TestPointShared
        @raise  Exception:  error on switching to expert mode
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
        """
        @brief  Leave expert mode in TestPointShared
        @raise  Exception:  error on switching to regular mode
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
    """
    @description  Class for linux host with started switchdShared
    """

    def __init__(self, ipaddr, ssh_port, ssh_user, ssh_pass, prompt, app_name):
        """
        @brief  Initialize LinuxAppHost class with switchdShared application
        @param  ipaddr:  Linux host IP address
        @type  ipaddr:  str
        @param  ssh_port:  Linux host ssh port
        @type  ssh_port:  int
        @param  ssh_user:  Linux host user
        @type  ssh_user:  str
        @param  ssh_pass:  Linux host password
        @type  ssh_pass:  str
        @param  prompt:  Linux host ssh prompt
        @type  prompt:  str
        @param  app_name:  Application name
        @type  app_name:  str
        """
        super(SwitchdSharedApp, self).__init__(ipaddr, ssh_port, ssh_user, ssh_pass, prompt, app_name, "")
        self.exit_command = "\x03"  # Ctrl-C to exit switchdShared

    def connect(self):
        """
        @copydoc  LinuxAppHost::connect()
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
        """
        @copydoc  LinuxAppHost::disconnect()
        """
        super(SwitchdSharedApp, self).disconnect(app_disconnect_command=self.exit_command)
