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

@file  lab.py

@summary  general lab functionality.
"""

from . import clitelnet
from . import loggers
from .custom_exceptions import SwitchException


class GeneralPortServer(clitelnet.TelnetCMD):
    """
    @description  General functionality for console connection
    """

    class_logger = loggers.ClassLogger()

    def initial_config(self, config):
        """
        @brief  Performs initial configuration
        @param  config:  Configuration information.
        @type  config:  dict
        """
        self.config = config
        self.sw_user = config["telnet_user"]
        self.sw_pass = config["telnet_pass"]
        self.sw_loginprompt = config["telnet_loginprompt"]
        self.sw_passprompt = config["telnet_passprompt"]
        self.sw_prompt = config["telnet_prompt"]
        self.ps_port = config["portserv_tty"]
        self.ps_host = config["portserv_host"]
        self.ps_user = config["portserv_user"]
        self.ps_pass = config["portserv_pass"]
        self.name = config.get('name', 'noname')

    def telnet_connect(self, timeout=45, with_login=None, wait_login=0):
        """
        @brief  Perform telnet connection to the device
        @param  timeout:  time out to wait connection
        @type  timeout:  int
        @param  with_login:  Perform login procedure or not.
                             If param isn't set try automatically determine login necessity. (True|False|None)
        @type  with_login:  bool
        @param  wait_login:  time to wait login before sending <Enter>.
                             <Enter> is necessary if login is already appiered.
        @type  wait_login:  int
        @raise  NotImplementedError:  not implemented
        """
        raise NotImplementedError

    def get_serial(self, timeout=90, with_login=None, wait_login=0):
        """
        @brief  Connect to switch via serial.
        @param  timeout:  time out to wait connection
        @type  timeout:  int
        @param  with_login:  Perform login procedure or not.
                             If param isn't set try automatically determine login necessity. (True|False|None)
        @type  with_login:  bool
        @param  wait_login:  time to wait login before sending <Enter>.
                             <Enter> is necessary if login is already appiered.
        @type  wait_login:  int
        @note  Create(or check) class attribute telnet with active telnet connection to switch and do login.
        """
        self.class_logger.debug("Establishing telnet connection to switch...")

        try:
            self.class_logger.debug("Telnet connection exists. Checking ...")
            self.check_shell()
        except Exception as err:
            self.class_logger.debug(err)
            self.class_logger.debug("Telnet connection check failed. Reconnecting ...")
            self.telnet_connect(timeout=timeout, with_login=with_login, wait_login=wait_login)

        self.class_logger.debug("Telnet connection to switch is established.")

    def close_serial(self):
        """
        @brief  Close telnet connection to switch.
        """
        self.class_logger.debug("Closing telnet connection...")
        self.exit(wait_close=False)
        self.disconnect(with_exit=False)


class ConsoleServer(GeneralPortServer):
    """
    @description  Class responsible for console connection
    """

    def telnet_connect(self, timeout=45, with_login=None, wait_login=0):
        """
        @copydoc  GeneralPortServer::telnet_connect()
        """
        raise NotImplementedError

    def __new__(cls, config):
        """
        @brief  Get PortServer class related to console type
        @raise  SwitchException:  unsupported console type
        """
        console_type = config.get("console_type", "portserver")
        try:
            # don't create the object directly, call super new to create it
            return super(ConsoleServer, cls).__new__(_console_server_classes[console_type], config)
        except KeyError:
            raise SwitchException("Console type %s is not supported" % console_type)


class KVMServer(ConsoleServer):
    """
    @description  KVM functionality
    """

    def __init__(self, config):
        self.initial_config(config)
        super(KVMServer, self).__init__(host=self.ps_host, username=self.ps_user,
                                        password=self.ps_pass, page_break="--More--",
                                        prompt="admin >", pass_prompt="Password:", timeout=90,
                                        login_prompt="Username:")

    def telnet_connect(self, timeout=45, with_login=None, wait_login=0):
        """
        @copydoc  GeneralPortServer::telnet_connect()
        """
        self.class_logger.debug("Performing telnet connection to switch ...")
        output = self.connect(with_login=True)
        output = [x for x in output if isinstance(x, str)]
        self.kvm_connect(output)

    def kvm_connect(self, output):
        """
        @brief  Perform connection via KVM
        @param  output:  KVM output
        @type  output:  list[str]
        @raise  SwitchException:  error on connection
        """
        self.class_logger.debug("Output: %s" % (output, ))
        kvm_number = None
        lines = [x for x in output if self.name in x][0].splitlines()
        for line in lines:
            if self.name in line:
                kvm_number = [list(filter(str.isdigit, str(x.split(self.name)[0]))) for x in line.split('    ') if self.name in x][0]
        if kvm_number:
            alternatives = [(self.sw_loginprompt, self.sw_user, False, False),
                            (self.sw_passprompt, self.sw_pass, False, False),
                            (' login:', self.sw_user, False, False),
                            ("You are now master for the port", " ", False, False)]
            output, err = self.shell_command(kvm_number.encode("ascii"), alternatives=alternatives, timeout=60, ret_code=False, quiet=True,
                                             new_prompt=self.sw_prompt)
            self.prompt = self.sw_prompt
            self.sudoprompt = self.sw_passprompt
            self.password = self.sw_pass
            self.class_logger.debug("Setup console output:\n%s" % (output, ))
            if err or "returnCode=FAILED" in output:
                message = "Cannot connect to the device StdErr: %s, StdOut: %s" % (err, output, )
                self.class_logger.error(message)
                raise SwitchException(message)


class PortServer(ConsoleServer):
    """
    @description  PortServer functionality
    """

    def __init__(self, config):
        self.initial_config(config)
        super(PortServer, self).__init__(host=self.ps_host, port=self.ps_port,
                                         username=self.sw_user, password=self.sw_pass,
                                         page_break="--More--", prompt=self.sw_prompt,
                                         pass_prompt=self.sw_passprompt,
                                         sudo_prompt=self.sw_passprompt, timeout=90,
                                         login_prompt=self.sw_loginprompt, exit_cmd="exit")

    def release_serial(self):
        """
        @brief  Release serial port on port server.
        @raise  SwitchException:  error on terminating
        @note  This method kill tty on power server.
        """
        self.class_logger.debug("Killing tty for assurance on port server...")
        port_server = clitelnet.TelnetCMD(host=self.ps_host, username=self.ps_user,
                                          password=self.ps_pass, page_break="--More--", prompt="#>",
                                          pass_prompt="password:", timeout=45,
                                          login_prompt="login:")

        port_server.connect(with_login=False)
        output, err, _ = port_server.exec_command("kill %s" % self.ps_port,
                                                  ret_code=False)
        if err:
            raise SwitchException("Error while killing tty on port server.\nStdOut: %s\nStdErr: %s" % (output, err))
        port_server.disconnect()
        del port_server

    def telnet_connect(self, timeout=45, with_login=None, wait_login=0):
        """
        @copydoc  GeneralPortServer::telnet_connect()
        """
        self.release_serial()
        self.class_logger.debug("Performing telnet connection to switch ...")
        alternatives = [(self.sw_loginprompt, self.sw_user, False, False),
                        ("shell\>", "exit", False)]
        self.connect(with_login=with_login, wait_login=wait_login, alternatives=alternatives)


# define this here to avoid referring before definition
_console_server_classes = {
    "kvm": KVMServer,
    "portserver": PortServer
}
