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

@file  clinns.py

@summary  Module contains classes for managing device using SSH connection or SSH connection emulation for Linux Network
Namespaces.
"""
from subprocess import Popen, PIPE

import pexpect

from . import loggers
from .cli_template import CLIGenericMixin
from .custom_exceptions import CLINNSException


def ip_net_namespace_mode(function):
    """
    @brief Decorator: get clissh_instance for class methods
    """
    def wrapper(*args, **kwargs):
        """
        @brief  Add "ip netns exec " prefix to all commands to forward them into network namespace.
        """

        if "command" in kwargs:
            command_line = kwargs.pop("command")
            command_list = command_line.split()
        else:
            command_list = args[1].split()

        if command_list[0] == "sudo":
            command_list.pop(0)
            use_sudo = True
        else:
            use_sudo = False

        cmd_prefix = ["ip", "netns", "exec", args[0].netns_name]
        if use_sudo:
            cmd_prefix.insert(0, "sudo")

        command_list = cmd_prefix + command_list
        result = ' '.join(command_list)
        _args = list(args)
        _args[1] = result
        args = tuple(_args)

        return function(*args, **kwargs)

    return wrapper


class CLISSHNetNS(CLIGenericMixin):
    """
    @description Class for executing command inside of namespace. Unused parameters added to support the same interface
    for other CLI classes.

    @code{.py}
    client = CLISSHNetNS("some_nns", timeout=10)
    client.exec_command("some_command")
    @endcode

    """
    class_logger = loggers.ClassLogger()

    def __init__(self, nsname, port=None, username=None, password=None, page_break=None, prompt=None, pass_prompt=None,
                 sudo_prompt=None, login_prompt=None, page_break_lines=None, exit_cmd=None, timeout=10, quiet=False):
        """
        @brief  Initialize CLISSHNetNS class

        @param  nsname:  NNS name.
        @type  nsname:  str
        @param  port:  Host port.
        @type  port:  int
        @param  username:  Host user
        @type  username:  str
        @param  password:  Host password
        @type  password:  str
        @param  page_break:  Page brake marker.
        @type  page_break:  str
        @param  prompt:  Shell prompt.
        @type  prompt:  str
        @param  pass_prompt:  Login password prompt.
        @type  pass_prompt:  str
        @param  sudo_prompt:  Sudo password prompt.
        @type  sudo_prompt:  str
        @param login_prompt:  Login prompt (str).
        @type  login_prompt:  str
        @param page_break_lines:  Number of page brake lines (int).
        @type  page_break_lines:  int
        @param exit_cmd:  Command to perform telnet exit (str).
        @type  exit_cmd:  str
        @param  timeout:  Default timeout for commands.
        @type  timeout:  int
        @param  quiet:  Flag for return code verification.
        @type  quiet:  bool
        """

        super(CLISSHNetNS, self).__init__()

        self.netns_name = nsname
        self.page_break = page_break
        self.prompt = prompt
        self.sudoprompt = sudo_prompt
        self.timeout = timeout
        self.login_status = False
        self.password = None
        self.child = None

        # Default action: raise an exception if the command's exit code isn't 0 or not.
        self.quiet = quiet

    def login(self, *args, **kwargs):
        """
        @brief  Shell is always opened for Popen\\Pexpect.
        """
        self.login_status = True

    def open_shell(self):
        """
        @brief  Shell is always opened for Popen\\Pexpect.
        """
        pass

    def close_shell(self):
        """
        @brief  Shell is always opened for Popen\\Pexpect.
        """
        pass

    def check_shell(self):
        """
        @brief  Shell is always existed for Popen\\Pexpect.
        """
        pass

    def close(self):
        """
        @brief  Popen\\Pexpect object is always opened and doesn't have 'close' method.
        """
        pass

    def shell_read(self, timeout=0, interval=0.1):
        """
        @copydoc testlib::cli_template::CLIGenericMixin::shell_read()
        """
        data = ""
        if self.child:
            data = self.child.read()
        else:
            self.class_logger.warning("Child object isn't created, reading is skipped")
        return data

    @ip_net_namespace_mode
    def exec_command(self, command, timeout=None):
        """
        @copydoc testlib::cli_template::CLIGenericMixin::exec_command()
        """
        self.class_logger.debug(command)
        command = command.split(" ")
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        process.wait()
        so = process.stdout.read()
        se = process.stderr.read()
        self.class_logger.debug(self.cmd_output_log(so, se))
        return so, se

    # TODO: Implement bash creation for shell_command
    @ip_net_namespace_mode
    def shell_command(self, command, alternatives=None, timeout=None, sudo=False, ret_code=True, expected_rc="0",
                      quiet=None, raw_output=False, interval=0.1):
        """
        @copydoc testlib::cli_template::CLIGenericMixin::shell_command()
        @param  interval:  Interval between read data cycles.
        @type  interval:  int | float
        @raise  CLINNSException:  unexpected return code
        """
        self.class_logger.debug("Command {0}".format(command))
        if timeout is None:
            timeout = self.timeout

        if quiet is None:
            quiet = self.quiet

        if isinstance(expected_rc, int):
            expected_rc = str(expected_rc)

        data = ""
        return_code = None

        command, alternatives, end_pattern = self.prepare_alter(command, alternatives, sudo=True)

        self.child = pexpect.spawn('bash', ['-c', command], maxread=1)
        self.child = self.prepare_pexpect_obj(self.child)
        data = self.action_on_expect(self.child, alternatives, timeout, interval)

        if not raw_output:
            data, return_code = self.normalize_output(data, command, ret_code, end_pattern)

        self.class_logger.debug("Command output:\n{0}".format(data))

        if ret_code and not quiet:
            if return_code != expected_rc:
                raise CLINNSException("Command returned the unexpected code: {0}".format(return_code))

        return data, return_code

    @ip_net_namespace_mode
    def send_command(self, command):
        """
        @copydoc testlib::cli_template::CLIGenericMixin::send_command()
        """

        self.class_logger.debug(command)
        command = command.split(" ")
        Popen(command, stdout=PIPE, stderr=PIPE)

    def put_file(self, src, dst):
        """
        @copydoc testlib::cli_template::CLIGenericMixin::put_file()
        """
        if isinstance(src, str):
            src = [src, ]
            dst = [dst, ]
        for _src, _dst in zip(src, dst):
            command = "sudo cp {0} {1}".format(_src, _dst)
            so, se, rc = self.native_cmd(command, verbose=False)
            if rc != "0":
                self.class_logger.warning("Error when copy {0} to {1} : \n{2}".format(_src, _dst, se))

    def get_file(self, src, dst):
        """
        @copydoc testlib::cli_template::CLIGenericMixin::get_file()
        """
        self.put_file(src, dst)

    def native_cmd(self, command, shell=False, wait=True, verbose=True):
        """
        @brief  Execute popen command.
        @param  command:  Command to be executed.
        @type  command:  str
        @param  shell:  Flag specifies whether to use the shell as the program to execute.
        @type  shell:  bool
        @param  wait:  Flag specifies whether to wait for command output.
        @type  wait:  bool
        @param  verbose:  Flag specifies whether to print command output.
        @type  verbose:  bool
        """
        if verbose:
            self.class_logger.debug(command)
        command = command.split(" ")

        stderr = PIPE
        stdout = PIPE

        process = Popen(command, stdout=stdout, stderr=stderr, shell=shell)
        if wait:
            rc = process.wait()

            so = process.stdout.read()
            se = process.stderr.read()
            if verbose:
                self.class_logger.debug(self.cmd_output_log(so, se))

            return so, se, str(rc)
