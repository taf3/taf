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

"""``clitelnet.py``

`Basic telnet class with command oriented functionality`

"""

import telnetlib
import time
import re

from .cli_template import CLIGenericMixin
from .cli_template import CmdStatus
from .custom_exceptions import CLITelnetException
from . import loggers


# TODO: cmd retry
# TODO: Add logout/exit command for proper closing telnet connections
class TelnetCMD(CLIGenericMixin):
    """HighLevel telnet command oriented class. Unused parameters added to support the same interface for other CLI classes.

    Examples::

        client = TelnetCMD("1.1.1.1", 22)
        client.login("username", "paSSword")

    """

    class_logger = loggers.ClassLogger()

    def __init__(self, host=None, port=23, username=None, password=None, page_break="--More--",
                 prompt=None, pass_prompt="Password: ", sudo_prompt=None, timeout=10, login_prompt="login: ", page_break_lines=3,
                 exit_cmd=None, quiet=False):
        """Initialize TelnetCMD class.

        Args:
            host(str):  Target host IP address.
            port(int):  SSH port.
            username(str):  SSH login user.
            password(str):  SSH user password.
            page_break(str):  Page brake marker.
            prompt(str, list[str]):  Shell prompt or list of shell prompts.
            pass_prompt(str):  Login password prompt.
            sudo_prompt(str):  Sudo password prompt.
            timeout(int):  Default timeout for commands.
            login_prompt(str):  Login prompt.
            page_break_lines(int):  Number of page brake lines.
            exit_cmd(str):  Command to perform telnet exit (str).
            quiet(bool):  Flag for return code verification.

        """

        super(TelnetCMD, self).__init__()

        self.host = host
        self.port = port
        self.user = username
        self.password = password
        self.prompt = prompt
        self.pass_prompt = pass_prompt
        self.login_prompt = login_prompt
        self.page_break = page_break
        self.page_break_lines = page_break_lines
        self.timeout = timeout
        self.telnet_obj = None
        self.prompt_stack = []
        self.exit_cmd = exit_cmd
        # Prompt for sudo password.
        self.sudo_pass_prompt = None
        # Global alternatives for commands.
        self.alternatives_global = []
        self.login_status = False
        self.connect_status = False
        self.sudoprompt = sudo_prompt

        # Default action: raise an exception if command's exit code isn't 0 or not.
        self.quiet = quiet

    def connect(self, with_login=True, wait_login=5, alternatives=None, wait_prompt=True, socket_closed=False):
        """Create telnet connection and do login if necessary.

        Args:
            with_login(bool):  Perform login procedure or not.
                               If param isn't set try automatically determine login necessity. (True|False|None)
            wait_login(int):  time to wait login before sending <Enter>.
                              <Enter> is necessary if login is already appeared.
            alternatives(tuple): Tuples of ("expected line", "action if line is found", <Exit execution? (bool)>, <Use ones? (bool)>).
                                 action can be:
                                     - str - in case this is just command;
                                     - function - callable object to execute without parameters;
            wait_prompt(bool):  Wait for prompt message or not.
            socket_closed(bool):  Determines if socket has been closed or not.

        Raises:
            Exception:  self.host is None; self.prompt is None

        Returns:
            str:  telnet stdout

        """
        if not self.host:
            raise Exception("Remote host was not defined.")
        telnet_output = []

        if socket_closed:
            self.telnet_obj.open(self.host, self.port)
        else:
            self.telnet_obj = telnetlib.Telnet(self.host, self.port, self.timeout)

        if with_login is None:
            prompt_re = re.compile(re.escape(self.prompt))
            login_prompt_re = re.compile(re.escape(self.login_prompt))
            _output = (-1, None, None)
            if wait_login > 0:
                _output = self.telnet_obj.expect([prompt_re, login_prompt_re], timeout=wait_login)
            if _output[0] == -1:
                self.telnet_obj.write("\n")
                _output = self.telnet_obj.expect([prompt_re, login_prompt_re], timeout=self.timeout)
            if _output[0] == 1:
                with_login = True
            else:
                with_login = False
        if with_login:
            _output = self.login(wait_login=wait_login, alternatives=alternatives, connect=False)
            telnet_output += _output
        else:
            if wait_prompt:
                if not self.prompt:
                    raise Exception("Prompt isn't defined. Please set the prompt.")
                # Send <Enter> to ensure that prompt is appeared
                self.telnet_obj.write("\n")
                _output = self.telnet_obj.read_until(self.prompt, self.timeout)
                telnet_output += _output
            else:
                # Skip reading output. Just connect.
                pass
        self.connect_status = True
        self.telnet_obj_prep = self.prepare_telnet_obj(self.telnet_obj)  # pylint: disable=attribute-defined-outside-init
        return telnet_output

    def _check_telnet_obj(self):
        """Check if telnet object exists (connection is established).

        Raises:
            Exception:  telnet connection is not established

        """
        if not (self.telnet_obj and self._check_telnet_obj_connection()):
            raise Exception("Connection to host has not been established yet.")

    def check_shell(self):
        """Check if CLI connection is alive.

        Raises:
            CLITelnetException:  telnet connection is not established; user is not logged in

        """
        # Why are we raising execptions, return False
        if not self.telnet_obj or not self._check_telnet_obj_connection():
            return False
        else:
            if not self.login_status:
                return False
            return True

    def close(self):
        """Close CLI object connection.

        """
        self.telnet_obj.close()

    def close_shell(self):
        """Close interactive CLI shell on existing connection.

        """
        self.close()

    def shell_read(self, timeout=0, interval=0.1):
        """Read data from output buffer.

        Args:
            timeout(int):  Increases time to read data from output buffer.
            interval(int):  Time delay between attempts to read data from output buffer.

        """
        self.check_shell()
        data = ""
        # The following loop has to be executed at least one time.
        end_time = time.time() + timeout
        end_flag = False
        self.telnet_obj.write("\n")
        while not end_flag:
            data += self.telnet_obj.read_very_eager()
            if time.time() >= end_time:
                end_flag = True
            else:
                time.sleep(interval)
        return data

    def send_command(self, command):
        """Run command without waiting response.

        Args:
            command(str):  Command to be executed.

        """
        self.check_shell()
        self.class_logger.debug("{0}@{1}: {2}".format(self.user, self.host, command))
        self.telnet_obj.write(command + "\n")

    def open_shell(self, raw_output=False):
        """Call login method. Added to support other CLI objects interface.

        Args:
            raw_output(bool): Flag whether to read output buffer.

        Raises:
            CLITelnetException:  telnet connection is not established

        Returns:
            str:  telnet output

        """
        data = ""
        if self._check_telnet_obj_connection():
            if self.check_shell():
                self.login_status = True
                if not raw_output:
                    data = self.shell_read(2)
                return data
            else:
                self.login()
                if not raw_output:
                    data = self.shell_read(2)
                return data
        else:
            raise CLITelnetException("Telnet object has no connection")

    def _check_telnet_obj_connection(self):
        """Verify if telnet connection exists.

        Returns:
            bool:  True if telnet connection exists

        """
        flag = True
        try:
            self.telnet_obj.sock.sendall(telnetlib.IAC + telnetlib.NOP)
        except Exception as err:
            self.class_logger.error("Telnet connection failure: %s", err)
            flag = False

        return flag

    def login(self, username=None, password=None, timeout=None, wait_login=0, alternatives=None, connect=True):
        """Do CLI object login procedure.

        Args:
            username(str):  Host login (string).
            password(str): Host password(string).
            timeout(int): Time to execute login procedure (integer).
            wait_login(int):  time to wait login prompt before sending <Enter>.
                              <Enter> is necessary if login prompt has been already appeared
                              before connection is established.
            alternatives(list of tuples): list of alternative prompts and actions.
            connect(bool): Flag if connection should be established before login procedure (bool).

        Returns:
            None

        Raises:
            Exception:  username is not defined
            CLITelnetException:  login timeout exceeded, unexpected login prompt

        """
        if not self.user and not username:
            raise Exception("User login name was not defined.")

        if not self.connect_status and connect:
            self.connect(with_login=False, wait_prompt=False)

        if self.telnet_obj:
            if self.telnet_obj.sock == 0:
                self.connect(with_login=False, wait_prompt=False, socket_closed=True)

        self._check_telnet_obj()
        telnet_output = []
        err = False
        alternatives = alternatives or []

        expect_list = [re.compile(re.escape(self.login_prompt)), ]
        action_list = [(self.user if not username else username, False if self.password or password else True), ]
        if self.password or password:
            expect_list.append(re.compile(re.escape(self.pass_prompt)))
            action_list.append((self.password if self.password else password, True))
        for alter_item in alternatives:
            expect_list.append(re.compile(alter_item[0]))
            action_list.append((alter_item[1].encode("ascii"), alter_item[2]))
        for alter_item in self.alternatives_global:
            expect_list.append(re.compile(alter_item[0]))
            action_list.append((alter_item[1].encode("ascii"), alter_item[2]))

        enter_sent = False
        stop_flag = False
        while not stop_flag:
            _output = self.telnet_obj.expect(expect_list, wait_login or self.timeout)
            telnet_output.append(_output[1])
            self.class_logger.debug("Output: %s" % (_output[1], ))
            if _output[0] == -1:
                # Reset wait_login to set default timeout for next iteration.
                if wait_login > 0:
                    wait_login = 0
                if not enter_sent:
                    # Send <Enter> to ensure that login prompt appeared.
                    self.telnet_obj.write("\n")
                    enter_sent = True
                else:
                    # If <Enter> is already sent and still no response - set error flag.
                    err = True
                    stop_flag = True
                continue
            self.class_logger.debug("Action: %s" % (action_list[_output[0]], ))
            self.telnet_obj.write(str("%s\n" % (action_list[_output[0]][0], )))
            stop_flag = action_list[_output[0]][1]

        if err:
            message = "Telnet timeout exceeded. Expected prompt did not appear during %s seconds.\nTelnet output: %s" %\
                      (self.timeout, "\n".join(telnet_output))
            self.class_logger.error(message)
            raise CLITelnetException(message)
        elif self.prompt:
            _output = self.telnet_obj.read_until(self.prompt, self.timeout)
            telnet_output.append(_output)
        # Verification that login is successful if prompt isn't defined
        else:
            # time.sleep is used to wait until data appear in buffer
            time.sleep(2)
            # _output = self.telnet_obj.read_very_eager()
            telnet_output.append(_output)
            _output_1 = self.telnet_obj.read_very_eager()
            self.prompt = _output_1.split("\n")[-1]
            self.telnet_obj.write("\n")
            # time.sleep is used to wait until data appear in buffer
            time.sleep(2)
            _output = self.telnet_obj.read_very_eager()
            last_line = _output.splitlines()[-1]

            if self.prompt != last_line:
                self.class_logger.error(telnet_output)
                raise CLITelnetException("Login prompt is not as expected: {0} != {1}".format(self.prompt, last_line))

        self.login_status = True
        return telnet_output

    def exit(self, wait_close=True):
        """Do telnet exit/logout procedure. Wait until connection closed.

        Args:
            wait_close(bool):  Flag specifies whether to verify successful exit and to return output data.

        """
        self._check_telnet_obj()
        telnet_output = []
        # Send <Enter> to ensure that login prompt is appeared
        self.telnet_obj.write("\n")
        _output = self.telnet_obj.read_until(self.prompt, self.timeout)
        telnet_output.append(_output)
        self.telnet_obj.write("%s\n" % (self.exit_cmd, ))
        if not wait_close:
            self.telnet_obj.read_eager()
            return None
        end_time = time.time() + self.timeout
        while time.time() <= end_time:
            try:
                _output = self.telnet_obj.read_eager()
                telnet_output.append(_output)
                time.sleep(0.3)
            except EOFError:
                return telnet_output
        return None

    def disconnect(self, with_exit=True):
        """Do disconnect.

        Args:
            with_exit(bool):  Flag specifies whether perform exit procedure.

        """
        if self.telnet_obj:
            try:
                if with_exit and self.exit_cmd is not None:
                    # print "TELNETCMD: Try to do exit()"
                    self.exit()
            finally:
                self.telnet_obj.close()
                self.class_logger.debug("Connection to %s:%s is closed." % (self.host, self.port))

    def shell_command(self, command, alternatives=None, timeout=None, sudo=False, ret_code=True,
                      new_prompt=None, expected_rc="0", quiet=None, raw_output=False, interval=0.1):
        """Run interactive command on previously created shell (tty).

        Args:
            command(str):  Command to be executed.
            alternatives(tuple):  Tuples of ("expected line", "action if line is found", <Exit execution? (bool)>, <Use ones? (bool)>).
                                  action can be:
                                      - str - in case this is just command;
                                      - function - callable object to execute without parameters;
            timeout(int):  Expecting timeout.
            sudo(bool):  Flag if sudo should be added to the list of alternatives.
            ret_code(bool):  Flag if return code should be added to the list of alternatives.
            expected_rc(int): Sets return code and verifies if return code of executed command the same as expected return code (int or str).
            quiet(bool):  Flag to verify if expected return equals expected.
            raw_output(bool):  Flag whether to return 'pure' output.
            interval(int | float):  Interval between read data cycles.
            new_prompt(str):  Prompt which will replace current prompt after successful mode changing.

        Raises:
            CLITelnetException:  unexpected return code

        """
        self._check_telnet_obj()
        self.class_logger.debug("{0}@{1}: {2}".format(self.user, self.host, command))

        if timeout is None:
            timeout = self.timeout

        if quiet is None:
            quiet = self.quiet

        if isinstance(expected_rc, int):
            expected_rc = str(expected_rc)

        data = ""
        return_code = None

        command, alternatives, end_pattern = self.prepare_alter(command, alternatives, sudo=sudo, ret_code=ret_code)
        # Expand alternatives for telnet specific login.
        alternatives.append((self.sudoprompt, str(self.password), False, False))
        if new_prompt:
            alternatives.append((new_prompt, None, True, False))

        self.telnet_obj.write(command + "\n")

        data = self.action_on_expect(self.telnet_obj_prep, alternatives, timeout, interval)

        if not raw_output:
            data, return_code = self.normalize_output(data, command, ret_code, end_pattern)

        self.class_logger.debug("Command output:\n{0}".format(data))

        if ret_code and not quiet:
            if return_code != expected_rc:
                raise CLITelnetException("Command return unexpected return code: {0}".format(return_code))

        return data, return_code

    def exec_command(self, command, timeout=None, sudo=False, ret_code=False):
        """Execute command without shell (tty).

        Args:
            command(str):  Command to be executed.
            timeout(int):  Timeout for command execution.
            sudo(bool):  Flag  if sudo should be added to the list of alternatives.
            ret_code(bool):  Flag if return code should be added to the list of alternatives (bool).

        Returns:
            tuple(str, str, int): output, "", return code

        """

        output, rc = self.shell_command(command, timeout=timeout, sudo=sudo, ret_code=ret_code)
        # no stderr so use empty string
        return CmdStatus(output, "", rc)

    def enter_mode(self, cmd=None, new_prompt=None):
        """Enter config/priv or other mode with specific prompt.

        Args:
            cmd(str):  Command to change mode.
            new_prompt(str):  Prompt which will replace current prompt after successful mode changing.

        Raises:
            Exception:  undefined prompt, unexpected new prompt

        Note:
            After success execution current prompt will be replaced with new propmt and saved in prompt_stack.

        """
        if not self.prompt:
            message = "Prompt isn't defined. Please set the prompt."
            raise Exception(message)

        self._check_telnet_obj()
        telnet_output, error = self.shell_command(cmd, ret_code=False, new_prompt=new_prompt)
        if error:
            message = "Cannot enter priv mode. Command: %s. Expected prompt: %s. Error: %s. Last output: %s" % (cmd, new_prompt, error, telnet_output, )
            self.class_logger.log(loggers.levels['ERROR'], message)
            raise Exception(message)
        else:
            self.prompt_stack.append(self.prompt)
            self.prompt = new_prompt
        return self.prompt

    def exit_mode(self, exit_cmd=None):
        """Exit config/priv or other mode with specific prompt.

        Args:
            exit_cmd(str):  Command to exit from current mode.

        Raises:
            Exception:  undefined prompt, unexpected new prompt

        """
        if not self.prompt:
            message = "Prompt isn't defined. Please set the prompt."
            raise Exception(message)

        self._check_telnet_obj()
        prev_prompt = self.prompt_stack[-1]
        telnet_output, error = self.shell_command(exit_cmd, ret_code=False, new_prompt=prev_prompt)
        if error:
            message = 'Cannot exit priv mode. Command: %s. Expected prompt: %s. Error: %s. Last output: %s' % (exit_cmd, prev_prompt, error, telnet_output)
            self.class_logger.log(loggers.levels['ERROR'], message)
            raise Exception(message)
        else:
            self.prompt = prev_prompt
            self.prompt_stack.pop()
        return self.prompt

    def _normalize_output(self, output=None, cmd=None, prompt=None):
        """Remove everything from the response except the actual command output.

        Args:
            output(str):  Output data to be normalized.
            cmd(str):  Command which was used for program execution.
            prompt(str):  Prompt which will be removed form output data.

        """
        lines = output.splitlines(True)
        # If command was echoed back, remove it from the output
        if cmd in lines[0]:
            lines.pop(0)
        # Remove the last element, which is the prompt or page break marker being displayed again
        if len(lines) > 0 and lines[-1] == prompt:
            lines.pop()
        if len(lines) > 0 and lines[-1] == self.page_break:
            for _ in range(self.page_break_lines):
                lines.pop()
        # Restore output
        return "".join(lines)

    def put_file(self):
        """This method isn't supported by telnetlib.

        Raises:
            CLITelnetException:  unsupported

        """
        raise CLITelnetException("cli_telnet object doesn't support put_file method ")

    def get_file(self):
        """This method isn't supported by telnetlib.

        Raises:
            CLITelnetException:  unsupported

        """
        raise CLITelnetException("cli_telnet object doesn't support get_file method ")
