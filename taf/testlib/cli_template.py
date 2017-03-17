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

"""``cli_template.py``

`Abstract class for any CLI classes`

"""

import io
import random
import time
import re
from abc import ABCMeta, abstractmethod
from collections import namedtuple
import collections

from .custom_exceptions import CLIException
from . import loggers


class Raw(str):
    """This class represents raw commands for cli object.

    """
    pass


CmdStatus = namedtuple("CmdStatus", "stdout, stderr, rc")


class CLIGenericMixin(object, metaclass=ABCMeta):
    """Base class for CLI configuration.

    """

    Raw = Raw
    class_logger = loggers.ClassLogger()

    def __init__(self):
        """Entry __init__ method defines class variable.

        """
        self.CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        self.prompt = None
        self.page_break = None
        self.sudoprompt = None
        self.password = None

    def randstr(self, length):
        """Return random string with required length.

        Args:
            length(int):  Required length

        """
        return "".join(random.choice(self.CHARS) for x in range(length))

    def expect(self, obj, expect_list, timeout=60, interval=0.1, remove_cmd=True, is_shell=False):
        """Expecting prompts and return prompt index in expect_list.

        Args:
            obj(Channel):  CLI obj of different types.
            expect_list(list):  List of compiled re objects to find prompt in data.
            timeout(int):  Expecting timeout.
            interval(int):  Interval between read data cycles.
            remove_cmd(bool):  Flag whether to remove command from output during searching prompt in data.
            is_shell(bool):  Indicates shell command

        Returns:
            tuple:  Found position from expect_list and full command output

        """
        full_out = ""
        temp_data = ""

        end_time = time.time() + timeout
        while True:
            time.sleep(interval)

            # Read data from IO.
            data = obj.read()
            # Remove command from searched data
            if data:
                if remove_cmd and not is_shell:
                    if "END_COMMAND" in data and len(data.split("\n")) <= 2:
                        temp_data = data
                    else:
                        counter = 0
                        while len(data.split("\n")) < 2 and counter < 30:
                            data += obj.read()
                            counter += 1
                            time.sleep(0.1)

                        if "\n" in data:
                            temp_data = " ".join(data.split("\n")[1:])
                        else:
                            temp_data = ""
                        remove_cmd = False
                else:
                    temp_data = data
            full_out += data

            # Update action and exit_flag
            for position, expect_re in enumerate(expect_list):
                if expect_re.search(temp_data) is not None:
                    return position, full_out

            # When timeout ends exit from loop and return None
            if time.time() >= end_time:
                return -1, full_out

    def action_on_expect(self, obj, alternatives, timeout=60, interval=0.1, command_timeout=600, is_shell=False):
        """Performs actions on found prompts. Returns command output data.

        Args:
            obj(Channel):  CLI object of different types.
            alternatives(tuple | list):  Tuples of ("expected line", "action if line is found", <Exit execution? (bool)>, <Use ones? (bool)>).
                                         action can be:
                                             - str - in case this is just command;
                                             - function - callable object to execute without parameters;
            timeout(int):  Expecting timeout.
            interval(int | float):  Interval between read data cycles.
            command_timeout(int): Command execution timeout.
            is_shell(bool): Indicates shell command

        Raises:
            CLIException:  timeout exceeded for command execution

        Returns:
            str:  Full output

        """
        # Flag whether to remove command from output during searching prompt in data
        remove_cmd = True

        # Update alternatives.
        expect_list = []
        for alter_item in alternatives:
            if alter_item[0]:
                expect_list.append((re.compile(re.escape(alter_item[0])), alter_item[1], alter_item[2], alter_item[3]))

        full_out = ""
        exit_flag = None
        end_time = time.time() + timeout + command_timeout
        while not exit_flag:
            if time.time() >= end_time:
                # class_logger is defined in subclasses
                self.class_logger.error(full_out + "\n")  # pylint: disable=no-member
                raise CLIException("Command execution is not finished: timeout %s" % (timeout + command_timeout))

            prompt_list = []
            for expect_item in expect_list:
                prompt_list.append(expect_item[0])
            _output = None
            _output = obj.expect(prompt_list, timeout=timeout, interval=interval, remove_cmd=remove_cmd, is_shell=is_shell)
            # command has to be removed only from the 1st output part.
            remove_cmd = False
            if _output[0] == -1:
                err = "Timeout exceeded. Expected prompt didn't appear in %s seconds.\n" % timeout
                full_out += _output[1]
                # class_logger is defined in subclasses
                self.class_logger.error(full_out)  # pylint: disable=no-member
                raise CLIException(err)

            full_out += _output[1]
            _action = expect_list[_output[0]][1]

            if _action:
                if isinstance(_action, Raw):
                    obj.write(_action)
                elif isinstance(_action, str):
                    obj.write(str(_action) + "\n")
                elif isinstance(_action, collections.Callable):
                    _action()

            exit_flag = expect_list[_output[0]][2]

            # Remove alternative from list if it's requested
            if expect_list[_output[0]][3]:
                expect_list.pop(_output[0])

        return full_out

    def action_on_connect(self, obj, alternatives, timeout=60, interval=0.1, command_timeout=600, is_shell=False):
        """Performs actions on found prompts. Returns command output data. This is only for CLI connect. See action_on_expect for details.

        Args:
            obj(Channel):  CLI object of different types.
            alternatives(tuple):  Tuples of ("expected line", "action if line is found", <Exit execution? (bool)>, <Use ones? (bool)>).
                                  action can be:
                                      - str - in case this is just command;
                                      - function - callable object to execute without parameters;
            timeout(int):  Expecting timeout.
            interval(int):  Interval between read data cycles.
            command_timeout(int): Command execution timeout.
            is_shell(bool): Indicates shell command

        Raises:
            CLIException:  sudoprompt is not defined

        Returns:
            str:  Full output

        """
        # Update alternatives.
        expect_list = []
        for alter_item in alternatives:
            if alter_item[0]:
                expect_list.append((re.compile(re.escape(alter_item[0])), alter_item[1], alter_item[2], alter_item[3]))

        full_out = ""
        prompt_list = []

        for expect_item in expect_list:
            prompt_list.append(expect_item[0])
        _output = None
        _output = obj.expect(prompt_list, timeout=timeout, interval=interval, remove_cmd=True, is_shell=is_shell)

        full_out += _output[1]
        _action = expect_list[_output[0]][1]

        if _action:
            if isinstance(_action, Raw):
                obj.write(_action)
            elif isinstance(_action, str):
                obj.write(str(_action) + "\n")
            elif isinstance(_action, collections.Callable):
                _action()

        # Remove alternative from list if it's requested
        if expect_list[_output[0]][3]:
            expect_list.pop(_output[0])

        return full_out

    def prepare_ssh_shell_obj(self, shell):
        """Add read(), write() and expect() methods to emulate object IO methods.

        Args:
            shell(paramiko.Channel):  paramiko.Channel object.

        Returns:
            paramiko.Channel:  paramiko.Channel object.

        """
        # use a closure
        def read():
            """ Non blocking read implementation.

            """
            data = ""
            while shell.recv_ready():
                # += for strings is optimized, don't worry.
                # we still have to decode here since there can be unicode
                data += shell.recv(200000).decode()
            return data

        def expect(alternatives=None, timeout=60, interval=0.1, remove_cmd=True, is_shell=False):
            return self.expect(shell, alternatives, timeout, interval, remove_cmd, is_shell)

        shell.write = shell.sendall
        shell.read = read
        shell.expect = expect
        return shell

    def normalize_output(self, data, command, ret_code, end_pattern=None):
        """Removes command and command's end flag from output data. Extracts return code of the command.

        Args:
            data(str):  Output data of command.
            command(str):  Executed command.
            ret_code(bool):  Flag which shows if return code command was added to main command.
            end_pattern(str): pattern which is used to find end command flag.

        Returns:
            tuple:  data and return code

        """

        # Remove command itself from output
        data_list = data.split("\n")

        updated_data_list = []

        # Prepare output data(it removes \r in case if long command is used)
        for item in data_list:
            data_l = []
            temp_data_list = item.split(" ")
            for data_string in temp_data_list:
                data_l.append(data_string.lstrip('\r').rstrip('\r'))
            item = " ".join(data_l)
            updated_data_list.append(item)

        # Remove command from output
        count = 0
        indexes_list = []
        for data_item in updated_data_list:
            if command.split(";")[0] in data_item:
                indexes_list.append(count)
            count += 1
        count = 0
        for index in indexes_list:
            data_list.pop(index - count)
            count += 1
        data = "\n".join(data_list)

        # Removes prompt from output data
        if self.prompt:
            for single_prompt in self.prompt if isinstance(self.prompt, list) else [self.prompt]:
                if single_prompt in data.split("\n")[-1]:
                    temp_data_list = data.split("\n")
                    if temp_data_list[-1].endswith(single_prompt):
                        data_string = temp_data_list[-1].rsplit(single_prompt, 1)[0]
                        temp_data_list[-1] = data_string
                    data = "\n".join(temp_data_list)
                    break

        return_code = ""
        # Remove end_command flag.
        if ret_code:
            end_pattern += r"=\[(-*\d{,3})"
            ret_code_re = re.compile(end_pattern)
            re_s = ret_code_re.search(data)
            if re_s is not None:
                _start, _ = re_s.regs[0]
                return_code = re_s.groups()[-1]
                data = data[:_start]
        else:
            return_code = None

        return data, return_code

    def prepare_pexpect_obj(self, pexp_obj):
        """Add read(), write() and expect() methods to emulate object IO methods.

        Args:
            pexp_obj(pexpect):  pexpect object.

        Returns:
            pexpect:  pexpect object.

        """

        pexp_obj.mod_expect = pexp_obj.expect

        def wrap_exp(obj, prompt_list, timeout, interval, remove_cmd, is_shell):
            """Add expect() method to emulate object IO methods.

            """
            rc, data = self.expect(obj, prompt_list, timeout, interval, remove_cmd, is_shell)

            return rc, data

        def wrap_read(pexp_obj):
            """Add read() method to emulate object IO methods.

            """
            try:
                data = pexp_obj.read_nonblocking(200000, 1)
            except Exception:
                data = ""

            return data

        pexp_obj.expect = lambda prompt, timeout, interval, remove_cmd=True, is_shell=False: wrap_exp(pexp_obj, prompt, timeout, interval, remove_cmd, is_shell)
        pexp_obj.write = lambda cmd: pexp_obj.sendline(cmd.replace("\n", ""))
        pexp_obj.read = lambda: wrap_read(pexp_obj)

        return pexp_obj

    def prepare_telnet_obj(self, telnet_obj):
        """Add read() and expect() methods to object to emulate object IO methods.

        Args:
            telnet_obj(telnetlib):  telnetlib  object.

        Returns:
            telnetlib:  telnetlib object

        """

        telnet_obj.mod_expect = telnet_obj.expect

        def wrap_exp(obj, prompt_list, timeout, interval, remove_cmd, is_shell):
            """Add expect() method to emulate object IO methods.

            """
            rc, data = self.expect(obj, prompt_list, timeout, interval, remove_cmd, is_shell)

            return rc, data

        def wrap_read(telnet_obj):
            """Add read() method to emulate object IO methods.

            """
            try:
                data = telnet_obj.read_very_eager()
            except Exception:
                data = ""

            return data

        # telnet_obj.expect = lambda prompt, timeout, interval, remove_cmd=True, is_shell=False: wrap_exp(telnet_obj, prompt, timeout, interval,
        #                                                                                                remove_cmd, is_shell)
        telnet_obj.expect = lambda alternatives=None, timeout=60, interval=0.1, remove_cmd=True, is_shell=False: self.expect(telnet_obj, alternatives, timeout,
                                                                                                                             interval, remove_cmd, is_shell)
        telnet_obj.read = lambda: wrap_read(telnet_obj)
        # Clear output buffer from previous programs
        telnet_obj.read_very_eager()

        return telnet_obj

    def cmd_output_log(self, so, se):
        """log message normalizer.

        Args:
            so(str):  StdOut
            se(str):  StdErr

        Returns:
            str: Normalized output

        """
        message = "Command output:"
        if so:
            message += " StdOut\n{0}".format(so)
        else:
            message += " StdOut: <empty>"
        if se:
            message += " StdErr:\n{0}".format(se)
        else:
            message += " StdErr: <empty>"
        return message

    def prepare_alter(self, command, alternatives=None, sudo=False, ret_code=True, page_break=None):
        """Adds specified alternatives to list, updates command with end command and sudo if needed.

        Args:
            command(str):  Command to be executed.
            alternatives(tuple):  Tuples of ("expected line", "action if line is found", <Exit execution? (bool)>, <Use ones? (bool)>).
                                  action can be:
                                      - str - in case this is just command;
                                      - function - callable object to execute without parameters;
            sudo(bool):  Flag if sudo should be added to the list of alternatives .
            ret_code(bool):  Flag if return code should be added to the list of alternatives.
            page_break(bool):  Flag if page break should be added to the list of alternatives.

        Returns:
            tuple:  command, alternatives, end_pattern

        """

        if alternatives is None:
            alternatives = []

        # Add one or few expected prompt(s) and action(s) to alternatives list
        if self.prompt:
            if isinstance(self.prompt, list):
                for single_prompt in self.prompt:
                    alternatives.append((single_prompt, None, True, False))
            elif isinstance(self.prompt, str):
                alternatives.append((self.prompt, None, True, False))

        # Append page_break tuple with exit_flag = False.
        if self.page_break:
            alternatives.append((self.page_break, Raw(" "), False, False))
        elif page_break:
            alternatives.append((page_break, Raw(" "), False, False))

        # FYI: shell.recv_exit_status() returns exit status of shell process, and any attempts
        #      to read it before shell is closed invokes "dead" lock.
        end_pattern = None
        if ret_code:
            # '' is required to exclude false end command detection on command send.
            end_flag = "END_COM''MAND_{0}_{1}".format(id(self), self.randstr(10))
            # Remove '' for expect pattern.
            end_pattern = end_flag[:7] + end_flag[9:]
            command += "; echo {0}=[$?]".format(end_flag)
            alternatives.append((end_pattern, None, True, False))

        if sudo:
            command = "sudo " + command
            if self.sudoprompt is None:
                raise CLIException("sudo prompt is not defined. Cannot execute command with sudo.")
            alternatives.append((self.sudoprompt, self.password, False, True))

        return command, alternatives, end_pattern

    @abstractmethod
    def login(self):
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

        """
        pass

    @abstractmethod
    def close(self):
        """Close CLI object connection.

        """
        pass

    @abstractmethod
    def open_shell(self):
        """Create interactive CLI shell on existing connection.

        """
        pass

    @abstractmethod
    def close_shell(self):
        """Close interactive CLI shell on existing connection.

        """
        pass

    @abstractmethod
    def check_shell(self):
        """Check if CLI connection is alive.

        """
        pass

    @abstractmethod
    def shell_read(self):
        """Read data from output buffer.

        Args:
            timeout(int):  Increases time to read data from output buffer.
            interval(int):  Time delay between attempts to read data from output buffer.

        """
        pass

    @abstractmethod
    def send_command(self):
        """Run command without waiting response.

        Args:
            command(str):  Command to be executed.

        """
        pass

    @abstractmethod
    def exec_command(self):
        """Execute command without shell (tty).

        Args:
            command(str):  Command to be executed.
            timeout(int):  Timeout for command execution.

        Returns:
            tuple(str, str, int): tuple of stdout, stderr, rc

        """
        pass

    @abstractmethod
    def shell_command(self):
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

        """
        pass

    @abstractmethod
    def put_file(self):
        """Transfer file from/to remote host.

        Args:
            src(str):  File's source.
            dst(str):  File's destination.

        """
        pass

    @abstractmethod
    def get_file(self):
        """Put file to remote host.

        Args:
            src(str):  File's source.
            dst(str):  File's destination.

        """
        pass
