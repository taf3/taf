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

@file  clissh.py

@summary Module contains classes for managing device using SSH connection or SSH connection emulation for Linux Network Namespaces.
"""

import socket
import time
from io import StringIO
import curses.ascii as ascii_char
from contextlib import closing

import paramiko

from . import loggers
from .custom_exceptions import CLISSHException
from .cli_template import CLIGenericMixin
from .cli_template import CmdStatus


def probe_port(ipaddr, port, logger):
    """
    @brief  Check if device listen on port.
    @param ipaddr: IP address
    @type  ipaddr:  str
    @param port:  SSH port
    @type  port:  int
    @param logger:  logger instance
    @type  logger:  loggers.ClassLogger
    @rtype:  bool
    @return:  True or False
    @note  This verification is necessary before establishing ssh connection.
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(3)
        try:
            time.sleep(1)
            sock.connect((ipaddr, port))
        except (socket.gaierror, socket.error):
            logger.debug("IP address %s port %s doesn't respond" % (ipaddr, port))
            return False
        else:
            logger.debug("IP address %s port %s opened" % (ipaddr, port))
            return True


class CLISSH(CLIGenericMixin):
    """
    @description  Class for configure device using CLI over ssh with paramiko. Unused parameters added to support the same interface for other CLI classes.

    @code{.py}
    client = CLISSH("1.1.1.1", 22)
    client.login("username", "paSSword")
    @endcode
    """

    class_logger = loggers.ClassLogger()

    def __init__(self, host, port=22, username=None, password=None,
                 page_break=None, prompt=None, pass_prompt="Password:", sudo_prompt=None, login_prompt=None, page_break_lines=None,
                 exit_cmd=None, timeout=60, quiet=False, pkey=None, key_filename=None):
        """
        @brief  Initialize CLISSH class

        @param  host:  Target host IP address.
        @type  host:  str
        @param  port:  SSH port (integer).
        @type  port:  int
        @param  username:  SSH login user.
        @type  username:  str
        @param  password:  SSH user password.
        @type  password:  str
        @param  page_break:  Page brake marker.
        @type  page_break:  str
        @param  prompt:  Shell prompt or list of shell prompts.
        @type  prompt:  str, list[str]
        @param  pass_prompt:  Login password prompt.
        @type  pass_prompt:  str
        @param  sudo_prompt:  Sudo password prompt.
        @type  sudo_prompt:  str
        @param  timeout:  Default timeout for commands.
        @type  timeout:  int
        @param login_prompt:  Login prompt (str).
        @type  login_prompt:  str
        @param page_break_lines:  Number of page brake lines (int).
        @type  page_break_lines:  int
        @param exit_cmd:  Command to perform telnet exit (str).
        @type  exit_cmd:  str
        @param  quiet:  Flag for return code verification.
        @type  quiet:  bool
        """

        super(CLISSH, self).__init__()

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.page_break = page_break
        self.prompt = prompt
        self.passprompt = pass_prompt
        self.sudoprompt = sudo_prompt
        self.timeout = timeout
        if isinstance(pkey, str):
            pkey = paramiko.RSAKey.from_private_key(StringIO(str(pkey)))
        self.pkey = pkey
        self.key_filename = key_filename

        self.shell = None
        self.prompt_stack = []
        self.timesleep = 1
        self.delay = None
        self.login_status = False

        # Default action: raise an exception if command's exit code isn't 0 or not.
        self.quiet = quiet

    def login(self, username=None, password=None, timeout=None):
        """
        @copydoc testlib::cli_template::CLIGenericMixin::login()
        """
        if self.login_status:
            self.class_logger.debug("SSH client is already opened.")
            if self.check_client():
                return
            else:
                self.close()
                self.class_logger.debug("SSH client is dead. Reconnect...")
        username = username or self.username
        password = password or self.password
        timeout = timeout or self.timeout
        self.class_logger.debug("Connecting to {0}@{1}...".format(username, self.host))
        self.client.connect(self.host,
                            self.port,
                            username,
                            password,
                            timeout=timeout,
                            pkey=self.pkey,
                            key_filename=self.key_filename,)
        transport = self.client.get_transport()
        transport.packetizer.REKEY_PACKETS = 2**35
        transport.packetizer.REKEY_BYTES = 2**35
        self.username = username
        self.login_status = True

    def check_client(self):
        """
        @brief  Check if SSH client is alive.
        """
        try:
            transport = self.client.get_transport()
            result = transport.is_active()
            return result
        except AttributeError:
            return False

    def close(self):
        """
        @copydoc testlib::cli_template::CLIGenericMixin::close()
        """
        self.class_logger.debug("Closing connection to {0}@{1}...".format(self.username, self.host))
        self.client.close()
        self.shell = None
        self.login_status = False

    def open_shell(self, timeout=20, raw_output=False):
        """
        @brief  Create interactive SSH shell on existing connection.

        @param  timeout: Timeout until prompt is appeared.
        @type  timeout:  int
        @param  raw_output: Flag whether to read output buffer.
        @type  raw_output:  bool
        @raise  CLISSHException:  not connected
        """
        output = ""
        if self.login_status and self.check_client():
            if self.check_shell():
                self.class_logger.debug("Shell for {0}@{1} is already invoked.".format(self.username, self.host))
                return
            self.class_logger.debug("Opening shell for {0}@{1} ...".format(self.username, self.host))
            # to avoid command line wrapping increase width as big as possible
            shell = self.client.invoke_shell(width=1000, height=1000)
            self.shell = self.prepare_ssh_shell_obj(shell)
            if self.prompt and not raw_output:
                alter = []

                # Add one or few expected prompt(s) and action(s) to alternatives list
                if isinstance(self.prompt, list):
                    for single_prompt in self.prompt:
                        alter.append((single_prompt, None, True, False))
                elif isinstance(self.prompt, str):
                    alter.append((self.prompt, None, True, False))
                output = self.action_on_expect(self.shell, alter, timeout=timeout)
            elif not raw_output:
                output = self.shell_read(0.5)
            self.class_logger.info("Shell is opened:\n{0}".format(output))
            return output
        else:
            raise CLISSHException("Cannot invoke shell before connecting.")

    def close_shell(self):
        """
        @copydoc testlib::cli_template::CLIGenericMixin::close_shell()
        """
        if self.shell and not self.shell.closed:
            self.class_logger.debug("Closing shell for {0}@{1} ...".format(self.username, self.host))
            self.shell.close()

    def check_shell(self):
        """
        @copydoc testlib::cli_template::CLIGenericMixin::close_shell()
        """
        return not getattr(self.shell, "closed", True)

    def _check_shell_obj(self):
        """
        @brief  Check if shell object exists.
        @raise  CLISSHException:  shell is not open
        """
        if not self.check_shell():
            raise CLISSHException("Cannot execute command. Shell is not open.")

    def exec_command(self, command, timeout=None):
        """
        @copydoc testlib::cli_template::CLIGenericMixin::exec_command()
        """
        self.class_logger.debug("{0}@{1}: {2}".format(self.username, self.host, command))

        if timeout is None:
            timeout = self.timeout

        _, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        out = stdout.read().decode('UTF-8')
        err = stderr.read().decode('UTF-8')
        exit_status = stdout.channel.recv_exit_status()

        self.class_logger.debug(self.cmd_output_log(out, err))
        return CmdStatus(out, err, exit_status)

    def shell_command(self, command, alternatives=None, timeout=None, sudo=False, ret_code=True, expected_rc="0",
                      quiet=None, raw_output=False, interval=0.1, tabulation=None):
        """
        @copydoc testlib::cli_template::CLIGenericMixin::shell_command()
        @param  interval:  Interval between read data cycles.
        @type  interval:  int | float
        @param  tabulation:  Tabulation characters.
        @type  tabulation:  str
        @raise  CLISSHException:  unexpected return code
        """
        self._check_shell_obj()
        self.class_logger.debug("{0}@{1}: {2}".format(self.username, self.host, command))

        if timeout is None:
            timeout = self.timeout

        if quiet is None:
            quiet = self.quiet

        if isinstance(expected_rc, int):
            expected_rc = str(expected_rc)

        data = ""
        return_code = None
        command, alternatives, end_pattern = self.prepare_alter(command, alternatives, sudo, ret_code)

        #
        # THIS HAS A BUG WHEN THE COMMAND LINE IS TOO LONG WRAPPING DOENS"T
        # WORK.
        #  DON"T USE THIS!!!!
        #

        if tabulation:
            self.shell.sendall(command + tabulation)
        # Three spaces added because some CLI commands after executing return mesh output.
        else:
            self.shell.sendall(command + "   \n")
        data = self.action_on_expect(self.shell, alternatives, timeout, interval)

        # Clearing console line from previous command.
        if tabulation:
            self.shell.sendall(ascii_char.ctrl("u"))

        if not raw_output:
            data, return_code = self.normalize_output(data, command, ret_code, end_pattern)
        self.class_logger.debug("Command output:\n{0}".format(data))

        if ret_code and not quiet:
            if return_code != expected_rc:
                raise CLISSHException("Command return unexpected return code: {0}".format(return_code))

        return data, return_code

    def shell_read(self, timeout=0, interval=0.1):
        """
        @copydoc testlib::cli_template::CLIGenericMixin::shell_read()
        """
        self._check_shell_obj()
        data = ""
        # The following loop has to be executed at least one time.
        end_time = time.time() + timeout
        end_flag = False
        while not end_flag:
            data += self.shell.read()  # pylint: disable=no-member
            if time.time() >= end_time:
                end_flag = True
            else:
                time.sleep(interval)
        return data

    def send_command(self, command):
        """
        @copydoc testlib::cli_template::CLIGenericMixin::send_command()
        """
        self.class_logger.debug("{0}@{1}: {2}".format(self.username, self.host, command))
        self._check_shell_obj()
        if isinstance(command, self.Raw):
            self.shell.sendall(command)
        else:
            self.shell.sendall(command + "\n")

    def _transfer_file(self, direction, src, dst, proto="scp"):
        """
        @brief  Transfer file from/to remote host.
        @param  direction:  transfer direction. set/get.
        @type  direction:  str
        @param  src:  Source file location.
        @type  src:  str
        @param  dst:  Destination file location.
        @type  dst:  str
        @param  proto:  Protocol to be used for file transfer. scp(default)/sftp.
        @type  proto:  str
        @raise  CLISSHException:  direction not in {"put", "get"}
        """
        if direction not in {"put", "get"}:
            raise CLISSHException("Incorrect file transfer direction '%s'." %
                                  (direction, ))
        if proto == "scp":
            self._scp_trans_file(direction, src, dst)
        elif proto == "sftp":
            self._sftp_trans_file(direction, src, dst)

    def _scp_trans_file(self, direction, src, dst):
        """
        @brief  Transfer file from/to remote host using scp.
        @param  direction:  transfer direction. set/get.
        @type  direction:  str
        @param  src:  Source file location.
        @type  src:  str
        @param  dst:  Destination file location.
        @type  dst:  str
        @raise  CLISSHException:  not supported direction "put"
        """
        if direction == "get":
            with open(dst, 'wb') as local_file:
                local_file.write(
                    self.client.exec_command('cat "{0}"'.format(src))[1].read())
        elif direction == "put":
            raise CLISSHException("Currently 'put' method is not supported for 'scp'")

    def _sftp_trans_file(self, direction, src, dst):
        """
        @brief  Transfer file from/to remote host using sftp.
        @param  direction:  transfer direction. set/get.
        @type  direction:  str
        @param  src:  Source file location.
        @type  src:  str
        @param  dst:  Destination file location.
        @type  dst:  str
        """
        ftp = None
        try:
            ftp = self.client.open_sftp()
            if isinstance(src, str):
                src = [src, ]
                dst = [dst, ]
            for _src, _dst in zip(src, dst):
                getattr(ftp, direction)(_src, _dst)
        finally:
            if ftp is not None:
                ftp.close()

    def get_file(self, src, dst, proto="sftp"):
        """
        @brief  Get file from remote host using sftp.
        @param  src:  Source file location.
        @type  src:  str
        @param  dst:  Destination file location.
        @type  dst:  str
        @param  proto:  Protocol to be used for file transfer. sftp(default)/scp.
        @type  proto:  str
        """
        self._transfer_file("get", src, dst, proto=proto)

    def put_file(self, src, dst, proto="sftp"):
        """
        @brief  Put file to remote host using sftp.
        @param  src:  Source file location.
        @type  src:  str
        @param  dst:  Destination file location.
        @type  dst:  str
        @param  proto:  Protocol to be used for file transfer. sftp(default)/scp.
        @type  proto:  str
        """
        self._transfer_file("put", src, dst, proto=proto)
