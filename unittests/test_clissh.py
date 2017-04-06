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

"""``test_clissh.py``

`Unittests for cli<X>.py modules`

"""

import os
import re
import time
import socket
from unittest.mock import MagicMock

import paramiko
import pytest

from testlib import clissh
from testlib import clitelnet
from testlib import clinns
from testlib.custom_exceptions import CLIException


def create_ssh(request, host, login):
    ssh_conn = clissh.CLISSH(host, username=login, sudo_prompt="[sudo] password")
    return ssh_conn


def create_telnet(request, host, login):
    telnet_conn = clitelnet.TelnetCMD(host, username=login, sudo_prompt="[sudo] password")
    return telnet_conn


def create_nns(request, host, login):
    os.system("sudo ip netns add %s" % host)
    os.system("sudo ip netns exec %s ifconfig lo up" % host)
    request.addfinalizer(lambda: os.system("sudo ip netns del %s" % host))
    nns_obj = clinns.CLISSHNetNS(host, username=login, sudo_prompt="[sudo] password")
    return nns_obj


@pytest.fixture(scope="session", params=["ssh", "telnet", "nns"])
def credentials(request):
    if request.param not in request.config.option.cli_api:
        pytest.skip("{0} API is skipped for test.".format(request.param.upper()))
    if request.param == "nns" and os.getenv("USER") != "root":
        pytest.fail("NNS unittests require root permissions.")
    ipaddr = request.config.option.ssh_ip
    username = request.config.option.ssh_user
    password = request.config.option.ssh_pass
    return ipaddr, username, password, request.param


@pytest.fixture
def cli_obj(request, credentials):
    request.config.login = credentials[0]
    obj = globals()["create_{0}".format(credentials[3])](request, credentials[0], credentials[1])
    request.addfinalizer(obj.close)
    obj.login(credentials[1], credentials[2], timeout=5)
    return obj


@pytest.fixture
def request_object(request, credentials):
    obj = globals()["create_{0}".format(credentials[3])](request, credentials[0], credentials[1])
    return obj


@pytest.mark.unittests
class TestSSH(object):
    """CLISSH unittests.

    """
    def test_login_true(self, credentials, request_object):
        """Verify login/logout.

        """
        obj = request_object
        obj.login(credentials[1], credentials[2], timeout=5)
        obj.close()

    def test_multiple_login_logout(self, credentials, request_object):
        """Verify login after logout multiple times.

        """
        for i in range(5):
            request_object.login(credentials[1], credentials[2], timeout=5)
            request_object.close()

    @pytest.mark.skipif("'telnet' not in config.option.cli_api", reason="Skip telnet testcase.")
    def test_enter_exit_mode(self, cli_obj, credentials):
        """Verify enter/exit mode.

        """
        message = "Telnet specific test case"
        if isinstance(cli_obj, clinns.CLISSHNetNS):
            pytest.skip(message)
        if isinstance(cli_obj, clissh.CLISSH):
            pytest.skip(message)
        assert cli_obj.enter_mode(cmd="python", new_prompt=">>>") == ">>>"
        out, err, _ = cli_obj.exec_command("print 'O' + 'K'")
        assert "OK" in out
        assert credentials[1] in cli_obj.exit_mode(exit_cmd="exit()")

    @pytest.mark.skipif(True, reason="Skip this test because user doesn't have root permission")
    def test_sudo_shell_command_ssh(self, cli_obj, credentials):
        """Verify sudo mode for ssh.

        """
        message = "SSH specific test case"
        if isinstance(cli_obj, clinns.CLISSHNetNS):
            pytest.skip(message)
        if isinstance(cli_obj, clitelnet.TelnetCMD):
            pytest.skip(message)
        cli_obj.open_shell()
        # Clear shell output
        time.sleep(0.5)
        cli_obj.shell_read()
        cli_obj.password = credentials[2]
        # cmd = "env | $(which grep) TTY"
        cmd = "stty -a"
        data, ret_code = cli_obj.shell_command(cmd, timeout=5, sudo=True)
        assert ret_code == "0"
        assert data

    @pytest.mark.skipif("'telnet' not in config.option.cli_api", reason="Skip telnet testcase.")
    def test_sudo_shell_command_telnet(self, cli_obj, credentials):
        """Verify sudo mode for telnet.

        """
        message = "Telnet specific test case"
        if isinstance(cli_obj, clinns.CLISSHNetNS):
            pytest.skip(message)
        if isinstance(cli_obj, clissh.CLISSH):
            pytest.skip(message)
        cli_obj.password = credentials[2]
        cmd = "ls"
        data, ret_code = cli_obj.shell_command(cmd, timeout=5, sudo=True)

    def test_login_false_username_ssh(self, credentials):
        """Verify AuthenticationException in case Incorrect username for ssh object.

        """
        ssh_conn = clissh.CLISSH(credentials[0])
        with pytest.raises(paramiko.AuthenticationException):
            ssh_conn = clissh.CLISSH(credentials[0])
            ssh_conn.login(ssh_conn.randstr(30), credentials[2], timeout=5)

    @pytest.mark.skipif("'telnet' not in config.option.cli_api", reason="Skip telnet testcase.")
    def test_login_false_username_telnet(self, credentials):
        """Verify AuthenticationException in case Incorrect username for telnet object.

        """
        telnet_conn = clitelnet.TelnetCMD(credentials[0])
        with pytest.raises(CLIException):
            telnet_conn = clitelnet.TelnetCMD(credentials[0])
            telnet_conn.login(telnet_conn.randstr(30), credentials[2], timeout=5)

    def test_login_false_userpass_ssh(self, credentials):
        """Verify AuthenticationException in case Incorrect password for ssh object.

        """
        ssh_conn = clissh.CLISSH(credentials[0])
        with pytest.raises(paramiko.AuthenticationException):
            ssh_conn = clissh.CLISSH(credentials[0])
            ssh_conn.login(credentials[1], ssh_conn.randstr(30), timeout=5)

    @pytest.mark.skipif("'telnet' not in config.option.cli_api", reason="Skip telnet testcase.")
    def test_login_false_userpass_telnet(self, credentials):
        """Verify AuthenticationException in case Incorrect password for telnet object.

        """
        telnet_conn = clitelnet.TelnetCMD(credentials[0])
        with pytest.raises(CLIException):
            telnet_conn = clitelnet.TelnetCMD(credentials[0])
            telnet_conn.login(credentials[1], telnet_conn.randstr(30), timeout=5)

    # Negative tests for nns module isn't implemented, because nns module always in 'login' mode

    def test_shell_command_1(self, cli_obj):
        """Non interactive shell command. No prompt is defined.

        """
        cli_obj.open_shell()
        # Clear shell output
        time.sleep(0.5)
        cli_obj.shell_read()

        # cmd = "env | $(which grep) TTY"
        cmd = "stty -a"
        data, ret_code = cli_obj.shell_command(cmd, timeout=5, sudo=False)
        assert ret_code == "0"
        assert data

    def test_shell_command_2(self, cli_obj):
        """Non interactive shell command. Read prompt and set prompt.

        """
        if isinstance(cli_obj, clinns.CLISSHNetNS):
            pytest.skip("clinns objects don't have login procedure")

        data = cli_obj.open_shell()
        # Last line in login greater has to be prompt.
        # Wait 3 seconds for it.
        # data = cli_obj.shell_read(3)
        # Read prompt
        prompt = data.split("\n")[-1]
        # Set prompt to ssh object
        assert prompt
        cli_obj.prompt = prompt
        # Execute command with ret_code=False
        cmd = "stty -a"
        data, ret_code = cli_obj.shell_command(cmd, timeout=5, ret_code=False)
        # Return code isn't read
        assert ret_code is None
        assert data
        # Check return code manually
        cmd = "echo ENV_RET_CODE=$?"
        data, _ = cli_obj.shell_command(cmd, timeout=5, ret_code=False)
        assert "ENV_RET_CODE=0" in data

    def test_shell_command_3(self, cli_obj):
        """Non interactive shell command. Non 0 exit code.

        """
        cli_obj.open_shell()
        # Execute command that has to exit with non 0 exit code
        cmd = "test ! -d /"
        data, ret_code = cli_obj.shell_command(cmd, timeout=5, expected_rc=1)
        # Return code isn't read
        assert ret_code == "1"

    def test_put_file(self, cli_obj, credentials):
        """Copying file to remote host.

        """
        if isinstance(cli_obj, clitelnet.TelnetCMD):
            pytest.xfail("put_file in not supported by clitelnet objects")

        # Test file is test module itself
        src = os.path.abspath(__file__)
        dst = "/tmp/testfile_for_taf_clissh_put_file_method_unittest_{0}".format(credentials[3])

        # Get size of test file in bytes.
        fsize = os.path.getsize(src)

        # Remove testfile on remote host
        rm_command = "rm {0}".format(dst)
        _out, _err, _ = cli_obj.exec_command(rm_command, timeout=3)
        # Verify  that test file doesn't exist on remote host
        command = "ls {0}".format(dst)
        _out, _err, _ = cli_obj.exec_command(command, timeout=3)
        assert "file_method_unittest" not in _out
        # Copying file to remote host, and verify that it exists
        cli_obj.put_file(src, dst)
        _out, _err, _ = cli_obj.exec_command(command, timeout=3)
        assert "file_method_unittest" in _out
        # Verify file size
        command = "wc -c {0}".format(dst)
        _out, _err, _ = cli_obj.exec_command(command, timeout=3)
        r_fsize = _out.split(" ")[0]
        assert str(fsize) == r_fsize

        # Remove testfile on remote host
        _out, _err, _ = cli_obj.exec_command(rm_command, timeout=3)

    def test_get_file(self, tmpdir, cli_obj, credentials):
        """Copying file to remote host.

        """
        if isinstance(cli_obj, clitelnet.TelnetCMD):
            pytest.skip("get_file in not supported by clitelnet objects")

        pid = os.getpid()
        remote_file = "/tmp/testfile_for_taf_clissh_get_file_method_unittest_{0}_{1}_remote".format(credentials[3], pid)
        local_file = tmpdir.join("testfile_for_taf_clissh_get_file_method_unittest_{0}_{1}_local".format(credentials[3], pid))

        # Remove local file is exists
        try:
            local_file.remove()
        except EnvironmentError:
            pass
        assert not local_file.exists()

        # Create testfile on remote host
        cli_obj.open_shell()
        command = "echo Some test data > {0}".format(remote_file)
        _rc, _out = cli_obj.shell_command(command, timeout=3)
        # Verify  that test file exists on remote host
        command = "ls {0}".format(remote_file)
        time.sleep(0.3)
        _out, _err, _ = cli_obj.exec_command(command, timeout=3)
        assert "file_method_unittest" in _out
        # Copying file to remote host, and verify that it exists
        cli_obj.get_file(remote_file, str(local_file))
        assert local_file.exists()
        # Verify file size. (text in echo command above has to create file of 15 bytes size.)
        l_fsize = local_file.size()
        assert l_fsize == 15

        # Remove testfile on remote host
        rm_command = "rm {0}".format(remote_file)
        _out, _err, _ = cli_obj.exec_command(rm_command, timeout=3)

    def test_interactive_command_1(self, cli_obj):
        """Interactive shell command with str actions.

        """
        cli_obj.open_shell()
        # Execute command
        cmd = "python3"
        # Add interactive commands
        alternatives = []
        # First check some host
        alternatives.append((">>>", "a", False, True))
        # Second - exit
        alternatives.append(("is not defined", "exit()", False, True))
        data, ret_code = cli_obj.shell_command(cmd, alternatives=alternatives, timeout=5)
        # Verify output
        assert ret_code == "0"
        # Verify that our commands are in output
        assert [s for s in data.split("\n") if ">>> a" in s]
        assert [s for s in data.split("\n") if ">>> exit()" in s]

    def test_interactive_command_2(self, cli_obj):
        """Interactive shell command with func action.

        """
        flag = []

        def append_flag():
            """Append mutable object to verify that action is called and called only once.

            """
            flag.append(1)

        cli_obj.open_shell()
        # Execute command
        # cmd = "ping -c7 127.0.0.1"
        cmd = "python3"
        # Add interactive commands
        alternatives = []
        # Call action on 3th ICMP request
        alternatives.append((">>>", "import time; print('1\\n2\\nabcd\\n'); time.sleep(2)", False, True))
        alternatives.append(("abcd", append_flag, False, True))
        alternatives.append((">>>", "exit()", False, True))
        data, ret_code = cli_obj.shell_command(cmd, alternatives=alternatives, timeout=5)
        # Verify output
        assert ret_code == "0"
        assert flag

    def test_send_command(self, cli_obj):
        """Send command without waiting exit.

        """
        if isinstance(cli_obj, clinns.CLISSHNetNS):
            pytest.skip("For clinns objects must be created child object first, then shell_read() can be used")
        cli_obj.open_shell()
        # Clear shell buffer
        time.sleep(1)
        cli_obj.shell_read()
        # Execute command with ret_code=False
        cmd = "ping -c3 127.0.0.1"
        cli_obj.send_command(cmd)
        # Wait untill command is executed
        time.sleep(5)
        # Verify output
        out = cli_obj.shell_read()
        # original was icmp_req=3 which is not in the output
        # the standard ping output on Linux is icmp_seq=3 so use re to be safe
        assert re.search(r"icmp_[rs]eq=3", out)
        assert "rtt min/avg/max/mdev" in out

    def test_cleared_shell_buffer(self, cli_obj):
        """Cleared buffer after open_shell().

        """
        if isinstance(cli_obj, clinns.CLISSHNetNS):
            pytest.skip("For clinns objects open_shell() is not implemented")
        cli_obj.open_shell()
        # Execute command with ret_code=False
        cmd = "ping -c3 127.0.0.1"
        cli_obj.send_command(cmd)
        # Wait untill command is executed
        time.sleep(5)
        # Verify output
        out = cli_obj.shell_read()
        # original was icmp_req=3 which is not in the output
        # the standard ping output on Linux is icmp_seq=3 so use re to be safe
        assert re.search(r"icmp_[rs]eq=3", out)
        assert "rtt min/avg/max/mdev" in out
        assert "Last login:" not in out

    def test_exec_command_timeout_telnet(self, cli_obj):
        """Verify timeout for exec_command.

        """
        if isinstance(cli_obj, clinns.CLISSHNetNS) or isinstance(cli_obj, clissh.CLISSH):
            pytest.skip("CLISSHException raises only for clitelnet objects")
        # The following ping command requires 10s to execute.
        cmd = "ping -i1 -c10 127.0.0.1"
        # Set timeout to 1s
        with pytest.raises(CLIException):
            cli_obj.exec_command(cmd, timeout=1)

    def test_exec_command_timeout_ssh(self, cli_obj):
        """Verify timeout for exec_command.

        """
        if isinstance(cli_obj, clinns.CLISSHNetNS) or isinstance(cli_obj, clitelnet.TelnetCMD):
            pytest.skip("CLISSHException raises only for clitelnet and clinns objects")
        # The following ping command requires 10s to execute.
        cmd = "ping -i1 -c10 127.0.0.1"
        # Set timeout to 1s
        with pytest.raises(socket.timeout):
            cli_obj.exec_command(cmd, timeout=0.5)

    def test_shell_command_timeout(self, cli_obj):
        """Verify timeout for shell_command.

        """
        cli_obj.open_shell()
        # The following ping command requires 5s to execute.
        cmd = "ping -i1 -c5 127.0.0.1"
        # Set timeout to 1s
        with pytest.raises(CLIException):
            cli_obj.shell_command(cmd, timeout=1)

    def test_quiet_1(self, cli_obj):
        """Verify raising an exception on return code != 0.

        """
        cli_obj.open_shell()
        # The command has to return exit code 2.
        cmd = "ping -l"
        with pytest.raises(CLIException):
            cli_obj.shell_command(cmd)

    def test_quiet_2(self, cli_obj):
        """Check expected_rc parameter.

        """
        cli_obj.open_shell()
        # The command has to return exit code 2.
        cmd = "ping -l"
        cli_obj.shell_command(cmd, expected_rc="2")

    def test_quiet_3(self, cli_obj, monkeypatch):
        """Verify an exception isn't raised on return code != 0 and default quiet option.

        """
        cli_obj.open_shell()
        # The command has to return exit code 2.
        cmd = "ping -l"
        monkeypatch.setattr(cli_obj, "quiet", True)
        out, rc = cli_obj.shell_command(cmd)
        assert rc == "2"

    def test_alter_in_command(self, cli_obj):
        """Verify if prompt present in command it doesn't influence on finding prompt in output data.

        """
        cli_obj.open_shell()
        cmd = "echo some_test_data"
        # Add interactive commands
        alternatives = []
        # Call action on 3th ICMP request
        alternatives.append(("some_test_data", None, True, False))
        data, ret_code = cli_obj.shell_command(cmd, alternatives=alternatives, timeout=5)
        # Verify output
        assert ret_code == "0"
        assert len(data.split("\n")) == 2

    @pytest.mark.skipif(True, reason="Stupid fails intermittently due to incomplete reads")
    def test_send_command_continuous_output(self, cli_obj):
        """Send command without waiting exit and read continuous output.

        """
        if isinstance(cli_obj, clinns.CLISSHNetNS):
            pytest.xfail("For clinns objects must be created child object first, then shell_read() can be used")
        if isinstance(cli_obj, clitelnet.TelnetCMD):
            pytest.xfail("For clitelnet objects commands with continuous output must be launched in batch mode")
        cli_obj.open_shell()
        # Clear shell buffer
        time.sleep(1)
        cli_obj.shell_read()
        # Execute command with ret_code=False
        cmd = "top -d1"
        cli_obj.send_command(cmd)
        # Wait some time untill command is running
        time.sleep(2)
        # Verify output
        out1 = cli_obj.shell_read()
        # Verify that output contains top headers
        # pytest bug with % in compound assert so split them
        # https://bitbucket.org/hpk42/pytest/issue/604/valueerror-unsupported-format-character-in
        # the column headers are not re-output because of curses
        # only the load average header is re-written for each update
        assert "%" "Cpu" in out1
        # this fails intermittently, possibly increase the sleep or implement a better
        # select poll or read loop.  But we don't care right now
        assert "users," in out1
        assert "load average" in out1
        # Save time from top output
        regexp = re.compile(r"top - \d\d:\d\d:\d\d")
        time1 = regexp.search(out1)
        assert time1 is not None
        time1 = time1.group()
        time.sleep(2)
        out2 = cli_obj.shell_read()
        open("/tmp/out2", "w").write(out2)
        assert "%" "Cpu" in out2
        assert "users," in out2
        assert "load average" in out2
        # But out2 should contain differ data
        time2 = regexp.search(out2)
        assert time2 is not None
        time2 = time2.group()
        assert time1 != time2
        # Send Ctrl + C
        cli_obj.send_command(cli_obj.Raw("\x03"))
        out3 = cli_obj.shell_read()
        # Verify that there is no top output
        assert "%" "Cpu" not in out3
        assert "users," not in out3
        assert "load average" not in out3
        # Verify that there is no top output again
        time.sleep(1)
        out4 = cli_obj.shell_read()
        assert "%" "Cpu" not in out4
        assert "users," not in out4
        assert "load average" not in out4


@pytest.mark.unittests
class TestCLISSH(object):

    EMPTY_PASSWORD_KEY = """\
-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAybpzWXae7rYCORumvBc6f+J77fhZ/WU2fiqLgv62DojfWFqY
92U0Bo8NtynU4NcVwQBrNCCpinMD3JdDcLSXsN70ON5z5FLm1Ms4gvpICei7TegC
FVTEMsa9gfiMygDAOAapLlsZP6v1F/r/zQtsV9Nqm5pTlZ5gF6e/FmlQbg/sF52K
A3sB762eBKfwq9p5/l2XfAELY4ypvGaAS+alVStuop3hhax5D6RUy1hG7IsMfT1x
tFfwqgKqbO0AahjojakTlKZ+VBrGQYb9SUWSEOTN/EdU2wYDK9u08ilSCYW1HbN7
rV4yX4ZZXZBuddll8DRVQIs5fZP1xKQBKfiSZQIDAQABAoIBAQCaIPwrGafbKXNP
YOInCfRna4tWyg8vvVpCUY1gm+5L8qX7ItWHCGsUq85F6Q8+bvevC/vcyyvenXwQ
2f3sKf9QYzjkDosro2+8nDzkTggmkgwyPRcCZ060oQaAPICNgr9azzQKOA51iJPu
K5eweY7hF6Z3lxVP1r8Cs+cbX4HVZLbmva+98476zw9MD+XEd2qkjgldLAmVCsiR
E3H862GU0yk+mReSs0Qz8OYjyWAGXPN9SmMPIv4qZg4qVLw6y17pN+A4aMmL1ThK
h9jPoAsXL+5lpi3T1rHUes1ene9hQLyv46B6TKTiTRPnP2aUeJF7xXS4aZSEVy23
0zTphoatAoGBAPMosVDw+iT8bMzmG5cFHEA2CAd/EdXKkPEvWUCf4uFcqzslImUW
Vq0asuFyOHBCHsVxsA5BmYRsCcQdn8jUuTHM3GAUwf29rmhW584W5Jznv1bByNMQ
Og35zXNYm+CgxWOaD8ayXtAZ+3GgjKA+JbpsIh1wqwrv/q4atiha1CTvAoGBANRh
pnCBFgLt6l5TsnmqB4yUiSC+SIluuz5csoQnCSgb4DBKe6yjDzqXTStHQOBv5l7o
wcuXzziX3rXZ5ym14aU20Dix7H+fjjTDCOT/A4r44PhZBKcC53RnndJ3a283BrAK
s2p4gn0iGPtG24UG9UokDD56vDChED3Bc8a3ngXrAoGBAOJXIpbBeVcsUOp513zA
GQf8Q4UW1zc2k6yt8lqhecNlS06GxnlqTcxcad5JQBfetF398W+TyJ7nIkAXg0Ci
IrEkjI4zRFA5XDtrieLglHUpk4XiZFlzZVbVDFUuSgrSHGsWYVEHgBId3VxrofsX
Xm8lcKwO0Ggh9eOCocT2pzqpAoGBAJFfIekiQqnQpjrYuXKT0sUEKvTRqp7/v4UJ
OFxCx/6/Te5gHVVm65akV/sGs76seZh/Y59zEzFeqt/4/kTLrV9ELLSR/RrCYTl2
QpFUiN1IS91SOWAEGd/QyPN2MICYvqgjOvnm8RKsE0N0FfBxeda84/CkXEpBBPfw
gcoEh1LvAoGBAN0Tv5gSXLkEaUfL6BTeOKr+PxKrdmUfLHSKTTT0MlA/oAig9FmZ
dVcroxqKsqWhQmY4EgXH20IOyNdRX4d8oMyTEA1Xyorq78DVfPQAhE2y6wO0Z8K/
mAvF7/+hRzNa4l25lailJFHR7VgwLPo24xNlWgyjn9T5JNnor8TIimoy
-----END RSA PRIVATE KEY-----
"""

    def test_invalid_pkey_raises_SSHException(self, credentials):
        ipaddr, username, password, param = credentials
        if param == "ssh":
            with pytest.raises(paramiko.SSHException):
                ssh_conn = clissh.CLISSH(ipaddr, username=username, pkey="")
                assert ssh_conn.pkey

    def test_pkey(self, credentials):
        ipaddr, username, password, param = credentials
        if param == "ssh":
            ssh_conn = clissh.CLISSH(ipaddr, username=username, pkey=self.EMPTY_PASSWORD_KEY)
            assert ssh_conn.pkey
            assert ssh_conn.pkey.get_bits() == 2048

    def test_probe_port_1(self):
        """Test probe_port function.

        """
        assert clissh.probe_port('127.0.0.1', 22, MagicMock()) is True

    def test_probe_port_2(self):
        """Test probe_port function negative.

        """
        assert clissh.probe_port('8.8.8.8', 8081, MagicMock()) is False
