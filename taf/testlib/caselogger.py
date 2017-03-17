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

"""``caselogger.py``

`Caselogger functionality`

"""

import re
import time
from . import clissh


class CaseLogger(object):
    """Base class for switch caselogger functionality.

    """

    def __init__(self, sw, logger):
        """Initialize CaseLogger instance.

        Args:
            sw(SwitchGeneral):  Switch instance
            logger(ClassLogger):  Logger instance

        """
        self.sw = sw
        self.logger = logger

        # Get related config
        for conf_id in sw.config["related_conf"]:
            if sw.config["related_conf"][conf_id]["name"] == "loghost":
                conf = sw.config["related_conf"][conf_id]

        self.rhost = conf["ip_host"]
        self.rport = conf["sshtun_port"]
        self.rlogin = conf["sshtun_user"]
        self.rpassw = conf["sshtun_pass"]

        self.rssh = clissh.CLISSH(self.rhost, port=self.rport, username=self.rlogin, password=self.rpassw)

        self.close_ssh = False

    def switch_connect(self):
        """Open ssh connection to the switch.

        """
        if not self.sw.ssh.check_shell():
            self.sw.ssh.login()
            self.sw.ssh.open_shell()
            self.close_ssh = True

    def switch_disconnect(self):
        """Close ssh connection to the switch.

        """
        if self.close_ssh:
            self.sw.ssh.close()

    def get_test_case_logs(self, test_name, timestamp, logtype):
        """Get test case logs.

        Args:
            test_name(str):  Test case name
            timestamp(int):  Test case timestamp
            logtype(str):  Logs type to store (Single, All)

        """
        if self.sw.status:

            # Open ssh connection and use management tool for log files if exists
            self.switch_connect()
            out, err, rc = self.sw.ssh.exec_command("journalctl -h")
            if rc != 127:
                self.sw.ssh.exec_command("journalctl -b > /var/log/messages")

            if logtype == "Single":
                log_name = "_".join([test_name, str(timestamp).replace('.', '_'), self.sw.name])
                assert re.match(r'\w+', log_name), "Log file {0} contains incorrect symbols".format(log_name)
                get_log = "/tmp/{0}.gz".format(log_name)
                buf_log = "/tmp/{0}.gz".format(log_name)
                put_log = "/home/loguser/logs/{0}.gz".format(log_name)

                logcomm = "sed -n '/[QA].*started.*{0}/,/[QA].*teardown.*{0}/p' /var/log/messages > /tmp/{1}".format(str(timestamp), log_name)
                zipcomm = "gzip '/tmp/{0}'".format(log_name)
                command = "{0} && {1}".format(logcomm, zipcomm)
                command_timeout = 15
            elif logtype == "All":
                get_log = "/tmp/logs_{0}_{1}_{2}.tar.gz".format(self.sw.name, test_name, timestamp)
                buf_log = "/tmp/logs_{0}_{1}_{2}.tar.gz".format(self.sw.name, test_name, timestamp)
                put_log = "/home/loguser/logs/logs_{0}_{1}_{2}.tar.gz".format(self.sw.name, test_name, timestamp)

                command = "tar -h -czf '/tmp/logs_{0}_{1}_{2}.tar.gz' /var/log/".format(self.sw.name, test_name, timestamp)
                command_timeout = 120

            self.sw.ssh.shell_command(command, timeout=command_timeout, alternatives=[
                ('password', self.sw._sshtun_pass, False, True), ], sudo=True, ret_code=True, quiet=True)  # pylint: disable=protected-access

            self.sw.ssh.get_file(get_log, buf_log, proto="scp")

            self.rssh.login()
            self.rssh.open_shell()

            try:
                self.rssh.put_file(buf_log, put_log, proto="sftp")
            finally:
                self.rssh.close()

            self.sw.ssh.shell_command("rm -- '{0}'".format(get_log), timeout=25, alternatives=[
                ('password', self.sw._sshtun_pass, False, True), ], sudo=True, ret_code=True, quiet=True)  # pylint: disable=protected-access

            self.switch_disconnect()

    def get_core_logs(self, suite_name):
        """Get test suite core logs.

        Args:
            suite_name(str):  Test suite name

        """
        if self.sw.status:
            self.switch_connect()

            # Get core
            buf_list = []
            _core_entry = self.sw.ssh.exec_command("ls /var/preserve")
            if _core_entry.stdout != '':
                for core_file in _core_entry[0].split('\n'):
                    if 'gz' in core_file:
                        get_core = "/var/preserve/{0}".format(core_file)
                        buf_core = "/tmp/{0}".format(core_file)
                        buf_list.append(buf_core)
                        self.sw.ssh.get_file(get_core, buf_core, proto="scp")
                        self.sw.ssh.shell_command("rm -- '{0}'".format(get_core), alternatives=[
                            ('password', self.sw._sshtun_pass, False, True), ], timeout=15, sudo=True, ret_code=True, quiet=True)  # pylint: disable=protected-access

            self.switch_disconnect()

            self.rssh.login()
            self.rssh.open_shell()

            try:
                # Put cores if exist:
                if buf_list:
                    timestamp = time.time()
                    self.rssh.exec_command("mkdir /home/loguser/cores/{0}".format(self.sw.name, ))
                    self.rssh.exec_command("mkdir /home/loguser/cores/{0}/{1}_{2}".format(self.sw.name, suite_name, timestamp))
                    for core in buf_list:
                        put_core = "/home/loguser/cores/{0}/{1}_{2}/{3}".format(self.sw.name, suite_name, timestamp, core.split('/')[-1])
                        self.rssh.put_file(core, put_core, proto="sftp")
            finally:
                self.rssh.close()
