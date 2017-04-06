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

"""``syslog.py``

`Class for remote loggin functionality`

"""

import re
import time

from testlib import loggers
from testlib import clissh
from .custom_exceptions import SysLogException


class SystemLog(object):
    """Syslog object class.

    """

    class_logger = loggers.ClassLogger()

    def __init__(self, host=None, user=None, pasw=None, log_path=None):
        """Initialize SystemLog class.

        Args:
            host(str):  Host IP address
            user(str):  Host user
            pasw(str):  Host password
            log_path(str):  Path to logs

        """
        self.host = host
        self.user = user
        self.pasw = pasw
        self.log_path = log_path
        self.ssh = clissh.CLISSH(self.host)

    def __del__(self):
        """Try to close CLI connection on object destroy.

        """
        self.ssh.close()

    def get_checkpoint(self):
        """Get syslog checkpoint.

        Notes:
            Checkpoint it's an integer value which can be used for log reading from checkpoint till the end.

        Returns:
            int: checkpoint

        Examples::

            syslog_1 = syslog.SystemLog("1.1.1.1", "usr", "PaSsWd", "/some/path")
            cp = syslog_1.get_checkpoint()
            # cp = 57899427

        """
        try:
            check_alive_ssh = self.ssh.client.open_sftp()
            check_alive_ssh.close()
            self.class_logger.debug('SSH session is active.')
        except Exception:
            self.class_logger.debug('ERROR: No active SSH.')
            self.class_logger.debug('Connecting...')
            self.ssh.login(self.user, self.pasw)
        # open sftp:
        sftp = self.ssh.client.open_sftp()
        # get remote logfile:
        remote_log_file = sftp.open(self.log_path)
        # go to end of remote log file:
        remote_log_file.seek(0, 2)
        # get end position for logfile
        checkpoint = remote_log_file.tell()
        remote_log_file.close()
        sftp.close()
        # return end position for logfile
        return checkpoint

    def get_log(self, checkpoint=None, timeout=60):
        """Read log from remote host.

        Args:
            checkpoint(int):  Log file checkpoint
            timeout(int):  Get log timeout

        Raises:
            SysLogException:  syslog timeout exceeded

        Returns:
            tuple: log_list (list), new_checkpoint (integer)

        Notes:
            If checkpoint present read from checkpoint till the end, if not read full file.

        Examples::

            log_list, checkpoint = get_log(34134654, 30)

        """
        log_list = []
        checkpoint_temp = 0
        try:
            check_alive_ssh = self.ssh.client.open_sftp()
            check_alive_ssh.close()
            self.class_logger.debug('SSH session is active.')
        except Exception:
            self.class_logger.debug('ERROR: No active SSH.')
            self.class_logger.debug('Connecting...')
            self.ssh.login(self.user, self.pasw)

        sftp = self.ssh.client.open_sftp()
        remote_log_file = sftp.open(self.log_path, bufsize=50000)
        if checkpoint is None:
            self.class_logger.debug('No checkpoint value. Full log file will be download it can take a while.')
            # when no checkpoint parameter, read full file and return new checkpoint
            log_list = remote_log_file.readlines()
            checkpoint_new = remote_log_file.tell()
        else:
            # wait until new records appear; compare checkpoint with temp_checkpoint
            end_time = time.time() + timeout
            while checkpoint >= checkpoint_temp:
                if time.time() >= end_time:
                    self.ssh.close()
                    message = "Syslog Timeout exceeded. No Syslog messages in %s second" % (timeout,)
                    raise SysLogException(message)
                # move in end of file
                remote_log_file.seek(0, 2)
                # get end possition
                checkpoint_temp = remote_log_file.tell()
                # wait 0.5 sec to repeat operation
                time.sleep(0.5)
            # move to checkpoint possition
            remote_log_file.seek(checkpoint)
            # read remote log file:
            log_list = remote_log_file.readlines()
            # get new_checkpoint - log file end possition:
            checkpoint_new = remote_log_file.tell()
        self.class_logger.debug('log file is successfully readed.')
        remote_log_file.close()
        sftp.close()
        # return logfile and end possition for logfile
        return log_list, checkpoint_new

    def search(self, log_list, paterntuple):
        """Find command records in log file.

        Args:
            log_list(list):  logfiles
            paterntuple(tuple):  commands part what function should find in loglist

        Returns:
            list:  find_list_result

        Examples::

            \>>> test_command = 'sshd', '', 'Accepted password'
            \>>> syslog_1.search(test_log, test_command)
            ['Aug 10 08:54:03 <platform> sshd[13275]: Accepted password for root from 127.0.0.1 port 59212 ssh2\n',
             'Aug 10 08:54:03 <platform> sshd[13275]: Accepted password for root from 127.0.0.1 port 59212 ssh2\n']

        """
        # create empty list for search result:
        find_list_result = []
        # backslashed input commands from paterntuple:
        # Compile a regular expression pattern into a regular expression object, patern consist from findlist elements:
        log_regexp = re.compile(r"(%s.*?%s.*?%s.*?\n)" % (re.escape(paterntuple[0]), re.escape(paterntuple[1]), re.escape(paterntuple[2])))
        # applied regular expression object to input list and if result not empty append it to find_list_result list:
        find_list_result = [x for x in log_list if log_regexp.findall(x)]
        return find_list_result

    def find_duplicated_records(self, log_list):
        """Find duplicated records in log file.

        Args:
            log_list(list):  logfiles

        Returns:
            list: None or list of duplicated records

        """
        # compare list length:
        if len(set(log_list)) == len(log_list):
            return None
        # if present duplicate records, find and return list with duplicated records:
        log_duplicate = []
        for index, row in enumerate(log_list):
            if row in log_list[:index]:
                log_duplicate.append(row)
        return log_duplicate
