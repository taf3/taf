# Copyright (c) 2016 - 2017, Intel Corporation.
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

"""``testpmd.py``

`Class for testpmd operations`

Note:
    Examples of testpmd usage in tests::

        inst.ui.testpmd.start(end_options='--burst=64', cores='0x3', mem_channels=4, driver_dir='librte_pmd_e1000.so', socket_mem='1024,0', huge_unlink=True)
        inst.ui.testpmd.exec_cmd('help')
        inst.ui.testpmd.stop()

"""

import re

from testlib.custom_exceptions import CustomException


ARGS_MAP = {'cores': '-c',
            'core_list': '-l',
            'lcores': '--lcores',
            'master_lcore': '--master-lcore',
            'mem_channels': '-n',
            'allocate_mem': '-m',
            'ranks': '-r',
            'blacklist': '-b',
            'whitelist': '-w',
            'vdev': '--vdev',
            'driver_dir': '-d',
            'vmware_tsc_map': '--vmware-tsc-map',
            'proc_type': '--proc-type',
            'syslog': '--syslog',
            'log-level': '--log-level',
            'version': '-v',
            'socket_mem': '--socket-mem',
            'huge_dir': '--huge-dir',
            'file_prefix': '--file-prefix',
            'base_virtaddr': '--base-virtaddr',
            'create_uio_dev': '--create-uio-dev',
            'vfio_intr': '--vfio-intr',
            'xen_dom0': '--xen-dom0'}

STANDALONE_ARGS = {'huge_unlink': '--huge-unlink',
                   'no_huge': '--no-huge',
                   'no_pci': '--no-pci',
                   'no_hpet': '--no-hpet',
                   'no_shconf': '--no-shconf'}


class TestPmd(object):
    def __init__(self, host):
        """Initialize TestPmd class.

        """
        super(TestPmd, self).__init__()
        self.host = host
        self.ssh_prompt = self.host.config.get('cli_user_prompt', self.host.config.get('ssh_user', 'root') + '@')
        self.interactive_prompt = 'testpmd>'
        self.non_interactive_prompt = 'Press enter to exit'
        self.interactive = False
        self.run_status = False

    def start(self, interactive_shell=True, end_options='', timeout=10, **kwargs):
        """Start testpmd tool.

        Args:
            interactive_shell(bool):  Interactive shell flag
            end_options(str):  Arguments to be passed after '--' in command line
            timeout(int):  Timeout
            kwargs(dict):  Arguments to be passed for testpmd tool

        Raises:
            AssertionError: in case unsupported arguments are passed

        Returns:
            None

        """
        assert all([par in ARGS_MAP or par in STANDALONE_ARGS for par in kwargs]), \
            "Unsupported arguments are passed into current method. Supported are: \n {}\n{}".format(ARGS_MAP.keys(), STANDALONE_ARGS.keys())
        inserts = ' '.join('{} {}'.format(ARGS_MAP[param], str(val))
                           for param, val in kwargs.items() if param in ARGS_MAP)
        inserts = inserts + ' ' + ' '.join([str(STANDALONE_ARGS[param]) for param, val in kwargs.items() if param in STANDALONE_ARGS and val])

        if interactive_shell:
            command = 'testpmd {} -- {} -i'.format(inserts, end_options)
            self.host.ssh.prompt = self.interactive_prompt
            self.host.ssh.shell_command(command, timeout=timeout, expected_rc="", ret_code=False)
            self.interactive = True
        else:
            command = 'testpmd {} -- {}'.format(inserts, end_options)
            self.host.ssh.prompt = self.non_interactive_prompt
            self.host.ssh.shell_command(command, timeout=timeout, expected_rc="", ret_code=False)
            self.interactive = False
        self.run_status = True

    def stop(self, timeout=2):
        """Stop testpmd tool.

        Args:
            timeout(int):  Timeout

        Raises:
            CustomException:  in case testpmd is not started

        Returns:
            None

        """
        if self.run_status:
            self.host.ssh.prompt = self.ssh_prompt
            if self.interactive:
                self.host.ssh.shell_command('quit', timeout=timeout, ret_code=False)
            else:
                self.host.ssh.shell_command("\n", timeout=timeout, ret_code=False)
            self.run_status = False
        else:
            raise CustomException("Testpmd is not started. Nothing to stop")

    def exec_cmd(self, cmd, timeout=5):
        """Execute command in interactive testpmd shell.

        Args:
            timeout(int):  Timeout

        Raises:
            CustomException: in case testpmd is not started in interactive mode

        Returns:
            str:  Output of command execution

        """
        if self.interactive:
            data, _ = self.host.ssh.shell_command(cmd, raw_output=True, timeout=timeout, ret_code=False)
            reg_ex = "{}(.*?){}".format(cmd, self.interactive_prompt)
            return re.findall(reg_ex, data, re.DOTALL)[0].strip()
        else:
            raise CustomException("Testpmd is not started in interactive mode.")
