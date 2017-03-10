# Copyright (c) 2017, Intel Corporation.
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

"""``libvirt.py``

`Class to abstract libvirt operations`

Notes:
    Examples of libvirt usage in tests::

        env.lhost[1].ui.libvirt.start()
        env.lhost[1].ui.libvirt.stop()
        env.lhost[1].ui.libvirt.restart()
        env.lhost[1].ui.libvirt.virsh_execute_command('list')
        env.lhost[1].ui.libvirt.virsh_execute_command('domstats vm_name', exp_rc = frozenset({1})))

"""

from testlib.linux import service_lib


class Libvirt(object):
    SERVICE = 'libvirtd'

    def __init__(self, cli_send_command):
        """Initialize libvirt class.

        """
        super().__init__()
        self.cli_send_command = cli_send_command
        self.service_manager = service_lib.SpecificServiceManager(self.SERVICE, self.cli_send_command)

    def __getattr__(self, name):
        """Method for getting attribute from service_manager.

        Args:
            name(str):  attribute name

        """
        return getattr(self.service_manager, name)

    def __call__(self, cmd, expected_rc):
        """Overloaded call method.

        Args:
            cmd(str):  command to execute
            expected_rc(int | set | list | frozenset):  expected return code

        Returns:
            tuple: named tuple

        """
        return self.cli_send_command(cmd, expected_rcs=expected_rc)

    def virsh_execute_command(self, command,  expected_rc=frozenset({0})):
        """Method for virsh command execution.

        Args:
            command(str):  command to execute
            expected_rc(int | set | list | frozenset):  expected return code

        Returns:
            tuple: named tuple

        """
        return self('virsh {}'.format(command), expected_rc)
