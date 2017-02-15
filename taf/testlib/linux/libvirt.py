"""
@copyright Copyright (c) 2017, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  libvirt.py

@summary  Class to abstract libvirt operations
@note
Examples of libvirt usage in tests:
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
        """
        @brief  Initialize libvirt class.
        """
        super().__init__()
        self.cli_send_command = cli_send_command
        self.service_manager = service_lib.SpecificServiceManager(self.SERVICE, self.cli_send_command)

    def __getattr__(self, name):
        """
        @brief  Method for getting attribute from service_manager
        @param  name:  attribute name
        @type  name:  string
        """
        attr = getattr(self.service_manager, name)
        setattr(self, name, attr)
        return attr

    def __call__(self, cmd, exp_rc):
        """
        @brief  Overloaded call method
        @param  cmd:  command to execute
        @type  cmd:  string
        @param  exp_rc:  expected return code
        @type  exp_rc:  int | set | list | frozenset
        @rtype:  named tuple
        """
        return self.cli_send_command('{}'.format(cmd), expected_rcs=exp_rc)

    def virsh_execute_command(self, command,  exp_rc=frozenset({0})):
        """
        @brief  Method for virsh command execution
        @param  command:  command to execute
        @type  command:  string
        @param  exp_rc:  expected return code
        @type  exp_rc:  int | set | list | frozenset
        @rtype:  named tuple
        """
        return self('virsh {}'.format(command), exp_rc)
