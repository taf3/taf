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
        super(Libvirt, self).__init__()
        self.cli_send_command = cli_send_command
        self.service_manager = service_lib.SpecificServiceManager(self.SERVICE, self.cli_send_command)

    def start(self):
        """
        @brief  Start libvirt service
        """
        self.service_manager.start()

    def stop(self):
        """
        @brief  Stop libvirt service
        """
        self.service_manager.stop()

    def restart(self):
        """
        @brief  Restart libvirt service
        """
        return self.service_manager.restart()

    def status(self):
        """
        @brief  Get libvirt process status
        @rtype:  named tuple
        """
        return self.service_manager.status()

    def virsh_execute_command(self, command, exp_rc=frozenset({0})):
        """
        @brief  Method for virsh command execution
        @param  command:  command to execute
        @type  command:  string
        @param  exp_rc:  expected return code
        @type  exp_rc:  int | set | list | frozenset
        @rtype:  named tuple
        """
        return self.cli_send_command('virsh {}'.format(command), expected_rcs=exp_rc)
