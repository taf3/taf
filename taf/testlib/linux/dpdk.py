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

"""``dpdk.py``

`Class for dpdk operations`

Note:
    Examples of dpdk usage in tests::

        inst.ui.dpdk.modify_iface_status(bind_action='bind', ifaces=["0000:01:00.0", "01:00.0"],
                                         drv='igb_uio', force=False, show_status=True)

"""

import re

from testlib.custom_exceptions import CmdArgsException


class Dpdk(object):
    """Class for interfaces modifications using DPDK tools.

    """

    SERVICE = 'dpdk-devbind'

    def __init__(self, cli_send_command):
        """Initialize DPDK class.

        """
        super(Dpdk, self).__init__()
        self.send_command = cli_send_command

    def modify_iface_status(self, bind_action='', ifaces=None, drv='', force=False, show_status=False):
        """Performs binding, unbinding NICs to specific driver and/or showing NICs status.

        Args:
            ifaces(str):  List of network interfaces in format <domain:bus:slot.func> or <bus:slot.func>
            bind_action(str):  action to be performed on NICs: bind | unbind
            drv(str):  Driver file name (without extension)
            force(bool):  Flag to override modifying NIC used by Linux
            show_status(bool):  Flag to override modifying NIC used by Linux

        Returns:
            None or list(dict):  None or dictionary with interfaces status information

        """
        if bind_action == 'bind':
            # Action 'bind' mandatory arguments: ifaces, drv
            if not (ifaces or drv):
                raise CmdArgsException("Wrong command options specified.")
        elif bind_action == 'unbind':
            # Action 'unbind' mandatory arguments: ifaces
            if drv or not ifaces:
                raise CmdArgsException("Wrong command options specified.")
        else:
            # If action not in ['bind', 'unbind'], it is expected that show_status=True
            if not show_status:
                raise CmdArgsException("Wrong command options specified.")

        ifaces = ifaces if ifaces else []

        command = '"{cmd}"{force}{status} --{action} {drv} {ifaces}'.format(
            cmd=self.SERVICE, action=bind_action, drv=drv, ifaces=' '.join(ifaces), status=' -s' if show_status else '',
            force=' --force' if force else '')
        outp = self.send_command(command).stdout

        if show_status:
            devbind_fields = ('pci_slot', 'descr', 'iface', 'drv', 'unused', 'active')
            matched_groups = re.findall(r"(\S*)\s'(.*)'(?:\sif=)?(\S*)?(?:\sdrv=)?(\S*)?\sunused=(\S*)\s(\*.*\*)?", outp)
            assert matched_groups, 'Interfaces status information not received.'
            res = [dict(zip(devbind_fields, entry)) for entry in matched_groups]
            return res
