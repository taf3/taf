#!/usr/bin/env python
"""
@copyright Copyright (c) 2015-2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  dev_linux_host_vm.py

@summary  OpenStack VM host device related functionality.
"""

from . import clissh
from .dev_linux_host import GenericLinuxHost, NICHelper


class GenericLinuxVirtualHost(GenericLinuxHost):

    def __init__(self, config, opts):
        super(GenericLinuxVirtualHost, self).__init__(config, opts)
        self.nated_mgmt = config.get('nated_mgmt', None)
        self.tempest_ui = None
        self.os_networks = []

    def _set_mgmt_interface(self, mgmt_ip):
        # OpenStack instances management IP is NATed, we need to provide the
        # local IP (set in tempest_ui.create_server) to properly detect the management interface
        if self.nated_mgmt is None:
            raise Exception('nated_mgmt property not set, assign floating IP first.')
        super(GenericLinuxVirtualHost, self)._set_mgmt_interface(self.nated_mgmt)

    def _set_ssh(self, ipaddr):
        """Set ssh connection.

        Required in virtual environment. When we create VMs host object we do not know the IP yet.

        @param ipaddr:
        @return:
        """
        self.ipaddr = ipaddr
        ssh_eligible = self.ssh_pass or self.ssh_pkey or self.ssh_pkey_file
        if self.ipaddr and self.ssh_user and ssh_eligible:
            self.ssh = clissh.CLISSH(self.ipaddr, self.ssh_port, self.ssh_user, self.ssh_pass,
                                     pkey=self.ssh_pkey, key_filename=self.ssh_pkey_file)

    def _get_nics(self, force_check=False):
        """Returns list of detected network adapterrs in the system
        Note: Order of the adapters is very important. It should be according to how the
        networks are defined when VM is created. Proper order is in self.os_networks

        @param force_check: force re-reading nics
        @type force_check: bool
        @return: list of nics
        @rtype: list
        """
        if self.nics is None or force_check:
            self.nics = []
            iface_client = self.tempest_ui.interface_client
            detected_nics = self.ui.get_table_ports(ip_addr=True)
            os_int = iface_client.list_interfaces(self.id)['interfaceAttachments']
            for net, _, _ in self.os_networks:
                for interf in (int_net for int_net in os_int if int_net['net_id'] == net['id']):
                    for idx, nic in enumerate(detected_nics):
                        if interf['mac_addr'] == nic['macAddress']:
                            self.nics.append(detected_nics.pop(idx))
                            break
            self.nics.extend(detected_nics)

        return self.nics

    def get_nics_if(self, f, force_check=False):
        if f:
            return list(filter(f, self._get_nics(force_check)))
        return self._get_nics()

    def map_nics_if(self, f, mapper=NICHelper.NIC_OBJ, force_check=False):
        nics = self.get_nics_if(f, force_check)
        if mapper:
            return list(map(mapper, nics))
        return nics

    def get_nics(self, no_lo=True, mapper=None, force_check=False):
        f = NICHelper.NICS_IF_NO_LO if no_lo else None
        return self.map_nics_if(f=f, mapper=mapper, force_check=force_check)

    def get_nics_names(self, no_lo=True, force_check=False):
        f = NICHelper.NICS_IF_NO_LO if no_lo else None
        mapper = NICHelper.NIC_NAME
        return self.map_nics_if(f=f, mapper=mapper, force_check=force_check)

    def get_nics_ips(self, no_lo=True, force_check=False):
        f = NICHelper.NICS_IF_NO_LO if no_lo else None
        mapper = NICHelper.NIC_IP_ADDR
        return self.map_nics_if(f=f, mapper=mapper, force_check=force_check)

    def waiton(self, timeout=180):
        """
        @brief  Wait until device is fully operational.
        @param  timeout:  Wait timeout
        @type  timeout:  int
        @raise  SwitchException:  device doesn't response
        @rtype:  dict
        @return  Status dictionary from probe method or raise an exception.
        """
        return super(GenericLinuxVirtualHost, self).waiton(timeout)


ENTRY_TYPE = "openstack"
INSTANCES = {
    "vm": GenericLinuxVirtualHost,
}
NAME = "ostack"
LINK_NAME = "ost"
