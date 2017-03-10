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

"""``openvswitch.py``

`Class to abstract openvswitch operations`

Note:
    Examples of openvswitch usage in tests::

        env.lhost[1].ui.openvswitch.start()
        env.lhost[1].ui.openvswitch.stop()
        env.lhost[1].ui.openvswitch.restart()
        env.lhost[1].ui.openvswitch.add_bridge('br0')
        env.lhost[1].ui.openvswitch.get_interface_info('br0')
        env.lhost[1].ui.openvswitch.del_interface('br0')
        env.lhost[1].ui.openvswitch.set_ovsdb_manager(ptcp=6640)

"""

import re

from testlib.linux import service_lib
from testlib.custom_exceptions import CustomException


class OpenvSwitch(object):
    SERVICE = 'openvswitch-switch'

    def __init__(self, cli_send_command, switch_map, name_to_switchid_map):
        """Initialize openvswitch class.

        """
        super(OpenvSwitch, self).__init__()
        self.cli_send_command = cli_send_command
        self.switch_map = switch_map
        self.name_to_switchid_map = name_to_switchid_map
        self.service_manager = service_lib.SpecificServiceManager(self.SERVICE, self.cli_send_command)

    def update_map(self, iface_name, delete=False):
        """Update switch_map and name_to_switchid_map.

        Args:
            iface_name(str): name of ovs bridge or interface
            delete(bool):  if True - remove from switch_map and name_to_switchid_map

        """
        if delete:
            self.switch_map.pop(iface_name)
            self.name_to_switchid_map.pop(iface_name)
        else:
            self.switch_map.update({iface_name: iface_name})
            self.name_to_switchid_map.update({iface_name: iface_name})

    def start(self):
        """Start openvswitch service.

        """
        self.service_manager.start()
        # Update switch map
        bridges, interfaces = self.get_existing_bridges_interfaces()
        [self.update_map(bridge) for bridge in bridges]
        [self.update_map(iface) for iface in interfaces]

    def stop(self):
        """Stop openvswitch service.

        """
        # Update switch map
        bridges, interfaces = self.get_existing_bridges_interfaces()
        [self.update_map(bridge, delete=True) for bridge in bridges]
        [self.update_map(iface, delete=True) for iface in interfaces]
        self.service_manager.stop()

    def restart(self):
        """Restart openvswitch service.

        """
        return self.service_manager.restart()

    def status(self, exp_rc=frozenset({0, 3})):
        """Get openvswitch process status.

        Args:
            exp_rc(int | set | list | frozenset):  expected return code

        Returns:
            named tuple

        """
        return self.service_manager.status(expected_rcs=exp_rc)

    def get_status(self):
        """Method for get openvswitch status.

        Returns:
            list: ovs status 'active' or 'inactive'

        """
        output = self.status().stdout
        return re.findall(r'Active:\s(\S+)', output)

    def add_bridge(self, br_name):
        """Add new openvswitch bridge.

        Args:
            br_name(str):  name of ovs bridge

        """
        self.cli_send_command("ovs-vsctl add-br {}".format(br_name))
        self.update_map(br_name)

    def del_bridge(self, br_name):
        """Delete openvswitch bridgew.

        Args:
            br_name(str):  name of ovs bridge

        """
        self.cli_send_command(command="ovs-vsctl del-br {}".format(br_name))
        self.update_map(br_name, delete=True)

    def add_interface(self, br_name, iface_name):
        """Add new openvswitch interface.

        Args:
            br_name(str):  name of ovs bridge
            iface_name(str):  name of ovs interface

        """
        # options available
        command = 'ovs-vsctl add-port {0} {1}'.format(br_name, iface_name)
        self.cli_send_command(command)
        self.update_map(iface_name)

    def set_table_record(self, table, rec, **kwargs):
        """Set column values in record in specific table.

        Args:
            table(str):  name of ovs table
            rec(str):  name of ovs record
            kwargs(dict):  Column values dict to set

        """
        cmd = ['ovs-vsctl', 'set', table, rec]
        if kwargs:
            cmd.append(' '.join('{}={}'.format(x, y) if not isinstance(y, tuple) else '{}:{}={}'.format(x, *y)
                                for x, y in kwargs.items()))
        cmd = ' '.join(cmd)
        self.cli_send_command(cmd)

    def get_table_record(self, table, rec, column):
        """Get column value in record in specific table.

        Args:
            table(str):  name of ovs table
            rec(str):  name of ovs record
            column(str):  Column value to get

        Returns:
            str:  Returns StdOut of get command

        """
        cmd = 'ovs-vsctl get {table} {rec} {col}'.format(table=table, rec=rec, col=column)
        return self.cli_send_command(cmd).stdout

    def del_interface(self, br_name, iface_name):
        """Delete interface from openvswitch.

        Args:
            br_name(str):  name of ovs bridge
            iface_name(str):  name of ovs interface

        """
        self.cli_send_command(command="ovs-vsctl del-port {0} {1} ".format(br_name, iface_name))
        self.update_map(iface_name, delete=True)

    def set_ovsdb_manager(self, **kwargs):
        """Set connection type to ovsdb.

        Args:
            kwargs(dict):  type of ovsdb connection

        Raises:
            CustomException

        """
        if not kwargs:
            raise CustomException("Arguments are required for current method")
        else:
            for key, value in kwargs.items():
                self.cli_send_command(command="ovs-vsctl set-manager {0}:{1}".format(key, value))

    def get_interface_info(self, interface_name):
        """Get ovs interface information from ovsdb.

        Args:
            interface_name(str):  name of ovs interface

        Returns:
            dict: Output of OVS interface information

        """
        output = self.cli_send_command("ovs-vsctl list interface {}".format(interface_name)).stdout
        return dict(re.findall(r'(\S+)\s*:\s+(.+)', output))

    def get_interface_statistic(self, iface_name):
        """Get ovs interface statistic from ovsdb.

        Args:
            iface_name(str):  name of ovs interface

        Returns:
            dict:  Output of OVS interface statistics

        """
        data = self.get_interface_info(iface_name)
        # return dict(re.findall(r'{?\"*(\S+)\"*=(\d+)', data["statistics"]))
        return dict(re.findall(r'{?"*(\w+)"*=(\d+)', data["statistics"]))

    def get_existing_bridges_interfaces(self):
        """Get already existing bridges and interfaces from ovsdb.

        Returns:
            list:  list of existing ovs bridges and interfaces

        """
        output = self.cli_send_command(command="ovs-vsctl show").stdout
        bridges = re.findall(r'Bridge \"(.+)\"', output)
        interfaces = re.findall(r'Interface \"(.+)\"', output)

        # Get bridge interfaces
        br_interfaces = [item for item in interfaces if item not in bridges]
        return bridges, br_interfaces

    def delete_all_bridges(self):
        """Delete all existing bridges from ovsdb.

        """
        bridges, _ = self.get_existing_bridges_interfaces()
        [self.del_bridge(bridge) for bridge in bridges]

    def add_bond(self, br_name, bond_name, ports):
        """Method for bonding ovs interfaces.

        Args:
            br_name(str):  name of ovs bridge
            bond_name(str):  name of the bond
            ports(list):  ports to bond

        """
        command = "ovs-vsctl add-bond {0} {1} {2}".format(br_name, bond_name, ' '.join(ports))
        self.cli_send_command(command)

    def set_bridge_port_interface(self, inst_type, name, **kwargs):
        """Method set parameters for bridge, port ot interface.

        Args:
            inst_type(str):  could be Bridge, Port or Interface
            name(str):  name of ovs bridge, port or interface
            kwargs(dict):  options to be set for bridge, port or interface

        Raises:
            CustomException

        """
        if not kwargs:
            raise CustomException("Arguments are required for current method")
        options = ''.join(map(lambda x: ' {}={}'.format(*x), kwargs.items()))
        command = "ovs-vsctl set {0} {1}{2}".format(inst_type, name, options)
        self.cli_send_command(command)

    def get_interface_statistic_counter(self, iface_name, counter_name):
        """Get ovs interface statistic from ovsdb.

        Args:
            iface_name(str):  name of ovs interface
            counter_name(str):  name of ovs interface counter

        Returns:
            dict:  Output of OVS interface statistics

        """
        output = self.cli_send_command("ovs-vsctl get Interface {0} statistics:{1}".format(iface_name, counter_name))
        return int(output.stdout.strip())
