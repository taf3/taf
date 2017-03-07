"""
@copyright Copyright (c) 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  openvswitch.py

@summary  Class to abstract openvswitch operations
@note
Examples of openvswitch usage in tests:
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
        """
        @brief  Initialize openvswitch class.
        """
        super(OpenvSwitch, self).__init__()
        self.cli_send_command = cli_send_command
        self.switch_map = switch_map
        self.name_to_switchid_map = name_to_switchid_map
        self.service_manager = service_lib.SpecificServiceManager(self.SERVICE, self.cli_send_command)

    def update_map(self, iface_name, delete=False):
        """
        @brief  Update switch_map and name_to_switchid_map
        @param  iface_name:  name of ovs bridge or interface
        @type  iface_name:  str
        @param  delete:  if True - remove from switch_map and name_to_switchid_map
        @type  delete:  bool
        """
        if delete:
            self.switch_map.pop(iface_name)
            self.name_to_switchid_map.pop(iface_name)
        else:
            self.switch_map.update({iface_name: iface_name})
            self.name_to_switchid_map.update({iface_name: iface_name})

    def start(self):
        """
        @brief  Start openvswitch service
        """
        self.service_manager.start()
        # Update switch map
        bridges, interfaces = self.get_existing_bridges_interfaces()
        [self.update_map(bridge) for bridge in bridges]
        [self.update_map(iface) for iface in interfaces]

    def stop(self):
        """
        @brief  Stop openvswitch service
        """
        # Update switch map
        bridges, interfaces = self.get_existing_bridges_interfaces()
        [self.update_map(bridge, delete=True) for bridge in bridges]
        [self.update_map(iface, delete=True) for iface in interfaces]
        self.service_manager.stop()

    def restart(self):
        """
        @brief  Restart openvswitch service
        """
        return self.service_manager.restart()

    def status(self, exp_rc=frozenset({0, 3})):
        """
        @brief  Get openvswitch process status
        @param  exp_rc:  expected return code
        @type  exp_rc:  int | set | list | frozenset
        @rtype:  named tuple
        """
        return self.service_manager.status(expected_rcs=exp_rc)

    def get_status(self):
        """
        @brief  Method for get openvswitch status
        @rtype:  list
        @return:  ovs status 'active' or 'inactive'
        """
        output = self.status().stdout
        return re.findall(r'Active:\s(\S+)', output)

    def add_bridge(self, br_name):
        """
        @brief  Add new openvswitch bridge
        @param  br_name:  name of ovs bridge
        @type  br_name:  str
        """
        self.cli_send_command("ovs-vsctl add-br {}".format(br_name))
        self.update_map(br_name)

    def del_bridge(self, br_name):
        """
        @brief  Delete openvswitch bridgew
        @param  br_name:  name of ovs bridge
        @type  br_name:  str
        """
        self.cli_send_command(command="ovs-vsctl del-br {}".format(br_name))
        self.update_map(br_name, delete=True)

    def add_interface(self, br_name, iface_name):
        """
        @brief  Add new openvswitch interface
        @param  br_name:  name of ovs bridge
        @type  br_name:  str
        @param  iface_name:  name of ovs interface
        @type  iface_name:  str
        @param  iface_type:  type of added interface
        @type  iface_type:  str
        @param  kwargs:  interface options
        @type  kwargs:  dict
        """
        # options available
        command = 'ovs-vsctl add-port {0} {1}'.format(br_name, iface_name)
        self.cli_send_command(command)
        self.update_map(iface_name)

    def set_table_record(self, table, rec, **kwargs):
        """
        @brief  Set column values in record in specific table
        @param  table:  name of ovs table
        @type  table:  str
        @param  rec:  name of ovs record
        @type  rec:  str
        @param  kwargs:  Column values dict to set
        @type  kwargs:  dict
        """
        cmd = ['ovs-vsctl', 'set', table, rec]
        if kwargs:
            cmd.append(' '.join('{}={}'.format(x, y) if not isinstance(y, tuple) else '{}:{}={}'.format(x, *y)
                                for x, y in kwargs.items()))
        cmd = ' '.join(cmd)
        self.cli_send_command(cmd)

    def get_table_record(self, table, rec, column):
        """
        @brief  Get column value in record in specific table
        @param  table:  name of ovs table
        @type  table:  str
        @param  rec:  name of ovs record
        @type  rec:  str
        @param  column:  Column value to get
        @type  column:  str
        @rtype str
        @return  Returns StdOut of get command
        """
        cmd = 'ovs-vsctl get {table} {rec} {col}'.format(table=table, rec=rec, col=column)
        return self.cli_send_command(cmd).stdout

    def del_interface(self, br_name, iface_name):
        """
        @brief  Delete interface from openvswitch
        @param  br_name:  name of ovs bridge
        @type  br_name:  str
        @param  iface_name:  name of ovs interface
        @type  iface_name:  str
        """
        self.cli_send_command(command="ovs-vsctl del-port {0} {1} ".format(br_name, iface_name))
        self.update_map(iface_name, delete=True)

    def set_ovsdb_manager(self, **kwargs):
        """
        @brief  Set connection type to ovsdb
        @param  kwargs:  type of ovsdb connection
        @type  kwargs:  dict
        @raise:  CustomException
        """
        if not kwargs:
            raise CustomException("Arguments are required for current method")
        else:
            for key, value in kwargs.items():
                self.cli_send_command(command="ovs-vsctl set-manager {0}:{1}".format(key, value))

    def get_interface_info(self, interface_name):
        """
        @brief  Get ovs interface information from ovsdb
        @param  interface_name:  name of ovs interface
        @type  interface_name:  str
        @rtype:  dict
        @return:  Output of OVS interface information
        """
        output = self.cli_send_command("ovs-vsctl list interface {}".format(interface_name)).stdout
        return dict(re.findall(r'(\S+)\s*:\s+(.+)', output))

    def get_interface_statistic(self, iface_name):
        """
        @brief  Get ovs interface statistic from ovsdb
        @param  iface_name:  name of ovs interface
        @type  iface_name:  str
        @rtype:  dict
        @return:  Output of OVS interface statistics
        """
        data = self.get_interface_info(iface_name)
        # return dict(re.findall(r'{?\"*(\S+)\"*=(\d+)', data["statistics"]))
        return dict(re.findall(r'{?"*(\w+)"*=(\d+)', data["statistics"]))

    def get_existing_bridges_interfaces(self):
        """
        @brief  Get already existing bridges and interfaces from ovsdb
        @rtype:  list
        @return:  list of existing ovs bridges and interfaces
        """
        output = self.cli_send_command(command="ovs-vsctl show").stdout
        bridges = re.findall(r'Bridge \"(.+)\"', output)
        interfaces = re.findall(r'Interface \"(.+)\"', output)

        # Get bridge interfaces
        br_interfaces = [item for item in interfaces if item not in bridges]
        return bridges, br_interfaces

    def delete_all_bridges(self):
        """
        @brief  Delete all existing bridges from ovsdb
        """
        bridges, _ = self.get_existing_bridges_interfaces()
        [self.del_bridge(bridge) for bridge in bridges]

    def add_bond(self, br_name, bond_name, ports):
        """
        @brief  Method for bonding ovs interfaces
        @param  br_name:  name of ovs bridge
        @type  br_name:  str
        @param  bond_name:  name of the bond
        @type  bond_name:  str
        @param  ports:  ports to bond
        @type  ports:  list
        """
        command = "ovs-vsctl add-bond {0} {1} {2}".format(br_name, bond_name, ' '.join(ports))
        self.cli_send_command(command)

    def set_bridge_port_interface(self, inst_type, name, **kwargs):
        """
        @brief  Method set parameters for bridge, port ot interface
        @param  inst_type:  could be Bridge, Port or Interface
        @type  inst_type:  str
        @param  name:  name of ovs bridge, port or interface
        @type  name:  str
        @param  kwargs:  options to be set for bridge, port or interface
        @type  kwargs:  dict
        @raise:  CustomException
        """
        if not kwargs:
            raise CustomException("Arguments are required for current method")
        options = ''.join(map(lambda x: ' {}={}'.format(*x), kwargs.items()))
        command = "ovs-vsctl set {0} {1}{2}".format(inst_type, name, options)
        self.cli_send_command(command)

    def get_interface_statistic_counter(self, iface_name, counter_name):
        """
        @brief  Get ovs interface statistic from ovsdb
        @param  iface_name:  name of ovs interface
        @type  iface_name:  str
        @param  counter_name:  name of ovs interface counter
        @type  counter_name:  str
        @rtype:  dict
        @return:  Output of OVS interface statistics
        """
        output = self.cli_send_command("ovs-vsctl get Interface {0} statistics:{1}".format(iface_name, counter_name))
        return int(output.stdout.strip())
