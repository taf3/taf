"""
@copyright Copyright (c) 2011 - 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  ui_wrapper.py

@summary  XMLRPC UI wrappers.
"""

from abc import abstractmethod
# from abc import ABCMeta


class UiInterface(object):
    # disable this for now so we can instantiate subclasses without
    # all the abstract methods defined.  Re-enable once implemented
    # __metaclass__ = ABCMeta
    """
    @description  Abstract class to store UI wrapper interface methods
    """

    @abstractmethod
    def connect(self):
        """
        @brief  Mandatory method for UI wrapper connection.
        """
        pass

    @abstractmethod
    def disconnect(self):
        """
        @brief  Mandatory method for UI wrapper disconnection.
        """
        pass

    @abstractmethod
    def restart(self):
        """
        @brief  Perform device reboot via User Interface.
        """
        pass

# Clear Config
    @abstractmethod
    def clear_config(self):
        """
        @brief  Clear device configuration
        """
        pass

    @abstractmethod
    def save_config(self):
        """
        @brief  Save device configuration
        """
        pass

    @abstractmethod
    def restore_config(self):
        """
        @brief  Restore device configuration
        """
        pass

# Application Check
    @abstractmethod
    def check_device_state(self):
        """
        @brief  Attempts to connect to the shell retries number of times
        """

# Platform
    @abstractmethod
    def get_table_platform(self):
        """
        @brief  Get 'Platform' table
        """
        pass

# Syslog configuration
    @abstractmethod
    def create_syslog(self, syslog_proto, syslog_ip, syslog_port, syslog_localport, syslog_transport, syslog_facility, syslog_severity):
        """
        @brief  Configure Syslog settings
        @param  syslog_proto:  syslog host protocol Udp | Tcp
        @type  syslog_proto:  str
        @param  syslog_ip:  syslog host IP address
        @type  syslog_ip:  str
        @param  syslog_port:  syslog host port
        @type  syslog_port:  int
        @param  syslog_localport:  syslog host local port
        @type  syslog_localport:  int
        @param  syslog_transport:  syslog host transport
        @type  syslog_transport:  str
        @param  syslog_facility:  syslog host facility
        @type  syslog_facility:  int
        @param  syslog_severity:  syslog host severity
        @type  syslog_severity:  str
        """
        pass

    @abstractmethod
    def logs_add_message(self, level, message):
        """
        @brief  Add message into device logs
        @param  level:  log severity
        @type  level:  str
        @param  message:  log message
        @type  message:  str
        """
        pass

# Temperature information
    @abstractmethod
    def get_temperature(self):
        """
        @brief  Get temperature from Sensors table
        @rtype:  dict
        @return:  CPU temperature information (Sensors table)
        """
        pass

# System information
    @abstractmethod
    def get_memory(self, mem_type='usedMemory'):
        """
        @brief  Returns free cached/buffered memory from switch
        @param  mem_type:  memory type
        @type  mem_type:  str
        @rtype:  float
        @return:  memory size
        """
        pass

    @abstractmethod
    def get_cpu(self):
        """
        @brief  Returns cpu utilization from switch
        @rtype:  float
        @return:  cpu utilization from switch
        """
        pass

# Applications configuration
    @abstractmethod
    def get_table_applications(self):
        """
        @brief  Get 'Applications' table
        @rtype:  list[dict]
        @return:  'Applications' table
        """
        pass

    @abstractmethod
    def configure_application(self, application, loglevel):
        """
        @brief  Set application loglevel
        @param  application:  Application Name.
        @type  application:  str
        @param  loglevel:  Application loglevel.
        @type  loglevel:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_application('L1PortControlApp', 'Debug')
        @endcode
        """
        pass

# STP configuration
    @abstractmethod
    def configure_spanning_tree(self, **kwargs):
        """
        @brief  Configure 'SpanningTree' table
        @param  kwargs:  Possible parameters from 'SpanningTree' table to configure:
                             "enable" - globally enable STP;
                             "mode" - set STP mode. RSTP|MSTP|STP;
                             "maxAge" - set maxAge value;
                             "forwardDelay" - set forwardDelay value;
                             "bridgePriority" - set bridgePriority value;
                             "bpduGuard" - set bpduGuard value;
                             "forceVersion" - set forceVersion value;
                             "mstpciName" - set mstpciName value.
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_spanning_tree(mode='MSTP')
        @endcode
        """
        pass

    @abstractmethod
    def create_stp_instance(self, instance, priority):
        """
        @brief  Create new STP instance in 'STPInstances' table
        @param  instance:  Instance number.
        @type  instance:  int
        @param  priority:  Instance priority.
        @type  priority:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_stp_instance(instance=3, priority=2)
        @endcode
        """
        pass

    @abstractmethod
    def configure_stp_instance(self, instance, **kwargs):
        """
        @brief  Configure existing STP instance
        @param  instance:  Instance number.
        @type  instance:  int
        @param  kwargs:  Possible parameters to configure:
                             "priority" - change instance priority;
                             "vlan" - assign instance to the existed vlan.
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_stp_instance(instance=3, priority=2) - change instance priority
        env.switch[1].ui.configure_stp_instance(instance=3, vlan=10) - assign instance to the existed vlan
        @endcode
        """
        pass

    @abstractmethod
    def get_table_spanning_tree(self):
        """
        @brief  Get 'SpanningTree' table
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_spanning_tree()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_spanning_tree_mst(self):
        """
        @brief  Get 'STPInstances' table
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_spanning_tree_mst()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_mstp_ports(self, ports=None, instance=None):
        """
        @brief  Get 'MSTPPorts' table
        @param ports:  list of ports.
        @type  ports:  list
        @param instance:  Instance number.
        @type  instance:  int
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @note  Return all table or information about particular ports and STP instance.
        @par Example:
        @code
        env.switch[1].ui.get_table_mstp_ports()
        env.switch[1].ui.get_table_mstp_ports([1, 2])
        env.switch[1].ui.get_table_mstp_ports([1, 2], instance=3)
        @endcode
        """
        pass

    @abstractmethod
    def modify_mstp_ports(self, ports, instance=0, **kwargs):
        """
        @brief  Modify records in 'MSTPPorts' table
        @param ports:  list of ports.
        @type  ports:  list
        @param instance:  Instance number.
        @type  instance:  int
        @param  kwargs:  Parameters to be modified. Parameters names should be the same as in XMLRPC nb.MSTPPorts.set.* calls:
                             "adminState" - change adminState;
                             "portFast" - set portFast value;
                             "rootGuard" - set rootGuard value;
                             "bpduGuard" - set bpduGuard value;
                             "autoEdgePort" - set autoEdgePort value;
                             "adminPointToPointMAC" - set adminPointToPointMAC value;
                             "externalCost" - set externalCost value;
                             "internalCost" - set internalCost value.
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.modify_mstp_ports([1, 2], instance=3, adminState='Enabled')
        @endcode
        """
        pass

    @abstractmethod
    def modify_rstp_ports(self, ports, **kwargs):
        """
        @brief  Modify records in 'RSTPPorts' table
        @param ports:  list of ports.
        @type  ports:  list
        @param  kwargs:  Parameters to be modified. Parameters names should be the same as in XMLRPC nb.RSTPPorts.set.* calls:
                             "adminState" - change adminState;
                             "portFast" - set portFast value;
                             "rootGuard" - set rootGuard value;
                             "bpduGuard" - set bpduGuard value;
                             "autoEdgePort" - set autoEdgePort value;
                             "adminPointToPointMAC" - set adminPointToPointMAC value;
                             "cost" - set cost value.
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.modify_rstp_ports([1, 2], adminState='Enabled')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_rstp_ports(self, ports=None):
        """
        @brief  Get 'MSTPPorts' table
        @param  ports:  list of ports.
        @type  ports:  list
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @note  Return all table or information about particular ports.
        @par Example:
        @code
        env.switch[1].ui.get_table_rstp_ports()
        env.switch[1].ui.get_table_rstp_ports([1, 2])
        @endcode
        """
        pass

# Ports configuration
    @abstractmethod
    def set_all_ports_admin_disabled(self):
        """
        @brief  Set all ports into admin Down state
        @return:  None
        @note  This method is used in helpers.set_all_ports_admin_disabled() for all functional test case.
        """
        pass

    @abstractmethod
    def wait_all_ports_admin_disabled(self):
        """
        @brief  Wait for all ports into admin Down state
        @return:  None
        @note  This method is used in helpers.set_all_ports_admin_disabled() for all functional test case.
        """
        pass

    @abstractmethod
    def modify_ports(self, ports, **kwargs):
        """
        @brief  Modify records in 'Ports' table
        @param ports:  list of port IDs.
        @type  ports:  list
        @param  kwargs:  Parameters to be modified. Parameters names should be the same as in XMLRPC nb.Ports.set.* calls:
                         "pvid" - set pvid value;
                         "pvpt" - set pvpt value;
                         "adminMode" - set adminMode value;
                         "ingressFiltering" - set ingressFiltering value;
                         "maxFrameSize" - set maxFrameSize value;
                         "discardMode" - set discardMode value;
                         "cutThrough" - set cutThrough value;
                         "flowControl" - set flowControl value;
                         "speed" - set speed value;
                         "learnMode" - set learnMode value.
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.modify_ports([1, 2], adminMode='Down')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_ports(self, ports=None, all_params=False):
        """
        @brief  Get 'Ports' table
        @param ports:  list of port IDs.
        @type  ports:  list
        @param  all_params:  get additional port properties
        @type  all_params:  bool
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @note  Return all table or information about particular ports.
        @par Example:
        @code
        env.switch[1].ui.get_table_ports()
        env.switch[1].ui.get_table_ports([1, 2])
        @endcode
        """
        pass

# Flow Confrol configuration
    @abstractmethod
    def set_flow_control_type(self, ports=None, control_type=None):
        """
        @brief Enable/disable sending/accepting pause frames
        @param ports: list of port IDs
        @type ports: list
        @param control_type: 'Rx', 'Tx', 'RxTx' and 'None'
        @type: string
        @return: None
        @par Example:
        @code
        env.switch[1].ui.set_flow_control([1, 2], 'RxTx')
        @endcode
        """
        pass

# Ustack configuration
    @abstractmethod
    def start_ustack_with_given_mesh_ports(self, mesh_ports=tuple(), dbglevel=0):
        """
        @brief  Start ustack with given mesh ports on command line
        @param mesh_ports:  List of mesh ports given by command line user
        @type mesh_ports:  list
        @param  dbglevel:  dbglevel value
        @type  dbglevel:  int
        @return: success or failure report
        @code
        env.switch[1].ui.start_ustack_with_given_mesh_ports('sw0p1,sw0p2')
        @endcode
        """
        pass

# Vlan configuration
    @abstractmethod
    def create_vlans(self, vlans=None):
        """
        @brief  Create new Vlans
        @param  vlans:  list of vlans to be created.
        @type  vlans:  list[int]
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_vlans([2, 3])
        @endcode
        """
        pass

    @abstractmethod
    def delete_vlans(self, vlans=None):
        """
        @brief  Delete existing Vlans
        @param vlans:  list of vlans to be deleted.
        @type  vlans:  list[int]
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.delete_vlans([2, 3])
        @endcode
        """
        pass

    @abstractmethod
    def get_table_vlans(self):
        """
        @brief  Get 'Vlans' table
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_vlans()
        @endcode
        """
        pass

    @abstractmethod
    def create_vlan_ports(self, ports=None, vlans=None, tagged='Tagged'):
        """
        @brief  Create new Ports2Vlans records
        @param  ports:  list of ports to be added to Vlans.
        @type  ports:  list[int]
        @param  vlans:  list of vlans.
        @type  vlans:  list[int]
        @param  tagged:  information about ports tagging state.
        @type  tagged:  str
        @return:  None
        @par Example:
        @code
        Port 1 will be added into the vlans 3 and 4 as Untagged and port 2 will be added into the vlans 3 and 4 as Untagged
        env.switch[1].ui.create_vlan_ports([1, 2], [3, 4], 'Untagged')
        @endcode
        """
        pass

    @abstractmethod
    def delete_vlan_ports(self, ports=None, vlans=None):
        """
        @brief  Delete Vlan from port
        @param ports:  list of ports.
        @type  ports:  list[int]
        @param vlans:  list of vlans.
        @type  vlans:  list[int]
        @return:  None
        @par Example:
        @code
        Ports 1 and 2 will be removed from the vlan 3:
        env.switch[1].ui.delete_vlan_ports([1, 2], [3, ])
        @endcode
        """
        pass

    @abstractmethod
    def modify_vlan_ports(self, ports=None, vlans=None, tagged='Tagged'):
        """
        @brief  Modify Ports2Vlans records
        @param ports:  list of ports.
        @type ports:  list[int]
        @param vlans:  list of vlans.
        @type vlans:  list[int]
        @param tagged:  information about ports tagging state.
        @type tagged:  str
        @return:  None
        @par Example:
        @code
        Port 1 will be modified in the vlans 3 and 4 as Tagged
        env.switch[1].ui.create_vlan_ports([1, ], [3, 4], 'Tagged')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_ports2vlans(self):
        """
        @brief  Get 'Ports2Vlans' table
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_ports2vlans()
        @endcode
        """
        pass

# ACL configuration
    @abstractmethod
    def create_acl_name(self, acl_name=None):
        """
        @brief  Create ACL name
        @param acl_name:  ACL name to be created
        @type  acl_name:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_acl_name('Test-1')
        @endcode
        """
        pass

    @abstractmethod
    def add_acl_rule_to_acl(self, acl_name=None, rule_id='', action=None, conditions=None):
        """
        @brief  Add rule to ACL
        @param acl_name:  ACL name where rule is added to.
        @type  acl_name:  str
        @param rule_id:  Rule Id used for adding.
        @type  rule_id:  str|int
        @param action:  ACL Action
        @type  action:  list[str]
        @param conditions:  List of ACL conditions
        @type  conditions:  list[list[str]]
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.add_acl_rule_to_acl(acl_name='Test-1',
                                             rule_id=1,
                                             action=['forward', '1'],
                                             conditions=[['ip-source',
                                                         '192.168.10.10',
                                                         '255.255.255.255']])
        @endcode
        """
        pass

    @abstractmethod
    def bind_acl_to_ports(self, acl_name=None, ports=None):
        """
        @brief  Bind ACL to ports
        @param acl_name:  ACL name
        @type  acl_name:  str
        @param ports:  list of ports where ACL will be bound.
        @type  ports:  list[int]
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.bind_acl_to_ports(acl_name='Test-1', ports=[1, 2, 3])
        @endcode
        """
        pass

    @abstractmethod
    def unbind_acl(self, acl_name=None):
        """
        @brief  Unbind ACL
        @param acl_name:  ACL name
        @type  acl_name:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.unbind_acl('Test-1')
        @endcode
        """
        pass

    @abstractmethod
    def create_acl(self, ports=None, expressions=None, actions=None, rules=None, acl_name='Test-ACL'):
        """
        @brief  Create ACLs
        @param ports:  list of ports where ACLs will be created.
        @type  ports:  list[int]
        @param expressions:  list of ACL expressions.
        @type  expressions:  list[list]
        @param actions:  list of ACL actions.
        @type  actions:  list[list]
        @param rules:  list of ACL rules.
        @type  rules:  list[list]
        @param acl_name:  ACL name to which add rules
        @type  acl_name:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_acl(ports=[1, 2], expressions=[[1, 'SrcMac', 'FF:FF:FF:FF:FF:FF', '00:00:00:11:11:11'], ],
                                    actions=[[1, 'Drop', ''], ], [[1, 1, 1, 'Ingress', 'Enabled', 0], ])
        @endcode
        """
        pass

    @abstractmethod
    def delete_acl(self, ports=None, expression_ids=None, action_ids=None, rule_ids=None, acl_name=None):
        """
        @brief  Delete ACLs
        @param ports:  list of ports where ACLs will be deleted (mandatory).
        @type  ports:  list[int]
        @param expression_ids:  list of ACL expression IDs to be deleted (optional).
        @type  expression_ids:  list[int]
        @param action_ids:  list of ACL action IDs to be deleted (optional).
        @type  action_ids:  list[int]
        @param rule_ids:  list of ACL rule IDs to be deleted (optional).
        @type  rule_ids:  list[int]
        @param acl_name:  ACL name
        @type  acl_name:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.delete_acl(ports=[1, 2], rule_ids=[1, 2])
        @endcode
        """
        pass

    @abstractmethod
    def get_table_acl(self, table=None, acl_name=None):
        """
        @brief  Get ACL table
        @param table:  ACL table name to be returned. ACLStatistics|ACLExpressions|ACLActions
        @type  table:  str
        @param acl_name:  ACL name
        @type  acl_name:  str
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_acl('ACLStatistics')
        @endcode
        """
        pass

    @abstractmethod
    def get_acl_names(self):
        """
        @brief  Get ACL names
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_acl_names()
        @endcode
        """
        pass

# FDB configuration
    @abstractmethod
    def create_static_macs(self, port=None, vlans=None, macs=None):
        """
        @brief  Create static FDB records
        @param port:  port where static Fbds will be created (mandatory).
        @type  port:  int
        @param vlans:  list of vlans where static Fbds will be created (mandatory).
        @type  vlans:  list[int]
        @param macs:  list of MACs to be added (mandatory).
        @type  macs:  list[str]
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_static_macs(10, [1, 2], ['00:00:00:11:11:11', ])
        @endcode
        """
        pass

    @abstractmethod
    def delete_static_mac(self, port=None, vlan=None, mac=None):
        """
        @brief  Delete static FDB records
        @param port:  port where static Fbds will be deleted.
        @type  port:  int
        @param vlan:  list of vlans where static Fbds will be deleted (mandatory).
        @type  vlan:  list[int]
        @param mac:  list of MACs to be deleted (mandatory).
        @type  mac:  list[str]
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.delete_static_mac([1, 2], ['00:00:00:11:11:11', ])
        @endcode
        """
        pass

    @abstractmethod
    def get_table_fdb(self, table='Fdb'):
        """
        @brief  Get Fbd table
        @param table:  Fbd record type to be returned ('Fbd' or 'Static')
        @type  table:  str
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_fdb()
        env.switch[1].ui.get_table_fdb('Static')
        @endcode
        """
        pass

    @abstractmethod
    def clear_table_fdb(self):
        """
        @brief  Clear Fdb table
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.clear_table_fdb()
        @endcode
        """
        pass

# QoS configuration

    @abstractmethod
    def get_table_ports_qos_scheduling(self, port=None, param=None):
        """
        @brief  Get PortsQoS scheduling information
        @param port:  port Id to get info about
        @type  port:  int
        @param param:  param name to get info about
        @type  param:  str
        @rtype:  list[dict] | str | int
        @return  table (list of dictionaries) or dictionary or param value
        @par Example:
        @code
        env.switch[1].ui.get_table_ports_qos_scheduling(port=1, param='schedMode')
        env.switch[1].ui.get_table_ports_qos_scheduling('Static')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_ports_dot1p2cos(self, port=None, rx_attr_flag=True):
        """
        @brief  Get PortsDot1p2CoS table
        @param port:  port Id to get info about ('All' or port id)
        @type  port:  str|int
        @param rx_attr_flag:  whether get rx or tx attribute information
        @type  rx_attr_flag:  bool
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_ports_dot1p2cos(1)
        env.switch[1].ui.get_table_ports_dot1p2cos('All')
        @endcode
        """
        pass

    @abstractmethod
    def configure_cos_global(self, **kwargs):
        """
        @brief  Configure global mapping of ingress VLAN priority to CoS per port or per switch (PortsDot1p2CoS records)
        @param  kwargs:  parameters to be modified
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_cos_global(dotp2CoS=6)
        @endcode
        """
        pass

    @abstractmethod
    def configure_dscp_to_cos_mapping_global(self, **kwargs):
        """
        @brief  Configure PortsDscp2CoS records
        @param  kwargs:  parameters to be modified
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_dscp_to_cos_mapping_global(dscp0CoS=6)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_ports_dscp2cos(self):
        """
        @brief  Get PortsDscp2CoS records
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_ports_dscp2cos()
        @endcode
        """
        pass

    @abstractmethod
    def configure_schedweight_to_cos_mapping(self, ports, **kwargs):
        """
        @brief  Configure schedweight to cos mapping
        @param ports:  list of port Ids
        @type  ports:  list[int]
        @param  kwargs:  parameters to be modified
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_schedweight_to_cos_mapping(ports=[1,2], schedWeight0=35)
        @endcode
        """
        pass

    @abstractmethod
    def configure_port_cos(self, ports=None, **kwargs):
        """
        @brief  Configure PortsQoS records
        @param ports:  list of ports to be modified
        @type  ports:  list[int]
        @param  kwargs:  parameters to be modified
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_port_cos([1, ], trustMode='Dot1p')
        @endcode
        """
        pass

    @abstractmethod
    def create_dot1p_to_cos_mapping(self, ports, rx_attr_flag=False, **kwargs):
        """
        @brief  Configure mapping of ingress VLAN priority to CoS per port or per switch (PortsDot1p2CoS mapping)
        @param ports:  list of ports to be modified
        @type  ports:  list[int]
        @param  rx_attr_flag:  whether rx or tx attribute to be modified
        @type rx_attr_flag: bool
        @param  kwargs:  parameters to be modified
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_dot1p_to_cos_mapping([1, ], dotp7CoS=6)
        @endcode
        """
        pass

    @abstractmethod
    def modify_dot1p_to_cos_mapping(self, ports, rx_attr_flag=False, **kwargs):
        """
        @brief  Modify mapping of ingress VLAN priority to CoS per port or per switch (PortsDot1p2CoS mapping)
        @param ports:  list of ports to be modified
        @type  ports:  list[int]
        @param  rx_attr_flag:  whether rx or tx attribute to be modified
        @type rx_attr_flag: bool
        @param  kwargs:  parameters to be modified
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.modify_dot1p_to_cos_mapping([1, ], dotp7CoS=6)
        @endcode
        """
        pass

    @abstractmethod
    def clear_per_port_dot1p_cos_mapping(self, ports, rx_attr_flag=False, dot1p=None):
        """
        @brief  Clear PortsDot1p2CoS mapping
        @param ports:  list of ports to be modified
        @type  ports:  list[int]
        @param rx_attr_flag:  whether to use rx attribute or tx attribute
        @type rx_attr_flag: bool
        @param dot1p:  list of Dot1p priority required to clear.
        @type dot1p: list[int]
        @par Example:
        @code
        env.switch[1].ui.clear_per_port_dot1p_cos_mapping(ports=[port1, ], dot1p=[6, ])
        @endcode
        """
        pass

# Statistics configuration
    @abstractmethod
    def map_stat_name(self, generic_name):
        """
        @brief Get the UI specific stat name for given generic name
        @param generic_name: generic statistic name
        @type generic_name: str
        @rtype: str
        @return: UI specific stat name
        """
        pass

    @abstractmethod
    def get_table_statistics(self, port=None, stat_name=None):
        """
        @brief  Get Statistics table
        @param port:  port Id to get info about ('cpu' or port id) (optional)
        @type  port:  str|int|None
        @param stat_name:  name of statistics parameter (optional)
        @type  stat_name:  str
        @rtype:  list[dict]|int
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_statistics()
        env.switch[1].ui.get_table_statistics(port=1)
        env.switch[1].ui.get_table_statistics(port='cpu')
        @endcode
        """
        pass

    @abstractmethod
    def clear_statistics(self):
        """
        @brief  Clear Statistics
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.clear_statistics()
        @endcode
        """
        pass

# Bridge Info configuration
    @abstractmethod
    def get_table_bridge_info(self, param=None, port=None):
        """
        @brief  Get Bridge Info table or specific parameter value in
                Bridge Info table
        @param param:  parameter name (optional)
        @type  param:  str
        @param port:  port ID (optional)
        @type  port:  int
        @rtype:  list[dict]|str|int
        @return  table (list of dictionaries) or value
        @par Example:
        @code
        env.switch[1].ui.get_table_bridge_info()
        env.switch[1].ui.get_table_bridge_info('agingTime')
        @endcode
        """
        pass

    @abstractmethod
    def modify_bridge_info(self, **kwargs):
        """
        @brief  Modify BridgeInfo table
        @param  kwargs:  Parameters to be modified:
                             "agingTime" - set agingTime value;
                             "defaultVlanId" - set defaultVlanId value.
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.modify_bridge_info(agingTime=5)
        @endcode
        """
        pass

# LAG configuration
    @abstractmethod
    def create_lag(self, lag=None, key=None, lag_type='Static', hash_mode='None'):
        """
        @brief  Create LAG instance
        @param lag:  LAG id
        @type  lag:  int
        @param key:  LAG key
        @type  key:  int
        @param lag_type:  LAG type. 'Static'|'Dynamic'
        @type  lag_type:  str
        @param hash_mode:  LAG hash type:
                               'None'|'SrcMac'|'DstMac'|'SrcDstMac'|'SrcIp'|'DstIp'|
                               'SrcDstIp'|'L4SrcPort'|'L4DstPort'|'L4SrcPort,L4DstPort'|
                               'OuterVlanId'|'InnerVlanId'|'EtherType'|'OuterVlanPri'|
                               'InnerVlanPri'|'Dscp'|'IpProtocol'|'DstIp,L4DstPort'|
                               'SrcIp,L4SrcPort'|'SrcMac,OuterVlanId'|'DstMac,OuterVlanId'|
                               'SrcIp,DstIp,L4SrcPort'|'DstIp,IpProtocol'|'SrcIp,IpProtocol'|'Ip6Flow'
        @type  hash_mode:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_lag(3800, 1, 'Static', 'None')
        @endcode
        """
        pass

    @abstractmethod
    def delete_lags(self, lags=None):
        """
        @brief  Delete LAG instance
        @param lags:  list of LAG Ids
        @type  lags:  list[int]
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.delete_lags([3800, ])
        @endcode
        """
        pass

    @abstractmethod
    def get_table_lags(self):
        """
        @brief  Get LagsAdmin table
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_lags()
        @endcode
        """
        pass

    @abstractmethod
    def modify_lags(self, lag, key=None, lag_type=None, hash_mode=None):
        """
        @brief  Modify LagsAdmin table
        @param lag:  LAG id
        @type  lag:  int
        @param key:  LAG key
        @type  key:  int
        @param lag_type:  LAG type (Static or Dynamic)
        @type  lag_type:  str
        @param hash_mode:  LAG hash mode
        @type  hash_mode:  str
        @return  None
        @par Example:
        @code
        env.switch[1].ui.modify_lags(lag=3800, lag_type="Static")
        @endcode
        """
        pass

    @abstractmethod
    def get_table_link_aggregation(self):
        """
        @brief  Get LinkAggregation table
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_link_aggregation()
        @endcode
        """
        pass

    @abstractmethod
    def modify_link_aggregation(self, globalenable=None, collectormaxdelay=None, globalhashmode=None, priority=None, lacpenable=None):
        """
        @brief  Modify LinkAggregation table
        @param globalenable:  globalEnable parameter value
        @type  globalenable:  str
        @param collectormaxdelay:  collectorMaxDelay parameter value
        @type  collectormaxdelay:  int
        @param globalhashmode:  globalHashMode parameter value
        @type  globalhashmode:  str
        @param priority:  priority parameter value
        @type  priority:  int
        @param lacpenable:  lacpEnable parameter value
        @param  lacpenable:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.modify_link_aggregation(globalhashmode='SrcMac')
        @endcode
        """
        pass

    @abstractmethod
    def create_lag_ports(self, ports, lag, priority=1, key=None, aggregation='Multiple', lag_mode='Passive', timeout='Long', synchronization=False,
                         collecting=False, distributing=False, defaulting=False, expired=False, partner_system='00:00:00:00:00:00', partner_syspri=32768,
                         partner_number=1, partner_key=0, partner_pri=32768):
        """
        @brief  Add ports into created LAG
        @param ports:  list of ports to be added into LAG
        @type  ports:  list[int]
        @param lag:  LAG Id
        @type  lag:  int
        @param priority:  LAG priority
        @type  priority:  int
        @param key:  LAG key
        @type  key:  int
        @param aggregation:  LAG aggregation
        @type  aggregation:  str
        @param lag_mode:  LAG mode
        @type  lag_mode:  str
        @param timeout:  LAG timeout
        @type  timeout:  str
        @param synchronization:  LAG synchronization
        @type  synchronization:  bool
        @param collecting:  LAG collecting
        @type  collecting:  bool
        @param distributing:  LAG distributing
        @type  distributing:  bool
        @param defaulting:  LAG defaulting
        @type  defaulting:  bool
        @param expired:  LAG expired
        @type  expired:  bool
        @param partner_system:  LAG partner system MAC address
        @type  partner_system:  str
        @param partner_syspri:  LAG partner system priority
        @type  partner_syspri:  int
        @param partner_number:  LAG partner number
        @type  partner_number:  int
        @param partner_key:  LAG partner key
        @type  partner_key:  int
        @param partner_pri:  LAG partner priority
        @type  partner_pri:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_lag_ports([1, ], 3800, priority=1, key=5)
        @endcode
        """
        pass

    @abstractmethod
    def delete_lag_ports(self, ports, lag):
        """
        @brief  Delete ports from created LAG
        @param ports:  list of ports to be added into LAG
        @type  ports:  list[int]
        @param lag:  LAG Id
        @type  lag:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.delete_lag_ports([1, ], 3800)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_ports2lag(self):
        """
        @brief  Get Ports2LagAdmin table
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_ports2lag()
        @endcode
        """
        pass

    @abstractmethod
    def modify_ports2lag(self, port, lag, priority=None, key=None, aggregation=None, lag_mode=None, timeout=None, synchronization=None,
                         collecting=None, distributing=None, defaulting=None, expired=None, partner_system=None, partner_syspri=None,
                         partner_number=None, partner_key=None, partner_pri=None):
        """
        @brief  Modify Ports2LagAdmin table
        @param port:  LAG port
        @type  port:  int
        @param lag:  LAG Id
        @type  lag:  int
        @param priority:  port priority
        @type  priority:  int
        @param key:  port key
        @type  key:  int
        @param aggregation:  port aggregation (multiple or individual)
        @type  aggregation:  str
        @param lag_mode:  LAG mode (Passive or Active)
        @type  lag_mode:  str
        @param timeout:  port timeout (Short or Long)
        @type  timeout:  str
        @param synchronization:  port synchronization (True or False)
        @type  synchronization:  str
        @param collecting:  port collecting (True or False)
        @type  collecting:  str
        @param distributing:  port distributing (True or False)
        @type  distributing:  str
        @param defaulting:  port defaulting state (True or False)
        @type  defaulting:  str
        @param expired:  port expired state (True or False)
        @type  expired:  str
        @param partner_system:  partner LAG MAC address
        @type  partner_system:  str
        @param partner_syspri:  partner LAG  priority
        @type  partner_syspri:  int
        @param partner_number:  partner port number
        @type  partner_number:  int
        @param partner_key:  partner port key
        @type  partner_key:  int
        @param partner_pri:  partner port priority
        @type  partner_pri:  int
        @return  None
        @par Example:
        @code
        env.switch[1].ui.modify_ports2lag(1, 3800, priority=100)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_lags_local(self, lag=None):
        """
        @brief  Get LagsLocal table
        @param lag:  LAG Id
        @type  lag:  int
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_lags_local()
        env.switch[1].ui.get_table_lags_local(3800)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_lags_local_ports(self, lag=None):
        """
        @brief  Get Ports2LagLocal table
        @param lag:  LAG Id
        @type  lag:  int
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_lags_local_ports()
        env.switch[1].ui.get_table_lags_local_ports(3800)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_lags_remote(self, lag=None):
        """
        @brief  Get LagsRemote table
        @param lag:  LAG Id
        @type  lag:  int
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_lags_remote()
        env.switch[1].ui.get_table_lags_remote(3800)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_lags_remote_ports(self, lag=None):
        """
        @brief  Get Ports2LagRemote table
        @param lag:  LAG Id
        @type  lag:  int
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_lags_remote_ports()
        env.switch[1].ui.get_table_lags_remote_ports(lag=3800)
        @endcode
        """
        pass

# IGMP configuration
    @abstractmethod
    def configure_igmp_global(self, mode='Enabled', router_alert=None, unknown_igmp_behavior=None, query_interval=None, querier_robustness=None):
        """
        @brief  Modify IGMPSnoopingGlobalAdmin table
        @param mode:  mode parameter value. 'Enabled'|'Disabled'
        @type  mode:  str
        @param router_alert:  routerAlertEnforced parameter value. 'Enabled'|'Disabled'
        @type  router_alert:  str
        @param unknown_igmp_behavior:  unknownIgmpBehavior parameter value. 'Broadcast'|'Drop'
        @type  unknown_igmp_behavior:  str
        @param query_interval:  queryInterval parameter value
        @type  query_interval:  int
        @param querier_robustness:  querierRobustness parameter value
        @type  querier_robustness:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_igmp_global(mode='Enabled')
        @endcode
        """
        pass

    @abstractmethod
    def configure_igmp_per_ports(self, ports, mode='Enabled', router_port_mode=None):
        """
        @brief  Modify IGMPSnoopingPortsAdmin table
        @param ports:  list of ports
        @type  ports:  list[int]
        @param mode:  igmpEnabled parameter value. 'Enabled'|'Disabled'
        @type  mode:  str
        @param router_port_mode:  routerPortMode parameter value. 'Auto'|'Always'
        @type  router_port_mode:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_igmp_per_ports([1, 2], mode='Enabled')
        @endcode
        """
        pass

    @abstractmethod
    def create_multicast(self, port, vlans, macs):
        """
        @brief  Create StaticL2Multicast record
        @param port:  port Id
        @type  port:  int
        @param vlans:  list of vlans
        @type  vlans:  list[int]
        @param macs:  list of multicast MACs
        @type  macs:  list[str]
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_multicast(10, [5, ], ['01:00:05:11:11:11', ])
        @endcode
        """
        pass

    @abstractmethod
    def delete_multicast(self, port=None, vlan=None, mac=None):
        """
        @brief  Delete StaticL2Multicast record
        @param port:  port Id
        @type  port:  int
        @param vlan:  vlan Id
        @type  vlans:  int
        @param mac:  multicast MAC
        @type  mac:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.delete_multicast(10, 5, '01:00:05:11:11:11')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_l2_multicast(self):
        """
        @brief  Get L2Multicast table
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_l2_multicast()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_igmp_snooping_global_admin(self, param=None):
        """
        @brief  Get IGMPSnoopingGlobalAdmin table
        @param param:  parameter name
        @type  param:  str
        @rtype:  list[dict]|int|str
        @return  table (list of dictionaries) or value
        @par Example:
        @code
        env.switch[1].ui.get_table_igmp_snooping_global_admin()
        env.switch[1].ui.get_table_igmp_snooping_global_admin('queryInterval')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_igmp_snooping_port_oper(self, port, param=None):
        """
        @brief  Get IGMPSnoopingPortsOper table
        @param port:  port Id
        @type  port:  int
        @param param:  parameter name
        @type  param:  str
        @rtype:  list[dict]|int|str
        @return  table (list of dictionaries) or value
        @par Example:
        @code
        env.switch[1].ui.get_table_igmp_snooping_port_oper()
        env.switch[1].ui.get_table_igmp_snooping_port_oper('queryInterval')
        @endcode
        """
        pass

    @abstractmethod
    def clear_l2_multicast(self):
        """
        @brief  Clear L2Multicast table
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.clear_l2_multicast()
        @endcode
        """
        pass

# L3 configuration
    @abstractmethod
    def configure_routing(self, routing='Enabled', ospf=None):
        """
        @brief  Configure L3 routing
        @param routing:  enable L3 routing
        @type  routing:  str
        @param ospf:  enable OSPF. None|'Enabled'
        @type  ospf:  str|None
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_routing(routing='Enabled', ospf='Enabled')
        @endcode
        """
        pass

    @abstractmethod
    def create_route_interface(self, vlan, ip, ip_type='InterVlan', bandwidth=1000, mtu=1500, status='Enabled', vrf=0, mode='ip'):
        """
        @brief  Create Route Interface
        @param vlan:  vlan Id
        @type  vlan:  int
        @param ip:  Route Interface network
        @type  ip:  str
        @param ip_type:  Route interface type
        @type  ip_type:  str
        @param bandwidth:  Route interface bandwidth
        @type  bandwidth:  int
        @param mtu:  Route interface mtu
        @type  mtu:  int
        @param status:  Route interface status
        @type  status:  str
        @param vrf:  Route interface vrf
        @type  vrf:  int
        @param mode:  'ip' or 'ipv6'
        @type  mtu:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_route_interface(10, '10.0.5.101/24', 'InterVlan', 1000, 1500, 'Enabled, 0, 'ip')
        env.switch[1].ui.create_route_interface(10, '2000::01/96', 'InterVlan', 1000, 1500, 'Enabled, 0, 'ipv6')
        @endcode
        """
        pass

    @abstractmethod
    def delete_route_interface(self, vlan, ip, bandwith=1000, mtu=1500, vrf=0, mode='ip'):
        """
        @brief  Delete Route Interface
        @param vlan:  vlan Id
        @type  vlan:  int
        @param ip:  Route Interface network
        @type  ip:  str
        @param bandwith:  Route interface bandwidth
        @type  bandwith:  int
        @param mtu:  Route interface mtu
        @type  mtu:  int
        @param vrf:  Route interface vrf
        @type  vrf:  int
        @param mode:  'ip' or 'ipv6'
        @type  mode:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.delete_route_interface(10, '10.0.5.101/24', 1000, 1500, 0, 'ip')
        env.switch[1].ui.create_route_interface(10, '2000::01/96', 1000, 1500, 0, 'ipv6')
        @endcode
        """
        pass

    @abstractmethod
    def modify_route_interface(self, vlan, ip, **kwargs):
        """
        @brief  Modify Route Interface
        @param vlan:  vlan Id
        @type  vlan:  int
        @param ip:  Route Interface network
        @type  ip:  str
        @param  kwargs:  parameters to be modified:
                             "adminMode" - set adminMode value.
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.modify_route_interface(10, '10.0.5.101/24', adminMode='Disabled')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_route_interface(self):
        """
        @brief  Get RouteInterface table
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_route_interface()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_route(self, mode='ip'):
        """
        @brief  Get Route table
        @param mode:  'ip' or 'ipv6'
        @type  mode:  str
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_route()
        @endcode
        """
        pass

    @abstractmethod
    def configure_arp(self, garp=None, refresh_period=None, delay=None, secure_mode=None, age_time=None, attemptes=None, arp_len=None):
        """
        @brief  Configure ARPConfig table
        @param garp:  AcceptGARP value. 'True'|'False'
        @type  garp:  str
        @param refresh_period:  RefreshPeriod value
        @type  refresh_period:  int
        @param delay:  RequestDelay value
        @type  delay:  int
        @param secure_mode:  SecureMode value. 'True'|'False'
        @type  secure_mode:  str
        @param age_time:  AgeTime value
        @type  age_time:  int
        @param attemptes:  NumAttempts value
        @type  attemptes:  int
        @param arp_len:  length value for ARP
        @type  arp_len:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_arp(garp='Enabled')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_arp_config(self):
        """
        @brief  Get ARPConfig table
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_arp_config()
        @endcode
        """
        pass

    @abstractmethod
    def create_arp(self, ip, mac, network, mode='arp'):
        """
        @brief  Create StaticARP record
        @param ip:  ARP ip address
        @type  ip:  str
        @param mac:  ARP mac address
        @type  mac:  str
        @param network:  RouteInterface network
        @type  network:  str
        @param mode:  'arp' or 'ipv6 neigbor'
        @type  mode:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_arp('10.0.5.102', '00:00:22:22:22', '10.0.5.101/24')
        @endcode
        """
        pass

    @abstractmethod
    def delete_arp(self, ip, network, mode='arp'):
        """
        @brief  Delete ARP record
        @param ip:  ARP ip address
        @type  ip:  str
        @param network:  RouteInterface network
        @type  network:  str
        @param mode:  'arp' or 'ipv6 neigbor'
        @type  mode:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.delete_arp('10.0.5.102', '10.0.5.101/24')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_arp(self, mode='arp'):
        """
        @brief  Get ARP table
        @param mode:  'arp' or 'ipv6 neigbor'
        @type  mode:  str
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_arp()
        @endcode
        """
        pass

    @abstractmethod
    def create_static_route(self, ip, nexthop, network, distance=-1, mode='ip'):
        """
        @brief  Create StaticRoute record
        @param ip:  Route IP network
        @type  ip:  str
        @param nexthop:  Nexthop IP address
        @type  nexthop:  str
        @param network:  RouteInterface network
        @type  network:  str
        @param distance:  Route distance
        @type  distance:  int
        @param mode:  'ip' or 'ipv6'
        @type  mode:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_static_route('20.20.20.0/24', '10.0.5.102', '10.0.5.101/24')
        @endcode
        """
        pass

    @abstractmethod
    def delete_static_route(self, network):
        """
        @brief  Delete StaticRoute record
        @param network:  RouteInterface network
        @type  network:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.delete_static_route('10.0.5.101/24')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_static_route(self, mode='ip'):
        """
        @brief  Get StaticRoute table
        @param mode:  'ip' or 'ipv6'
        @type  mode:  str
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_static_route()
        @endcode
        """
        pass

    @abstractmethod
    def configure_ospf_router(self, **kwargs):
        """
        @brief  Configure OSPFRouter table
        @param  kwargs:  parameters to be modified:
                             "logAdjacencyChanges" - set logAdjacencyChanges value;
                             "routerId" - set routerId value.
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_ospf_router(routerId='1.1.1.1')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_ospf_router(self):
        """
        @brief  Get OSPFRouter table
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_ospf_router()
        @endcode
        """
        pass

    @abstractmethod
    def create_ospf_area(self, area, **kwargs):
        """
        @brief  Create OSPFAreas record
        @param area:  Area Id to be created
        @type  area:  int
        @param  kwargs:  parameters to be added
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_ospf_area("0.0.0.0")
        @endcode
        """
        pass

    @abstractmethod
    def get_table_ospf_area(self):
        """
        @brief  Get OSPFAreas table
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_ospf_area()
        @endcode
        """
        pass

    @abstractmethod
    def create_network_2_area(self, network, area, mode):
        """
        @brief  Create OSPFNetworks2Area record
        @param network:  RouteInterface network
        @type  network:  str
        @param area:  Area Id
        @type  area:  int
        @param mode:  Area mode
        @type  mode:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_network_2_area('10.0.5.101/24', "0.0.0.0", 'Disabled')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_network_2_area(self):
        """
        @brief  Get OSPFNetworks2Area table
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_network_2_area()
        @endcode
        """
        pass

    @abstractmethod
    def create_area_ranges(self, area, range_ip, range_mask, substitute_ip, substitute_mask):
        """
        @brief  Create OSPFAreas2Ranges record
        @param area:  Area Id
        @type  area:  int
        @param range_ip:  IP address
        @type  range_ip:  str
        @param range_mask:  mask
        @type  range_mask:  str
        @param substitute_ip:  IP address
        @type  substitute_ip:  str
        @param substitute_mask:  mask
        @type  substitute_mask:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_area_ranges("0.0.0.0", "10.0.2.0", "255.255.255.0", "11.0.2.0", "255.255.255.0")
        @endcode
        """
        pass

    @abstractmethod
    def get_table_area_ranges(self):
        """
        @brief  Get OSPFAreas2Ranges table
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_area_ranges()
        @endcode
        """
        pass

    @abstractmethod
    def create_route_redistribute(self, mode):
        """
        @brief  Create OSPFRouteRedistribute record
        @param mode:  redistribute mode
        @type  mode:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_route_redistribute("Static")
        @endcode
        """
        pass

    @abstractmethod
    def get_table_route_redistribute(self):
        """
        @brief  Get OSPFRouteRedistribute table
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_route_redistribute()
        @endcode
        """
        pass

    @abstractmethod
    def create_interface_md5_key(self, vlan, network, key_id, key):
        """
        @brief  Create OSPFInterfaceMD5Keys record
        @param vlan:  Vlan Id
        @type  vlan:  int
        @param network:  Route Interface network
        @type  network:  str
        @param key_id:  key Id
        @type  key_id:  int
        @param key:  key
        @type  key:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_interface_md5_key(10, "10.0.5.101/24", 1, "Key1")
        @endcode
        """
        pass

    @abstractmethod
    def get_table_interface_authentication(self):
        """
        @brief  Get OSPFInterfaceMD5Keys table
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_interface_authentication()
        @endcode
        """
        pass

    @abstractmethod
    def create_ospf_interface(self, vlan, network, dead_interval=40, hello_interval=5, network_type="Broadcast", hello_multiplier=3, minimal='Enabled',
                              priority=-1, retransmit_interval=-1):
        """
        @brief  Create OSPFInterface record
        @param vlan:  Vlan Id
        @type  vlan:  int
        @param network:  Route Interface network
        @type  network:  str
        @param dead_interval:  dead interval
        @type  dead_interval:  int
        @param hello_interval:  hello interval
        @type  hello_interval:  int
        @param network_type:  network type
        @type  network_type:  str
        @param hello_multiplier:  hello multiplier
        @type  hello_multiplier:  int
        @param minimal:  minimal
        @type  minimal:  str
        @param priority:  priority
        @type  priority:  int
        @param retransmit_interval:  retransmit interval
        @type  retransmit_interval:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_ospf_interface(vlan_id, "10.0.5.101/24", 40, 5, network_type='Broadcast', minimal='Enabled', priority=1, retransmit_interval=3)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_ospf_interface(self):
        """
        @brief  Get OSPFInterface table
        @rtype:  list[dict]
        @return  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_interface_authentication()
        @endcode
        """
        pass

    @abstractmethod
    def create_area_virtual_link(self, area, link):
        """
        @brief  Create OSPFInterface record
        @param area:  OSPF Area
        @type  area:  str
        @param link:  Virtual link IP
        @type  link:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_area_virtual_link("0.0.0.0", "1.1.1.2")
        @endcode
        """
        pass

# BGP configuration
    @abstractmethod
    def configure_bgp_router(self, asn=65501, enabled='Enabled'):
        """
        @brief  Modify BGPRouter record
        @param asn:  AS number
        @type  asn:  int
        @param enabled:  enabled status
        @type  enabled:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_bgp_router(asn=65501, enabled='Enabled')
        @endcode
        """
        pass

    @abstractmethod
    def create_bgp_neighbor_2_as(self, asn, ip, remote_as):
        """
        @brief  Create BGPNeighbor2As record
        @param asn:  AS number
        @type  asn:  int
        @param ip:  IP address
        @type  ip:  str
        @param remote_as:  Remote AS number
        @type  remote_as:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_bgp_neighbor_2_as(65501, '10.0.5.102', 65502)
        @endcode
        """
        pass

    @abstractmethod
    def create_bgp_neighbor(self, asn=65501, ip='192.168.0.1'):
        """
        @brief  Create BGPNeighbor record
        @param asn:  AS number
        @type  asn:  int
        @param ip:  IP address
        @type  ip:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_bgp_neighbor(asn=65501, ip='192.168.0.1')
        @endcode
        """
        pass

    @abstractmethod
    def create_bgp_neighbor_connection(self, asn=65501, ip='192.168.0.1', port=179):
        """
        @brief  Create BGPNeighborConnection record
        @param asn:  AS number
        @type  asn:  int
        @param ip:  IP address
        @type  ip:  str
        @param port:  connection port
        @type  port:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_bgp_neighbor_connection(asn=65501, ip='192.168.0.1', port=179)
        @endcode
        """
        pass

    @abstractmethod
    def create_bgp_bgp(self, asn=65501, router_id="1.1.1.1"):
        """
        @brief  Create BGPBgp record
        @param asn:  AS number
        @type  asn:  int
        @param router_id:  OSPF router Id
        @type  router_id:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_bgp_bgp(asn=65501, router_id="1.1.1.1")
        @endcode
        """
        pass

    @abstractmethod
    def create_bgp_peer_group(self, asn=65501, name="mypeergroup"):
        """
        @brief  Create BGPPeerGroups record
        @param asn:  AS number
        @type  asn:  int
        @param name:  peer group name
        @type  name:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_bgp_peer_group(65501, "test_name")
        @endcode
        """
        pass

    @abstractmethod
    def create_bgp_peer_group_member(self, asn=65501, name="mypeergroup", ip="12.1.0.2"):
        """
        @brief  Create BGPPeerGroupMembers record
        @param asn:  AS number
        @type  asn:  int
        @param name:  peer group name
        @type  name:  str
        @param ip:  IP address
        @type  ip:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_bgp_peer_group_member(65501, "test_name", "12.1.0.2")
        @endcode
        """
        pass

    @abstractmethod
    def create_bgp_redistribute(self, asn=65501, rtype="OSPF"):
        """
        @brief  Create BGPRedistribute record
        @param asn:  AS number
        @type  asn:  int
        @param rtype:  redistribute type
        @type  rtype:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_bgp_redistribute(65501, "OSPF")
        @endcode
        """
        pass

    @abstractmethod
    def create_bgp_network(self, asn=65501, ip='10.0.0.0', mask='255.255.255.0', route_map='routeMap'):
        """
        @brief  Create BGPNetwork record
        @param asn:  AS number
        @type  asn:  int
        @param ip:  IP address
        @type  ip:  str
        @param mask:  IP address mask
        @type  mask:  str
        @param route_map:  route map name
        @type  route_map:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_bgp_network(asn=65501, ip='10.0.0.0', mask='255.255.255.0', route_map='routeMap')
        @endcode
        """
        pass

    @abstractmethod
    def create_bgp_aggregate_address(self, asn=65501, ip='22.10.10.0', mask='255.255.255.0'):
        """
        @brief  Create BGPAggregateAddress record
        @param asn:  AS number
        @type  asn:  int
        @param ip:  IP address
        @type  ip:  str
        @param mask:  IP address mask
        @type  mask:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_bgp_aggregate_address(asn=65501, ip='10.0.0.0', mask='255.255.255.0')
        @endcode
        """
        pass

    @abstractmethod
    def create_bgp_confederation_peers(self, asn=65501, peers=70000):
        """
        @brief  Create BGPBgpConfederationPeers record
        @param asn:  AS number
        @type  asn:  int
        @param peers:  peers number
        @type  peers:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_bgp_confederation_peers(asn=65501, peers=70000)
        @endcode
        """
        pass

    @abstractmethod
    def create_bgp_distance_network(self, asn=65501, ip="40.0.0.0/24", mask='255.255.255.0', distance=100, route_map='routeMap'):
        """
        @brief  Create BGPDistanceNetwork record
        @param asn:  AS number
        @type  asn:  int
        @param ip:  IP address
        @type  ip:  str
        @param mask:  IP address mask
        @type  mask:  str
        @param distance:  IP address distance
        @type  distance:  int
        @param route_map:  route map name
        @type  route_map:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_bgp_distance_network(asn=65501, ip="40.0.0.0", mask='255.255.255.0', distance=100, route_map='routeMap')
        @endcode
        """
        pass

    @abstractmethod
    def create_bgp_distance_admin(self, asn=65501, ext_distance=100, int_distance=200, local_distance=50):
        """
        @brief  Create BGPDistanceAdmin record
        @param asn:  AS number
        @type  asn:  int
        @param ext_distance:  external distance
        @type  ext_distance:  int
        @param int_distance:  internal distance
        @type  int_distance:  int
        @param local_distance:  local distance
        @type  local_distance:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_bgp_distance_admin(asn=65501, ext_distance=100, int_distance=200, local_distance=50)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_bgp_neighbor(self):
        """
        @brief  Get BGPNeighbour table
        @rtype:  list[dict]
        @return  table
        @par Example:
        @code
        env.switch[1].ui.get_table_bgp_neighbor()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_bgp_neighbor_connections(self):
        """
        @brief  Get BGPNeighborConnection table
        @rtype:  list[dict]
        @return  table
        @par Example:
        @code
        env.switch[1].ui.get_table_bgp_neighbor_connections()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_bgp_aggregate_address(self):
        """
        @brief  Get BGPAggregateAddress table
        @rtype:  list[dict]
        @return  table
        @par Example:
        @code
        env.switch[1].ui.get_table_bgp_aggregate_address()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_bgp_confederation_peers(self):
        """
        @brief  Get BGPBgpConfederationPeers table
        @rtype:  list[dict]
        @return  table
        @par Example:
        @code
        env.switch[1].ui.get_table_bgp_confederation_peers()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_bgp_distance_admin(self):
        """
        @brief  Get BGPDistanceAdmin table
        @rtype:  list[dict]
        @return  table
        @par Example:
        @code
        env.switch[1].ui.get_table_bgp_distance_admin()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_bgp_distance_network(self):
        """
        @brief  Get BGPDistanceNetwork table
        @rtype:  list[dict]
        @return  table
        @par Example:
        @code
        env.switch[1].ui.get_table_bgp_distance_network()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_bgp_network(self):
        """
        @brief  Get BGPNetwork table
        @rtype:  list[dict]
        @return  table
        @par Example:
        @code
        env.switch[1].ui.get_table_bgp_network()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_bgp_peer_group_members(self):
        """
        @brief  Get BGPPeerGroupMembers table
        @rtype:  list[dict]
        @return  table
        @par Example:
        @code
        env.switch[1].ui.get_table_bgp_peer_group_members()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_bgp_peer_groups(self):
        """
        @brief  Get BGPPeerGroups table
        @rtype:  list[dict]
        @return  table
        @par Example:
        @code
        env.switch[1].ui.get_table_bgp_peer_groups()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_bgp_redistribute(self):
        """
        @brief  Get BGPRedistribute table
        @rtype:  list[dict]
        @return:  table
        @par Example:
        @code
        env.switch[1].ui.get_table_bgp_redistribute()
        @endcode
        """
        pass

# HWOA Flow configuration
    @abstractmethod
    def create_match_api_tcam_subtable(self, source_id, table_id, table_name,
                                       max_table_entries, match_field_type_pairs,
                                       actions):
        """
        @brief  create a sub-table of tcam
        @param  source_id:  the source id in the tcam table.
        @type  source_id:  int
        @param  table_id:  a given table id.
                           If switchd running, table id starts from 5
                           If matchd is running, table id starts from 4
        @type  table_id:  int
        @param  table_name:  a given table name.
        @type  table_name:  str
        @param  max_table_entries:  maximum number of flows can be set.
        @type  max_table_entries:  int
        @param  match_field_type_pairs:  list of given match field with match type
        @type  match_field_type_pairs:  list[tuple(str, str)]
        @param  actions:  list of actions for configurable matches
        @type  actions:  list[str]
        """
        pass

    @abstractmethod
    def create_match_api_rule(self, prio_id, handle_id, table_id,
                              match_field_value_mask_list, action, action_value=None):
        """
        @brief set a rule into the table
        @param  prio_id:  Higher id has a higher priority.
        @type  prio_id:  int
        @param  handle_id:  handle for match.
        @type  handle_id:  int
        @param  table_id:  the source table id where match to be set.
        @type  table_id:  int
        @param  match_field_value_mask_list:  field with match field, value and mask.
        @type  match_field_value_mask_list:  list[tuple(str, str, str)]
        @param  action:  given action for source table
        @type  action:  str
        @raise  UIException:  for TypeError - Not enough arguments for format string
        @raise  UIException:  In case of Command execution Error reported in MatchAPI
        """
        pass

    @abstractmethod
    def get_table_match_api(self, table_id=None):
        """
        @brief  Lists the match api tables
        @param  table_id:  table ID
        @type  int
        @rtype:  list[dict]
        """
        pass

    @abstractmethod
    def get_rules_match_api(self, table_id=None, handle_id=None):
        """
        @brief  Lists the match api rules of the table
        @params  table_id:  table ID (mandatory parameter)
        @type  table_id:  int
        @params  handle_id:  optional parameter
        @type  handle_id:   int
        @rtype:  list[dict]
        """
        pass

    @abstractmethod
    def delete_match_api_rule(self, handle_id, table_id):
        """
        @brief delete a rule from the table
        @param  handle_id:  handle for match.[MANDATORY]
        @type  handle_id:  int
        @param  table_id:  the source table id where match to be set.[MANDATORY]
        @type  table_id:  int
        """
        pass

    @abstractmethod
    def delete_match_api_tcam_subtable(self, source_id, table_id=0, table_name=None):
        """
        @brief  Destroy a sub-table of tcam
        @param  source_id:  the source id in the tcam table.[MANDATORY]
        @type  source_id:  int
        @param  table_id:  a given table id.[MANDATORY if table_name not specified]
        @type  table_id:  int
        @param  table_name:  a given table name.[MANDATORY if table_id not specified]
        @type  table_name:  str
        """
        pass

# OVS configuration
    @abstractmethod
    def create_ovs_bridge(self, bridge_name):
        """
        @brief  Create OvsBridges record
        @param bridge_name:  OVS bridge name
        @type  bridge_name:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_ovs_bridge('spp0')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_ovs_bridges(self):
        """
        @brief  Get OvsBridges table
        @rtype:  list[dict]
        @return:  table (list of dictionaries))
        @par Example:
        @code
        env.switch[1].ui.get_table_ovs_bridges()
        @endcode
        """
        pass

    @abstractmethod
    def delete_ovs_bridge(self):
        """
        @brief  Delete OVS Bridge
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.delete_ovs_bridge()
        @endcode
        """
        pass

    @abstractmethod
    def create_ovs_port(self, port, bridge_name):
        """
        @brief  Create OvsPorts record
        @param port:  port Id
        @type  port:  int
        @param bridge_name:  OVS bridge name
        @type  bridge_name:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_ovs_port(1, 'spp0')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_ovs_ports(self):
        """
        @brief  Get OvsPorts table
        @rtype:  list[dict]
        @return:  table (list of dictionaries))
        @par Example:
        @code
        env.switch[1].ui.get_table_ovs_ports()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_ovs_rules(self):
        """
        @brief  Get OvsFlowRules table
        @rtype:  list[dict]
        @return:  table (list of dictionaries))
        @par Example:
        @code
        env.switch[1].ui.get_table_ovs_rules()
        @endcode
        """
        pass

    @abstractmethod
    def create_ovs_bridge_controller(self, bridge_name, controller):
        """
        @brief  Create OvsControllers record
        @param bridge_name:  OVS bridge name
        @type  bridge_name:  str
        @param controller:  controller address
        @type  controller:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_ovs_bridge_controller("spp0", "tcp:127.0.0.1:6633")
        @endcode
        """
        pass

    @abstractmethod
    def get_table_ovs_controllers(self):
        """
        @brief  Get OvsControllers table
        @rtype:  list[dict]
        @return:  table (list of dictionaries))
        @par Example:
        @code
        env.switch[1].ui.get_table_ovs_controllers()
        @endcode
        """
        pass

    @abstractmethod
    def create_ovs_flow_rules(self, bridge_id, table_id, flow_id, priority, enabled):
        """
        @brief  Create OvsFlowRules table
        @param bridge_id:  OVS bridge ID
        @type  bridge_id:  int
        @param table_id:  Table ID
        @type  table_id:  int
        @param flow_id:  Flow ID
        @type  flow_id:  int
        @param priority:  Rule priority
        @type  priority:  int
        @param enabled:  Rule status
        @type  enabled:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_ovs_flow_rules(0, 0, 1, 2000, "Enabled")
        @endcode
        """
        pass

    @abstractmethod
    def delete_ovs_flow_rules(self, bridge_id, table_id, flow_id, priority):
        """
        @brief  Delete row from OvsFlowRules table
        @param bridge_id:  OVS bridge ID
        @type  bridge_id:  int
        @param table_id:  Table ID
        @type  table_id:  int
        @param flow_id:  Flow ID
        @type  flow_id:  int
        @param priority:  Rule priority
        @type  priority:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.delete_ovs_flow_rules(bridgeId, tableId, flowId, priority)
        @endcode
        """
        pass

    @abstractmethod
    def configure_ovs_resources(self, **kwargs):
        """
        @brief  Configure OvsResources table
        @param kwargs:  parameters to be configured:
                            "controllerRateLimit";
                            "vlansLimit";
                            "untaggedVlan";
                            "rulesLimit".
        @type  kwargs:  dict
        @return:  None

        @par Example:
        @code
        env.switch[1].ui.configure_ovs_resources(rulesLimit=2000)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_ovs_flow_actions(self):
        """
        @brief  Get OvsFlowActions table
        @rtype:  list[dict]
        @return:  table (list of dictionaries))
        @par Example:
        @code
        env.switch[1].ui.get_table_ovs_flow_actions()
        @endcode
        """
        pass

    @abstractmethod
    def create_ovs_flow_actions(self, bridge_id, table_id, flow_id, action, param, priority=2000):
        """
        @brief  Add row to OvsFlowActions table
        @param bridge_id:  OVS bridge ID
        @type  bridge_id:  int
        @param table_id:  Table ID
        @type  table_id:  int
        @param flow_id:  Flow ID
        @type  flow_id:  int
        @param priority:  Rule priority
        @type  priority:  int
        @param action:  Action name
        @type  action:  str
        @param param:  Action parameter
        @type  param:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_ovs_flow_actions(0, 0, 1, 'Output', '25')
        @endcode
        """
        pass

    @abstractmethod
    def delete_ovs_flow_actions(self, bridge_id, table_id, flow_id, action, priority=2000):
        """
        @brief  Delete row from OvsFlowActions table
        @param bridge_id:  OVS bridge ID
        @type  bridge_id:  int
        @param table_id:  Table ID
        @type  table_id:  int
        @param flow_id:  Flow ID
        @type  flow_id:  int
        @param priority:  Rule priority
        @type  priority:  int
        @param action:  Action name
        @type  action:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.delete_ovs_flow_actions(0, 0, 1, 'Output')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_ovs_flow_qualifiers(self):
        """
        @brief  Get OvsFlowQualifiers table
        @rtype:  list[dict]
        @return:  table (list of dictionaries))
        @par Example:
        @code
        env.switch[1].ui.get_table_ovs_flow_qualifiers()
        @endcode
        """
        pass

    @abstractmethod
    def create_ovs_flow_qualifiers(self, bridge_id, table_id, flow_id, field, data, priority=2000):
        """
        @brief  Add row to OvsFlowQualifiers table
        @param bridge_id:  OVS bridge ID
        @type  bridge_id:  int
        @param table_id:  Table ID
        @type  table_id:  int
        @param flow_id:  Flow ID
        @type  flow_id:  int
        @param priority:  Rule priority
        @type  priority:  int
        @param field:  Expression name
        @type  field:  str
        @param data:  Expression data
        @type  data:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_ovs_flow_qualifiers(0, 0, i, 'EthSrc', '00:00:00:00:00:01')
        @endcode
        """
        pass

    @abstractmethod
    def delete_ovs_flow_qualifiers(self, bridge_id, table_id, flow_id, field, priority=2000):
        """
        @brief  Delete row from OvsFlowQualifiers table
        @param bridge_id:  OVS bridge ID
        @type  bridge_id:  int
        @param table_id:  Table ID
        @type  table_id:  int
        @param flow_id:  Flow ID
        @type  flow_id:  int
        @param priority:  Rule priority
        @type  priority:  int
        @param field:  Expression name
        @type  field:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.delete_ovs_flow_qualifiers(bridgeId, tableId, flowId, field)
        @endcode
        """
        pass

# LLDP configuration

    @abstractmethod
    def configure_global_lldp_parameters(self, **kwargs):
        """
        @brief Configure global LLDP parameters
        @param  kwargs:  parameters to be modified:
                             'messageFastTx';
                             'messageTxHoldMultiplier';
                             'messageTxInterval';
                             'reinitDelay';
                             'txCreditMax';
                             'txFastInit';
                             'locChassisIdSubtype'.
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_global_lldp_parameters(messageTxInterval=5)
        @endcode
        """
        pass

    @abstractmethod
    def configure_lldp_ports(self, ports, **kwargs):
        """
        @brief Configure LldpPorts records
        @param ports:  list of ports
        @type  ports:  list[int]
        @param  kwargs:  parameters to be modified:
                             'adminStatus';
                             'tlvManAddrTxEnable';
                             'tlvPortDescTxEnable';
                             'tlvSysCapTxEnable';
                             'tlvSysDescTxEnable';
                             'tlvSysNameTxEnable'.
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_lldp_ports([1, 2], adminStatus='Disabled')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_lldp(self, param=None):
        """
        @brief  Get Lldp table
        @param param:  parameter name (optional)
        @type  param:  str
        @rtype:  list[dict]|int|str
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_lldp()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_lldp_ports(self, port=None, param=None):
        """
        @brief  Get LldpPorts table
        @param port:  port Id (optional)
        @type  port:  int
        @param param:  parameter name (optional)
        @type  param:  str
        @rtype:  list[dict]|int|str
        @return:  table (list of dictionaries) or value
        @par Example:
        @code
        env.switch[1].ui.get_table_lldp_ports(1)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_lldp_ports_stats(self, port=None, param=None):
        """
        @brief  Get LldpPorts table statistics
        @param port:  port Id (optional)
        @type  port:  int
        @param param:  parameter name (optional)
        @type  param:  str
        @rtype:  list[dict]|int|str
        @return:  table (list of dictionaries) or value
        @par Example:
        @code
        env.switch[1].ui.get_table_lldp_ports_stats(1)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_lldp_remotes(self, port=None):
        """
        @brief  Get LldpRemotes table
        @param port:  port Id (optional)
        @type  port:  int
        @rtype:  list[dict]
        @return:  table (list of dictionaries) or value
        @par Example:
        @code
        env.switch[1].ui.get_table_lldp_remotes(1)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_remotes_mgmt_addresses(self, port=None):
        """
        @brief  Get LldpRemotesMgmtAddresses table
        @param port:  port Id (optional)
        @type  port:  int
        @rtype:  list[dict]
        @return:  table (list of dictionaries) or value
        @par Example:
        @code
        env.switch[1].ui.get_table_remotes_mgmt_addresses(1)
        @endcode
        """
        pass

    @abstractmethod
    def disable_lldp_on_device_ports(self, ports=None):
        """
        @brief  Disable Lldp on device ports (if port=None Lldp should be disabled on all ports)
        @param ports:  list of ports
        @type  ports:  list[int]
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.disable_lldp_on_device_ports()
        @endcode
        """
        pass

# DCBX configuration

    @abstractmethod
    def set_dcb_admin_mode(self, ports, mode='Enabled'):
        """
        @brief Enable/Disable DCB on ports
        @param ports:  list of ports
        @type  ports:  list[int]
        @param mode:  "Enabled" or 'Disabled'
        @type  mode:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.set_dcb_admin_mode([1, 2], "Enabled")
        @endcode
        """
        pass

    @abstractmethod
    def enable_dcbx_tlv_transmission(self, ports, dcbx_tlvs="all", mode="Enabled"):
        """
        @brief Enable/Disable the transmission of all Type-Length-Value messages
        @param ports:  list of ports
        @type  ports:  list[int]
        @param dcbx_tlvs:  TLV message types
        @type  dcbx_tlvs:  str
        @param mode:  "Enabled" or 'Disabled'
        @type  mode:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.enable_dcbx_tlv_transmission([1, 2], dcbx_tlvs="all", mode="Enabled")
        @endcode
        """
        pass

    @abstractmethod
    def get_table_dcbx_ports(self, port=None, param=None):
        """
        @brief  Get DcbxPorts table
        @param port:  port Id (optional)
        @type  port:  int
        @param param:  parameter name (optional)
        @type  param:  str
        @rtype:  list[dict]
        @return:  table (list of dictionaries) or value
        @par Example:
        @code
        env.switch[1].ui.get_table_dcbx_ports()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_dcbx_app_remote(self, port=None):
        """
        @brief  Get DcbxAppRemotes table
        @param port:  port Id (optional)
        @type  port:  int
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_dcbx_app_remote()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_dcbx_app_ports(self, table_type="Admin", port=None):
        """
        @brief  Get DcbxAppPorts* table
        @param table_type:  "Admin", "Local"
        @type  table_type:  str
        @param port:  port Id (optional)
        @type  port:  int
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_dcbx_app_ports("Admin", 1)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_dcbx_app_maps(self, table_type="Admin", port=None):
        """
        @brief  Get DcbxAppMaps* table
        @param table_type:  "Admin", "Local" or "Remote"
        @type  table_type:  str
        @param port:  port Id (optional)
        @type  port:  int
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_dcbx_app_maps("Admin", 1)
        @endcode
        """
        pass

    @abstractmethod
    def configure_application_priority_rules(self, ports, app_prio_rules, delete_params=False, update_params=False):
        """
        @brief Configure Application Priority rules
        @param ports:  list of ports
        @type  ports:  list[int]
        @param app_prio_rules:  list of rules dictionaries
        @type  app_prio_rules:  list[dict]
        @param delete_params: if delete specified params or not
        @type delete_params: bool
        @param update_params: if update specified params or not
        @type update_params: bool
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_application_priority_rules([1, 2], [{"selector": 1, "protocol": 2, "priority":1}, ])
        @endcode
        """
        pass

    @abstractmethod
    def configure_dcbx_ets(self, ports, **kwargs):
        """
        @brief Configure DCBx ETS Conf/Reco parameter for ports list
        @param ports:  list of ports
        @type  ports:  list[int]
        @param  kwargs:  parameters to be modified:
                             "willing";
                             "cbs";
                             "maxTCs";
                             "confBandwidth";
                             "confPriorityAssignment";
                             "confAlgorithm";
                             "recoBandwidth";
                             "recoPriorityAssignment";
                             "recoAlgorithm".
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_dcbx_ets([1, 2], confBandwidth=100)
        @endcode
        """
        pass

    @abstractmethod
    def configure_dcbx_cn(self, ports, **kwargs):
        """
        @brief Configure DCBx CN parameter for the ports list
        @param ports:  list of ports
        @type  ports:  list[int]
        @param  kwargs:  parameters to be modified:
                             "cnpvSupported";
                             "cnpvReady".
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_dcbx_cn([1, 2], cnpvSupported='Enabled')
        @endcode
        """
        pass

    @abstractmethod
    def configure_dcbx_pfc(self, ports, **kwargs):
        """
        @brief Configure DCBx PFC parameter for the ports list
        @param ports:  list of ports
        @type  ports:  list[int]
        @param  kwargs:  parameters to be modified:
                             "mbc";
                             "enabled";
                             "willing".
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_dcbx_pfc([1, 2])
        @endcode
        """
        pass

    @abstractmethod
    def configure_dcbx_app(self, ports, **kwargs):
        """
        @brief Configure DCBx APP parameter for the ports list
        @param ports:  list of ports
        @type  ports:  list[int]
        @param  kwargs:  parameters to be modified:
                             "willing".
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_dcbx_app([1, 2])
        @endcode
        """
        pass

    @abstractmethod
    def get_table_dcbx_remotes(self, port=None, param=None):
        """
        @brief  Get DcbxRemotes* table
        @param port:  port Id (optional)
        @type  port:  int
        @param param:  parameter name (optional)
        @type  param:  str
        @rtype:  list[dict]|int|str
        @return:  table (list of dictionaries) or value
        @par Example:
        @code
        env.switch[1].ui.get_table_dcbx_remotes(1)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_dcbx_pfc(self, table_type="Local", port=None):
        """
        @brief  Get DcbxRemotes* table
        @param port:  port Id (optional)
        @type  port:  int
        @param table_type:  Table types "Admin"| "Local"| "Remote"
        @type  table_type:  str
        @rtype:  list[dict]|int|str
        @return:  table (list of dictionaries) or value
        @par Example:
        @code
        env.switch[1].ui.get_table_dcbx_pfc()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_dcbx_ets_ports(self, table_type='Admin', port=None):
        """
        @brief  Get DcbxEtsPorts* table
        @param port:  port Id (optional)
        @type  port:  int
        @param table_type:  Table types "Admin"| "Local"
        @type  table_type:  str
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_dcbx_ets_ports()
        @endcode
        """
        pass

# UFD configuration

    @abstractmethod
    def get_table_ufd_config(self):
        """
        @brief  Get UFDConfig table
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_ufd_config()
        @endcode
        """
        pass

    @abstractmethod
    def configure_ufd(self, enable='Enabled', hold_on_time=None):
        """
        @brief  Modify UFDConfig table
        @param enable:  Enable or disable UFD
        @type  enable:  str
        @param hold_on_time:  hold on time
        @type  hold_on_time:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_ufd(enable='Enabled')
        @endcode
        """
        pass

    @abstractmethod
    def create_ufd_group(self, group_id, threshold=None, enable='Enabled'):
        """
        @brief  Create UFDGroups record
        @param group_id:  UFD group ID
        @type  group_id:  int
        @param threshold:  group threshold
        @type  threshold:  int
        @param enable:  Enable or disable UFD group
        @type  enable:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_ufd_group(1)
        @endcode
        """
        pass

    @abstractmethod
    def modify_ufd_group(self, group_id, threshold=None, enable=None):
        """
        @brief  Modify UFDGroups record
        @param group_id:  UFD group ID
        @type  group_id:  int
        @param threshold:  group threshold
        @type  threshold:  int
        @param enable:  Enable or disable UFD group
        @type  enable:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.modify_ufd_group(1, enable='Disabled')
        @endcode
        """
        pass

    @abstractmethod
    def delete_ufd_group(self, group_id):
        """
        @brief  Delete UFDGroups record
        @param group_id:  UFD group ID
        @type  group_id:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.delete_ufd_group(2)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_ufd_groups(self):
        """
        @brief  Get UFDGroups table
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_ufd_groups()
        @endcode
        """
        pass

    @abstractmethod
    def create_ufd_ports(self, ports, port_type, group_id):
        """
        @brief  Create UFDPorts2Groups record
        @param ports:  list of ports
        @type  ports:  list[int]
        @param port_type:  type of port
        @type  port_type:  str
        @param group_id:  UFD group Id
        @type  group_id:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_ufd_ports([1, ], 'LtM' 2)
        @endcode
        """
        pass

    @abstractmethod
    def delete_ufd_ports(self, ports, port_type, group_id):
        """
        @brief  Delete UFDPorts2Groups record
        @param ports:  list of ports
        @type  ports:  list[int]
        @param port_type:  type of port
        @type  port_type:  str
        @param group_id:  UFD group Id
        @type  group_id:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.delete_ufd_ports([1, ], 'LtM' 2)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_ufd_ports(self):
        """
        @brief  Get UFDPorts2Groups table
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_ufd_ports()
        @endcode
        """
        pass

# QinQ configuration

    @abstractmethod
    def configure_qinq_ports(self, ports, **kwargs):
        """
        @brief Configure QinQ Ports
        @param ports:  list of ports
        @type  ports:  list[int]
        @param  kwargs:  parameters to be modified:
                             "mode";
                             "tpid".
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_qinq_ports([1, ], tpid=2)
        @endcode
        """
        pass

    @abstractmethod
    def configure_qinq_vlan_stacking(self, ports, provider_vlan_id, provider_vlan_priority):
        """
        @brief Configure QinQVlanStacking
        @param ports:  list of ports
        @type  ports:  list[int]
        @param provider_vlan_id:  provider vlan Id
        @type  provider_vlan_id:  int
        @param provider_vlan_priority:  provider vlan priority
        @type  provider_vlan_priority:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_qinq_vlan_stacking([1, ], 2, 7)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_qinq_vlan_stacking(self):
        """
        @brief  Get QinQVlanStacking table
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_qinq_vlan_stacking()
        @endcode
        """
        pass

    @abstractmethod
    def configure_qinq_vlan_mapping(self, ports, customer_vlan_id, customer_vlan_priority, provider_vlan_id, provider_vlan_priority):
        """
        @brief Configure QinQCustomerVlanMapping and QinQProviderVlanMapping
        @param ports:  list of ports
        @type  ports:  list[int]
        @param customer_vlan_id:  customer vlan Id
        @type  customer_vlan_id:  int
        @param customer_vlan_priority:  customer vlan priority
        @type  customer_vlan_priority:  int
        @param provider_vlan_id:  provider vlan Id
        @type  provider_vlan_id:  int
        @param provider_vlan_priority:  provider vlan priority
        @type  provider_vlan_priority:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_qinq_vlan_mapping([1, ], 2, 7, 5, 6)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_qinq_customer_vlan_mapping(self):
        """
        @brief Get QinQCustomerVlanMapping table
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_qinq_customer_vlan_mapping()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_qinq_provider_vlan_mapping(self):
        """
        @brief Get QinQProviderVlanMapping table
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_qinq_provider_vlan_mapping()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_qinq_ports(self, port=None, param=None):
        """
        @brief Get QinQPorts table
        @param port:  port Id (optional)
        @type  port:  int
        @param param:  parameter name (optional)
        @type  param:  str
        @rtype:  list[dict]|int|str
        @return:  table (list of dictionaries) or value
        @par Example:
        @code
        env.switch[1].ui.get_table_qinq_ports()
        @endcode
        """
        pass

# Errdisable configuration

    @abstractmethod
    def get_table_errdisable_errors_config(self, app_name=None, app_error=None):
        """
        @brief Get ErrdisableErrorsConfig table
        @param app_name:  application name
        @type  app_name:  str
        @param app_error:  application error
        @type  app_error:  str
        @rtype:  list[dict]|str
        @return:  table (list of dictionaries) or value
        @par Example:
        @code
        env.switch[1].ui.get_table_errdisable_errors_config()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_errdisable_config(self):
        """
        @brief Get ErrdisableConfig table
        @rtype:  list[dict]
        @return:  table (list of dictionaries)
        @par Example:
        @code
        env.switch[1].ui.get_table_errdisable_config()
        @endcode
        """
        pass

    @abstractmethod
    def modify_errdisable_errors_config(self, detect=None, recovery=None, app_name=None, app_error=None):
        """
        @brief Configure ErrdisableErrorsConfig table
        @param detect:  detect status
        @type  detect:  str
        @param recovery:  recovery status
        @type  recovery:  str
        @param app_name:  application name
        @type  app_name:  str
        @param app_error:  application error
        @type  app_error:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.modify_errdisable_errors_config(detect="Enabled", app_name='L2UfdControlApp', app_error='ufd')
        @endcode
        """
        pass

    @abstractmethod
    def modify_errdisable_config(self, interval=None):
        """
        @brief Configure ErrdisableConfig table
        @param interval:  recovery interval
        @type  interval:  int
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.modify_errdisable_config(10)
        @endcode
        """
        pass

    @abstractmethod
    def get_errdisable_ports(self, port=None, app_name=None, app_error=None, param=None):
        """
        @brief Get ErrdisablePorts table
        @param port:  port Id (optional)
        @type  port:  int
        @param app_name:  application name (optional)
        @type  app_name:  str
        @param app_error:  application error (optional)
        @type  app_error:  str
        @param param:  parameter name (optional)
        @type  param:  str
        @rtype:  list[dict]|int|str
        @return:  table (list of dictionaries) or value
        @par Example:
        @code
        env.switch[1].ui.get_errdisable_ports()
        @endcode
        """
        pass

# Mirroring configuration

    @abstractmethod
    def create_mirror_session(self, port, target, mode):
        """
        @brief Configure PortsMirroring table
        @param port:  source port Id
        @type  port:  int
        @param target:  target port Id
        @type  target:  int
        @param mode:  mirroring mode
        @type  mode:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_mirror_session(1, 2, 'Redirect')
        @endcode
        """
        pass

    @abstractmethod
    def get_mirroring_sessions(self):
        """
        @brief Get PortsMirroring table
        @rtype:  list[dict]|int|str
        @return:  table (list of dictionaries) or value
        @par Example:
        @code
        env.switch[1].ui.get_mirroring_sessions()
        @endcode
        """
        pass

    @abstractmethod
    def delete_mirroring_session(self, port, target, mode):
        """
        @brief Delete mirroring session from the PortsMirroring table
        @param port:  source port Id
        @type  port:  int
        @param target:  target port Id
        @type  target:  int
        @param mode:  mirroring mode
        @type  mode:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.delete_mirroring_session(1, 2, 'Redirect')
        @endcode
        """
        pass

# DHCP Relay configuration

    @abstractmethod
    def create_dhcp_relay(self, iface_name='global', server_ip=None, fwd_iface_name=None):
        """
        @brief  Configure DhcpRelayAdmin or DhcpRelayV6Admin table
        @param iface_name:  VLAN inteface name
        @type  iface_name:  str
        @param server_ip:  DHCP Server IP address
        @type  server_ip:  str
        @param fwd_iface_name:  VLAN forward interface name (for IPv6 config only)
        @type  fwd_iface_name:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_dhcp_relay(iface_name='global', server_ip='10.10.0.2')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_dhcp_relay(self, dhcp_relay_ipv6=False):
        """
        @brief  Return DhcpRelayAdmin or DhcpRelayV6Admin table
        @param dhcp_relay_ipv6:  is IPv6 config defined
        @type  dhcp_relay_ipv6:  bool
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.get_table_dhcp_relay(dhcp_relay_ipv6=False)
        @endcode
        """
        pass

# VxLAN configuration

    @abstractmethod
    def configure_tunneling_global(self, **kwargs):
        """
        @brief  Configure TunnelingGlobalAdmin table
        @param  kwargs:  parameters to be modified:
                             "vnTag";
                             "vxlanInnerVlanProcessing";
                             "mode",
                             "vxlanDestUDPPort".
        @type  kwargs:  dict
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.configure_tunneling_global()
        @endcode
        """
        pass

    @abstractmethod
    def create_tunnels(self, tunnel_id=None, destination_ip=None, vrf=0, encap_type=None):
        """
        @brief  Configure TunnelsAdmin table
        @param tunnel_id:  Tunnel ID
        @type  tunnel_id:  int
        @param destination_ip:  Destination IP address
        @type  destination_ip:  str
        @param vrf:  Tunnel VRF
        @type  vrf:  int
        @param encap_type:  Tunnel encapsulation type
        @type  encap_type: str
        @return:  None
        @par Example:
        @code
        env.switch[1].ui.create_tunnels(tunnel_id=records_count, destination_ip=ip_list, encap_type='VXLAN')
        @endcode
        """
        pass

    @abstractmethod
    def get_table_tunnels_admin(self):
        """
        @brief  Return TunnelsAdmin table
        @rtype:  list[dict]
        @return  table
        @par Example:
        @code
        env.switch[1].ui.get_table_tunnels_admin()
        @endcode
        """
        pass
