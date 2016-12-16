"""
@copyright Copyright (c) 2015 - 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  linux_host_interface.py

@summary  LinuxHostInteface class
"""

from abc import abstractmethod
# from abc import ABCMeta


class LinuxHostInterface(object):
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

    @abstractmethod
    def configure_arp(self, garp=None, refresh_period=None, delay=None, secure_mode=None, age_time=None, attemptes=None):
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
    def configure_application_priority_rules(self, ports, app_prio_rules):
        """
        @brief Configure Application Priority rules
        @param ports:  list of ports
        @type  ports:  list[int]
        @param app_prio_rules:  list of rules dictionaries
        @type  app_prio_rules:  list[dict]
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

# Netns functionality
    @abstractmethod
    def create_namespace(self, name):
        """
        @brief  Create network namespace
        @param name: netns name
        @type  name: str
        """
        pass

    @abstractmethod
    def enter_namespace(self, name):
        """
        @brief  Add netns prefix to the command
        @param name: netns name
        @type  name: str
        """
        pass

    @abstractmethod
    def exit_namespace(self):
        """
        @brief  Remove netns prefix from the command
        """
        pass

    @abstractmethod
    def delete_namespace(self, name):
        """
        @brief  Delete network namespace
        @param name: netns name
        @type  name: str
        """
        pass

# Work with files and folder
    @abstractmethod
    def create_folder(self, name):
        """
        @brief  Create folder
        @param name: folder name
        @type  name: str
        """
        pass

    @abstractmethod
    def delete_folder(self, name):
        """
        @brief  Delete folder
        @param name: folder name
        @type  name: str
        """
        pass
