# Copyright (c) 2015 - 2017, Intel Corporation.
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

"""``linux_host_interface.py``

`LinuxHostInteface class`

"""

from abc import abstractmethod
# from abc import ABCMeta


class LinuxHostInterface(object):
    # disable this for now so we can instantiate subclasses without
    # all the abstract methods defined.  Re-enable once implemented
    # __metaclass__ = ABCMeta
    """Abstract class to store UI wrapper interface methods.

    """

    @abstractmethod
    def connect(self):
        """Mandatory method for UI wrapper connection.

        """
        pass

    @abstractmethod
    def disconnect(self):
        """Mandatory method for UI wrapper disconnection.

        """
        pass

    @abstractmethod
    def restart(self):
        """Perform device reboot via User Interface.

        """
        pass

# Clear Config
    @abstractmethod
    def clear_config(self):
        """Clear device configuration.

        """
        pass

    @abstractmethod
    def save_config(self):
        """Save device configuration.

        """
        pass

    @abstractmethod
    def restore_config(self):
        """Restore device configuration.

        """
        pass

# Application Check
    @abstractmethod
    def check_device_state(self):
        """Attempts to connect to the shell retries number of times.

        """

# Platform
    @abstractmethod
    def get_table_platform(self):
        """Get 'Platform' table.

        """
        pass

# Syslog configuration
    @abstractmethod
    def create_syslog(self, syslog_proto, syslog_ip, syslog_port, syslog_localport, syslog_transport, syslog_facility, syslog_severity):
        """Configure Syslog settings.

        Args:
            syslog_proto(str):  syslog host protocol Udp | Tcp
            syslog_ip(str):  syslog host IP address
            syslog_port(int):  syslog host port
            syslog_localport(int):  syslog host local port
            syslog_transport(str):  syslog host transport
            syslog_facility(int):  syslog host facility
            syslog_severity(str):  syslog host severity

        """
        pass

    @abstractmethod
    def logs_add_message(self, level, message):
        """Add message into device logs.

        Args:
            level(str):  log severity
            message(str):  log message

        """
        pass

# Temperature information
    @abstractmethod
    def get_temperature(self):
        """Get temperature from Sensors table.

        Returns:
            dict:  CPU temperature information (Sensors table)

        """
        pass

# System information
    @abstractmethod
    def get_memory(self, mem_type='usedMemory'):
        """Returns free cached/buffered memory from switch.

        Args:
            mem_type(str):  memory type

        Returns:
            float:  memory size

        """
        pass

    @abstractmethod
    def get_cpu(self):
        """Returns cpu utilization from switch.

        Returns:
            float:  cpu utilization from switch

        """
        pass

# Applications configuration
    @abstractmethod
    def get_table_applications(self):
        """Get 'Applications' table.

        Returns:
            list[dict]:  'Applications' table

        """
        pass

    @abstractmethod
    def configure_application(self, application, loglevel):
        """Set application loglevel.

        Args:
            application(str):  Application Name.
            loglevel(str):  Application loglevel.

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_application('L1PortControlApp', 'Debug')

        """
        pass

# Ports configuration
    @abstractmethod
    def set_all_ports_admin_disabled(self):
        """Set all ports into admin Down state.

        Returns:
            None

        Notes:
            This method is used in helpers.set_all_ports_admin_disabled() for all functional test case.

        """
        pass

    @abstractmethod
    def wait_all_ports_admin_disabled(self):
        """Wait for all ports into admin Down state.

        Returns:
            None

        Notes:
            This method is used in helpers.set_all_ports_admin_disabled() for all functional test case.

        """
        pass

    @abstractmethod
    def modify_ports(self, ports, **kwargs):
        """Modify records in 'Ports' table.

        Args:
            ports(list):  list of port IDs.
            kwargs(dict):  Parameters to be modified. Parameters names should be the same as in XMLRPC nb.Ports.set.* calls:
                             - "pvid" - set pvid value;
                             - "pvpt" - set pvpt value;
                             - "adminMode" - set adminMode value;
                             - "ingressFiltering" - set ingressFiltering value;
                             - "maxFrameSize" - set maxFrameSize value;
                             - "discardMode" - set discardMode value;
                             - "cutThrough" - set cutThrough value;
                             - "flowControl" - set flowControl value;
                             - "speed" - set speed value;
                             - "learnMode" - set learnMode value.

        Returns:
            None

        Examples::

            env.switch[1].ui.modify_ports([1, 2], adminMode='Down')

        """
        pass

    @abstractmethod
    def get_table_ports(self, ports=None, all_params=False):
        """Get 'Ports' table.

        Args:
            ports(list):  list of port IDs.
            all_params(bool):  get additional port properties

        Returns:
            list(dict): table (list of dictionaries)

        Notes:
            Return all table or information about particular ports.

        Examples::

            env.switch[1].ui.get_table_ports()
            env.switch[1].ui.get_table_ports([1, 2])

        """
        pass

# Flow Confrol configuration
    @abstractmethod
    def set_flow_control_type(self, ports=None, control_type=None):
        """Enable/disable sending/accepting pause frames.

        Args:
            ports(list): list of port IDs
            control_type(str): 'Rx', 'Tx', 'RxTx' and 'None'

        Returns:
            None

        Examples::

            env.switch[1].ui.set_flow_control([1, 2], 'RxTx')

        """
        pass

# Vlan configuration
    @abstractmethod
    def create_vlans(self, vlans=None):
        """Create new Vlans

        Args:
            vlans(list[int]):  list of vlans to be created.

        Returns:
            None

        Examples::

            env.switch[1].ui.create_vlans([2, 3])

        """
        pass

    @abstractmethod
    def delete_vlans(self, vlans=None):
        """Delete existing Vlans.

        Args:
            vlans(list[int]):  list of vlans to be deleted.

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_vlans([2, 3])

        """
        pass

    @abstractmethod
    def get_table_vlans(self):
        """Get 'Vlans' table.

        Returns:
            list(dict): table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_vlans()

        """
        pass

    @abstractmethod
    def create_vlan_ports(self, ports=None, vlans=None, tagged='Tagged'):
        """Create new Ports2Vlans records.

        Args:
            ports(list[int]):  list of ports to be added to Vlans.
            vlans(list[int] | set(int)):  list of vlans.
            tagged(str):  information about ports tagging state.

        Returns:
            None

        Examples::

            Port 1 will be added into the vlans 3 and 4 as Untagged and port 2 will be added into the vlans 3 and 4 as Untagged
            env.switch[1].ui.create_vlan_ports([1, 2], [3, 4], 'Untagged')

        """
        pass

    @abstractmethod
    def delete_vlan_ports(self, ports=None, vlans=None):
        def delete_vlan_ports(self, ports=None, vlans=None):
            """ Delete Vlan from port.

            Args:
                ports(list[int]):  list of ports.
                vlans(list[int]):  list of vlans.

            Returns:
                None

            Examples::

                Ports 1 and 2 will be removed from the vlan 3:
                env.switch[1].ui.delete_vlan_ports([1, 2], [3, ])

            """
        pass

    @abstractmethod
    def modify_vlan_ports(self, ports=None, vlans=None, tagged='Tagged'):
        """Modify Ports2Vlans records.

        Args:
            ports(list):  list of ports to be added to Vlans.
            vlans(list[int] | set(int)):  list of vlans.
            tagged(str):  information about ports tagging state.

        Returns:
            None

        Examples::

            Port 1 will be modified in the vlans 3 and 4 as Tagged
            env.switch[1].ui.create_vlan_ports([1, ], [3, 4], 'Tagged')

        """
        pass

    @abstractmethod
    def get_table_ports2vlans(self):
        """Get 'Ports2Vlans' table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ports2vlans()

        """
        pass

    @abstractmethod
    def get_table_fdb(self, table='Fdb'):
        """Get Fbd table.

        Args:
            table(str):  Fbd record type to be returned ('Fbd' or 'Static')

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_fdb()
            env.switch[1].ui.get_table_fdb('Static')

        """
        pass

    @abstractmethod
    def clear_table_fdb(self):
        """Clear Fdb table.

        Returns:
            None

        Examples::

            env.switch[1].ui.clear_table_fdb()

        """
        pass

# Statistics configuration
    @abstractmethod
    def map_stat_name(self, generic_name):
        """Get the UI specific stat name for given generic name.

        Args:
            generic_name(str): generic statistic name

        Returns:
            str: UI specific stat name

        """
        pass

    @abstractmethod
    def get_table_statistics(self, port=None, stat_name=None):
        """Get Statistics table.

        Args:
            port(str|int|None):  port Id to get info about ('cpu' or port id) (optional)
            stat_name(str):  name of statistics parameter (optional)

        Returns:
            list[dict]|int:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_statistics()
            env.switch[1].ui.get_table_statistics(port=1)
            env.switch[1].ui.get_table_statistics(port='cpu')

        """
        pass

    @abstractmethod
    def clear_statistics(self):
        """Clear Statistics.

        Returns:
            None

        Examples:

            env.switch[1].ui.clear_statistics()

        """
        pass

    @abstractmethod
    def configure_arp(self, garp=None, refresh_period=None, delay=None, secure_mode=None, age_time=None, attemptes=None):
        """Configure ARPConfig table.

        Args:
            garp(str):  AcceptGARP value. 'True'|'False'
            refresh_period(int):  RefreshPeriod value
            delay(int):  RequestDelay value
            secure_mode(str):  SecureMode value. 'True'|'False'
            age_time(int):  AgeTime value
            attemptes(int):  NumAttempts value

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_arp(garp='Enabled')

        """
        pass

    @abstractmethod
    def get_table_arp_config(self):
        """Get ARPConfig table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_arp_config()

        """
        pass

    @abstractmethod
    def create_arp(self, ip, mac, network, mode='arp'):
        """Create StaticARP record.

        Args:
            ip(str):  ARP ip address
            mac(str):  ARP mac address
            network(str):  RouteInterface network
            mode(str):  'arp' or 'ipv6 neigbor'

        Returns:
            None

        Examples::

            env.switch[1].ui.create_arp('10.0.5.102', '00:00:22:22:22', '10.0.5.101/24')

        """
        pass

    @abstractmethod
    def delete_arp(self, ip, network, mode='arp'):
        """Delete ARP record.

        Args:
            ip(str):  ARP ip address
            network(str):  RouteInterface network
            mode(str):  'arp' or 'ipv6 neigbor'

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_arp('10.0.5.102', '10.0.5.101/24')

        """
        pass

    @abstractmethod
    def get_table_arp(self, mode='arp'):
        """Get ARP table.

        Args:
            mode(str):  'arp' or 'ipv6 neigbor'

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_arp()

        """
        pass

    @abstractmethod
    def create_static_route(self, ip, nexthop, network, distance=-1, mode='ip'):
        """Create StaticRoute record.

        Args:
            ip(str):  Route IP network
            nexthop(str):  Nexthop IP address
            network(str):  RouteInterface network
            distance(int):  Route distance
            mode(str):  'ip' or 'ipv6'

        Returns:
            None

        Examples::

            env.switch[1].ui.create_static_route('20.20.20.0/24', '10.0.5.102', '10.0.5.101/24')

        """
        pass

    @abstractmethod
    def delete_static_route(self, network):
        """Delete StaticRoute record.

        Args:
            network(str):  RouteInterface network

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_static_route('10.0.5.101/24')

        """
        pass

    @abstractmethod
    def get_table_static_route(self, mode='ip'):
        """Get StaticRoute table.

        Args:
            mode(str):  'ip' or 'ipv6'

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_static_route()

        """
        pass

# HWOA Flow configuration
    @abstractmethod
    def create_match_api_tcam_subtable(self, source_id, table_id, table_name,
                                       max_table_entries, match_field_type_pairs,
                                       actions):
        """Create a sub-table of tcam.

        Args:
            source_id(int):  the source id in the tcam table.
            table_id(int):  a given table id.
                            If switchd running, table id starts from 5
                            If matchd is running, table id starts from 4
            table_name(str):  a given table name.
            max_table_entries(int):  maximum number of flows can be set.
            match_field_type_pairs(list[tuple(str, str)]):  list of given match field with match type
            actions(list[str]):  list of actions for configurable matches

        """
        pass

    @abstractmethod
    def create_match_api_rule(self, prio_id, handle_id, table_id,
                              match_field_value_mask_list, action, action_value=None):
        """Set a rule into the table.

        Args:
            prio_id(int):  Higher id has a higher priority.
            handle_id(int):  handle for match.
            table_id(int):  the source table id where match to be set.
            match_field_value_mask_list(list[tuple(str, str, str)]):  field with match field, value and mask.
            action(str):  given action for source table
            action_value(int): action value

        Raises:
            UIException:  for TypeError - Not enough arguments for format string
            UIException:  In case of Command execution Error reported in MatchAPI

        """
        pass

    @abstractmethod
    def get_table_match_api(self, table_id=None):
        """Lists the match api tables.

        Args:
            table_id(int):  table ID

        Returns:
            list[dict]

        """
        pass

    @abstractmethod
    def get_rules_match_api(self, table_id=None, handle_id=None):
        """Lists the match api rules of the table.

        Args:
            table_id(int):  table ID (mandatory parameter)
            handle_id(int):  optional parameter

        Returns:
            list[dict]

        """
        pass

    @abstractmethod
    def delete_match_api_rule(self, handle_id, table_id):
        """Delete a rule from the table.

        Args:
            handle_id(int):  handle for match.[MANDATORY]
            table_id(int):  the source table id where match to be set.[MANDATORY]

        """
        pass

    @abstractmethod
    def delete_match_api_tcam_subtable(self, source_id, table_id=0, table_name=None):
        """Destroy a sub-table of tcam.

        Args:
            source_id(int):  the source id in the tcam table.[MANDATORY]
            table_id(int):  a given table id.[MANDATORY if table_name not specified]
            table_name(str):  a given table name.[MANDATORY if table_id not specified]

        """
        pass
# LLDP configuration

    @abstractmethod
    def configure_global_lldp_parameters(self, **kwargs):
        """Configure global LLDP parameters.

        Args:
            **kwargs(dict):  parameters to be modified:
                             'messageFastTx';
                             'messageTxHoldMultiplier';
                             'messageTxInterval';
                             'reinitDelay';
                             'txCreditMax';
                             'txFastInit';
                             'locChassisIdSubtype'.

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_global_lldp_parameters(messageTxInterval=5)

        """
        pass

    @abstractmethod
    def configure_lldp_ports(self, ports, **kwargs):
        """Configure LldpPorts records.

        Args:
            ports(list[int]):  list of ports
            **kwargs(dict):  parameters to be modified:
                             'adminStatus';
                             'tlvManAddrTxEnable';
                             'tlvPortDescTxEnable';
                             'tlvSysCapTxEnable';
                             'tlvSysDescTxEnable';
                             'tlvSysNameTxEnable'.

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_lldp_ports([1, 2], adminStatus='Disabled')

        """
        pass

    @abstractmethod
    def get_table_lldp(self, param=None):
        """Get Lldp table.

        Args:
            param(str):  parameter name (optional)

        Returns:
            list[dict]|int|str: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_lldp()

        """
        pass

    @abstractmethod
    def get_table_lldp_ports(self, port=None, param=None):
        """Get LldpPorts table.

        Args:
            port(int):  port Id (optional)
            param(str):  parameter name (optional)

        Returns:
            list[dict]|int|str:  table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_table_lldp_ports(1)

        """
        pass

    @abstractmethod
    def get_table_lldp_ports_stats(self, port=None, param=None):
        """Get LldpPorts table statistics.

        Args:
            port(int):  port Id (optional)
            param(str):  parameter name (optional)

        Returns:
            list[dict]|int|str: table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_table_lldp_ports_stats(1)

        """
        pass

    @abstractmethod
    def get_table_lldp_remotes(self, port=None):
        """Get LldpRemotes table.

        Args:
            port(int):  port Id (optional)

        Returns:
            list[dict]: table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_table_lldp_remotes(1)

        """
        pass

    @abstractmethod
    def get_table_remotes_mgmt_addresses(self, port=None):
        """Get LldpRemotesMgmtAddresses table.

        Args:
            port(int):  port Id (optional)

        Returns:
            list[dict]: table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_table_remotes_mgmt_addresses(1)

        """
        pass

    @abstractmethod
    def disable_lldp_on_device_ports(self, ports=None):
        """Disable Lldp on device ports (if port=None Lldp should be disabled on all ports).

        Args:
            ports(list[int]):  list of ports

        Returns:
            None

        Examples::

            env.switch[1].ui.disable_lldp_on_device_ports()

        """
        pass

# DCBX configuration

    @abstractmethod
    def set_dcb_admin_mode(self, ports, mode='Enabled'):
        """Enable/Disable DCB on ports.

        Args:
            ports(list[int]):  list of ports
            mode(str):  "Enabled" or 'Disabled'

        Returns:
            None

        Examples::

            env.switch[1].ui.set_dcb_admin_mode([1, 2], "Enabled")

        """
        pass

    @abstractmethod
    def enable_dcbx_tlv_transmission(self, ports, dcbx_tlvs="all", mode="Enabled"):
        """Enable/Disable the transmission of all Type-Length-Value messages.

        Args:
            ports(list[int]):  list of ports
            dcbx_tlvs(str):  TLV message types
            mode(str):  "Enabled" or 'Disabled'

        Returns:
            None

        Examples::

            env.switch[1].ui.enable_dcbx_tlv_transmission([1, 2], dcbx_tlvs="all", mode="Enabled")

        """
        pass

    @abstractmethod
    def get_table_dcbx_ports(self, port=None, param=None):
        """Get DcbxPorts table.

        Args:
            port(int):  port Id (optional)
            param(str):  parameter name (optional)

        Returns:
            list[dict]:  table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_table_dcbx_ports()

        """
        pass

    @abstractmethod
    def get_table_dcbx_app_maps(self, table_type="Admin", port=None):
        """Get DcbxAppMaps* table

        Args:
            table_type(str):  "Admin", "Local" or "Remote"
            port(int):  port Id (optional)

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_dcbx_app_maps("Admin", 1)

        """
        pass

    @abstractmethod
    def configure_application_priority_rules(self, ports, app_prio_rules):
        """Configure Application Priority rules.

        Args:
            ports(list[int]):  list of ports
            app_prio_rules(list[dict]):  list of rules dictionaries

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_application_priority_rules([1, 2], [{"selector": 1, "protocol": 2, "priority":1}, ])

        """
        pass

    @abstractmethod
    def configure_dcbx_ets(self, ports, **kwargs):
        """Configure DCBx ETS Conf/Reco parameter for ports list.

        Args:
            ports(list[int]):  list of ports
            **kwargs(dict):  parameters to be modified:
                             "willing";
                             "cbs";
                             "maxTCs";
                             "confBandwidth";
                             "confPriorityAssignment";
                             "confAlgorithm";
                             "recoBandwidth";
                             "recoPriorityAssignment";
                             "recoAlgorithm".

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_dcbx_ets([1, 2], confBandwidth=100)

        """
        pass

    @abstractmethod
    def configure_dcbx_cn(self, ports, **kwargs):
        """Configure DCBx CN parameter for the ports list.

        Args:
            ports(list[int]):  list of ports
            **kwargs(dict):  parameters to be modified:
                             "cnpvSupported";
                             "cnpvReady".

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_dcbx_cn([1, 2], cnpvSupported='Enabled')

        """
        pass

    @abstractmethod
    def configure_dcbx_pfc(self, ports, **kwargs):
        """Configure DCBx PFC parameter for the ports list.

        Args:
            ports(list[int]):  list of ports
            **kwargs(dict):  parameters to be modified:
                             "mbc";
                             "enabled";
                             "willing".

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_dcbx_pfc([1, 2])

        """
        pass

    @abstractmethod
    def configure_dcbx_app(self, ports, **kwargs):
        """Configure DCBx APP parameter for the ports list.

        Args:
            ports(list[int]):  list of ports
            **kwargs(dict):  parameters to be modified:
                             "willing".

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_dcbx_app([1, 2])

        """
        pass

    @abstractmethod
    def get_table_dcbx_remotes(self, port=None, param=None):
        """Get DcbxRemotes* table.

        Args:
            port(int):  port Id (optional)
            param(str):  parameter name (optional)

        Returns:
            list[dict]|int|str: table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_table_dcbx_remotes(1)

        """
        pass

    @abstractmethod
    def get_table_dcbx_pfc(self, table_type="Local", port=None):
        """Get DcbxRemotes* table.

        Args:
            port(int):  port Id (optional)
            table_type(str):  Table types "Admin"| "Local"| "Remote"

        Returns:
            list[dict]|int|str:  table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_table_dcbx_pfc()

        """
        pass

# Netns functionality
    @abstractmethod
    def create_namespace(self, name):
        """Create network namespace

        Args:
            name(str): netns name

        """
        pass

    @abstractmethod
    def enter_namespace(self, name):
        """Add netns prefix to the command.

        Args:
            name(str): netns name

        """
        pass

    @abstractmethod
    def exit_namespace(self):
        """Remove netns prefix from the command.

        """
        pass

    @abstractmethod
    def delete_namespace(self, name):
        """Delete network namespace.

        Args:
            name(str): netns name

        """
        pass

# Work with files and folder
    @abstractmethod
    def create_folder(self, name):
        """Create folder.

        Args:
            name(str): folder name

        """
        pass

    @abstractmethod
    def delete_folder(self, name):
        """Delete folder.

        Args:
            name(str): folder name

        """
        pass
