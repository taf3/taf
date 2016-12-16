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

@file  ui_iss_cli.py

@summary  ISS CLI UI wrappers.
"""
import time
from abc import abstractmethod

from testlib import helpers
from testlib.ui_helpers import UiHelperMixin
from testlib.ui_wrapper import UiInterface
from testlib import clicmd_iss

MIN_LAG_ID = 3800


class UiIssCli(UiHelperMixin, UiInterface):
    # disable this for now so we can instantiate subclasses without
    # all the abstract methods defined.  Re-enable once implemented
    # __metaclass__ = ABCMeta
    """
    @description  Abstract class to store UI wrapper interface methods
    """
    def __init__(self, switch):
        """
        @brief Initialize UiIssCli Class
        """
        self.switch = switch
        self.ris = {}
        self.networks = []
        self.is_config_mode = False
        self.mode_prompt = ""
        self.switch.cli = clicmd_iss.CLICmd(
                    # don't use _sshtun_port, we need port 23
                    self.switch.ipaddr, None,
                    self.switch.config['cli_user'],
                    self.switch.config['cli_user_passw'],
                    self.switch.config['cli_user_prompt'], self.switch.type)

    def connect(self):
        self.ris = {}
        self.networks = []
        time.sleep(15)
        self.switch.cli.cli_connect(prompt="iss")
        self.is_config_mode = False
        self.mode_prompt = 'iss#'

    def disconnect(self):
        self.is_config_mode = False
        self.mode_prompt = 'iss#'
        self.switch.cli.cli_disconnect()

    def generate_port_name_mapping(self):
        _ports = self.switch.ui.get_table_ports()
        self.port_map = {x['portId']: x['name'] for x in _ports}
        self.name_to_portid_map = {x['name']: x['portId'] for x in _ports}

    def _return_user_mode(self, results):
        commands = [['exit'], ]
        while results and results[-1].split('\n')[-1].strip() != self.mode_prompt:
            results = self.cli_set(commands)

    def enter_config_mode(self):
        commands = [['configure'], ]
        if not self.is_config_mode:
            self.is_config_mode = True
            self.mode_prompt = 'Switch (config)#'
            try:
                self.cli_set(commands)
            except Exception:
                self.is_config_mode = False
                self.mode_prompt = 'Switch #'

    def exit_config_mode(self):
        commands = [['exit'], ]
        if self.is_config_mode:
            self.is_config_mode = False
            self.mode_prompt = 'Switch #'
            try:
                self.cli_set(commands)
            except Exception:
                self.is_config_mode = True
                self.mode_prompt = 'Switch (config)#'

    def cli_set(self, commands, timeout=10, fail_message='Fail to configure'):
        if commands:
            results = self.switch.cli.cli_get_all(commands, timeout=timeout)
            self._return_user_mode(results)
            helpers.process_cli_results(results)
            return results
        else:
            return []

    def cli_get_all(self, commands, timeout=10):
        results = self.switch.cli.cli_get_all(commands, timeout=timeout)
        self._return_user_mode(results)
        return results

    def process_table_data(self, show_command, data, table_keys_mapping, header_rows=1):
        table_data = data[0].replace(show_command, '')
        table_data = [x for x in table_data.strip().split("\n")][:-2]
        table = []
        _column_length = [len(x) for x in table_data[header_rows].split()]
        _real_keys = ["" for x in _column_length]
        for row in table_data[:header_rows]:
            i = 0
            for x in _column_length:
                _real_keys[i] = _real_keys[i] + ' ' + row[: x].rstrip()
                row = row[x + 1:]
                i += 1

        _real_keys = [x.strip() for x in _real_keys]

        keys = [table_keys_mapping[x] for x in _real_keys]
        for row in table_data[header_rows + 1:]:
            if row:
                _row = []
                for x in _column_length:
                    _row.append(row[: x].strip())
                    row = row[x + 1:].strip()
                empty_row = True
                for el in _row:
                    if el != "":
                        empty_row = False
                if not empty_row:
                    table.append(dict(list(zip(keys, _row))))

        return table

    def process_vertical_table_data(self, show_command, data, table_keys_mapping):
        table_data = data[0].replace(show_command, '')
        table_data = [x.strip() for x in table_data.strip().split("\n") if '--' not in x]
        table = {}
        for row in table_data:
            str_row = row.split(' .')
            if str_row[0].strip() in list(table_keys_mapping.keys()):
                table[table_keys_mapping[str_row[0].strip()]] = row.split('. ')[-1].strip()
        return table

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
    def check_device_state(self):
        """
        @brief  Attempts to connect to the shell retries number of times
        """

        if not self.switch.cli.conn.check_shell():
            try:
                self.switch.ui.connect()
            except:
                raise Exception("Device is not ready.")
                self.switch.ui.disconnect()

        # Add cli application check

# Platform
    def get_table_platform(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_platform()
        """
        # Note: No central area to pull stats; this is for display only
        return [{"ethernetSwitchType": "ISS Switch",
                 "name": "NA",
                 "model": "NA",
                 "chipVersion": "NA",
                 "chipSubType": "NA",
                 "apiVersion": "NA",
                 "switchppVersion": "NA",
                 "cpu": "NA",
                 "cpuArchitecture": "NA",
                 "osType": "NA",
                 "osVersion": "NA",
                 "chipName": "NA",
                 "serialNumber": "NA"}]

# Syslog configuration
    @abstractmethod
    def create_syslog(self, syslog_proto, syslog_ip, syslog_port, syslog_localport, syslog_transport, syslog_facility, syslog_severity):
        """
        @brief  Configure Syslog settings
        """
        pass

    @abstractmethod
    def logs_add_message(self, level, message):
        """
        @brief  Add message into device logs
        """
        pass

# Temperature information
    @abstractmethod
    def get_temperature(self):
        """
        @brief  Get temperature from Sensors table
        """
        pass

# System information
    @abstractmethod
    def get_memory(self, mem_type='usedMemory'):
        """
        @brief UiInterface::get_memory()
        """
        pass

    @abstractmethod
    def get_cpu(self):
        """
        @brief UiInterface::get_cpu()
        """
        pass

# Applications configuration
    @abstractmethod
    def get_table_applications(self):
        """
        @brief  Get 'Applications' table
        """
        pass

    @abstractmethod
    def configure_application(self, application, loglevel):
        """
        @brief  Set application loglevel
        @param application:  Application Name.
        @param loglevel:  Application loglevel.

        @return  None

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
        @param  **kwargs  Possible parameters from 'SpanningTree' table to configure.

        @return  None

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
        @param instance:  Instance number(int).
        @param priority:  Instance priority(int).

        @return  None

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
        @param instance:  Instance number(int).
        @param  **kwargs  Possible parameters to configure.

        @return  None

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

        @return  table (list of dictionaries)

        @par Example:
        @code
        env.switch[1].ui.get_table_spanning_tree()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_mstp_ports(self, ports=None, instance=None):
        """
        @brief  Get 'MSTPPorts' table

        @note  Return all table or information about particular ports and STP instance.

        @param ports:  list of ports.
        @param instance:  Instance number(int).

        @return  table (list of dictionaries)

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
        @param instance:  Instance number(int).
        @param  **kwargs  Parameters to be modified. Parameters names should be the same as in XMLRPC nb.MSTPPorts.set.* calls

        @return  None

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
        @param  **kwargs  Parameters to be modified. Parameters names should be the same as in XMLRPC nb.RSTPPorts.set.* calls

        @return  None

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

        @note  Return all table or information about particular ports.

        @param ports:  list of ports.

        @return  table (list of dictionaries)

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

        @note  This method is used in helpers.set_all_ports_admin_disabled() for all functional test case.

        @return  None
        """
        pass

    @abstractmethod
    def wait_all_ports_admin_disabled(self):
        """
        @brief  Wait for all ports into admin Down state

        @note  This method is used in helpers.set_all_ports_admin_disabled() for all functional test case.

        @return  None
        """
        pass

    @abstractmethod
    def check_device_status(self, dev=None, dev_status=None):

        """
        @brief check_device_status

        @param dev: port/switch name.
        @param dev_status: specify the state to which device must be checked.

        @return returns True if the dev_status matches actual status of device

        @par Example:
        @code
        env.switch[1].ui.check_device_status(['fm0-0', ], "up")
        @endcode
        """
        pass

    @abstractmethod
    def read_ports(self, port, **kwargs):
        """
        @brief  Reads Port Attribute values from sysfs device files

        @param port:  port name to read from the list.
        @param  **kwargs  Tag Parameter to identify the Port Config Attribute.

        @return  Port Config Attribute value

        @par Example:
        @code
        env.switch[1].ui.modify_ports(['fm0-0', ], getAttr='def_cfi')
        @endcode
        """
        pass

    @abstractmethod
    def modify_ports(self, ports, **kwargs):
        """
        @brief  Modify records in 'Ports' table

        @param ports:  list of ports.
        @param  **kwargs  Parameters to be modified. Parameters names should be the same as in XMLRPC nb.Ports.set.* calls

        @return  None

        @par Example:
        @code
        env.switch[1].ui.modify_ports([1, 2], adminMode='Down')
        @endcode
        """
        pass

    def get_table_ports(self, ports=None, all_params=False):
        """
        @copydoc  UiInterface::get_table_ports()
        """

        SAMPLE = """\
vlan1 up, line protocol is down (not connect)
Interface SubType: Not Applicable
Interface Alias: vlan1
"""
        self.exit_config_mode()
        cli_keys = {"Port": "portId",
                    "Name": "name",
                    "Description": "description",
                    "MAC Address": "macAddress",
                    "Type": "type",
                    "Administrative Mode": "adminMode",
                    "Operational Status": "operationalStatus",
                    "Auto Negotiate": "autoNegotiate",
                    "Speed": "speed",
                    "Duplex": "duplex",
                    "Flow Control": "flowControl",
                    "Maximum Frame Size": "maxFrameSize",
                    "PVID": "pvid",
                    "PVPT": "pvpt",
                    "Learning Mode": "learnMode",
                    "Ingress Filtering": "ingressFiltering",
                    "Discard Mode": "discardMode",
                    "Cut Through": "cutThrough",
                    "Application Error": "appError",
                    "Mac Mode": "macMode"}
        _table = []
        if ports is not None:
            for port in ports:
                if int(port) >= MIN_LAG_ID:
                    port_name = 'port-channel %s detail' % (port, )
                else:
                    port_name = self.port_map[port]
                commands = [['show interface %s' % (port_name, )], ]
                res_list = self.switch.cli.cli_get_all(commands)
                _table.append(self.process_vertical_table_data(commands[0][0], res_list, cli_keys))
        else:
            commands = [['show interface'], ]
            res_list = self.switch.cli.cli_get_all(commands)
            table_rows = res_list[0].replace(commands[0][0], '').strip().split('Port')
            for row in table_rows:
                if row.strip():
                    _table.append(self.process_vertical_table_data(commands[0][0], ['Port      ' + row, ], cli_keys))
        for row in _table:
            row['portId'] = int(row['portId'])
            row['speed'] = int(row['speed'])
            row['maxFrameSize'] = int(row['maxFrameSize'])
            row['pvid'] = int(row['pvid'])
            row['pvpt'] = int(row['pvpt'])
        return _table

# Ustack configuration
    @abstractmethod
    def start_ustack_with_given_mesh_ports(self, mesh_ports=tuple(), dbglevel=0):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::start_ustack_with_given_mesh_ports()
        """
        pass

# Vlan configuration
    @abstractmethod
    def create_vlans(self, vlans=None):
        """
        @brief  Create new Vlans

        @param vlans:  list of vlans to be created.

        @return  None

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

        @return  None

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

        @return  table (list of dictionaries)

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

        @param ports:  list of ports to be added to Vlans.
        @param vlans:  list of vlans.
        @param tagged:  information about ports tagging state.

        @return  None

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
        @brief  Delete Ports2Vlans records

        @param ports:  list of ports to be added to Vlans.
        @param vlans:  list of vlans.

        @return  None

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

        @param ports:  list of ports to be added to Vlans.
        @param vlans:  list of vlans.
        @param tagged:  information about ports tagging state.

        @return  None

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

        @return  table (list of dictionaries)

        @par Example:
        @code
        env.switch[1].ui.get_table_ports2vlans()
        @endcode
        """
        pass

# ALC configuration

    @abstractmethod
    def create_acl(self, ports=None, expressions=None, actions=None, rules=None):
        """
        @brief  Create ACLs

        @param ports:  list of ports where ACLs will be created.
        @param expressions:  list of ACL expressions.
        @param actions:  list of ACL actions.
        @param rules:  list of ACL rules.

        @return  None

        @par Example:
        @code
        env.switch[1].ui.create_acl(ports=[1, 2], expressions=[[1, 'SrcMac', 'FF:FF:FF:FF:FF:FF', '00:00:00:11:11:11'], ],
                                    actions=[[1, 'Drop', ''], ], [[1, 1, 1, 'Ingress', 'Enabled', 0], ])
        @endcode
        """
        pass

    @abstractmethod
    def delete_acl(self, ports=None, expression_ids=None, action_ids=None, rule_ids=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_acl()
        """
        pass

    @abstractmethod
    def get_table_acl(self, table):
        """
        @brief  Get ACL table

        @param table:  ACL table name to be returned

        @return  table (list of dictionaries)

        @par Example:
        @code
        env.switch[1].ui.get_table_acl('ACLStatistics')
        @endcode
        """
        pass

# FDB configuration
    @abstractmethod
    def create_static_macs(self, port=None, vlans=None, macs=None):
        """
        @brief  Create static FDB records

        @param port:  port where static Fbds will be created (mandatory).
        @param vlans:  list of vlans where static Fbds will be created (mandatory).
        @param macs:  list of MACs to be added (mandatory).

        @return  None

        @par Example:
        @code
        env.switch[1].ui.create_static_macs(10, [1, 2], ['00:00:00:11:11:11', ])
        @endcode
        """
        pass

    @abstractmethod
    def delete_static_mac(self, port=None, vlan=None, mac=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_static_mac()
        """
        pass

    @abstractmethod
    def get_table_fdb(self, table='Fdb'):
        """
        @brief  Get Fbd table

        @param table:  Fbd record type to be returned ('Fbd' oe 'Static')

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
        @return  None

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
        @param param:  param name to get info about

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
        @brief  Configure PortsDot1p2CoS records

        @param  **kwargs  parameters to be modified

        @return  None

        @par Example:
        @code
        env.switch[1].ui.configure_cos_global(dotp2CoS=6)
        @endcode
        """
        pass

    @abstractmethod
    def configure_port_cos(self, ports=None, **kwargs):
        """
        @brief  Configure PortsQoS records

        @param ports:  list of ports to be modified
        @param  **kwargs  parameters to be modified

        @return  None

        @par Example:
        @code
        env.switch[1].ui.configure_port_cos([1, ], trustMode='Dot1p')
        @endcode
        """
        pass

    @abstractmethod
    def create_dot1p_to_cos_mapping(self, ports, **kwargs):
        """
        @brief  Create PortsDot1p2CoS mapping

        @param ports:  list of ports to be modified
        @param  **kwargs  parameters to be modified

        @return  None

        @par Example:
        @code
        env.switch[1].ui.create_dot1p_to_cos_mapping([1, ], dotp7CoS=6)
        @endcode
        """
        pass

    @abstractmethod
    def modify_dot1p_to_cos_mapping(self, ports, **kwargs):
        """
        @brief  Modify PortsDot1p2CoS mapping

        @param ports:  list of ports to be modified
        @param  **kwargs  parameters to be modified

        @return  None

        @par Example:
        @code
        env.switch[1].ui.modify_dot1p_to_cos_mapping([1, ], dotp7CoS=6)
        @endcode
        """
        pass

# Statistics configuration
    @abstractmethod
    def get_table_statistics(self, port=None, stat_name=None):
        """
        @brief  Get Statistics table

        @param port:  port Id to get info about ('cpu' or port id) (optional)
        @param stat_name:  name of statistics parameter (optional)

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

        @return  None

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
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bridge_info()
        """
        pass

    @abstractmethod
    def modify_bridge_info(self, **kwargs):
        """
        @brief  Modify BridgeInfo table

        @param  **kwargs  Parameters to be modified

        @return  None

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
        @param key:  LAG key
        @param lag_type:  LAG type
        @param hash_mode:  LAG hash type

        @return  None

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

        @return  None

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

        @return  table (list of dictionaries)

        @par Example:
        @code
        env.switch[1].ui.get_table_lags()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_link_aggregation(self):
        """
        @brief  Get LinkAggregation table

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
        @param collectormaxdelay:  collectorMaxDelay parameter value
        @param globalhashmode:  globalHashMode parameter value
        @param priority:  priority parameter value
        @param lacpenable:  lacpEnable parameter value

        @return  None

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
        @copydoc  testlib::ui_wrapper::UiInterface::create_lag_ports()
        """
        pass

    @abstractmethod
    def delete_lag_ports(self, ports, lag):
        """
        @brief  Delete ports from created LAG

        @param ports:  list of ports to be added into LAG
        @param lag:  LAG Id

        @return  None

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

        @return  table (list of dictionaries)

        @par Example:
        @code
        env.switch[1].ui.get_table_ports2lag()
        @endcode
        """
        pass

    @abstractmethod
    def get_table_lags_local(self, lag=None):
        """
        @brief  Get LagsLocal table

        @param lag:  LAG Id

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

        @return  table (list of dictionaries)

        @par Example:
        @code
        env.switch[1].ui.get_table_lags_local_ports()
        env.switch[1].ui.get_table_lags_local_ports(3800)
        @endcode
        """
        pass

# IGMP configuration
    @abstractmethod
    def configure_igmp_global(self, mode='Enabled', router_alert=None, unknown_igmp_behavior=None, query_interval=None, querier_robustness=None):
        """
        @brief  Modify IGMPSnoopingGlobalAdmin table

        @param mode:  mode parameter value
        @param router_alert:  routerAlertEnforced parameter value
        @param unknown_igmp_behavior:  unknownIgmpBehavior parameter value
        @param query_interval:  queryInterval parameter value
        @param querier_robustness:  querierRobustness parameter value

        @return  None

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
        @param mode:  igmpEnabled parameter value
        @param router_port_mode:  routerPortMode parameter value

        @return  None

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
        @param vlans:  list of vlans
        @param macs:  list of multicast MACs

        @return  None

        @par Example:
        @code
        env.switch[1].ui.create_multicast(10, [5, ], ['01:00:05:11:11:11', ])
        @endcode
        """
        pass

    @abstractmethod
    def get_table_l2_multicast(self):
        """
        @brief  Get L2Multicast table

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
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_igmp_snooping_port_oper()
        """
        pass

    @abstractmethod
    def clear_l2_multicast(self):
        """
        @brief  Clear L2Multicast table

        @return  None

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
        @param ospf:  enable OSPF

        @return  None

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
        @param ip:  Route Interface network
        @param ip_type:  Route interface type
        @param bandwidth:  Route interface bandwidth
        @param mtu:  Route interface mtu
        @param status:  Route interface status
        @param vrf:  Route interface vrf
        @param mode:  'ip' or 'ipv6'

        @return  None

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
        @copydoc  testlib::ui_wrapper::UiInterface::delete_route_interface()
        """
        pass

    @abstractmethod
    def modify_route_interface(self, vlan, ip, **kwargs):
        """
        @brief  Modify Route Interface

        @param vlan:  vlan Id
        @param ip:  Route Interface network
        @param  **kwargs  parameters to be modified

        @return  None

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

        @return  table (list of dictionaries)

        @par Example:
        @code
        env.switch[1].ui.get_table_route()
        @endcode
        """
        pass

    @abstractmethod
    def configure_arp(self, garp=None, refresh_period=None, delay=None, secure_mode=None, age_time=None, attemptes=None):
        """
        @brief  Configure ARPConfig table

        @param garp:  AcceptGARP value
        @param refresh_period:  RefreshPeriod value
        @param delay:  RequestDelay value
        @param secure_mode:  SecureMode value
        @param age_time:  AgeTime value
        @param attemptes:  NumAttempts value

        @return  None

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
        @param mac:  ARP mac address
        @param network:  RouteInterface network
        @param mode:  'arp' or 'ipv6 neigbor'

        @return  None

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
        @param network:  RouteInterface network
        @param mode:  'arp' or 'ipv6 neigbor'

        @return  None

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
        @param nexthop:  Nexthop IP address
        @param network:  RouteInterface network
        @param distance:  Route distance
        @param mode:  'ip' or 'ipv6'

        @return  None

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

        @return  None

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

        @param  **kwargs  parameters to be modified

        @return  None

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
        @param  **kwargs  parameters to be added

        @return  None

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
        @param area:  Area Id
        @param mode:  Area mode

        @return  None

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
        @param range_ip:  IP address
        @param range_mask:  mask
        @param substitute_ip:  IP address
        @param substitute_mask:  mask

        @return  None

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

        @return  None

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
        @param network:  Route Interface network
        @param key_id:  key Id
        @param key:  key

        @return  None

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
        @param network:  Route Interface network
        @param dead_interval:  dead interval
        @param hello_interval:  hello interval
        @param network_type:  network type
        @param hello_multiplier:  hello multiplier
        @param minimal:  minimal
        @param priority:  priority
        @param retransmit_interval:  retransmit interval

        @return  None

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
        @param link:  Virtual link IP

        @return  None

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
        @param enabled:  enabled status

        @return  None

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
        @param ip:  IP address
        @param remote_as:  Remote AS number

        @return  None

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
        @param ip:  IP address

        @return  None

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
        @param ip:  IP address
        @param port:  connection port

        @return  None

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
        @param router_id:  OSPF router Id

        @return  None

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
        @param name:  peer group name

        @return  None

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
        @param name:  peer group name
        @param ip:  IP address

        @return  None

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
        @param rtype:  redistribute type

        @return  None

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
        @param ip:  IP address
        @param mask:  IP address mask
        @param route_map:  route map name

        @return  None

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
        @param ip:  IP address
        @param mask:  IP address mask

        @return  None

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
        @param peers:  peers number

        @return  None

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
        @param ip:  IP address
        @param mask:  IP address mask
        @param distance:  IP address distance
        @param route_map:  route map name

        @return  None

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
        @param ext_distance:  external distance
        @param int_distance:  internal distance
        @param local_distance:  local distance

        @return  None

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

        @return  table

        @par Example:
        @code
        env.switch[1].ui.get_table_bgp_redistribute()
        @endcode
        """
        pass

# OVS configuration
    @abstractmethod
    def create_ovs_bridge(self, bridge_name):
        """
        @brief  Create OvsBridges record

        @param bridge_name:  OVS bridge name

        @return  None

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

        @return  table (list of dictionaries))

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

        @return  None

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
        @param bridge_name:  OVS bridge name

        @return  None

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

        @return  table (list of dictionaries))

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

        @return  table (list of dictionaries))

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
        @param controller:  controller address

        @return  None

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

        @return  table (list of dictionaries))

        @par Example:
        @code
        env.switch[1].ui.get_table_ovs_controllers()
        @endcode
        """
        pass

    @abstractmethod
    def create_ovs_flow_rules(self, bridge_id, table_id, flow_id, priority, enabled):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_flow_rules()
        """
        pass

    @abstractmethod
    def delete_ovs_flow_rules(self, bridge_id, table_id, flow_id, priority):
        """
        @brief  Delete row from OvsFlowRules table

        @param bridge_id:  OVS bridge ID
        @param table_id:  Table ID
        @param flow_id:  Flow ID
        @param priority:  Rule priority

        @return  None

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

        @return  None

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

        @return  table (list of dictionaries))

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
        @param table_id:  Table ID
        @param flow_id:  Flow ID
        @param priority:  Rule priority
        @param action:  Action name
        @param param:  Action parameter

        @return  None

        @par Example:
        @code
        env.switch[1].ui.create_ovs_flow_actions(0, 0, i, 'Output', str(1))
        @endcode
        """
        pass

    @abstractmethod
    def delete_ovs_flow_actions(self, bridge_id, table_id, flow_id, action, priority=2000):
        """
        @brief  Delete row from OvsFlowActions table

        @param bridge_id:  OVS bridge ID
        @param table_id:  Table ID
        @param flow_id:  Flow ID
        @param priority:  Rule priority
        @param action:  Action name

        @return  None

        @par Example:
        @code
        env.switch[1].ui.delete_ovs_flow_actions(bridgeId, tableId, flowId, action)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_ovs_flow_qualifiers(self):
        """
        @brief  Get OvsFlowQualifiers table

        @return  table (list of dictionaries))

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
        @param table_id:  Table ID
        @param flow_id:  Flow ID
        @param priority:  Rule priority
        @param field:  Expression name
        @param data:  Expression data

        @return  None

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
        @param table_id:  Table ID
        @param flow_id:  Flow ID
        @param priority:  Rule priority
        @param field:  Expression name

        @return  None

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

        @param  **kwargs  parameters to be modified

        @return  None

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
        @param  **kwargs  parameters to be modified

        @return  None

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

        @return  table (list of dictionaries)

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
        @param param:  parameter name (optional)

        @return  table (list of dictionaries) or value

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
        @param param:  parameter name (optional)

        @return  table (list of dictionaries) or value

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

        @return  table (list of dictionaries) or value

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

        @return  table (list of dictionaries) or value

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

        @return  None

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
        @param mode:  "Enabled" or 'Disabled'

        @return  None

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
        @param dcbx_tlvs:  TLV message types
        @param mode:  "Enabled" or 'Disabled'

        @return  None

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
        @param param:  parameter name (optional)

        @return  table (list of dictionaries) or value

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
        @param port:  port Id (optional)

        @return  table (list of dictionaries)

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
        @param app_prio_rules:  list of rules dictionaries

        @return  None

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
        @param  **kwargs  parameters to be modified

        @return  None

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
        @param  **kwargs  parameters to be modified

        @return  None

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
        @param  **kwargs  parameters to be modified

        @return  None

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
        @param  **kwargs  parameters to be modified

        @return  None

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
        @param param:  parameter name (optional)

        @return  table (list of dictionaries) or value

        @par Example:
        @code
        env.switch[1].ui.get_table_dcbx_remotes(1)
        @endcode
        """
        pass

    @abstractmethod
    def get_table_dcbx_pfc(self, table_type="Local", port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_pfc()
        """
        pass

# UFD configuration

    @abstractmethod
    def get_table_ufd_config(self):
        """
        @brief  Get UFDConfig table

        @return  table (list of dictionaries)

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
        @param hold_on_time:  hold on time

        @return  None

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

        @param group_id:  Enable or disable UFD
        @param threshold:  group threshold
        @param enable:  Enable or disable UFD group

        @return  None

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

        @param group_id:  Enable or disable UFD
        @param threshold:  group threshold
        @param enable:  Enable or disable UFD group

        @return  None

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

        @param group_id:  Enable or disable UFD

        @return  None

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

        @return  table (list of dictionaries)

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
        @param port_type:  type of port
        @param group_id:  UFD group Id

        @return  None

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
        @param port_type:  type of port
        @param group_id:  UFD group Id

        @return  None

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

        @return  table (list of dictionaries)

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
        @param  **kwargs  parameters to be modified

        @return  None

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
        @param provider_vlan_id:  provider vlan Id
        @param provider_vlan_priority:  provider vlan priority

        @return  None

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

        @return  table (list of dictionaries)

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
        @param customer_vlan_id:  customer vlan Id
        @param customer_vlan_priority:  customer vlan priority
        @param provider_vlan_id:  provider vlan Id
        @param provider_vlan_priority:  provider vlan priority

        @return  None

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

        @return  table (list of dictionaries)

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

        @return  table (list of dictionaries)

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
        @param param:  parameter name (optional)

        @return  table (list of dictionaries) or value

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
        @param app_error:  application error

        @return  table (list of dictionaries) or value

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

        @return  table (list of dictionaries)

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
        @param recovery:  recovery status
        @param app_name:  application name
        @param app_error:  application error

        @return  None

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

        @return  None

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
        @param app_name:  recovery interval (optional)
        @param app_error:  recovery interval (optional)
        @param param:  parameter name (optional)

        @return  table (list of dictionaries) or value

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
        @param target:  target port Id
        @param mode:  mirroring mode

        @return  None

        @par Example:
        @code
        env.switch[1].ui.create_mirror_session(1, 2, 'Redirect')
        @endcode
        """
        pass

    def get_mirroring_sessions(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_mirroring_sessions()
        """
        pass

    def delete_mirroring_session(self, port, target, mode):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_mirroring_session()
        """
        pass

# DHCP Relay configuration

    @abstractmethod
    def create_dhcp_relay(self, iface_name='global', server_ip=None, fwd_iface_name=None):
        """
        @brief  Configure DhcpRelayAdmin or DhcpRelayV6Admin table

        @param iface_name:  VLAN inteface name
        @param server_ip:  DHCP Server IP address
        @param fwd_iface_name:  VLAN forward interface name (for IPv6 config only)

        @return  None

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

        @return  None

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

        @return  None

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
        @param destination_ip:  Destination IP address
        @param vrf:  Tunnel ID
        @param encap_type:  Tunnel ID

        @return  None

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

        @return  List

        @par Example:
        @code
        env.switch[1].ui.get_table_tunnels_admin()
        @endcode
        """
        pass
