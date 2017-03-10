# Copyright (c) 2011 - 2017, Intel Corporation.
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

"""``ui_ons_cli.py``

`ONS CLI UI wrappers`

"""

import time
import re
from socket import error as SocketError

import pytest
from paramiko import SSHException

from . import helpers
from .ui_helpers import UiHelperMixin
from .ui_wrapper import UiInterface
from .custom_exceptions import UIException
from .custom_exceptions import SwitchException
from .custom_exceptions import CLISSHException
from testlib import clicmd_ons

MIN_LAG_ID = 3800

STAT_MAP = {
    "RxUcstPktsIPv4": "IfInUcastPkts",
    "RxUcstPktsIPv6": "IfInUcastPkts",
    "RxUcstPktsNonIP": "IfInUcastPkts",
    "TxUcstPktsIPv4": "IfOutUcastPkts"
}


class UiOnsCli(UiHelperMixin, UiInterface):
    """Class with CLI wrappers.

    """
    def __init__(self, switch):
        """Initialize UiOnsCli class.

        Args:
            switch(SwitchGeneral):  Switch instance

        """
        self.switch = switch
        self.ris = {}
        self.networks = []
        self.is_config_mode = False
        self.mode_prompt = 'Switch #'
        self.switch.cli = clicmd_ons.CLICmd(
            self.switch.ipaddr, self.switch._sshtun_port,
            self.switch.config['cli_user'],
            self.switch.config['cli_user_passw'],
            self.switch.config['cli_user_prompt'], self.switch.type,
            build_path=self.switch.build_path,
            img_path=self.switch.cli_img_path,
            delay=self.switch.cli_delay,
            xmlrpcport=self.switch.xmlrpcport)

    def connect(self):
        """Attempts to connect to the CLI.

        """
        self.ris = {}
        self.networks = []
        self.switch.cli.cli_connect(prompt="Switch ")
        self.is_config_mode = False
        self.mode_prompt = 'Switch #'
        commands = [["enable"], ]
        self.cli_set(commands)
        self.generate_port_name_mapping()

    def disconnect(self):
        """Disconnects the CLI session from the switch.

        """
        self.is_config_mode = False
        self.mode_prompt = 'Switch #'
        self.switch.cli.cli_disconnect()

    def generate_port_name_mapping(self):
        """Generates port IDs to port names mapping and vice versa.

        """
        _ports = self.switch.ui.get_table_ports()
        self.port_map = {x['portId']: x['name'] for x in _ports}
        self.name_to_portid_map = {x['name']: x['portId'] for x in _ports}

    def _return_user_mode(self, results):
        """Method that returns to specific mode of a switch.

        Args:
            results(list):  list of command execution results
t
        """
        commands = [['exit'], ]
        while results and results[-1].split('\n')[-1].strip() != self.mode_prompt:
            results = self.cli_set(commands)

    def enter_config_mode(self):
        """Method that returns to config mode of a switch.

        """
        commands = [['configure'], ]
        if not self.is_config_mode:
            self.is_config_mode = True
            self.mode_prompt = 'Switch (config)#'
            try:
                self.cli_set(commands)
            except (CLISSHException, SSHException, SocketError):
                self.is_config_mode = False
                self.mode_prompt = 'Switch #'

    def exit_config_mode(self):
        """Method that returns to user mode of a switch.

        """
        commands = [['exit'], ]
        if self.is_config_mode:
            self.is_config_mode = False
            self.mode_prompt = 'Switch #'
            try:
                self.cli_set(commands)
            except (CLISSHException, SSHException, SocketError):
                self.is_config_mode = True
                self.mode_prompt = 'Switch (config)#'

    def cli_set(self, commands, timeout=10, fail_message='Fail to configure'):
        """Sends a list of commands.

        Args:
            commands(list[list[str]]):  list of commands to be executed
            timeout(int):  command execution timeout
            fail_message(str):  failure message

        Returns:
            list[list[str]]:  commands execution results

        """
        if commands:
            results = self.switch.cli.cli_get_all(commands, timeout=timeout)
            self._return_user_mode(results)
            helpers.process_cli_results(results)
            return results
        else:
            return []

    def cli_get_all(self, commands, timeout=10):
        """Sends a list of commands. Return to the initial CLI mode.

        Args:
            commands(list[list[str]]):  list of commands to be executed
            timeout(int):  command execution timeout

        Returns:
            list[list[str]:  commands execution results

        """
        results = self.switch.cli.cli_get_all(commands, timeout=timeout)
        self._return_user_mode(results)
        return results

    def process_table_data(self, show_command, data, table_keys_mapping, header_rows=1):
        """Generate table from the command output.

        Args:
            show_command(str):  CLI command
            data(list[str]):  CLI command output
            table_keys_mapping(dict):  CLI column name to XMLRPC column name mapping
            header_rows(int):  count of header rows with column names in CLI output

        Returns:
            dict:  XMLRPC table

        """
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
        """Generate table from the command output.

        Args:
            show_command(str):  CLI command
            data(list[str]):  CLI command output
            table_keys_mapping(dict):  CLI column name to XMLRPC column name mapping

        Returns:
            dict:  XMLRPC table

        """
        table_data = data[0].replace(show_command, '')
        table_data = [x.strip() for x in table_data.strip().split("\n") if '--' not in x]
        table = {}
        for row in table_data:
            str_row = row.split(' .')
            if str_row[0].strip() in list(table_keys_mapping.keys()):
                table[table_keys_mapping[str_row[0].strip()]] = row.split('. ')[-1].strip()
        return table

    def restart(self):
        """Restarts the switch via command line 'reboot' command.

        """
        self.exit_config_mode()
        commands = [['reload ::::yes'], ]
        try:
            self.cli_set(commands, timeout=3)
        except (CLISSHException, SSHException, SocketError):
            pass
        self.disconnect()

# Clear Config
    def clear_config(self):
        """Clear device configuration.

        """
        self.exit_config_mode()
        commands = [['clear config ::::yes'], ]
        self.cli_set(commands, timeout=60)

    def save_config(self):
        """Save device configuration.

        """
        self.exit_config_mode()
        commands = [['save config ::::yes'], ]
        self.cli_set(commands, timeout=60)

    def restore_config(self):
        """Restore device configuration.

        """
        self.exit_config_mode()
        commands = [['restore config ::::yes'], ]
        self.cli_set(commands, timeout=60)

# Application Check
    def check_device_state(self):
        """Attempts to connect to the shell retries number of times.

        Raises:
            Exception:  device is not ready

        """

        if not (self.switch.cli.conn.check_client() and self.switch.cli.conn.check_shell()):
            try:
                self.switch.ui.connect()
            except (CLISSHException, SSHException, SocketError):
                self.switch.ui.disconnect()
                raise Exception("Device is not ready.")

        # Add cli application check

# Platform
    def get_table_platform(self):
        """Get 'Platform' table.

        """
        self.enter_config_mode()
        cli_keys = {"Ethernet Switch Type": "ethernetSwitchType",
                    "Name": "name",
                    "Model": "model",
                    "Chip Version": "chipVersion",
                    "Chip Subtype": "chipSubType",
                    "Api Version": "apiVersion",
                    "Software Version": "switchppVersion",
                    "CPU": "cpu",
                    "CPU Architecture": "cpuArchitecture",
                    "OS": "osType",
                    "OS Version": "osVersion",
                    "Platform": "chipName",
                    "Serial Number": "serialNumber"}
        commands = [['show system'], ]
        res_list = self.switch.cli.cli_get_all(commands)
        _table = [self.process_vertical_table_data(commands[0][0], res_list, cli_keys)]

        return _table

# Syslog configuration
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
        self.enter_config_mode()
        commands = [
            ["logging host %s transport %s local-port %s remote-port %s trap %s "
             "facility %s" % (
                 syslog_ip, syslog_transport.lower(), syslog_localport, syslog_port,
                 syslog_severity.lower(), syslog_facility)]]
        self.cli_set(commands)

    def logs_add_message(self, level, message):
        """Add message into device logs.

        Args:
            level(str):  log severity
            message(str):  log message

        Raises:
             UIException:  not implemented

        """
        raise UIException("Could not be executed using CLI")

# Temperature information
    def get_temperature(self):
        """Get temperature from Sensors table.

        Returns:
            dict:  CPU temperature information (Sensors table)

        """
        self.enter_config_mode()
        cli_keys = {"ID": "id",
                    "Type": "type",
                    "Temperature": "value",
                    "Platform temperature sensor": "PlatformTemp",
                    "Alta switch temperature sensor": "SwitchTemp",
                    "Power supply controller temperature sensor": "PowerSupplyTemp"}

        commands = [['show environment temperature'], ]
        res_list = self.switch.cli.cli_get_all(commands)
        _table = self.process_table_data(commands[0][0], res_list, cli_keys)
        for row in _table:
            row["type"] = cli_keys[row['type']]
            row['value'] = int(row['value'])

        return _table

# System information
    def get_memory(self, mem_type='usedMemory'):
        """Returns free cached/buffered memory from switch.

        Args:
            mem_type(str):  memory type

        Returns:
            float::  memory size

        """
        cli_keys = {"Subsystem": "subsystem",
                    "Instance": "instance",
                    "Indicator": "indicator",
                    "Time": "time",
                    "Value": "value"}

        commands = [['show memory'], ]
        res_list = self.switch.cli.cli_get_all(commands)
        _table = self.process_table_data(commands[0][0], res_list, cli_keys)
        mem = [x["value"] for x in _table if x["indicator"] == mem_type]
        mem = mem[0].split()
        return float(mem[0])

    def get_cpu(self):
        """Returns cpu utilization from switch.

        Returns:
            float:  cpu utilization from switch

        """
        time.sleep(20)
        cli_keys = {"Subsystem": "subsystem",
                    "Instance": "instance",
                    "Indicator": "indicator",
                    "Time": "time",
                    "Value": "value"}

        commands = [['show cpu'], ]
        res_list = self.switch.cli.cli_get_all(commands)
        _table = self.process_table_data(commands[0][0], res_list, cli_keys)
        cpu_list = [x["value"] for x in _table if x["value"] != '0 B']
        total_cpu = 0
        for item in cpu_list:
            item = item.split()
            total_cpu += float(item[0])
        return total_cpu

# Applications configuration
    def get_table_applications(self):
        """Get 'Applications' table.

        Returns:
            list[dict]: 'Applications' table

        """
        self.enter_config_mode()
        cli_keys = {"Application": "name",
                    "Version": "version",
                    "Type": "type",
                    "Administrative State": "adminState",
                    "Operational State": "operationalState",
                    "Log Level": "logLevel"}

        commands = [['show applications'], ]
        res_list = self.switch.cli.cli_get_all(commands)
        _table = []
        apps = res_list[0].split("Application ..")[1:]
        for _row in apps:
            _table.append(self.process_vertical_table_data(commands[0][0], ["Application .." + _row], cli_keys))

        return _table

    def configure_application(self, application, loglevel):
        """Set application loglevel.

        Args:
            application(str):  Application Name.
            loglevel(str):  Application loglevel.

        Returns:
            None

        Example::

            env.switch[1].ui.configure_application('L1PortControlApp', 'Debug')

        """
        app_names = [x['name'] for x in self.get_table_applications()]
        if application in app_names:
            self.enter_config_mode()
            commands = [["logging application %s  level %s" % (application, loglevel.lower())], ]
            self.cli_set(commands)

# STP configuration
    def configure_spanning_tree(self, **kwargs):
        """Configure 'SpanningTree' table.

        Args:
            kwargs(dict):  Possible parameters from 'SpanningTree' table to configure:
                           "enable" - globally enable STP;
                           "mode" - set STP mode. RSTP|MSTP|STP;
                           "maxAge" - set maxAge value;
                           "forwardDelay" - set forwardDelay value;
                           "bridgePriority" - set bridgePriority value;
                           "bpduGuard" - set bpduGuard value;
                           "forceVersion" - set forceVersion value;
                           "mstpciName" - set mstpciName value.

        Returns:
            None

        Example::

            env.switch[1].ui.configure_spanning_tree(mode='MSTP')

        """
        self.enter_config_mode()
        stp_commands = []
        if 'enable' in kwargs and 'mode' in kwargs:
            if kwargs['enable'] == "Enabled":
                stp_commands.append(["no spanning-tree"])
                stp_commands.append(["spanning-tree mode %s" % (kwargs['mode'].lower(), )])
            else:
                stp_commands.append(["spanning-tree mode %s" % (kwargs['mode'].lower(), )])
                stp_commands.append(["no spanning-tree"])
        elif 'mode' in kwargs:
            stp_commands.append(["no spanning-tree"])
            stp_commands.append(["spanning-tree mode %s" % (kwargs['mode'].lower(), )])
        elif 'enable' in kwargs:
            if kwargs['enable'] == "Disabled":
                stp_commands.append(["no spanning-tree"])
            else:
                stp_table = self.get_table_spanning_tree()
                self.enter_config_mode()
                mode = stp_table[0]['mode']
                stp_commands.append(["spanning-tree mode %s" % (mode.lower())])

        if 'maxAge' in kwargs:
            stp_commands.append(["spanning-tree max-age %s" % (kwargs['maxAge'], )])
        if 'forwardDelay' in kwargs:
            stp_commands.append(["spanning-tree forward-time %s" % (kwargs['forwardDelay'], )])
        if 'bridgePriority' in kwargs:
            stp_commands.append(["spanning-tree priority %s" % (kwargs['bridgePriority'], )])
        if 'bpduGuard' in kwargs:
            stp_commands.append(["spanning-tree portfast bpduguard"])
        if 'mstpciName' in kwargs:
            stp_commands.append(["spanning-tree mst configuration"])
            stp_commands.append(["name %s" % (kwargs['mstpciName'], )])
        if 'forceVersion' in kwargs:
            if kwargs['forceVersion'] == 0:
                fv = 'stp'
            elif kwargs['forceVersion'] == 1:
                fv = 'mstp'
            elif kwargs['forceVersion'] == 2:
                fv = 'rstp'
            stp_commands.append(["spanning-tree force-version %s" % (fv, )])

        self.cli_set(stp_commands)

    def create_stp_instance(self, instance, priority):
        """Create new STP instance in 'STPInstances' table.

        Args:
            instance(int):  Instance number.
            priority(int):  Instance priority.

        Returns:
            None

        Examples::

            env.switch[1].ui.create_stp_instance(instance=3, priority=2)

        """
        self.enter_config_mode()
        stp_commands = [['spanning-tree mst configuration'], ["instance %s" % (instance, )], ["instance %s priority %s" % (instance, priority)]]
        self.cli_set(stp_commands)

    def configure_stp_instance(self, instance, **kwargs):
        """Configure existing STP instance.

        Args:
            instance(int):  Instance number.
            **kwargs(dict):  Possible parameters to configure.
                             "priority" - change instance priority;
                             "vlan" - assign instance to the existed vlan.

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_stp_instance(instance=3, priority=2)  # change instance priority
            env.switch[1].ui.configure_stp_instance(instance=3, vlan=10)  # assign instance to the existed vlan

        """
        self.enter_config_mode()
        stp_commands = [['spanning-tree mst configuration'], ]
        if 'priority' in kwargs:
            stp_commands.append(["instance %s priority %s" % (instance, kwargs['priority'])])
        if 'vlan' in kwargs:
            stp_commands.append(["instance %s vlan %s" % (instance, kwargs['vlan'])])
        self.cli_set(stp_commands)

    def get_table_spanning_tree(self):
        """Get 'SpanningTree' table.

        Returns:
            list(dict): table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_spanning_tree()

        """
        self.exit_config_mode()
        cli_keys = {"Aging Time": "agingTime",
                    "Bridge ID": "bridgeID",
                    "Bridge Priority": "bridgePriority",
                    "Designated Root": "designatedRoot",
                    "Force Version": "forceVersion",
                    "Forward Delay": "forwardDelay",
                    "Global Enable": "globalEnable",
                    "Hello Time": "helloTime",
                    "Maximum Age": "maxAge",
                    "Maximum Hops": "maxHops",
                    "Migration Time": "migrationTime",
                    "Mode": "mode",
                    "Root Path Cost": "rootPathCost",
                    "Root Priority": "designatedRootPriority",
                    "Root Port ID": "rootPortId",
                    "Root Times Forward Delay": "rootTimesForwardDelay",
                    "Root Times Hello Time": "rootTimesHelloTime",
                    "Root Times Maximum Age": "rootTimesMaxAge",
                    "TC": "tc",
                    "TC Count": "tcCount",
                    "Time Since TC": "timeSinceTc",
                    "TX Hold Count": "txHoldCount",
                    "PortFast BPDU Guard Status": "bpduGuard",
                    "BPDU Forwarding": "bpduForwarding"}
        commands = [['show spanning-tree'], ]
        res_list = self.switch.cli.cli_get_all(commands)
        _table = [self.process_vertical_table_data(commands[0][0], res_list, cli_keys)]

        for row in _table:
            row['agingTime'] = int(row['agingTime'])
            row['bridgePriority'] = int(row['bridgePriority'])
            row['designatedRootPriority'] = int(row['designatedRootPriority'])
            row['forceVersion'] = int(row['forceVersion'])
            row['forwardDelay'] = int(row['forwardDelay'])
            row['helloTime'] = int(row['helloTime'])
            row['maxAge'] = int(row['maxAge'])
            row['maxHops'] = int(row['maxHops'])
            row['migrationTime'] = int(row['migrationTime'])
            row['rootPathCost'] = int(row['rootPathCost'])
            row['rootPortId'] = int(row['rootPortId'])
            row['rootTimesForwardDelay'] = int(row['rootTimesForwardDelay'])
            row['rootTimesHelloTime'] = int(row['rootTimesHelloTime'])
            row['rootTimesMaxAge'] = int(row['rootTimesMaxAge'])
            row['tcCount'] = int(row['tcCount'])
            row['timeSinceTc'] = int(row['timeSinceTc'])
            row['txHoldCount'] = int(row['txHoldCount'])
        return _table

    def get_table_spanning_tree_mst(self):
        """Get 'STPInstances' table

         Returns:
             list[dict]:  table (list of dictionaries)

         Examples::

             env.switch[1].ui.get_table_spanning_tree_mst()

         """
        self.exit_config_mode()
        cli_keys = {"MST Instance": "msti",
                    "Bridge ID": "bridgeId",
                    "Bridge Priority": "bridgePriority",
                    "Bridge Forward Delay": "bridgeTimesForwardDelay",
                    "Bridge Hello Time": "bridgeTimesHelloTime",
                    "Bridge Maximum Age": "bridgeTimesMaxAge",
                    "Designated Root": "designatedRoot",
                    "Root Port ID": "rootPortId",
                    "Root Path Cost": "rootPathCost",
                    "Root Priority": "designatedRootPriority",
                    "Root Forward Delay": "rootTimesForwardDelay",
                    "Root Maximum Age": "rootTimesMaxAge",
                    "TC": "tc",
                    "TC Count": "tcCount",
                    "Time Since TC": "timeSinceTc",
                    "TX Limit": "transmissionLimit",
                    "MST Port Configuration Table": "mstPortConfigurationTable"}
        commands = [['show spanning-tree mst'], ]
        res_list = self.switch.cli.cli_get_all(commands)
        _table = [self.process_vertical_table_data(commands[0][0], res_list, cli_keys)]

        for row in _table:
            row['msti'] = int(row['msti'])
            row['bridgePriority'] = int(row['bridgePriority'])
            row['bridgeTimesForwardDelay'] = int(row['bridgeTimesForwardDelay'])
            row['bridgeTimesHelloTime'] = int(row['bridgeTimesHelloTime'])
            row['bridgeTimesMaxAge'] = int(row['bridgeTimesMaxAge'])
            row['rootPortId'] = int(row['rootPortId'])
            row['rootPathCost'] = int(row['rootPathCost'])
            row['designatedRootPriority'] = int(row['designatedRootPriority'])
            row['rootTimesForwardDelay'] = int(row['rootTimesForwardDelay'])
            row['rootTimesMaxAge'] = int(row['rootTimesMaxAge'])
            row['tcCount'] = int(row['tcCount'])
            row['timeSinceTc'] = int(row['timeSinceTc'])
            row['transmissionLimit'] = int(row['transmissionLimit'])
        return _table

    def get_table_mstp_ports(self, ports=None, instance=0):
        """Get 'MSTPPorts' table.

        Notes:
            Return all table or information about particular ports and STP instance.

        Args:
            ports(list):  list of ports.
            instance(int):  Instance number(int).

        Returns:
            list(dict): table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_mstp_ports()
            env.switch[1].ui.get_table_mstp_ports([1, 2])
            env.switch[1].ui.get_table_mstp_ports([1, 2], instance=3)

        """
        self.exit_config_mode()
        cli_keys = {"Interface": "portId",
                    "MST Instance": "msti",
                    "Administrative Point To Point MAC": "adminPointToPointMAC",
                    "Administrative State": "adminState",
                    "Administrative Edge Port": "adminEdgePort",
                    "Auto Edge Port": "autoEdgePort",
                    "Designated Bridge": "designatedBridge",
                    "Designated Cost": "designatedCost",
                    "Designated Port": "designatedPort",
                    "Designated Root": "designatedRoot",
                    "Disputed": "disputed",
                    "External Cost": "externalCost",
                    "Internal Cost": "internalCost",
                    "MAC Enabled": "macEnabled",
                    "MAC Operational": "macOperational",
                    "Mcheck Status": "mcheck",
                    "Operational Edge Port": "operEdgePort",
                    "Operational Point To Point MAC": "operPointToPointMAC",
                    "Port Hello Time": "portHelloTime",
                    "Port Transition": "portTransition",
                    "Priority": "priority",
                    "Restricted Role": "restrictedRole",
                    "Restricted Tcn": "restrictedTcn",
                    "BPDU Guard": "bpduGuard",
                    "PortFast BPDU Guard": "portFast",
                    "Root Guard": "rootGuard",
                    "Role": "role",
                    "State": "state",
                    "TC Ack": "tcAck",
                    "Uptime": "uptime",
                    "RX Config BPDU Counter": "rxConfigBpduCounter",
                    "RX MSTP BPDU Counter": "rxMstpBpduCounter",
                    "RX RSTP BPDU Counter": "rxRstpBpduCounter",
                    "RX TC BPDU Counter": "rxTcBpduCounter",
                    "RX TCN BPDU Counter": "rxTcnBpduCounter",
                    "TX Config BPDU Counter": "txConfigBpduCounter",
                    "TX MSTP BPDU Counter": "txMstpBpduCounter",
                    "TX RSTP BPDU Counter": "txRstpBpduCounter",
                    "TX TC BPDU Counter": "txTcBpduCounter",
                    "TX TCN BPDU Counter": "txTcnBpduCounter"}
        _table = []
        if ports:
            for port in ports:
                if port < MIN_LAG_ID:
                    port_name = self.port_map[port]
                else:
                    port_name = 'port-channel %s' % (port, )
                commands = [['show spanning-tree mst interface %s' % (port_name, )], ]
                res_list = self.switch.cli.cli_get_all(commands)
                table_rows = res_list[0].replace(commands[0][0], '').strip().split('\nInterface .')
                for row in table_rows:
                    if row.strip() and '..' in row:
                        _table.append(self.process_vertical_table_data(commands[0][0], ['Interface .' + row, ], cli_keys))
        else:
            commands = [['show spanning-tree mst interface'], ]
            res_list = self.switch.cli.cli_get_all(commands)
            table_rows = res_list[0].replace(commands[0][0], '').strip().split('\nInterface .')
            for row in table_rows:
                if row.strip() and '..' in row:
                    _table.append(self.process_vertical_table_data(commands[0][0], ['Interface .' + row, ], cli_keys))
        for row in _table:
            row['portId'] = int(self.name_to_portid_map[row['portId']] if 'e' in row['portId'] else row['portId'])
            row['msti'] = int(row['msti'])
            row['designatedCost'] = int(row['designatedCost'])
            row['designatedPort'] = int(row['designatedPort'], 16)
            row['externalCost'] = int(row['externalCost'])
            row['internalCost'] = int(row['internalCost'])
            row['portHelloTime'] = int(row['portHelloTime'])
            row['priority'] = int(row['priority'])
            row['uptime'] = int(row['uptime'])
            row['rxConfigBpduCounter'] = int(row['rxConfigBpduCounter'])
            row['rxMstpBpduCounter'] = int(row['rxMstpBpduCounter'])
            row['rxRstpBpduCounter'] = int(row['rxRstpBpduCounter'])
            row['rxTcBpduCounter'] = int(row['rxTcBpduCounter'])
            row['rxTcnBpduCounter'] = int(row['rxTcnBpduCounter'])
            row['txConfigBpduCounter'] = int(row['txConfigBpduCounter'])
            row['txMstpBpduCounter'] = int(row['txMstpBpduCounter'])
            row['txRstpBpduCounter'] = int(row['txRstpBpduCounter'])
            row['txTcBpduCounter'] = int(row['txTcBpduCounter'])
            row['txTcnBpduCounter'] = int(row['txTcnBpduCounter'])
        if instance:
            _table = [x for x in _table if x['msti'] == instance]
        return _table

    def modify_mstp_ports(self, ports, instance=0, **kwargs):
        """Modify records in 'MSTPPorts' table.

        Args:
            ports(list):  list of ports.
            instance(int):  Instance number.
            **kwargs(dict): Parameters to be modified. Parameters names should be the same as in XMLRPC nb.MSTPPorts.set.* calls
                            "adminState" - change adminState;
                            "portFast" - set portFast value;
                            "rootGuard" - set rootGuard value;
                            "bpduGuard" - set bpduGuard value;
                            "autoEdgePort" - set autoEdgePort value;
                            "adminPointToPointMAC" - set adminPointToPointMAC value;
                            "externalCost" - set externalCost value;
                            "internalCost" - set internalCost value.

        Returns:
            None

        Examples::

            env.switch[1].ui.modify_mstp_ports([1, 2], instance=3, adminState='Enabled')

        """
        self.enter_config_mode()
        commands = []
        in_ports = ",".join([self.port_map[x] if x < MIN_LAG_ID else str(x) for x in ports])
        if 'e' in in_ports:
            commands.append(["interface range %s" % (in_ports, )])
        else:
            commands.append(["interface port-channel range %s" % (in_ports, )])
        if 'adminState' in kwargs:
            if kwargs['adminState'] == 'Enabled':
                commands.append(["spanning-tree mst %s enable" % (instance, )])
            if kwargs['adminState'] == 'Disabled':
                commands.append(["no spanning-tree mst %s enable" % (instance, )])
        if 'portFast' in kwargs:
            if kwargs['portFast'] == 'Enabled':
                commands.append(["spanning-tree mst %s portfast" % (instance, )])
            if kwargs['portFast'] == 'Disabled':
                commands.append(["no spanning-tree mst %s portfast" % (instance, )])
        if 'rootGuard' in kwargs:
            if kwargs['rootGuard'] == 'Enabled':
                commands.append(["spanning-tree mst %s rootguard" % (instance, )])
            if kwargs['rootGuard'] == 'Disabled':
                commands.append(["no spanning-tree mst %s rootguard" % (instance, )])
        if 'bpduGuard' in kwargs:
            if kwargs['bpduGuard'] == 'Enabled':
                commands.append(["spanning-tree mst %s bpduguard enable" % (instance, )])
            if kwargs['bpduGuard'] == 'Disabled':
                commands.append(["no spanning-tree mst %s bpduguard enable" % (instance, )])
        if 'autoEdgePort' in kwargs:
            if kwargs['autoEdgePort'] == 'Enabled':
                commands.append(["spanning-tree mst %s edge-port auto" % (instance, )])
            if kwargs['autoEdgePort'] == 'Disabled':
                commands.append(["no spanning-tree mst %s edge-port auto" % (instance, )])
        if 'adminPointToPointMAC' in kwargs:
            if kwargs['adminPointToPointMAC'] == 'ForceFalse':
                commands.append(["spanning-tree mst %s point-to-point-mac not-force" % (instance, )])
        if 'externalCost' in kwargs:
            commands.append(["spanning-tree mst %s external cost %s" % (instance, kwargs['externalCost'])])
        if 'internalCost' in kwargs:
            commands.append(["spanning-tree mst %s internal cost %s" % (instance, kwargs['internalCost'])])
        self.cli_set(commands)

    def modify_rstp_ports(self, ports, **kwargs):
        """Modify records in 'RSTPPorts' table.

        Args:
            ports(list):  list of ports.
            **kwargs(dict):  Parameters to be modified. Parameters names should be the same as in XMLRPC nb.RSTPPorts.set.* calls
                             "adminState" - change adminState;
                             "portFast" - set portFast value;
                             "rootGuard" - set rootGuard value;
                             "bpduGuard" - set bpduGuard value;
                             "autoEdgePort" - set autoEdgePort value;
                             "adminPointToPointMAC" - set adminPointToPointMAC value;
                             "cost" - set cost value.

        Returns:
            None

        Examples::

            env.switch[1].ui.modify_rstp_ports([1, 2], adminState='Enabled')

        """
        self.enter_config_mode()
        commands = []
        in_ports = ",".join([self.port_map[x] if x < MIN_LAG_ID else str(x) for x in ports])
        if 'e' in in_ports:
            commands.append(["interface range %s" % (in_ports, )])
        else:
            commands.append(["interface port-channel range %s" % (in_ports, )])
        if 'adminState' in kwargs:
            if kwargs['adminState'] == 'Enabled':
                commands.append(["spanning-tree enable"])
            if kwargs['adminState'] == 'Disabled':
                commands.append(["no spanning-tree enable"])
        if 'portFast' in kwargs:
            if kwargs['portFast'] == 'Enabled':
                commands.append(["spanning-tree portfast"])
            if kwargs['portFast'] == 'Disabled':
                commands.append(["no spanning-tree portfast"])
        if 'rootGuard' in kwargs:
            if kwargs['rootGuard'] == 'Enabled':
                commands.append(["spanning-tree rootguard"])
            if kwargs['rootGuard'] == 'Disabled':
                commands.append(["no spanning-tree rootguard"])
        if 'bpduGuard' in kwargs:
            if kwargs['bpduGuard'] == 'Enabled':
                commands.append(["spanning-tree bpduguard enable"])
            if kwargs['bpduGuard'] == 'Disabled':
                commands.append(["no spanning-tree bpduguard enable"])
        if 'autoEdgePort' in kwargs:
            if kwargs['autoEdgePort'] == 'Enabled':
                commands.append(["spanning-tree edge-port auto"])
            if kwargs['autoEdgePort'] == 'Disabled':
                commands.append(["no spanning-tree edge-port auto"])
        if 'adminPointToPointMAC' in kwargs:
            if kwargs['adminPointToPointMAC'] == 'ForceFalse':
                commands.append(["spanning-tree point-to-point-mac not-force"])
        if 'cost' in kwargs:
            commands.append(["spanning-tree cost %s" % (kwargs['cost'], )])
        self.cli_set(commands)

    def get_table_rstp_ports(self, ports=None):
        """Get 'RSTPPorts' table.

        Notes:
            Return all table or information about particular ports.

        Args:
            ports(list):  list of ports.

        Returns:
            list(dict): table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_rstp_ports()
            env.switch[1].ui.get_table_rstp_ports([1, 2])

        """
        self.exit_config_mode()
        cli_keys = {"Interface": "portId",
                    "Administrative Point To Point MAC": "adminPointToPointMAC",
                    "Administrative State": "adminState",
                    "Administrative Edge Port": "adminEdgePort",
                    "Auto Edge Port": "autoEdgePort",
                    "Cost": "cost",
                    "Designated Bridge": "designatedBridge",
                    "Designated Cost": "designatedCost",
                    "Designated Port": "designatedPort",
                    "Designated Root": "designatedRoot",
                    "MAC Enabled": "macEnabled",
                    "MAC Operational": "macOperational",
                    "Mcheck Status": "mcheck",
                    "Operational Edge Port": "operEdgePort",
                    "Operational Point To Point MAC": "operPointToPointMAC",
                    "Port Transition": "portTransition",
                    "Priority": "priority",
                    "BPDU Guard": "bpduGuard",
                    "PortFast BPDU Guard": "portFast",
                    "Root Guard": "rootGuard",
                    "Role": "role",
                    "State": "state",
                    "TC Ack": "tcAck",
                    "Uptime": "uptime",
                    "RX Config BPDU Counter": "rxConfigBpduCounter",
                    "RX Rstp BPDU Counter": "rxRstpBpduCounter",
                    "RX TC BPDU Counter": "rxTcBpduCounter",
                    "RX TCN BPDU Counter": "rxTcnBpduCounter",
                    "TX Config BPDU Counter": "txConfigBpduCounter",
                    "TX Rstp BPDU Counter": "txRstpBpduCounter",
                    "TX TC BPDU Counter": "txTcBpduCounter",
                    "TX TCN BPDU Counter": "txTcnBpduCounter"}
        _table = []
        if ports:
            for port in ports:
                if port < MIN_LAG_ID:
                    port_name = self.port_map[port]
                else:
                    port_name = 'port-channel %s' % (port, )
                commands = [['show spanning-tree interface %s' % (port_name, )], ]
                res_list = self.switch.cli.cli_get_all(commands)
                _table.append(self.process_vertical_table_data(commands[0][0], res_list, cli_keys))
        else:
            commands = [['show spanning-tree interface'], ]
            res_list = self.switch.cli.cli_get_all(commands)
            table_rows = res_list[0].replace(commands[0][0], '').strip().split('\nInterface .')
            for row in table_rows:
                if row.strip() and '..' in row:
                    _table.append(self.process_vertical_table_data(commands[0][0], ['Interface .' + row, ], cli_keys))

        for row in _table:
            row['portId'] = int(self.name_to_portid_map[row['portId']] if 'e' in row['portId'] else row['portId'])
            row['designatedCost'] = int(row['designatedCost'])
            row['designatedPort'] = int(row['designatedPort'], 16)
            row['priority'] = int(row['priority'])
            row['uptime'] = int(row['uptime'])
            row['cost'] = int(row['cost'])
            row['rxConfigBpduCounter'] = int(row['rxConfigBpduCounter'])
            row['rxRstpBpduCounter'] = int(row['rxRstpBpduCounter'])
            row['rxTcBpduCounter'] = int(row['rxTcBpduCounter'])
            row['rxTcnBpduCounter'] = int(row['rxTcnBpduCounter'])
            row['txConfigBpduCounter'] = int(row['txConfigBpduCounter'])
            row['txRstpBpduCounter'] = int(row['txRstpBpduCounter'])
            row['txTcBpduCounter'] = int(row['txTcBpduCounter'])
            row['txTcnBpduCounter'] = int(row['txTcnBpduCounter'])
        return _table

# Ports configuration
    def set_all_ports_admin_disabled(self):
        """Set all ports into admin Down state.

        Notes:
            This method is used in helpers.set_all_ports_admin_disabled() for all functional test case.

        Returns:
            None

        """
        # define ports directly from the switch
        ports_table = self.get_table_ports(ports=None)
        assert ports_table, "Ports table is empty on device %s" % (self.switch.xmlproxy._ServerProxy__host, )
        # define multicall params for Ports.find method
        port_ids = [x["portId"] for x in ports_table if x["operationalStatus"] != 'NotPresent' and
                    x["type"] == 'Physical' and
                    x["portId"] not in self.switch.mgmt_ports]

        try:
            self.switch.ui.modify_ports(port_ids, adminMode='Down')
        except (CLISSHException, SSHException, SocketError):
            ports_table = self.get_table_ports(ports=None)
            port_check_params = [[x["portId"], x["operationalStatus"]] for x in ports_table if x['operationalStatus'] == 'Up']

            statuses = set([x[1] for x in port_check_params])
            assert statuses == set(['NotPresent']), "Not all ports were disabled"

    def wait_all_ports_admin_disabled(self):
        """Wait for all ports into admin Down state.

        Notes:
            This method is used in helpers.set_all_ports_admin_disabled() for all functional test case.

        Returns:
            None

        """
        def _retry(ports_list):
            start_time = time.time()
            _table = self.get_table_ports(ports_list)
            up_ports = [x['portId'] for x in _table if x['operationalStatus'] == 'Up']
            end_time = time.time()
            while end_time < start_time + 30 and len(up_ports) > 0:
                time.sleep(1)
                _table = self.get_table_ports(up_ports)
                up_ports = [x['portId'] for x in _table if x['operationalStatus'] == 'Up']
                end_time = time.time()
            return up_ports

        ports_table = self.get_table_ports(ports=None)
        # define multicall params for Ports.find method
        port_ids = [x["portId"] for x in ports_table if x["operationalStatus"] not in {'NotPresent', 'Down'} and
                    x["type"] == 'Physical' and
                    x["portId"] not in self.switch.mgmt_ports]

        if port_ids:
            up_ports = _retry(port_ids)

            attempts = 0

            while up_ports and attempts < 3:
                # retry: set adminMode in Up/Down
                # define multicall params for nb.Ports.set.adminMode method
                self.switch.ui.modify_ports(up_ports, adminMode='Up')

                self.switch.ui.modify_ports(up_ports, adminMode='Down')

                up_ports = _retry(up_ports)
                attempts += 1

            if up_ports:
                pytest.fail("Not all ports are in down state: %s" % up_ports)

    def modify_ports(self, ports, **kwargs):
        """Modify records in 'Ports' table.

        Args:
            ports(list(int)):  list of ports.
            **kwargs(dict): Parameters to be modified. Parameters names should be the same as in XMLRPC nb.Ports.set.* calls:
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

        Returns:
            None

        Examples::

            env.switch[1].ui.modify_ports([1, 2], adminMode='Down')

        """
        self.enter_config_mode()
        commands = []
        in_ports = ",".join([self.port_map[x] if x < MIN_LAG_ID else str(x) for x in ports])
        if len(ports) == 1:
            if 'e' in in_ports:
                commands.append(["interface %s" % (in_ports, )])
            else:
                commands.append(["interface port-channel %s" % (in_ports, )])
        elif len(ports) > 1:
            if 'e' in in_ports:
                commands.append(["interface range %s" % (in_ports, )])
            else:
                commands.append(["interface port-channel range %s" % (in_ports, )])
        if 'pvid' in kwargs:
            commands.append(["switchport pvid %s" % (kwargs['pvid'], )])
        if 'pvpt' in kwargs:
            commands.append(["switchport pvpt %s" % (kwargs['pvpt'], )])
        if 'adminMode' in kwargs:
            if kwargs['adminMode'] == 'Up':
                commands.append(["no shutdown"])
            if kwargs['adminMode'] == 'Down':
                commands.append(["shutdown"])
        if 'ingressFiltering' in kwargs:
            if kwargs['ingressFiltering'] == 'Enabled':
                commands.append(["switchport ingress-filtering"])
            if kwargs['ingressFiltering'] == 'Disabled':
                commands.append(["no switchport ingress-filtering"])
        if 'maxFrameSize' in kwargs:
            commands.append(["max-frame-size %s" % (kwargs['maxFrameSize'], )])
        if 'discardMode' in kwargs:
            if kwargs['discardMode'] == 'None':
                commands.append(["no switchport discard"])
            else:
                commands.append(["switchport discard %s" % (kwargs['discardMode'].lower(), )])
        if 'cutThrough' in kwargs:
            if kwargs['cutThrough'] == 'Enabled':
                commands.append(["cut-through"])
            if kwargs['cutThrough'] == 'Disabled':
                commands.append(["no cut-through"])
        if 'tx_cutThrough' in kwargs:
            pytest.fail("Configuring of tx_cutThrough attribute is not supported")
        if 'flowControl' in kwargs:
            if kwargs['flowControl'] == 'None':
                commands.append(["flowcontrol receive off"])
                commands.append(["flowcontrol send off"])
            if kwargs['flowControl'] == 'Rx':
                commands.append(["flowcontrol receive on"])
                commands.append(["flowcontrol send off"])
            if kwargs['flowControl'] == 'RxTx':
                commands.append(["flowcontrol receive on"])
                commands.append(["flowcontrol send on"])
            if kwargs['flowControl'] == 'Tx':
                commands.append(["flowcontrol receive off"])
                commands.append(["flowcontrol send on"])
        if 'speed' in kwargs:
            commands.append(["speed %s" % (kwargs['speed'], )])
        if 'learnMode' in kwargs:
            commands.append(["mac-address-table learning-mode %s" % (kwargs['learnMode'].lower(), )])
        if 'macAddress' in kwargs:
            commands.append(["mac-address  %s" % kwargs["macAddress"]])
        self.cli_set(commands)

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
                    "Mac Mode": "macMode",
                    "Port MAC Address": "macAddress"}
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

# Flow Confrol configuration
    def set_flow_control_type(self, ports=None, control_type=None):
        """Enable/disable sending/accepting pause frames

        Args:
            ports(list): list of port IDs
            control_type(str): 'Rx', 'Tx', 'RxTx' and 'None'

        Returns:
            None

        Examples::

            env.switch[1].ui.set_flow_control([1, 2], 'RxTx')

        """
        if ports is None:
            ports_table = self.get_table_ports()
            ports = [(x["portId"], ) for x in ports_table]

        self.modify_ports(ports, flowControl=control_type)

# Vlan configuration
    def create_vlans(self, vlans=None):
        """Create new Vlans

        Args:
            vlans(list[int]):  list of vlans to be created.

        Returns:
            None

        Examples::

            env.switch[1].ui.create_vlans([2, 3])

        Raises:
            UIException:  list of vlans required

        """
        self.exit_config_mode()
        # Create new vlans
        if vlans:
            _vlans = ",".join([str(x) for x in vlans])
            vlans_commands = [["vlan-database"], ["vlan %s" % (_vlans, )], ["exit"]]
            # Add vlans
            self.cli_set(vlans_commands)
        else:
            raise UIException("List of vlans require")

    def delete_vlans(self, vlans=None):
        """Delete existing Vlans.

        Args:
            vlans(list[int]):  list of vlans to be deleted.

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_vlans([2, 3])

        Raises:
            UIException:  list of vlans required

        """
        self.exit_config_mode()
        if vlans:
            _vlans = ",".join([str(x) for x in vlans])
            vlans_commands = [["vlan-database"], ["no vlan %s" % (_vlans, )]]
            self.cli_set(vlans_commands)
        else:
            raise UIException("List of vlans require")

    def get_table_vlans(self):
        """Get 'Vlans' table.

        Returns:
            list(dict): table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_vlans()

        """
        self.exit_config_mode()
        show_commands = [['show vlan'], ]
        cli_keys = {"VLAN": "vlanId", "Name": "name"}
        res_list = self.switch.cli.cli_get_all(show_commands)
        _table = self.process_table_data('show vlan', res_list, cli_keys)
        for _r in _table:
            _r['vlanId'] = int(_r['vlanId'])
        return _table

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

        Raises:
            UIException:  vlans and ports required

        """
        self.enter_config_mode()
        if vlans and ports:
            _vlans = ",".join([str(x) for x in vlans])
            for port in ports:
                if port < MIN_LAG_ID:
                    port_name = self.port_map[port]
                else:
                    port_name = "port-channel %s" % (port, )
                p2v_commands = [["interface %s" % port_name], ["switchport vlan add %s %s" % (_vlans, tagged.lower())]]
                self.cli_set(p2v_commands)
        else:
            raise UIException("List of vlans and ports required")

    def delete_vlan_ports(self, ports=None, vlans=None):
        """Delete Ports2Vlans records.

        Args:
            ports(list[int]):  list of ports to be added to Vlans.
            vlans(list[int]):  list of vlans.

        Returns:
            None

        Examples::

            Ports 1 and 2 will be removed from the vlan 3:
            env.switch[1].ui.delete_vlan_ports([1, 2], [3, ])

        Raises:
            UIException:  vlans and ports required

        """
        self.enter_config_mode()
        if vlans and ports:
            _vlans = ",".join([str(x) for x in vlans])
            for port in ports:
                if port < MIN_LAG_ID:
                    port_name = self.port_map[port]
                else:
                    port_name = 'port-channel %s' % (port, )
                p2v_commands = [["interface %s" % port_name], ["no switchport vlan add %s" % (_vlans, )]]
                self.cli_set(p2v_commands)
        else:
            raise UIException("List of vlans and ports required")

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
        self.enter_config_mode()
        if vlans and ports:
            _vlans = ",".join([str(x) for x in vlans])
            for port in ports:
                if port < MIN_LAG_ID:
                    port_name = self.port_map[port]
                else:
                    port_name = 'port-channel %s' % (port, )
                p2v_commands = [["interface %s" % port_name], ["switchport vlan add %s %s" % (_vlans, tagged.lower())]]
                self.cli_set(p2v_commands)
        else:
            raise UIException("List of vlans and ports required")

    def get_table_ports2vlans(self):
        """Get 'Ports2Vlans' table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ports2vlans()

        """
        self.exit_config_mode()
        vlan_table = self.get_table_vlans()
        vlan_list = [x['vlanId'] for x in vlan_table]
        _table = []
        for _vlan in vlan_list:
            show_commands = [['show vlan %s' % (_vlan, )], ]
            cli_keys = {"Interface": "portId", "Tagged": "tagged"}
            res_list = self.switch.cli.cli_get_all(show_commands)
            res_list = "Interface" + res_list[0].split("Interface")[1]
            _t = self.process_table_data('show vlan %s' % (_vlan, ), [res_list, ], cli_keys)
            for _r in _t:
                _r['vlanId'] = int(_vlan)
                _r['portId'] = int(_r['portId'].split('e')[-1])
            _table.extend(_t)

        # Add applicable PVID's (non-default vlan 1)
        self.exit_config_mode()
        cli_keys = {"Port": "portId",
                    "PVID": "pvid"}
        _table_ports = []
        commands = [['show interface'], ]
        res_list = self.switch.cli.cli_get_all(commands)
        table_rows = res_list[0].replace(commands[0][0], '').strip().split('Port')

        for row in table_rows:
            if row.strip():
                _table_ports.append(self.process_vertical_table_data(commands[0][0], ['Port      ' + row, ], cli_keys))

        for entry in _table:
            entry['pvid'] = any(int(row['portId']) == entry['portId'] and
                                int(row['pvid']) == entry['vlanId'] for row in _table_ports)

        # Return ports2vlan table with PVID
        return _table

# ACL configuration

    def create_acl_name(self, acl_name=None):
        """Create ACL name.

        Args:
            acl_name(str):  ACL name to be created

        Returns:
            None

        Examples::

            env.switch[1].ui.create_acl_name('Test-1')

        """
        raise SwitchException("Not supported")

    def add_acl_rule_to_acl(self, acl_name=None, rule_id='', action=None, conditions=None):
        """Add rule to ACL.

        Args:
            acl_name(str):  ACL name where rule is added to.
            rule_id(str|int):  Rule Id used for adding.
            action(list[str]):  ACL Action
            conditions(list[list[str]]):  List of ACL conditions

        Returns:
            None

        Examples::

            env.switch[1].ui.add_acl_rule_to_acl(acl_name='Test-1',
                                                 rule_id=1,
                                                 action=['forward', '1'],
                                                 conditions=[['ip-source',
                                                             '192.168.10.10',
                                                             '255.255.255.255']])

        """
        raise SwitchException("Not supported")

    def bind_acl_to_ports(self, acl_name=None, ports=None):
        """Bind ACL to ports.

        Args:
            acl_name(str):  ACL name
            ports(list[int]):  list of ports where ACL will be bound.

        Returns:
            None

        Examples::

            env.switch[1].ui.bind_acl_to_ports(acl_name='Test-1', ports=[1, 2, 3])

        """
        raise SwitchException("Not supported")

    def unbind_acl(self, acl_name=None):
        """Unbind ACL.

        Args:
            acl_name(str):  ACL name

        Returns:
            None

        Examples::

            env.switch[1].ui.unbind_acl('Test-1')

        """
        raise SwitchException("Not supported")

    def _get_tcp_flags(self, tcp_flags):
        """Convert XMLRPC TCP flags to CLI values.

        Args:
            tcp_flags(str):  TCP flags

        Returns:
            str:  CLI ACL TCP flag: ack|ns|cwr|ece|fin|psh|rst|syn|urg

        """
        try:
            flag = int(tcp_flags)
        except ValueError:
            flag = int(tcp_flags, 16)
        if flag == 16:
            return 'ack'
        elif flag == 1:
            return 'ns'
        elif flag == 2:
            return 'cwr'
        elif flag == 4:
            return 'ece'
        elif flag == 256:
            return 'fin'
        elif flag == 32:
            return 'psh'
        elif flag == 64:
            return 'rst'
        elif flag == 128:
            return 'syn'
        elif flag == 8:
            return 'urg'
        else:
            return 'ack'

    def _get_ip_frags(self, ip_frags):
        """Convert XMLRPC IP frags to CLI values.

        Args:
            ip_frags(str):  IP frags: Any|Sub|NoFragOrHead|NoFrag|Head

        Returns:
            str:  CLI ACL IP frag: any|sub|no-frag-or-head|no-frag|head

        """
        if ip_frags == 'Any':
            return 'any'
        elif ip_frags == 'Sub':
            return 'sub'
        elif ip_frags == 'NoFragOrHead':
            return 'no-frag-or-head'
        elif ip_frags == 'NoFrag':
            return 'no-frag'
        elif ip_frags == 'Head':
            return 'head'

    def _get_ip_type(self, ip_type):
        """Convert XMLRPC IP type to CLI values.

        Args:
            ip_type(str):  IP type: ArpRequest|ArpReply|Ipv4Any|Ipv6Any|NonIp

        Returns:
            str:  CLI ACL IP frag: arp request|arp reply|ipv4-any|ipv6-any|non-ip

        """
        if ip_type == 'ArpRequest':
            return 'arp request'
        elif ip_type == 'ArpReply':
            return 'arp reply'
        elif ip_type == 'Ipv4Any':
            return 'ipv4-any'
        elif ip_type == 'Ipv6Any':
            return 'ipv6-any'
        elif ip_type == 'NonIp':
            return 'non-ip'

    def create_acl(self, ports=None, expressions=None, actions=None, rules=None, acl_name='Test-ACL'):
        """Create ACLs.

        Args:
            ports(list[int]):  list of ports where ACLs will be created.
            expressions(list[list]):  list of ACL expressions.
            actions(list[list]):  list of ACL actions.
            rules(list[list]):  list of ACL rules.
            acl_name(str):  ACL name to which add rules

        Returns:
            None

        Examples::

            env.switch[1].ui.create_acl(ports=[1, 2], expressions=[[1, 'SrcMac', 'FF:FF:FF:FF:FF:FF', '00:00:00:11:11:11'], ],
                                        actions=[[1, 'Drop', ''], ], [[1, 1, 1, 'Ingress', 'Enabled', 0], ])

        Raises:
            UIException: list of ports required

        """
        _expressions, _actions, _rules = None, None, None
        if expressions:
            _expressions = expressions[:]
        if actions:
            _actions = actions[:]
        if rules:
            _rules = rules[:]

        acl_mapping = {"SrcMac": "mac source",
                       "DstMac": "mac destination",
                       "SrcIp": "ip source",
                       "DstIp": "ip destination",
                       "SrcIp6": "ipv6 source",
                       "DstIp6": "ipv6 destination",
                       "Dscp": "dscp",
                       "Tos": "tos",
                       "Ttl": "ttl",
                       "OuterVlanId": "vlan outer",
                       "InnerVlanId": "vlan inner",
                       "OuterVlanPri": "vlan outer priority",
                       "OuterVlanCfi": "vlan outer cfi",
                       "L4SrcPort": "l4-port source",
                       "L4DstPort": "l4-port destination",
                       "IntPriority": "cos",
                       "TcpFlags": "tcp flags",
                       "IpFrag": "ip fragment",
                       "IpHeaderSize": "ip header-size",
                       "IpProtocol": "ip protocol",
                       "IpType": "ip type",
                       "L2PayloadFirstEightBytes": "l2-payload-head",
                       "VlanFormat": "vlan format",
                       "EtherType": "ethertype",
                       "Drop": "deny",
                       "Allow": "permit",
                       "Normal": "normal",
                       "Flood": "flood",
                       "Count": "count",
                       "Redirect": "redirect",
                       "MirrorIngress": "mirror ingress",
                       "CopyToCpu": "copy-to-cpu",
                       "TrapToCpu": "trap-to-cpu",
                       "SetOuterVlan": "set vlan outer",
                       "SetOuterVlanPri": "set vlan outer priority",
                       "Ingress": "in",
                       "PermitDenyIngress": "in",
                       "Egress": "out",
                       "PermitDenyEgress": "out"}
        commands = []
        self.enter_config_mode()
        # Configure ACL Expressions
        if _expressions:
            for expression in _expressions:
                if expression[1] == 'TcpFlags':
                    expression[3] = self._get_tcp_flags(expression[3])
                if expression[1] == 'IpFrag':
                    expression[3] = self._get_ip_frags(expression[3])
                if expression[1] == 'VlanFormat':
                    expression[3] = expression[3].lower()
                if expression[1] == 'IpType':
                    expression[3] = self._get_ip_type(expression[3])
                mask = ''
                if expression[1] in ['SrcIp', 'DstIp', 'SrcMac', 'DstMac']:
                    mask = expression[2]
                if expression[1] in ['SrcIp6', 'DstIp6']:
                    expression[3] = expression[3] + expression[2]
                commands.append(["access-list expression %s %s %s %s" % (expression[0], acl_mapping[expression[1]], expression[3], mask)])
        # Configure ACL Actions
        if _actions:
            for action in _actions:
                if action[1] in ['MirrorIngress', 'MirrorEgress', 'Redirect']:
                    action[2] = ",".join([self.port_map[int(x)] if int(x) < MIN_LAG_ID else x for x in action[2].split(',')])
                commands.append(["access-list action %s %s %s" % (action[0], acl_mapping[action[1]], action[2])])
        # Configure ACL Rules
        if _rules:
            if not ports:
                raise UIException('List of ports require')
            in_ports = ",".join([self.port_map[x] if x < MIN_LAG_ID else str(x) for x in ports])
            if 'e' in in_ports:
                commands.append(["interface range %s" % (in_ports, )])
            else:
                commands.append(["interface port-channel range %s" % (in_ports, )])
            for rule in _rules:
                commands.append(["access-group %s %s %s %s ::::yes" % (rule[0], rule[1], rule[2], acl_mapping[rule[3]])])
        self.cli_set(commands)

    def delete_acl(self, ports=None, expression_ids=None, action_ids=None, rule_ids=None, acl_name=None):
        """Delete ACLs.

        Args:
            ports(list[int]):  list of ports where ACLs will be deleted (mandatory).
            expression_ids(list[int]):  list of ACL expression IDs to be deleted (optional).
            action_ids( list[int]):  list of ACL action IDs to be deleted (optional).
            rule_ids(list[int]):  list of ACL rule IDs to be deleted (optional).
            acl_name(str):  ACL name

        Returns:
            None

        Example::

            env.switch[1].ui.delete_acl(ports=[1, 2], rule_ids=[1, 2])

        Raises:
            UIException:  list of ports required

        """
        self.enter_config_mode()
        commands = []

        # Delete ACL Rules
        if rule_ids:
            if not ports:
                raise UIException('List of ports require')
            in_ports = ",".join([self.port_map[x] if x < MIN_LAG_ID else str(x) for x in ports])
            if 'e' in in_ports:
                commands.append(["interface range %s" % (in_ports, )])
            else:
                commands.append(["interface port-channel range %s" % (in_ports, )])
            for rule in rule_ids:
                commands.append(["no access-group %s ::::yes" % (rule, )])
            commands.append(['exit'])
        if action_ids:
            for action in action_ids:
                commands.append(["no access-list action %s" % (action[0], )])
        if expression_ids:
            for expression in expression_ids:
                commands.append(["no access-list expression %s" % (expression[0], )])
        self.cli_set(commands)

    def get_table_acl(self, table=None, acl_name=None):
        """Get ACL table.

        Args:
            table(str):  ACL table name to be returned. ACLStatistics|ACLExpressions|ACLActions
            acl_name(str):  ACL name

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_acl('ACLStatistics')

        """
        self.exit_config_mode()
        if table == 'ACLStatistics':
            commands = [['show access-lists statistics'], ]
            cli_keys = {"Rule ID": "ruleId", "Match Packets": "matchPkts", "Match Octets": "matchOctets"}
            res_list = self.cli_get_all(commands)
            _table = self.process_table_data('show access-lists statistics', res_list, cli_keys)
            for _row in _table:
                _row['ruleId'] = int(_row['ruleId'])
                _row['matchPkts'] = int(_row['matchPkts'])
                _row['matchOctets'] = int(_row['matchOctets'])

        elif table == 'ACLExpressions':
            commands = [['show access-lists expressions'], ]
            cli_keys = {"ID": "expressionId", "Expression": "field", "Data": "data", "Mask": "mask"}
            res_list = self.cli_get_all(commands)
            _table = self.process_table_data('show access-lists expressions', res_list, cli_keys)
            for _row in _table:
                _row['expressionId'] = int(_row['expressionId'])

        elif table == 'ACLActions':
            commands = [['show access-lists actions'], ]
            cli_keys = {"ID": "actionId", "Action": "action", "Parameters": "param"}
            res_list = self.cli_get_all(commands)
            _table = self.process_table_data('show access-lists actions', res_list, cli_keys)
            for _row in _table:
                _row['actionId'] = int(_row['actionId'])
                if _row['param'] == 'N/A':
                    _row['param'] = ''

        elif table == 'ACLRules':
            commands = [['show access-lists'], ]
            cli_keys = {"Rule ID": "ruleId",
                        "Action ID": "actionId",
                        "Expression ID": "expressionId",
                        "Stage": "stage",
                        "Status": "enabled",
                        "Priority": "priority"}
            res_list = self.cli_get_all(commands)
            _table = [self.process_vertical_table_data('show access-lists', [_row], cli_keys)
                      for _row in res_list[0].split('Mask') if 'Rule ID' in _row]
            for _row in _table:
                _row['ruleId'] = int(_row['ruleId'])
                _row['actionId'] = int(_row['actionId'])
                _row['expressionId'] = int(_row['expressionId'])
                _row['priority'] = int(_row['priority'])

        return _table

    def get_acl_names(self):
        """Get ACL names.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_acl_names()

        """
        raise SwitchException("Not supported")

# FDB configuration
    def create_static_macs(self, port=None, vlans=None, macs=None):
        """Create static FDB records.

        Args:
            port(int):  port where static Fbds will be created (mandatory).
            vlans( list[int]):  list of vlans where static Fbds will be created (mandatory).
            macs(list[str]):  list of MACs to be added (mandatory).

        Returns:
            None

        Examples::

            env.switch[1].ui.create_static_macs(10, [1, 2], ['00:00:00:11:11:11', ])

        Raises:
            UIException:  vlan and mac required, port must be int

        """
        if not isinstance(port, int):
            raise UIException('Port must be type int')
        if not vlans:
            raise UIException('List of vlans require')
        if not macs:
            raise UIException('List of mac require')
        command_list = []
        self.enter_config_mode()
        if port < MIN_LAG_ID:
            _port = self.port_map[port]
        else:
            _port = "port-channel %s" % (port, )

        for _vlan in vlans:
            for _mac in macs:
                command_list.append(['mac-address-table static %s vlan %s interface %s' % (_mac, _vlan, _port)])
        self.cli_set(command_list)

    def delete_static_mac(self, port=None, vlan=None, mac=None):
        """Delete static FDB records.

        Args:
            port(int):  port where static Fbds will be deleted.
            vlan(list[int]):  list of vlans where static Fbds will be deleted (mandatory).
            mac(list[str]):  list of MACs to be deleted (mandatory).

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_static_mac([1, 2], ['00:00:00:11:11:11', ])

        Raises:
            UIException:  vlan and mac required

        """
        if not vlan:
            raise UIException('List of vlans require')
        if not mac:
            raise UIException('List of mac require')
        command_list = []
        self.enter_config_mode()
        command_list.append(['no mac-address-table static %s vlan %s' % (mac, vlan)])
        self.cli_set(command_list)

    def get_table_fdb(self, table='Fdb'):
        """Get Fbd table.

        Args:
            table(str):  Fbd record type to be returned ('Fbd' or 'Static')

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_fdb()
            env.switch[1].ui.get_table_fdb('Static')

        Raises:
            UIException:  table name required

        """
        self.exit_config_mode()
        if table == 'Fdb':
            commands = [['show mac-address-table'], ]
            cli_keys = {"Interface": "portId", "MAC Address": "macAddress", "VLAN": "vlanId", "Type": "type"}
            res_list = self.cli_get_all(commands)
            res_list = res_list[0].split('Interface')
            res_list[1] = 'Interface%s' % res_list[1]
            _table = self.process_table_data('show mac-address-table', [res_list[1]], cli_keys)
        elif table == 'Static':
            commands = [['show mac-address-table static'], ]
            cli_keys = {"Interface": "portId", "MAC Address": "macAddress", "VLAN": "vlanId"}
            res_list = self.cli_get_all(commands)
            _table = self.process_table_data('show mac-address-table static', res_list, cli_keys)
        else:
            raise UIException('Table name required')
        for _r in _table:
            _r['vlanId'] = int(_r['vlanId'])
            _r['portId'] = int(_r['portId'].split('e')[-1])
        return _table

    def clear_table_fdb(self):
        """Clear Fdb table.

        Returns:
            None

        Examples::

            env.switch[1].ui.clear_table_fdb()

        """
        command_list = []
        self.exit_config_mode()
        command_list.append(['clear mac-address-table'])
        self.cli_set(command_list)

# QoS configuration

    def get_table_ports_qos_scheduling(self, port=None, indexes=None, param=None):
        """Get PortsQoS scheduling information.

        Args:
            port(int):  port Id to get info about
            param(str):  param name to get info about

        Returns:
            list[dict] | str | int: table (list of dictionaries) or dictionary or param value

        Examples::

            env.switch[1].ui.get_table_ports_qos_scheduling(port=1, param='schedMode')
            env.switch[1].ui.get_table_ports_qos_scheduling('Static')

        """
        self.exit_config_mode()
        cli_keys = {"Interface": 'portId',
                    "Sched Mode": 'schedMode',
                    "Trust Mode": 'trustMode',
                    'Weight0': 'schedWeight0',
                    'Weight1': 'schedWeight1',
                    'Weight2': 'schedWeight2',
                    'Weight3': 'schedWeight3',
                    'Weight4': 'schedWeight4',
                    'Weight5': 'schedWeight5',
                    'Weight6': 'schedWeight6',
                    'Weight7': 'schedWeight7'}

        not_int_values = ["portId", "schedMode", "trustMode"]

        def convert_srt_into_integer(table_row):
            """convert string values to integer

            """
            for key in table_row.keys():
                if key not in not_int_values:
                    table_row[key] = int(table_row[key])

        if port is not None:
            port_name = self.port_map[port]
            show_command = ['show mls qos scheduling interface %s' % port_name]
            res_list = self.switch.cli.cli_get_all([show_command])
            row = self.process_table_data(show_command[0], res_list, cli_keys)[0]
            convert_srt_into_integer(row)
            if row['schedMode'] == 'WRR':
                row['schedMode'] = 'WeightedDeficitRoundRobin'
            if param is not None:
                return row[param]
            else:
                return row
        else:
            show_command = ['show mls qos scheduling']
            res_list = self.switch.cli.cli_get_all([show_command])
            table = self.process_table_data(show_command[0], res_list, cli_keys)

            for idx, value in enumerate(table):
                convert_srt_into_integer(table[idx])
                if table[idx]['schedMode'] == 'WRR':
                    table[idx]['schedMode'] = 'WeightedDeficitRoundRobin'

            return table

    def get_table_ports_dot1p2cos(self, port=None, rx_attr_flag=True):
        """Get PortsDot1p2CoS table.

        Args:
            port(str|int):  port Id to get info about ('All' or port id)
            rx_attr_flag(bool):  whether get rx or tx attribute information

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ports_dot1p2cos(1)
            env.switch[1].ui.get_table_ports_dot1p2cos('All')

        """
        self.exit_config_mode()
        cli_keys = {"Interface": 'portId',
                    "Dot1p": 'Dot1p',
                    "CoS": 'CoS'}

        def convert_sting_to_int(table_row):
            """"Convert string value to integer

            """
            table_row["Dot1p"] = int(table_row["Dot1p"])
            table_row["CoS"] = int(table_row["CoS"])

            return table_row

        show_command = ['show mls qos map dot1p-cos']
        res_list = self.switch.cli.cli_get_all([show_command])
        table = self.process_table_data(show_command[0], res_list, cli_keys)
        table = [convert_sting_to_int(row) for row in table]

        for row in table:
            if row["portId"] == "All":
                row["portId"] = -1
            else:
                row["portId"] = self.name_to_portid_map[row["portId"]]

        if port is not None:
            if port == "All":
                return [row for row in table if row["portId"] == -1]
            else:
                return [row for row in table if row["portId"] == port]
        else:
            return table

    def configure_cos_global(self, **kwargs):
        """Configure global mapping of ingress VLAN priority to CoS per port or per switch (PortsDot1p2CoS records).

        Args:
            **kwargs(dict):  parameters to be modified

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_cos_global(dotp2CoS=6)

        """
        qos_commands = []
        config_dot1 = False
        for _key in kwargs:
            if 'dotp' in _key:
                config_dot1 = True
                break

        # Configure dot1p-cos mapping
        if config_dot1:
            _map = "mls qos map dot1p-cos "
            current_mapping = self.get_table_ports_dot1p2cos(port="All")
            self.enter_config_mode()
            current_mapping = {row["Dot1p"]: row["CoS"] for row in current_mapping}

            for i in range(8):
                try:
                    val = kwargs['dotp%sCoS' % (i, )]
                except KeyError:
                    val = current_mapping[i]
                _map = _map + str(val) + " "
            qos_commands.append([_map])

        self.cli_set(qos_commands)

    def configure_dscp_to_cos_mapping_global(self, **kwargs):
        """Configure DSCP to Cos mapping.

        """
        raise SwitchException("Functionality is not implemented completely via CLI")

    def get_table_ports_dscp2cos(self):
        """Get PortsDSCP2CoS table.

        """
        raise SwitchException("Functionality is not implemented completely via CLI")

    def configure_schedweight_to_cos_mapping(self, ports, **kwargs):
        """Configure Weight to CoS mapping.

        """
        raise SwitchException("Functionality is not implemented completely via CLI")

    def configure_port_cos(self, ports=None, **kwargs):
        """Configure PortsQoS records.

        Args:
            ports(list[int]):  list of ports to be modified
            **kwargs(dict):  parameters to be modified

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_port_cos([1, ], trustMode='Dot1p')

        """
        self.enter_config_mode()
        in_ports = ",".join([self.port_map[x] for x in ports])
        commands = [["interface range %s" % (in_ports, )], ]
        # Configure mode
        if 'trustMode' in kwargs:
            if kwargs['trustMode'] == 'None':
                commands.append(['no mls qos trust'])
            else:
                commands.append(['mls qos trust %s' % (kwargs['trustMode'].lower())])

        if 'schedMode' in kwargs:
            if kwargs['schedMode'] == 'WeightedDeficitRoundRobin':
                commands.append(['wrr-queue bandwidth 0 0 0 0 0 0 0 0'])

        config_band = False
        for _key in kwargs:
            if 'Bandwidth' in _key:
                config_band = True
                break
        if config_band:
            _map = "mls qos map cos-bandwidth "
            for i in range(0, 8):
                try:
                    val = kwargs['cos%sBandwidth' % (i, )]
                except KeyError:
                    val = -1
                _map = _map + str(val) + " "
            commands.append([_map])

        config_weight = False
        for _key in kwargs:
            if 'Weight' in _key:
                config_weight = True
                break
        if config_weight:
            _map = "wrr-queue bandwidth "
            for i in range(8):
                try:
                    val = kwargs['schedWeight%s' % (i, )]
                except KeyError:
                    val = 0
                _map = _map + str(val) + " "
            commands.append([_map])

        self.cli_set(commands)

    def create_dot1p_to_cos_mapping(self, ports, rx_attr_flag=False, **kwargs):
        """Configure mapping of ingress VLAN priority to CoS per port or per switch (PortsDot1p2CoS mapping).

        Args:
            ports(list[int]):  list of ports to be modified
            rx_attr_flag(bool):  whether rx or tx attribute to be modified
            **kwargs(dict):  parameters to be modified

        Returns:
            None

        Examples::

            env.switch[1].ui.create_dot1p_to_cos_mapping([1, ], dotp7CoS=6)

        """
        cos_list = ["dotp%sCoS" % idx for idx in range(8)]
        self.enter_config_mode()
        qos_commands = []

        for cos in cos_list:
            assert cos in list(kwargs.keys()), "Not all eight CoS values transmitted for configuring CoS per port"

        for port in ports:
            qos_commands.append(["interface %s" % self.port_map[port]])
            _map = "mls qos map dot1p-cos "

            for i in range(8):
                val = kwargs['dotp%sCoS' % (i, )]
                _map = _map + str(val) + " "
            qos_commands.append([_map])
            qos_commands.append(["exit"])

        self.cli_set(qos_commands)

    def modify_dot1p_to_cos_mapping(self, ports, rx_attr_flag=False, **kwargs):
        """Modify mapping of ingress VLAN priority to CoS per port or per switch (PortsDot1p2CoS mapping).

        Args:
            ports(list[int]):  list of ports to be modified
            rx_attr_flag(bool):  whether rx or tx attribute to be modified
            **kwargs(dict):  parameters to be modified

        Returns:
            None

        Examples::

            env.switch[1].ui.modify_dot1p_to_cos_mapping([1, ], dotp7CoS=6)

        """
        self.enter_config_mode()
        qos_commands = []

        config_dot1 = False
        for _key in kwargs:
            if 'dotp' in _key:
                config_dot1 = True
                break

        # Configure dot1p-cos mapping
        if config_dot1:
            for port in ports:
                qos_commands.append(["interface %s" % self.port_map[port]])
                _map = "mls qos map dot1p-cos "
                current_mapping = self.get_table_ports_dot1p2cos(port=port)
                current_mapping = {row["Dot1p"]: row["CoS"] for row in current_mapping}

                for i in range(8):
                    try:
                        val = kwargs['dotp%sCoS' % (i, )]
                    except KeyError:
                        val = current_mapping[i]
                    _map = _map + str(val) + " "
                qos_commands.append([_map])
                qos_commands.append(["exit"])

        self.cli_set(qos_commands)

    def clear_per_port_dot1p_cos_mapping(self, ports, rx_attr_flag=False, dot1p=None):
        """Clear CoS per port mapping.

        """
        self.enter_config_mode()
        qos_commands = []

        for port in ports:
            qos_commands.append(["interface %s" % self.port_map[port]])
            _map = "no mls qos map dot1p-cos "
            qos_commands.append([_map])
            qos_commands.append(["exit"])

        self.cli_set(qos_commands)

    def map_stat_name(self, generic_name):
        """Get the UI specific stat name for given generic name.

        Args:
            generic_name(str): generic statistic name

        Returns:
            str: UI specific stat name

        """
        return STAT_MAP.get(generic_name, generic_name)

# Statistics configuration
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
        stat_name = self.map_stat_name(stat_name)
        self.exit_config_mode()
        commands = []
        cli_keys = {"Interface": "portId",
                    "RX Broadcast Pkts": "IfInBroadcastPkts",
                    "RX Discards": "IfInDiscards",
                    "RX Errors": "IfInErrors",
                    "RX Multicast Pkts": "IfInMulticastPkts",
                    "RX NUcast Pkts": "IfInNUcastPkts",
                    "RX Octets": "IfInOctets",
                    "RX Ucast Pkts": "IfInUcastPkts",
                    "TX Broadcast Pkts": "IfOutBroadcastPkts",
                    "TX Discards": "IfOutDiscards",
                    "TX Errors": "IfOutErrors",
                    "TX Multicast Pkts": "IfOutMulticastPkts",
                    "TX NUcast Pkts": "IfOutMulticastPkts",
                    "TX Octets": "IfOutOctets",
                    "TX QLen": "IfOutQLen",
                    "TX Ucast Pkts": "IfOutUcastPkts"}
        if port == 'cpu':
            cli_keys = {"Interface": "portId",
                        "Dot1d Base Delay Exceeded Discards": "Dot1dBasePortDelayExceededDiscards",
                        "Dot1d Base MTU Exceeded Discards": "Dot1dBasePortMtuExceededDiscards",
                        "Dot1dTp In Discards": "Dot1dPortInDiscards",
                        "Dot1dTp In Frames": "Dot1dTpPortInFrames",
                        "Dot1dTp Out Frames": "Dot1dTpPortOutFrames",
                        "Dot3 Control In Unknown Opcodes": "Dot3ControlInUnknownOpcodes",
                        "Dot3 In Pause Frames": "Dot3InPauseFrames",
                        "Dot3 Alignment Errors": "Dot3StatsAlignmentErrors",
                        "Dot3 Carrier Sense Errors": "Dot3StatsCarrierSenseErrors",
                        "Dot3 Deferred Transmissions": "Dot3StatsDeferredTransmissions",
                        "Dot3 Excessive Collisions": "Dot3StatsExcessiveCollisions",
                        "Dot3 FCS Errors": "Dot3StatsFCSErrors",
                        "Dot3 Frame Too Long": "Dot3StatsFrameTooLongs",
                        "Dot3 Internal MAC Receive Errors": "Dot3StatsInternalMacReceiveErrors",
                        "Dot3 Internal MAC Transmit Errors": "Dot3StatsInternalMacTransmitErrors",
                        "Dot3 Late Collisions": "Dot3StatsLateCollisions",
                        "Dot3 Multiple Collision Frames": "Dot3StatsMultipleCollisionFrames",
                        "Dot3 Single Collision Frames": "Dot3StatsSingleCollisionFrames",
                        "Dot3 SQET Test Errors": "Dot3StatsSQETTestErrors",
                        "Dot3 Symbol Errors": "Dot3StatsSymbolErrors",
                        "Ethernet RX Oversize Packets": "EtherRxOversizePkts",
                        "Ethernet Broadcast Packets": "EtherStatsBroadcastPkts",
                        "Ethernet Collisions": "EtherStatsCollisions",
                        "Ethernet CRC Align Errors": "EtherStatsCRCAlignErrors",
                        "Ethernet Drop Events": "EtherStatsDropEvents",
                        "Ethernet Fragments": "EtherStatsFragments",
                        "Ethernet Jabbers": "EtherStatsJabbers",
                        "Ethernet Multicast Packets": "EtherStatsMulticastPkts",
                        "Ethernet Octets": "EtherStatsOctets",
                        "Ethernet Oversize Packets": "EtherStatsOversizePkts",
                        "Ethernet Packets": "EtherStatsPkts",
                        "Ethernet Packets 64 Octets": "EtherStatsPkts64Octets",
                        "Ethernet Packets 65 to 127 Octets": "EtherStatsPkts65to127Octets",
                        "Ethernet Packets 128 to 255 Octets": "EtherStatsPkts128to255Octets",
                        "Ethernet Packets 256 to 511 Octets": "EtherStatsPkts256to511Octets",
                        "Ethernet Packets 512 to 1023 Octets": "EtherStatsPkts512to1023Octets",
                        "Ethernet Packets 1024 to 1518 Octets": "EtherStatsPkts1024to1518Octets",
                        "Ethernet RX No Errors": "EtherStatsRXNoErrors",
                        "Ethernet TX No Errors": "EtherStatsTXNoErrors",
                        "Ethernet Undersize Packets": "EtherStatsUndersizePkts",
                        "Ethernet TX Oversize Packets": "EtherTxOversizePkts",
                        "Interface In Broadcast Packets": "IfInBroadcastPkts",
                        "Interface In Multicast Packets": "IfInMulticastPkts",
                        "Interface Out Broadcast Packets": "IfOutBroadcastPkts",
                        "Interface Out Multicast Packets": "IfOutMulticastPkts",
                        "Interface In Discards": "IfInDiscards",
                        "Interface In Octets": "IfInOctets",
                        "Interface In Errors": "IfInErrors",
                        "Interface In Not Unicast Packets": "IfInNUcastPkts",
                        "Interface In Unicast Packets": "IfInUcastPkts",
                        "Interface In Unknown Protos": "IfInUnknownProtos",
                        "Interface Out Discards": "IfOutDiscards",
                        "Interface Out Errors": "IfOutErrors",
                        "Interface Out Not Unicast Packets": "IfOutNUcastPkts",
                        "Interface Out Octets": "IfOutOctets",
                        "Interface Out Query Length": "IfOutQLen",
                        "Interface Out Unicast Packets": "IfOutUcastPkts",
                        "IP Forward Datagrams": "IpForwDatagrams",
                        "IP In Discards": "IpInDiscards",
                        "IP In Headers Errors": "IpInHdrErrors",
                        "Interface HC In Octets": "IfHCInOctets",
                        "Interface HC In Unicast Packets": "IfHCInUcastPkts",
                        "Interface HC In Multicast Packets": "IfHCInMulticastPkts",
                        "Interface HC In Broadcast Packets": "IfHCInBroadcastPkts",
                        "Interface HC Out Octets": "IfHCOutOctets",
                        "Interface HC Out Unicast Packets": "IfHCOutUcastPkts",
                        "Interface HC Out Multicast Packets": "IfHCOutMulticastPkts",
                        "Interface HC Out Broadcast Packets": "IfHCOutBroadcastPckts",
                        "IPv6 Interface In Receives": "Ipv6IfStatsInReceives",
                        "IPv6 Interface In Headers Errors": "Ipv6IfStatsInHdrErrors",
                        "IPv6 Interface In Too Big Errors": "Ipv6IfStatsInTooBigErrors",
                        "IPv6 Interface In No Routes": "Ipv6IfStatsInNoRoutes",
                        "IPv6 Interface In Address Errors": "Ipv6IfStatsInAddrErrors",
                        "IPv6 Interface In Unknown Protocols": "Ipv6IfStatsInUnknownProtos",
                        "IPv6 Interface In Discards": "Ipv6IfStatsInDiscards",
                        "IPv6 Interface In Delivers": "Ipv6IfStatsInDelivers",
                        "IPv6 Interface Out Forward Datagrams": "Ipv6IfStatsOutForwDatagrams",
                        "IPv6 Interface Out Requests": "Ipv6IfStatsOutRequests",
                        "IPv6 Interface Out Discards": "Ipv6IfStatsOutDiscards",
                        "IPv6 Interface In Multicast Packets": "Ipv6IfStatsInMcastPkts",
                        "Interface VLAN Ingress Drop": "IfVlanIngressDrop"}
            show_command = ['show statistics interface cpu']
            commands.append(show_command)
            res_list = self.cli_get_all(commands)
            _table = [self.process_vertical_table_data(show_command[0], res_list, cli_keys), ]
        elif port:
            port_name = self.port_map[port]
            show_command = ['show statistics interface %s' % (port_name, )]
            commands.append(show_command)
            res_list = self.cli_get_all(commands)
            _table = [self.process_vertical_table_data(show_command[0], res_list, cli_keys), ]
        else:
            show_command = ['show statistics interface']
            commands.append(show_command)
            res_list = self.cli_get_all(commands)
            row_list = res_list[0].split('Interface .')
            _table = []
            for _row in row_list:
                _table.append(self.process_vertical_table_data(show_command[0], ['Interface .' + _row, ], cli_keys))
        for row in _table:
            for key in row:
                try:
                    row[key] = int(row[key])
                except ValueError:
                    pass
        if not stat_name:
            return _table
        else:
            stat_name = self.map_stat_name(stat_name)
            return _table[0][stat_name]

    def clear_statistics(self):
        """Clear Statistics.

        Returns:
            None

        Examples:

            env.switch[1].ui.clear_statistics()

        """
        self.exit_config_mode()
        commands = [['clear statistics ::::yes'], ]
        self.cli_set(commands)

# Bridge Info configuration
    def get_table_bridge_info(self, param=None, port=None):
        """Get Bridge Info table or specific parameter value in Bridge Info table

        Args:
            param(str):  parameter name (optional)
            port(int):  port ID (optional)

        Returns:
            list[dict]|str|int: table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_table_bridge_info()
            env.switch[1].ui.get_table_bridge_info('agingTime')

        """
        self.exit_config_mode()
        cli_system_keys = {'Default VLAN': 'defaultVlanId',
                           'Gateway': 'inbandDefaultGateway',
                           'IP Address': 'inbandIpAddress',
                           'Mask': 'inbandIpNetMask',
                           'MAC Address': 'macAddress',
                           'System Name': 'systemName',
                           'System Description': 'systemDesc'}
        cli_span_tree_keys = {'Aging Time': 'agingTime'}

        # TO DO: Add "queueCount" and "inbandEnabled" ReadOnly parameters

        table = {}
        if param is None or param != 'agingTime':
            show_command = ['show system']
            res_list = self.switch.cli.cli_get_all([show_command])
            table.update(self.process_vertical_table_data(show_command[0], res_list, cli_system_keys))
            table['defaultVlanId'] = int(table['defaultVlanId'])
            if table['inbandDefaultGateway'] == "N/A":
                table['inbandDefaultGateway'] = ""

        if param is None or param == 'agingTime':
            show_command = ['show spanning-tree']
            res_list = self.switch.cli.cli_get_all([show_command])
            table.update(self.process_vertical_table_data(show_command[0], res_list, cli_span_tree_keys))
            table['agingTime'] = int(table['agingTime'])

        if param is None:
            if not isinstance(table, list) and table:
                table = [table, ]

            return table
        else:
            return table[param]

    def modify_bridge_info(self, **kwargs):
        """Modify BridgeInfo table.

        Args:
            **kwargs(dict):  Parameters to be modified:
                             "agingTime" - set agingTime value;
                             "defaultVlanId" - set defaultVlanId value.

        Returns:
            None

        Examples::

            env.switch[1].ui.modify_bridge_info(agingTime=5)

        """
        self.enter_config_mode()
        commands = []
        if 'agingTime' in kwargs:
            commands.append(['switch aging-time %s' % (
                kwargs['agingTime'], )])
        if 'defaultVlanId' in kwargs:
            commands.append(['switch default-vlan %s' % (
                kwargs['defaultVlanId'], )])
        if 'macAddress' in kwargs:
            commands.append(['switch mac-address %s' % (
                kwargs['macAddress'], )])

        self.cli_set(commands)

# LAG configuration
    def create_lag(self, lag=None, key=None, lag_type='Static', hash_mode='None'):
        """Create LAG instance.

        Args:
            lag(int):  LAG id
            key(int):  LAG key
            lag_type(str):  LAG type. 'Static'|'Dynamic'
            hash_mode(str):  LAG hash type:
                             'None'|'SrcMac'|'DstMac'|'SrcDstMac'|'SrcIp'|'DstIp'|
                             'SrcDstIp'|'L4SrcPort'|'L4DstPort'|'L4SrcPort,L4DstPort'|
                             'OuterVlanId'|'InnerVlanId'|'EtherType'|'OuterVlanPri'|
                             'InnerVlanPri'|'Dscp'|'IpProtocol'|'DstIp,L4DstPort'|
                             'SrcIp,L4SrcPort'|'SrcMac,OuterVlanId'|'DstMac,OuterVlanId'|
                             'SrcIp,DstIp,L4SrcPort'|'DstIp,IpProtocol'|'SrcIp,IpProtocol'|'Ip6Flow'

        Returns:
            None

        Examples::

            env.switch[1].ui.create_lag(3800, 1, 'Static', 'None')

        Raises:
            UIException:  lag required

        """
        self.enter_config_mode()
        commands = [['interface port-channel %s' % (lag, )]]
        if lag_type == 'Dynamic':
            commands.append(['lacp'])
        if key is not None:
            commands.append(['key %s' % (key, )])
        if hash_mode:
            # TODO: implement hashMode
            pass
        self.cli_set(commands)

    def delete_lags(self, lags=None):
        """Delete LAG instance.

        Args:
            lags(list[int]):  list of LAG Ids

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_lags([3800, ])

        """
        self.enter_config_mode()
        commands = []
        for lag in lags:
            commands.append(['no interface port-channel %s' % (lag, )])
        self.cli_set(commands)

    def get_table_lags(self):
        """Get LagsAdmin table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_lags()

        """
        self.exit_config_mode()
        command = [['show interface port-channel admin'], ]
        cli_keys = {'Port Channel': 'lagId',
                    'Name': 'name',
                    'Port Channel Type': 'lagControlType',
                    'Administrative LAG Key': 'actorAdminLagKey',
                    'Load-balance': 'hashMode'}
        res_list = self.cli_get_all(command)
        if 'Notice!' in res_list[0]:
            return []

        table_rows = res_list[0].replace(command[0][0], '').strip().split('Port Channel .')
        _table = []
        for row in table_rows:
            if row:
                _table.append(self.process_vertical_table_data(command[0][0], ['Port Channel .' + row, ], cli_keys))

        for row in _table:
            row['lagId'] = int(row['lagId'])
            row['actorAdminLagKey'] = int(row['actorAdminLagKey'])

        return _table

    def modify_lags(self, lag, key=None, lag_type=None, hash_mode=None):
        """Modify LagsAdmin table.

        Args:
            lag(int):  LAG id
            key(int):  LAG key
            lag_type(str):  LAG type (Static or Dynamic)
            hash_mode():  LAG hash mode

        Returns:
            None

        Examples:

            env.switch[1].ui.modify_lags(lag=3800, lag_type="Static")

        """
        self.enter_config_mode()
        commands = [['interface port-channel %s' % (lag, )], ]
        if key:
            commands.append(['key %s' % (key, )])
        if lag_type == 'Dynamic':
            commands.append(['lacp'])
        if lag_type == 'Static':
            commands.append(['no lacp'])
        if hash_mode:
            # TODO: implement hashMode
            pass

        self.cli_set(commands)

    def get_table_link_aggregation(self):
        """Get LinkAggregation table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_link_aggregation()

        """
        self.exit_config_mode()
        command = [['show port-channel'], ]
        cli_keys = {'MAC Address': 'macAddress',
                    'Priority': 'priority',
                    'Collector Maximum Delay': 'collectorMaxDelay',
                    'Port Channel Status': 'globalEnable',
                    'Load-balance': 'globalHash',
                    'Load-balance Mode': 'globalHashMode',
                    'LACP Status': 'lacpEnable'}

        res_list = self.switch.cli.cli_get_all(command)
        table_rows = [self.process_vertical_table_data(command[0][0], res_list, cli_keys)]
        for rows in table_rows:
            rows['collectorMaxDelay'] = int(rows['collectorMaxDelay'])
            rows['priority'] = int(rows['priority'])
        return table_rows

    def modify_link_aggregation(self, globalenable=None, collectormaxdelay=None, globalhashmode=None, priority=None, lacpenable=None):
        """Modify LinkAggregation table.

        Args:
            globalenable(str):  globalEnable parameter value
            collectormaxdelay(int):  collectorMaxDelay parameter value
            globalhashmode(str):  globalHashMode parameter value
            priority(int):  priority parameter value
            lacpenable(str):  lacpEnable parameter value

        Returns:
            None

        Examples::

            env.switch[1].ui.modify_link_aggregation(globalhashmode='SrcMac')

        """
        hash_mode = {'SrcMac': 'src-mac', 'DstMac': 'dst-mac',
                     'SrcIp': 'src-ip', 'DstIp': 'dst-ip'}
        self.enter_config_mode()
        command_list = []
        if globalenable == 'Disabled':
            command_list.append(['no port-channel disable'])
        elif globalenable == 'Enabled':
            command_list.append(['port-channel'])

        if collectormaxdelay:
            command_list.append(['port-channel collector-max-delay %s' % collectormaxdelay])

        if globalhashmode:
            command_list.append(['port-channel load-balance %s' % hash_mode[globalhashmode]])

        if priority:
            command_list.append(['lacp system-priority %s' % priority])

        if lacpenable == 'Disabled':
            command_list.append(['no lacp'])
        elif lacpenable == 'Enabled':
            command_list.append(['lacp enable'])

        self.cli_set(command_list)

    def create_lag_ports(self, ports, lag, priority=1, key=None, aggregation='Multiple', lag_mode='Passive', timeout='Long', synchronization=False,
                         collecting=False, distributing=False, defaulting=False, expired=False, partner_system='00:00:00:00:00:00', partner_syspri=32768,
                         partner_number=1, partner_key=0, partner_pri=32768):
        """Add ports into created LAG.

        Args:
            ports( list[int]):  list of ports to be added into LAG
            lag(int):  LAG Id
            priority(int):  LAG priority
            key(int):  LAG key
            aggregation(str):  LAG aggregation
            lag_mode(str):  LAG mode
            timeout(str):  LAG timeout
            synchronization(bool):  LAG synchronization
            collecting(bool):  LAG collecting
            distributing(bool):  LAG distributing
            defaulting(bool):  LAG defaulting
            expired(bool):  LAG expired
            partner_system(str):  LAG partner system MAC address
            partner_syspri(int):  LAG partner system priority
            partner_number(int):  LAG partner number
            partner_key(int):  LAG partner key
            partner_pri(int):  LAG partner priority

        Returns:
            None

        Examples::

            env.switch[1].ui.create_lag_ports([1, ], 3800, priority=1, key=5)

        """
        self.enter_config_mode()

        in_ports = ",".join([self.port_map[x] for x in ports])
        commands = [['interface range %s' % (in_ports, )], ['channel-group %s' % (lag, )]]
        if priority:
            commands.append(['channel-group %s lacp port-priority %s' % (lag, priority)])
        if key:
            commands.append(['channel-group %s key %s' % (lag, key)])
        commands.append(['channel-group %s aggregation %s' % (lag, aggregation.lower())])
        commands.append(['channel-group %s mode %s' % (lag, lag_mode.lower())])
        commands.append(['channel-group %s timeout %s' % (lag, timeout.lower())])
        if synchronization:
            commands.append(['channel-group %s synchronization' % (lag, )])
        if collecting:
            commands.append(['channel-group %s collecting' % (lag, )])
        if distributing:
            commands.append(['channel-group %s distributing' % (lag, )])
        if defaulting:
            commands.append(['channel-group %s defaulting' % (lag, )])
        if expired:
            commands.append(['channel-group %s expired' % (lag, )])
        commands.append(['channel-group %s partner system %s' % (lag, partner_system)])

        commands.append(['channel-group %s partner system priority %s' % (lag, partner_syspri)])
        commands.append(['channel-group %s partner number %s' % (lag, partner_number)])
        commands.append(['channel-group %s partner key %s' % (lag, partner_key)])
        commands.append(['channel-group %s partner priority %s' % (lag, partner_pri)])

        self.cli_set(commands)

    def modify_ports2lag(self, port, lag, priority=None, key=None, aggregation=None, lag_mode=None, timeout=None, synchronization=None,
                         collecting=None, distributing=None, defaulting=None, expired=None, partner_system=None, partner_syspri=None,
                         partner_number=None, partner_key=None, partner_pri=None):
        """Modify Ports2LagAdmin table.

        Args:
            port(int):  LAG port
            lag(int):  LAG Id
            priority(int):  port priority
            key(int):  port key
            aggregation(str):  port aggregation (multiple or individual)
            lag_mode(str):  LAG mode (Passive or Active)
            timeout(str):  port timeout (Short or Long)
            synchronization(str):  port synchronization (True or False)
            collecting(str):  port collecting (True or False)
            distributing(str):  port distributing (True or False)
            defaulting(str):  port defaulting state (True or False)
            expired(str):  port expired state (True or False)
            partner_system(str):  partner LAG MAC address
            partner_syspri(int):  partner LAG  priority
            partner_number(int):  partner port number
            partner_key(int):  partner port key
            partner_pri(int):  partner port priority

        Returns:
            None

        Examples::

            env.switch[1].ui.modify_ports2lag(1, 3800, priority=100)

        """
        self.enter_config_mode()

        in_ports = self.port_map[port]
        commands = [['interface %s' % in_ports]]
        if priority:
            commands.append(['channel-group %s lacp port-priority %s' % (lag, priority)])
        if key:
            commands.append(['channel-group %s key %s' % (lag, key)])
        if aggregation:
            commands.append(['channel-group %s aggregation %s' % (lag, aggregation.lower())])
        if lag_mode:
            commands.append(['channel-group %s mode %s' % (lag, lag_mode.lower())])
        if timeout:
            commands.append(['channel-group %s timeout %s' % (lag, timeout.lower())])
        if synchronization:
            commands.append(['channel-group %s synchronization' % (lag, )])
        if collecting:
            commands.append(['channel-group %s collecting' % (lag, )])
        if distributing:
            commands.append(['channel-group %s distributing' % (lag, )])
        if defaulting:
            commands.append(['channel-group %s defaulting' % (lag, )])
        if expired:
            commands.append(['channel-group %s expired' % (lag, )])
        if partner_system:
            commands.append(['channel-group %s partner system %s' % (lag, partner_system)])
        if partner_syspri:
            commands.append(['channel-group %s partner system priority %s' % (lag, partner_syspri)])
        if partner_number:
            commands.append(['channel-group %s partner number %s' % (lag, partner_number)])
        if partner_key:
            commands.append(['channel-group %s partner key %s' % (lag, partner_key)])
        if partner_pri:
            commands.append(['channel-group %s partner priority %s' % (lag, partner_pri)])

        self.cli_set(commands)

    def delete_lag_ports(self, ports, lag):
        """Delete ports from created LAG.

        Args:
            ports(list[int]):  list of ports to be added into LAG
            lag(int):  LAG Id

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_lag_ports([1, ], 3800)

        """
        self.enter_config_mode()

        in_ports = ",".join([self.port_map[x] for x in ports])
        commands = [['interface range %s' % (in_ports, )],
                    ['no channel-group %s' % (lag, )]]

        self.cli_set(commands)

    def get_table_ports2lag(self):
        """Get Ports2LagAdmin table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ports2lag()

        """
        self.exit_config_mode()
        command = [['show channel-group admin'], ['show chanel-group neighbor']]
        cli_keys = {'Port Channel': 'lagId',
                    'Interface': 'portId',
                    'Priority': 'actorPortPriority',
                    'Key': 'actorAdminPortKey',
                    'Aggregation': 'adminAggregation',
                    'Mode': 'adminActive',
                    'Time': 'adminTimeout',
                    'Synchronization': 'adminSynchronization',
                    'Collecting': 'adminCollecting',
                    'Distributing': 'adminDistributing',
                    'Defaulting': 'adminDefaulted',
                    'Expired': 'adminExpired'}
        res_list = self.cli_get_all(command)
        if 'Notice!' in res_list[0]:
            return []
        table_rows = res_list[0].replace(command[0][0], '').strip().split('Port Channel')
        _table = []
        for row in table_rows:
            if row.strip():
                _table.append(self.process_vertical_table_data(command[0][0], ['Port Channel     ' + row, ], cli_keys))
        for row in _table:
            row['portId'] = int(row['portId'].split('e')[-1])
            row['lagId'] = int(row['lagId'])
            row['actorAdminPortKey'] = int(row['actorAdminPortKey'])
            row['actorPortPriority'] = int(row['actorPortPriority'])
        return _table

    def get_table_lags_local(self, lag=None):
        """Get LagsLocal table.

        Args:
            lag(int):  LAG Id

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_lags_local()
            env.switch[1].ui.get_table_lags_local(3800)

        """
        self.exit_config_mode()
        command = [['show interface port-channel'], ]
        if lag:
            command = [['show interface port-channel %s' % (lag, )], ]
        cli_keys = {'Port Channel': 'lagId',
                    'Port Channel MAC Address': 'lagMacAddress',
                    'Operational Key': 'actorOperLagKey',
                    'Transmit State': 'transmitState',
                    'Receive State': 'receiveState',
                    'Ready to Send': 'ready'}
        res_list = self.cli_get_all(command)
        table_rows = res_list[0].replace(command[0][0], '').strip().split('Port Channel .')
        _table = []
        for row in table_rows[1:]:
            if row.strip():
                _table.append(self.process_vertical_table_data(command[0][0], ['Port Channel .' + row, ], cli_keys))
        for row in _table:
            row['lagId'] = int(row['lagId'])
            row['actorOperLagKey'] = int(row['actorOperLagKey'])
        return _table

    def get_table_lags_remote(self, lag=None):
        """Get LagsRemote table.

        Args:
            lag(int):  LAG Id

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_lags_remote()
            env.switch[1].ui.get_table_lags_remote(3800)

        """
        self.exit_config_mode()
        command = [['show interface port-channel neighbor'], ]
        if lag:
            command = [['show interface port-channel %s neighbor' % (lag, )], ]
        cli_keys = {'Local Port Channel': 'lagId',
                    'Neighbor Operational Key': 'partnerOperLagKey',
                    'Neighbor MAC Address': 'partnerSystemId',
                    'Neighbor System Priority': 'partnerSystemPriority'}
        res_list = self.cli_get_all(command)
        # workaround for CLI issue
        res_list = [res_list[0].split("\r\x1b[KSwitch #")[1]]
        _table = self.process_table_data(command[0][0], res_list, cli_keys, header_rows=2)

        for row in _table:
            row['lagId'] = int(row['lagId'])
            row['partnerOperLagKey'] = int(row['partnerOperLagKey'])
            row['partnerSystemPriority'] = int(row['partnerSystemPriority']) * 4096
        return _table

    def get_table_lags_local_ports(self, lag=None):
        """Get Ports2LagLocal table.

        Args:
            lag(int):  LAG Id

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_lags_local_ports()
            env.switch[1].ui.get_table_lags_local_ports(3800)

        """
        self.exit_config_mode()
        cli_keys = {'Interface': 'portId',
                    'Operational Conflict': 'operationalConflict',
                    'Operational Port Key': 'actorOperPortKey',
                    'Operational Port State': 'actorOperPortState',
                    'LACP Operational Status': 'lacpOperating',
                    'Churn Detection Status': 'actorChurn',
                    'Port Enabled': 'portEnabled',
                    'Selected Mode': 'selected',
                    'Received Counter': 'rxCounter',
                    'Transmit Counter': 'txCounter'}

        command = [['show channel-group detail'], ]
        if lag:
            command = [['show channel-group %s detail' % (lag, )], ]
        res_list = self.cli_get_all(command)
        lag_rows = res_list[0].replace(command[0][0], '').strip().split('Port Channel Interface .')
        _table = []
        for row in lag_rows[1:]:
            _lag_table = []
            if row.strip():
                lag = int(row.split('\n')[0].replace('.', '').strip())
                port_lag_rows = row.strip().split('Interface .')
                for port_row in port_lag_rows[1:]:
                    if '..' in port_row:
                        _lag_table.append(self.process_vertical_table_data(command[0][0], ['Interface .' + port_row, ], cli_keys))
                for _row in _lag_table:
                    _row['lagId'] = lag
            _table.extend(_lag_table)
        for row in _table:
            row['lagId'] = int(row['lagId'])
            row['portId'] = int(row['portId'].split('e')[-1])
            row['actorOperPortKey'] = int(row['actorOperPortKey'])
            row['rxCounter'] = int(row['rxCounter'])
            row['txCounter'] = int(row['txCounter'])

        return _table

    def get_table_lags_remote_ports(self, lag=None):
        """Get Ports2LagRemote table.

        Args:
            lag(int):  LAG Id

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_lags_remote_ports()
            env.switch[1].ui.get_table_lags_remote_ports(lag=3800)

        """
        self.enter_config_mode()
        cli_keys = {'Port Channel': 'lagId',
                    'Interface': 'portId',
                    'System': 'partnerOperSystem',
                    'System Priority': 'partnerOperSystemPriority',
                    'Port State': 'partnerOperPortState',
                    'Port Number': 'partnerOperPortNumber',
                    'Key': 'partnerOperKey',
                    'Port Priority': 'partnerOperPortPriority',
                    'Churn Detection Status': 'partnerChurn'}

        command = [['show channel-group neighbor'], ]
        if lag:
            command = [['show channel-group %s neighbor' % (lag, )], ]
        res_list = self.cli_get_all(command)
        table_rows = res_list[0].replace(command[0][0], '').strip().split('Port Channel .')
        _table = []
        for row in table_rows[1:]:
            if row.strip():
                _table.append(self.process_vertical_table_data(command[0][0], ['Port Channel .' + row, ], cli_keys))

        for row in _table:
            row['lagId'] = int(row['lagId'])
            row['portId'] = int(row['portId'].split('e')[-1])
            row['partnerOperPortPriority'] = int(row['partnerOperPortPriority'])
            row['partnerOperSystemPriority'] = int(row['partnerOperSystemPriority']) * 4096
            row['partnerOperPortNumber'] = int(row['partnerOperPortNumber'])
            row['partnerOperKey'] = int(row['partnerOperKey'])
        return _table

# IGMP configuration
    def configure_igmp_global(self, mode='Enabled', router_alert=None, unknown_igmp_behavior=None, query_interval=None, querier_robustness=None):
        """Modify IGMPSnoopingGlobalAdmin table.

        Args:
            mode(str):  mode parameter value. 'Enabled'|'Disabled'
            router_alert(str):  routerAlertEnforced parameter value. 'Enabled'|'Disabled'
            unknown_igmp_behavior(str):  unknownIgmpBehavior parameter value. 'Broadcast'|'Drop'
            query_interval(int):  queryInterval parameter value
            querier_robustness(int):  querierRobustness parameter value

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_igmp_global(mode='Enabled')

        Raises:
            UIException:  incorrect unknown-action type

        """
        self.enter_config_mode()
        commands = []
        if mode == 'Enabled':
            commands.append(['ip igmp snooping'])
        elif mode == 'Disabled':
            commands.append(['no ip igmp snooping'])
        if router_alert == 'Enabled':
            commands.append(['ip igmp snooping router-alert'])
        elif router_alert == 'Disabled':
            commands.append(['no ip igmp snooping router-alert'])
        if unknown_igmp_behavior:
            if unknown_igmp_behavior in ['Broadcast', 'Drop']:
                commands.append(['ip igmp snooping unknown-action %s' % (unknown_igmp_behavior.lower(), )])
            else:
                raise UIException('Wrong unknown-action type %s' % (unknown_igmp_behavior, ))
        if query_interval:
            commands.append(['ip igmp snooping query-interval %s' % (query_interval, )])
        if querier_robustness:
            commands.append(['ip igmp snooping querier-robustness %s' % (querier_robustness, )])
        self.cli_set(commands)

    def configure_igmp_per_ports(self, ports, mode='Enabled', router_port_mode=None):
        """Modify IGMPSnoopingPortsAdmin table.

        Args:
            ports(list[int]):  list of ports
            mode(str):  igmpEnabled parameter value. 'Enabled'|'Disabled'
            router_port_mode(str):  routerPortMode parameter value. 'Auto'|'Always'

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_igmp_per_ports([1, 2], mode='Enabled')

        """
        self.enter_config_mode()
        commands = []
        in_ports = ",".join([self.port_map[x] if x < MIN_LAG_ID else str(x) for x in ports])
        if 'e' in in_ports:
            commands.append(["interface range %s" % (in_ports, )])
        else:
            commands.append(["interface port-channel range %s" % (in_ports, )])
        if mode == 'Enabled':
            commands.append(['ip igmp snooping'])
        elif mode == 'Disabled':
            commands.append(['no ip igmp snooping'])
        if router_port_mode == 'Auto':
            commands.append(['no ip igmp snooping router-port'])
        elif router_port_mode == 'Always':
            commands.append(['ip igmp snooping router-port'])
        self.cli_set(commands)

    def create_multicast(self, port, vlans, macs):
        """Create StaticL2Multicast record.

        Args:
            port(int):  port Id
            vlans(list[int]):  list of vlans
            macs(list[str]):  list of multicast MACs

        Returns:
            None

        Examples::

            env.switch[1].ui.create_multicast(10, [5, ], ['01:00:05:11:11:11', ])

        Raises:
            UIException:  ports, vlans and macs required

        """
        if not port:
            raise UIException('Ports require')
        if not vlans:
            raise UIException('List of vlans require')
        if not macs:
            raise UIException('List of mac require')
        command_list = []
        self.enter_config_mode()
        if port < MIN_LAG_ID:
            _port = self.port_map[port]
        else:
            _port = "port-channel %s" % (port, )

        for _vlan in vlans:
            for _mac in macs:
                command_list.append(['mac-address-table multicast %s vlan %s interface %s' % (_mac, _vlan, _port)])
        self.cli_set(command_list)

    def delete_multicast(self, port=None, vlan=None, mac=None):
        """Delete StaticL2Multicast record.

        Args:
            port(int):  port Id
            vlan(int):  vlan Id
            mac(str):  multicast MAC

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_multicast(10, 5, '01:00:05:11:11:11')

        Raises:
            UIException:  port, vlan and mac required

        """
        if not port:
            raise UIException('PortID required')
        if not vlan:
            raise UIException('VlanID required')
        if not mac:
            raise UIException('MAC required')
        if port < MIN_LAG_ID:
            _port = self.port_map[port]
        else:
            _port = "port-channel %s" % (port, )
        self.enter_config_mode()
        command_list = [['no mac-address-table multicast %s vlan %s interface %s' % (mac, vlan, _port)]]
        self.cli_set(command_list)

    def get_table_l2_multicast(self):
        """Get L2Multicast table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_l2_multicast()

        """
        self.enter_config_mode()
        commands = [['show multicast'], ['show ip igmp snooping interface groups']]

        cli_keys = {'VLAN': 'vlanId',
                    'Interface': 'portId',
                    'Group MAC Address': 'macAddress',
                    'Group Type': 'type'}

        res_list = self.cli_get_all(commands)
        table = self.process_table_data(commands[0][0], [res_list[0], ], cli_keys)
        igmp_addresses = 'VLAN' + res_list[1].split('VLAN')[1]
        table_igmp = self.process_table_data(commands[1][0], [igmp_addresses, ], cli_keys)
        table.extend(table_igmp)
        for row in table:
            row['vlanId'] = int(row['vlanId'])
            row['portId'] = int(self.name_to_portid_map[row['portId']] if 'e' in row['portId'] else row['portId'])
        return table

    def get_table_igmp_snooping_global_admin(self, param=None):
        """Get IGMPSnoopingGlobalAdmin table.

        Args:
            param(str):  parameter name

        Returns:
            list[dict]|int|str:  table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_table_igmp_snooping_global_admin()
            env.switch[1].ui.get_table_igmp_snooping_global_admin('queryInterval')

        """
        self.enter_config_mode()
        commands = [['show ip igmp snooping'], ]

        cli_keys = {'Router Alert Detection': 'routerAlertEnforced',
                    'Unknown IGMP Behaviour': 'unknownIgmpBehaviour',
                    'Host Entry Timeout': 'querierRobustness',
                    'Router Port Timeout': 'queryInterval',
                    'IP IGMP status': 'mode'}

        res_list = self.cli_get_all(commands)
        table = [self.process_vertical_table_data(commands[0][0], res_list, cli_keys), ]
        for row in table:
            row['querierRobustness'] = int(row['querierRobustness'])
            row['queryInterval'] = int(row['queryInterval'])
        if param:
            return table[0][param]
        else:
            return table

    def get_table_igmp_snooping_port_oper(self, port, param=None):
        """Get IGMPSnoopingPortsOper table.

        Args:
            port(int):  port Id
            param(str):  parameter name

        Returns:
            list[dict]|int|str: table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_table_igmp_snooping_port_oper()
            env.switch[1].ui.get_table_igmp_snooping_port_oper('queryInterval')

        """
        self.enter_config_mode()
        if port < MIN_LAG_ID:
            commands = [["show ip igmp snooping interface %s" % (self.port_map[port], )], ]
        else:
            commands = [["show ip igmp snooping interface port-channel %s" % (port, )], ]

        cli_keys = {'Router Port Administrative Status': 'routerPort',
                    'Host Port': 'hostPort',
                    'RX IGMP v1 Queries': 'rxIgmpQueriesV1',
                    'RX IGMP v2 Queries': 'rxIgmpQueriesV2',
                    'RX IGMP v3 Queries': 'rxIgmpQueriesV3',
                    'RX IGMP v1 Reports': 'rxIgmpReportsV1',
                    'RX IGMP v2 Reports': 'rxIgmpReportsV2',
                    'RX IGMP v3 Reports': 'rxIgmpReportsV3',
                    'RX IGMP Leaves': 'rxIgmpLeaves',
                    'Number Of Groups': 'numGroups'}

        res_list = self.cli_get_all(commands)
        vert_data = res_list[0].split('Groups:')[0]
        table = [self.process_vertical_table_data(commands[0][0], [vert_data, ], cli_keys), ]
        for row in table:
            row['rxIgmpQueriesV1'] = int(row['rxIgmpQueriesV1'])
            row['rxIgmpQueriesV2'] = int(row['rxIgmpQueriesV2'])
            row['rxIgmpQueriesV3'] = int(row['rxIgmpQueriesV3'])
            row['rxIgmpReportsV1'] = int(row['rxIgmpReportsV1'])
            row['rxIgmpReportsV2'] = int(row['rxIgmpReportsV2'])
            row['rxIgmpReportsV3'] = int(row['rxIgmpReportsV3'])
            row['rxIgmpLeaves'] = int(row['rxIgmpLeaves'])
            row['numGroups'] = int(row['numGroups'])
        if param:
            return table[0][param]
        else:
            return table

    def clear_l2_multicast(self):
        """Clear L2Multicast table.

        Returns:
            None

        Examples::

            env.switch[1].ui.clear_l2_multicast()

        """
        self.exit_config_mode()
        commands = [['clear mac-address-table multicast'], ]
        self.cli_set(commands)

# L3 configuration
    def configure_routing(self, routing='Enabled', ospf=None):
        """Configure L3 routing.

        Args:
            routing(str):  enable L3 routing
            ospf(str|None):  enable OSPF. None|'Enabled'

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_routing(routing='Enabled', ospf='Enabled')

        """
        self.enter_config_mode()
        commands = []
        if routing == 'Enabled':
            commands.append(['ip routing'])
        elif routing == 'Disabled':
            commands.append(['no ip routing'])
        if ospf == 'Enabled':
            commands.append(['router ospf'])
        self.cli_set(commands)

    def create_route_interface(self, vlan, ip, ip_type='InterVlan', bandwidth=1000, mtu=1500, status='Enabled', vrf=0, mode='ip'):
        """Create Route Interface.

        Args:
            vlan(int):  vlan Id
            ip(str):  Route Interface network
            ip_type(str):  Route interface type
            bandwidth(int):  Route interface bandwidth
            mtu(int):  Route interface mtu
            status(str):  Route interface status
            vrf(int):  Route interface vrf
            mode(str):  'ip' or 'ipv6'

        Returns:
            None

        Examples::

            env.switch[1].ui.create_route_interface(10, '10.0.5.101/24', 'InterVlan', 1000, 1500, 'Enabled, 0, 'ip')
            env.switch[1].ui.create_route_interface(10, '2000::01/96', 'InterVlan', 1000, 1500, 'Enabled, 0, 'ipv6')

        """
        self.enter_config_mode()
        commands = [['interface vlan %s' % (vlan, )], ['%s address %s mtu %s bandwidth %s' % (mode, ip, mtu, bandwidth)]]
        self.cli_set(commands)
        self.ris[ip] = {'ifName': 'IfVlan%s' % (vlan, )}

    def delete_route_interface(self, vlan, ip, bandwith=1000, mtu=1500, vrf=0, mode='ip'):
        """Delete Route Interface.

        Args:
            vlan(int):  vlan Id
            ip(str):  Route Interface network
            bandwith(int):  Route interface bandwidth
            mtu(int):  Route interface mtu
            vrf(int):  Route interface vrf
            mode(str):  'ip' or 'ipv6'

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_route_interface(10, '10.0.5.101/24', 1000, 1500, 0, 'ip')
            env.switch[1].ui.create_route_interface(10, '2000::01/96', 1000, 1500, 0, 'ipv6')

        """
        self.enter_config_mode()
        commands = [['interface vlan %s' % (vlan, )], ['no %s address %s' % (mode, ip)]]
        self.cli_set(commands)

    def modify_route_interface(self, vlan, ip, **kwargs):
        """Modify Route Interface.

        Args:
            vlan(int):  vlan Id
            ip(str):  Route Interface network
            **kwargs(dict):   parameters to be modified:
                             "adminMode" - set adminMode value.

        Returns:
            None

        Examples::

            env.switch[1].ui.modify_route_interface(10, '10.0.5.101/24', adminMode='Disabled')

        """
        self.enter_config_mode()
        commands = [['interface vlan %s' % (vlan, )], ]
        if 'adminMode' in kwargs:
            if kwargs['adminMode'] == 'Disabled':
                commands.append(['shutdown'])
            elif kwargs['adminMode'] == 'Enabled':
                commands.append(['no shutdown'])
        self.cli_set(commands)

    def get_table_route_interface(self):
        """Get RouteInterface table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_route_interface()

        """
        self.enter_config_mode()
        commands = [['show interface vlan'], ]

        cli_keys = {'Interface': 'interface',
                    'Interface Type': 'type',
                    'Operational Status': 'operationalStatus',
                    'Administrative Status': 'adminMode',
                    'MAC Address': 'mac',
                    'MTU': 'mtu',
                    'Bandwidth': 'bandwidth',
                    'Origin': 'origin',
                    'Name': 'ifName',
                    'IP Address': 'ipAddress',
                    'Authorisation Type': 'authmode'}

        res_list = self.cli_get_all(commands)

        table_rows = res_list[0].replace(commands[0][0], '').replace('Switch (config)#', '').strip().split('Interface ..')
        _table = []
        for row in table_rows:
            if row.strip():
                _row_data = 'Interface ..' + row
                _vert, _hor = _row_data.split('Name ')
                _row = self.process_vertical_table_data(commands[0][0], [_vert, ], cli_keys)
                ip_addresses = self.process_table_data(commands[0][0], ['Name ' + _hor + "\n\nSwitch #", ], cli_keys)
                for address in ip_addresses:
                    address.update(_row)
                    if address['ipAddress'] != '':
                        _table.append(address)
        for row in _table:
            row['interface'] = int(row['interface'])
            row['bandwidth'] = int(row['bandwidth'])
            row['mtu'] = int(row['mtu'])
            row['VRF'] = 0
        return _table

    def get_table_route(self, mode='ip'):
        """Get Route table.

        Args:
            mode(str):  'ip' or 'ipv6'

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_route()

        """
        self.enter_config_mode()
        commands = [['show %s route' % (mode, )], ]
        cli_keys = {'Route': 'routeId',
                    'Interface ID': 'ifId',
                    'Network': 'network',
                    'Interface Name': 'ifName',
                    'Next Hop': 'nexthop',
                    'Metric': 'metric',
                    'Protocol': 'protocol',
                    'State': 'state'}

        res_list = self.cli_get_all(commands)
        if 'There are no configured ip routes' in res_list[0]:
            return []
        table = []
        for row in res_list[0].split('Interface Name')[1:]:
            table.append(self.process_vertical_table_data(commands[0][0], ['\nInterface Name' + row, ], cli_keys))
        return table

    def configure_arp(self, garp=None, refresh_period=None, delay=None, secure_mode=None, age_time=None, attemptes=None, arp_len=None):
        """Configure ARPConfig table.

        Args:
            garp(str):  AcceptGARP value. 'True'|'False'
            refresh_period(int):  RefreshPeriod value
            delay(int):  RequestDelay value
            secure_mode(str):  SecureMode value. 'True'|'False'
            age_time(int):  AgeTime value
            attemptes(int):  NumAttempts value
            arp_len(int):  length value for ARP

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_arp(garp='Enabled')

        """
        self.enter_config_mode()
        commands = []
        if garp == 'True':
            commands.append(['ip arp acceptgarp'])
        elif garp == 'False':
            commands.append(['no ip arp acceptgarp'])
        if refresh_period:
            commands.append(['ip arp refreshperiod %s' % (refresh_period, )])
        if delay:
            commands.append(['ip arp requestdelay %s' % (delay, )])
        if secure_mode == 'True':
            commands.append(['ip arp securemode'])
        if secure_mode == 'False':
            commands.append(['no ip arp securemode'])
        if age_time:
            commands.append(['ip arp agetime %s' % (age_time, )])
        if attemptes:
            commands.append(['ip arp numattempts %s' % (attemptes, )])
        self.cli_set(commands)

    def get_table_arp_config(self):
        """Get ARPConfig table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_arp_config()

        """
        self.enter_config_mode()
        commands = [['show arp configuration'], ]
        cli_keys = {'Secure mode': 'SecureMode',
                    'Gratuitous ARP': 'AcceptGARP',
                    'Age time': 'AgeTime',
                    'Number of attempts': 'NumAttempts',
                    'Refresh period': 'RefreshPeriod',
                    'Request delay': 'RequestDelay'}

        res_list = self.cli_get_all(commands)
        table = [self.process_vertical_table_data(commands[0][0], res_list, cli_keys)]
        for row in table:
            row['AgeTime'] = int(row['AgeTime'])
            row['NumAttempts'] = int(row['NumAttempts'])
            row['RefreshPeriod'] = int(row['RefreshPeriod'])
            row['RequestDelay'] = int(row['RequestDelay'])
        return table

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
        self.enter_config_mode()
        if_name = self.ris[network]['ifName']
        commands = [['%s %s %s %s' % (mode, if_name + str(" "), ip, mac)], ]
        self.cli_set(commands)

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
        self.enter_config_mode()
        commands = [['no %s %s' % (mode, ip)], ]
        self.cli_set(commands)

    def get_table_arp(self, mode='arp'):
        """Get ARP table.

        Args:
            mode(str):  'arp' or 'ipv6 neigbor'

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_arp()

        """
        self.enter_config_mode()
        commands = [['show %s' % (mode, )], ]

        cli_keys = {'MAC Address': 'phyAddress',
                    'IP Address': 'netAddress',
                    'Interface Name': 'ifName',
                    'Type': 'type'}

        res_list = self.cli_get_all(commands)
        table = self.process_table_data(commands[0][0], res_list, cli_keys)
        return table

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
        self.enter_config_mode()
        if_name = self.ris[network]['ifName'] + str(" ")
        commands = [['%s route %s %s %s %s' % (mode, ip, if_name, nexthop, distance if distance > 0 else '')], ]
        self.cli_set(commands)

    def delete_static_route(self, network):
        """Delete StaticRoute record.

        Args:
            network(str):  RouteInterface network

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_static_route('10.0.5.101/24')

        """
        self.enter_config_mode()
        commands = [['no ip route %s' % network], ]
        self.cli_set(commands)

    def get_table_static_route(self, mode='ip'):
        """Get StaticRoute table.

        Args:
            mode(str):  'ip' or 'ipv6'

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_static_route()

        """
        self.enter_config_mode()
        commands = [['show %s route static' % (mode, )], ]
        cli_keys = {'Interface ID': 'ifId',
                    'Network': 'network',
                    'Interface Name': 'ifName',
                    'Next Hop': 'nexthop',
                    'Distance': 'distance',
                    'VRF': 'VRF'}

        res_list = self.cli_get_all(commands)
        table_data = '\nInterface Name' + res_list[0].split('Interface Name')[1]
        table = self.process_table_data(commands[0][0], [table_data, ], cli_keys)
        return table

    def configure_ospf_router(self, **kwargs):
        """Configure OSPFRouter table.

        Args:
            **kwargs(dict):  parameters to be modified:
                             "logAdjacencyChanges" - set logAdjacencyChanges value;
                             "routerId" - set routerId value.

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_ospf_router(routerId='1.1.1.1')

        """
        self.enter_config_mode()
        commands = [['router ospf'], ]
        if 'logAdjacencyChanges' in kwargs:
            if kwargs['logAdjacencyChanges'] == 'Enabled':
                commands.append(['log-adjacency-changes'])
        if 'routerId' in kwargs:
            commands.append(['router-id %s' % (kwargs['routerId'], )])
        self.cli_set(commands)

    def get_table_ospf_router(self):
        """Get OSPFRouter table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ospf_router()

        """
        self.enter_config_mode()
        commands = [['show ip ospf config'], ]
        cli_keys = {'Router': 'routerId',
                    'OSPF Status': 'ospfEnabled',
                    'ABR Type': 'abrType',
                    'rfc1583 Compatible': 'rfc1583Compat',
                    'Maximum Metric': 'maxMetricAdmin',
                    'Maximum Metric Startup': 'maxMetricStartup',
                    'Maximum Metric Shutdown': 'maxMetricShutdown',
                    'Auto-cost Reference Bandwidth': 'autoCostRefBandwidth',
                    'Throttle Timer Status': 'tTimers',
                    'Throttle Timer Initial Delay': 'ttStart',
                    'Throttle Timer Initial Hold Time': 'ttInitHoldTime',
                    'Throttle Timer Maximum Hold Time': 'ttMaxHoldTime'}
        res_list = self.cli_get_all(commands)
        table = [self.process_vertical_table_data(commands[0][0], [res_list[0], ], cli_keys)]
        for row in table:
            if row['routerId'] == 'N/A':
                row['routerId'] = ''
            row['maxMetricStartup'] = int(row['maxMetricStartup'])
            row['maxMetricShutdown'] = int(row['maxMetricShutdown'])
            row['autoCostRefBandwidth'] = int(row['autoCostRefBandwidth'])
            row['ttInitHoldTime'] = int(row['ttInitHoldTime'])
            row['ttMaxHoldTime'] = int(row['ttMaxHoldTime'])
            row['ttStart'] = int(row['ttStart'])
        return table

    def create_ospf_area(self, area, **kwargs):
        """Create OSPFAreas record.

        Args:
            area(int):  Area Id to be created
            **kwargs(dict):  parameters to be added

        Returns:
            None

        Examples::

            env.switch[1].ui.create_ospf_area("0.0.0.0")

        """
        self.enter_config_mode()
        commands = [['router ospf'], ['area %s' % (area, )]]
        self.cli_set(commands)

    def get_table_ospf_area(self):
        """Get OSPFAreas table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ospf_area()

        """
        self.enter_config_mode()
        commands = [['show ip ospf area'], ]
        res_list = self.cli_get_all(commands)
        cli_keys = {'Area': 'area',
                    'Default Cost': 'defaultCost',
                    'Shortcut': 'shortcut',
                    'Stub': 'stub',
                    'Authentication': 'authentication',
                    'Export List': 'exportList',
                    'Import List': 'importList',
                    'Filter List In Prefix': 'filterListPrefixIn',
                    'Filter List Out Prefix': 'filterListPrefixOut',
                    'NSSA': 'nssa',
                    'NSSA Translate': 'nssaTranslate'}

        res_list = self.cli_get_all(commands)
        table = [self.process_vertical_table_data(commands[1][0], [res_list[1], ], cli_keys)]
        for row in table:
            row['defaultCost'] = int(row['defaultCost'])
            if row['exportList'] == 'N/A':
                row['exportList'] = ''
            if row['importList'] == 'N/A':
                row['importList'] = ''
            if row['filterListPrefixIn'] == 'N/A':
                row['filterListPrefixIn'] = ''
            if row['filterListPrefixOut'] == 'N/A':
                row['filterListPrefixOut'] = ''
        return table

    def create_network_2_area(self, network, area, mode):
        """Create OSPFNetworks2Area record.

        Args:
            network(str):  RouteInterface network
            area(int):  Area Id
            mode(str):  Area mode

        Returns:
            None

        Examples::

            env.switch[1].ui.create_network_2_area('10.0.5.101/24', "0.0.0.0", 'Disabled')

        """
        _ip, cidr = network.split('/')
        _ip_list = _ip.split('.')
        _ip_list[-1] = '0'
        _ip = '.'.join(_ip_list)
        _network = "/".join([_ip, cidr])
        self.networks.append((network, _network))
        self.enter_config_mode()
        commands = [['router ospf'], ['network %s area %s' % (_network, area)]]
        self.cli_set(commands)

    def get_table_network_2_area(self):
        """Get OSPFNetworks2Area table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_network_2_area()

        """
        self.enter_config_mode()
        commands = [['show ip ospf area network-map'], ]
        cli_keys = {'Area': 'areaId',
                    'Network': 'network',
                    'Passive Interface': 'passive'}
        res_list = self.cli_get_all(commands)
        table = self.process_table_data(commands[1][0], [res_list[1], ], cli_keys)
        for row in table:
            row['network'] = [x[0] for x in self.networks if x[1] == row['network']][0]
        return table

    def create_area_ranges(self, area, range_ip, range_mask, substitute_ip, substitute_mask):
        """Create OSPFAreas2Ranges record.

        Args:
            area(int):  Area Id
            range_ip(str):  IP address
            range_mask(str):  mask
            substitute_ip(str):  IP address
            substitute_mask(str):  mask

        Returns:
            None

        Examples::

            env.switch[1].ui.create_area_ranges("0.0.0.0", "10.0.2.0", "255.255.255.0", "11.0.2.0", "255.255.255.0")

        """
        self.enter_config_mode()
        commands = [['router ospf'],
                    ['area %s range %s %s substitute %s %s advertise' % (area, range_ip, range_mask, substitute_ip, substitute_mask)]]
        self.cli_set(commands)

    def get_table_area_ranges(self):
        """Get OSPFAreas2Ranges table.

          Returns:
              list[dict]:  table (list of dictionaries)

          Examples::

              env.switch[1].ui.get_table_area_ranges()

          """
        self.enter_config_mode()
        commands = [['show ip ospf area filtering range'], ['show ip ospf area filtering substitute']]
        res_list = self.cli_get_all(commands)
        cli_keys = {'Area': 'areaId',
                    'IP Address': 'ipv4Range',
                    'IP Mask': 'ipv4RangeMask',
                    'Cost': 'cost',
                    'Advertise': 'advertise',
                    'Substitute': 'substitute',
                    'Substitute Prefix': 'substitutePrefix',
                    'Substitute Mask': 'substituteMask'}

        res_list = self.cli_get_all(commands)
        table1 = self.process_table_data(commands[1][0], [res_list[1], ], cli_keys)
        table2 = self.process_table_data(commands[2][0], [res_list[2], ], cli_keys)
        table = []
        for i, v in enumerate(table1):
            table1[i].update(table2[i])
            table.append(table1[i])
        return table

    def create_route_redistribute(self, mode):
        """Create OSPFRouteRedistribute record.

        Args:
            mode(str):  redistribute mode

        Returns:
            None

        Examples::

            env.switch[1].ui.create_route_redistribute("Static")

        """
        self.enter_config_mode()
        commands = [['router ospf'],
                    ['redistribute %s' % (mode.lower(), )]]
        self.cli_set(commands)

    def get_table_route_redistribute(self):
        """Get OSPFRouteRedistribute table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_route_redistribute()

        """
        self.enter_config_mode()
        commands = [['show ip ospf route-redistribute'], ]
        res_list = self.cli_get_all(commands)
        cli_keys = {'Source': 'source',
                    'Metric Type': 'metricType',
                    'Metric': 'metric',
                    'Route Map Id': 'routeMapId'}
        res_list = self.cli_get_all(commands)
        table = self.process_table_data(commands[1][0], [res_list[1], ], cli_keys)
        for row in table:
            row['metricType'] = int(row['metricType'])
            row['metric'] = int(row['metric'])
            row['routeMapId'] = int(row['routeMapId'])
        return table

    def create_interface_md5_key(self, vlan, network, key_id, key):
        """Create OSPFInterfaceMD5Keys record.

        Args:
            vlan(int):  Vlan Id
            network(str):  Route Interface network
            key_id(int):  key Id
            key(str):  key

        Returns:
            None

        Example:

            env.switch[1].ui.create_interface_md5_key(10, "10.0.5.101/24", 1, "Key1")

        """
        self.enter_config_mode()
        commands = [['interface vlan %s' % (vlan, )],
                    ['ip ospf message-digest-key %s md5 %s %s' % (key_id, key, network[:-3])]]
        self.cli_set(commands)

    def get_table_interface_authentication(self):
        """Get OSPFInterfaceMD5Keys table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_interface_authentication()

        """
        self.enter_config_mode()
        commands = [['show ip ospf interface keys'], ]
        res_list = self.cli_get_all(commands)
        cli_keys = {'Interface Name': 'ifName',
                    'Key': 'key',
                    'IP Address': 'interfaceIp'}
        res_list = self.cli_get_all(commands)
        table = []
        table = self.process_table_data(commands[1][0], [res_list[1], ], cli_keys)
        return table

    def create_ospf_interface(self, vlan, network, dead_interval=None, hello_interval=None, network_type=None, hello_multiplier=3,
                              minimal=None, priority=None, retransmit_interval=None):
        """Create OSPFInterface record.

        Args:
            vlan(int):  Vlan Id
            network(str):  Route Interface network
            dead_interval(int):  dead interval
            hello_interval(int):  hello interval
            network_type(str):  network type
            hello_multiplier(int):  hello multiplier
            minimal(str):  minimal
            priority(int):  priority
            retransmit_interval(int):  retransmit interval

        Returns:
            None

        Examples::

            env.switch[1].ui.create_ospf_interface(vlan_id, "10.0.5.101/24", 40, 5, network_type='Broadcast', minimal='Enabled', priority=1, retransmit_interval=3)

        """
        self.enter_config_mode()
        commands = [['interface vlan %s' % (vlan, )], ]
        if hello_interval:
            commands.append(['ip ospf hello-interval %s' % (hello_interval, )])
        if dead_interval:
            commands.append(['ip ospf dead-interval %s' % (dead_interval, )])
        if network_type:
            commands.append(['ip ospf network %s' % (network_type.lower(), )])
        if priority:
            commands.append(['ip ospf priority %s' % (priority, )])
        if retransmit_interval:
            commands.append(['ip ospf retransmit-interval %s' % (retransmit_interval, )])
        if minimal == 'Enabled':
            commands.append(['ip ospf dead-interval minimal hello-multiplier %s' % (hello_multiplier, )])
        self.cli_set(commands)

    def get_table_ospf_interface(self):
        """Get OSPFInterface table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_interface_authentication()

        """
        self.enter_config_mode()
        commands = [['show ip ospf interface'], ]
        res_list = self.cli_get_all(commands)
        cli_keys = {'Interface Name': 'ifName',
                    'Interface ID': 'ifId',
                    'Hello Interval': 'helloInterval',
                    'Transmit Delay': 'transmitDelay',
                    'Retransmit Interval': 'retransmitInterval',
                    'Cost': 'cost',
                    'Network': 'network',
                    'Priority': 'priority',
                    'Minimal Dead Interval': 'minimal',
                    'Hello Multiplier': 'helloMultiplier',
                    'Dead Interval': 'deadInterval'}
        res_list = self.cli_get_all(commands)
        table = [self.process_vertical_table_data(commands[1][0], [res_list[1], ], cli_keys)]
        for row in table:
            row['ifId'] = int(row['ifId'])
            row['helloInterval'] = int(row['helloInterval'])
            row['transmitDelay'] = int(row['transmitDelay'])
            row['retransmitInterval'] = int(row['retransmitInterval'])
            row['cost'] = int(row['cost'])
            row['priority'] = int(row['priority'])
            row['helloMultiplier'] = int(row['helloMultiplier'])
            row['deadInterval'] = int(row['deadInterval'])
        return table

    def create_area_virtual_link(self, area, link):
        """Create OSPFInterface record.

        Args:
            area(str):  OSPF Area
            link(str):  Virtual link IP

        Returns:
            None

        Examples::

            env.switch[1].ui.create_area_virtual_link("0.0.0.0", "1.1.1.2")

        """
        self.enter_config_mode()
        commands = [['router ospf'],
                    ['area %s virtual-link %s' % (area, link)]]
        self.cli_set(commands)

# BGP configuration
    def configure_bgp_router(self, asn=65501, enabled='Enabled'):
        """Modify BGPRouter record.

        Args:
            asn(int):  AS number
            enabled(str):  enabled status

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_bgp_router(asn=65501, enabled='Enabled')

        """
        self.enter_config_mode()
        commands = [['router bgp %s' % (asn, )], ]
        self.cli_set(commands)

    def create_bgp_neighbor_2_as(self, asn, ip, remote_as):
        """Create BGPNeighbor2As record.

        Args:
            asn(int):  AS number
            ip(str):  IP address
            remote_as(int):  Remote AS number

        Returns:
            None

        Examples::

            env.switch[1].ui.create_bgp_neighbor_2_as(65501, '10.0.5.102', 65502)

        """
        self.enter_config_mode()
        commands = [['router bgp %s' % (asn, )],
                    ['neighbor %s remote-as %s' % (ip, remote_as)]]
        self.cli_set(commands)

    def create_bgp_neighbor(self, asn=65501, ip='192.168.0.1'):
        """Create BGPNeighbor record.

        Args:
            asn(int):  AS number
            ip(str):  IP address

        Returns:
            None

        Examples::

            env.switch[1].ui.create_bgp_neighbor(asn=65501, ip='192.168.0.1')

        """
        self.enter_config_mode()
        commands = [['router bgp %s' % (asn, )],
                    ['neighbor %s description TEST' % (ip, )]]
        self.cli_set(commands)

    def create_bgp_neighbor_connection(self, asn=65501, ip='192.168.0.1', port=179):
        """Create BGPNeighborConnection record.

        Args:
            asn(int):  AS number
            ip(str):  IP address
            port(int):  connection port

        Returns:
            None

        Examples::

            env.switch[1].ui.create_bgp_neighbor_connection(asn=65501, ip='192.168.0.1', port=179)

        """
        self.enter_config_mode()
        commands = [['router bgp %s' % (asn, )],
                    ['neighbor %s port %s' % (ip, port)]]
        self.cli_set(commands)

    def create_bgp_bgp(self, asn=65501, router_id="1.1.1.1"):
        """Create BGPBgp record.

        Args:
            asn(int):  AS number
            router_id(int):  OSPF router Id

        Returns:
            None

        Examples::

            env.switch[1].ui.create_bgp_bgp(asn=65501, router_id="1.1.1.1")

        """
        self.enter_config_mode()
        commands = [['router bgp %s' % (asn, )],
                    ['bgp router-id %s' % (router_id, )],
                    ['bgp default ipv4-unicast']]
        self.cli_set(commands)

    def create_bgp_peer_group(self, asn=65501, name="mypeergroup"):
        """Create BGPPeerGroups record.

        Args:
            asn(int):  AS number
            name(str):  peer group name

        Returns:
            None

        Examples::

            env.switch[1].ui.create_bgp_peer_group(65501, "test_name")

        """
        self.enter_config_mode()
        commands = [['router bgp %s' % (asn, )],
                    ['neighbor %s peer-group' % (name, )]]
        self.cli_set(commands)

    def create_bgp_peer_group_member(self, asn=65501, name="mypeergroup", ip="12.1.0.2"):
        """Create BGPPeerGroupMembers record.

        Args:
            asn(int):  AS number
            name(str):  peer group name
            ip(str):  IP address

        Returns:
            None

        Examples::

            env.switch[1].ui.create_bgp_peer_group_member(65501, "test_name", "12.1.0.2")

        """
        self.enter_config_mode()
        commands = [['router bgp %s' % (asn, )],
                    ['neighbor %s peer-group %s' % (ip, name)]]
        self.cli_set(commands)

    def create_bgp_redistribute(self, asn=65501, rtype="OSPF"):
        """Create BGPRedistribute record.

        Args:
            asn(int):  AS number
            rtype(str):  redistribute type

        Returns:
            None

        Examples::

            env.switch[1].ui.create_bgp_redistribute(65501, "OSPF")

        """
        self.enter_config_mode()
        commands = [['router bgp %s' % (asn, )],
                    ['redistribute %s' % (rtype.lower(), )]]
        self.cli_set(commands)

    def create_bgp_network(self, asn=65501, ip='10.0.0.0', mask='255.255.255.0', route_map='routeMap'):
        """Create BGPNetwork record.

        Args:
            asn(int):  AS number
            ip(str):  IP address
            mask(str):  IP address mask
            route_map(str):  route map name

        Returns:
            None

        Examples::

            env.switch[1].ui.create_bgp_network(asn=65501, ip='10.0.0.0', mask='255.255.255.0', route_map='routeMap')

        """
        self.enter_config_mode()
        commands = [['router bgp %s' % (asn, )],
                    ['network %s %s route-map %s' % (ip, mask, route_map)]]
        self.cli_set(commands)

    def create_bgp_aggregate_address(self, asn=65501, ip='22.10.10.0', mask='255.255.255.0'):
        """Create BGPAggregateAddress record

        Args:
            asn(int):  AS number
            ip(str):  IP address
            mask(str):  IP address mask

        Returns:
            None

        Examples::

            env.switch[1].ui.create_bgp_aggregate_address(asn=65501, ip='10.0.0.0', mask='255.255.255.0')

        """
        self.enter_config_mode()
        commands = [['router bgp %s' % (asn, )],
                    ['aggregate-address  %s %s' % (ip, mask)]]
        self.cli_set(commands)

    def create_bgp_confederation_peers(self, asn=65501, peers=70000):
        """Create BGPBgpConfederationPeers record.

        Args:
            asn(int):  AS number
            peers(int):  peers number

        Returns:
            None

        Examples::

            env.switch[1].ui.create_bgp_confederation_peers(asn=65501, peers=70000)

        """
        self.enter_config_mode()
        commands = [['router bgp %s' % (asn, )],
                    ['bgp confederation peers %s' % (peers, )]]
        self.cli_set(commands)

    def create_bgp_distance_network(self, asn=65501, ip="40.0.0.0/24", mask='255.255.255.0', distance=100, route_map='routeMap'):
        """Create BGPDistanceNetwork record.

        Args:
            asn(int):  AS number
            ip(str):  IP address
            mask(str):  IP address mask
            distance(int):  IP address distance
            route_map(str):  route map name

        Returns:
            None

        Examples::

            env.switch[1].ui.create_bgp_distance_network(asn=65501, ip="40.0.0.0", mask='255.255.255.0', distance=100, route_map='routeMap')

        """
        self.enter_config_mode()
        commands = [['router bgp %s' % (asn, )],
                    ['distance %s %s %s %s' % (distance, ip, mask, route_map)]]
        self.cli_set(commands)

    def create_bgp_distance_admin(self, asn=65501, ext_distance=100, int_distance=200, local_distance=50):
        """Create BGPDistanceAdmin record.

        Args:
            asn(int):  AS number
            ext_distance(int):  external distance
            int_distance(int):  internal distance
            local_distance(int):  local distance

        Returns:
            None

        Examples::

            env.switch[1].ui.create_bgp_distance_admin(asn=65501, ext_distance=100, int_distance=200, local_distance=50)

        """
        self.enter_config_mode()
        commands = [['router bgp %s' % (asn, )],
                    ['distance bgp %s %s %s' % (ext_distance, int_distance, local_distance)]]
        self.cli_set(commands)

    def get_table_bgp_neighbor(self):
        """Get BGPNeighbour table.

        Returns:
            list[dict]: table

        Examples::

            env.switch[1].ui.get_table_bgp_neighbor()

        """
        self.enter_config_mode()
        commands = [['show ip bgp neighbor'], ]
        cli_keys = {"Address Family": "addrFamily",
                    "Address Family Cast": "addrFamilyCast",
                    "Allow AS In": "allowAsIn",
                    "ASN": "asn",
                    "Attribute Unchanged AS Path": "attributeUnchangedAsPath",
                    "Attribute Unchanged MED": "attributeUnchangedMed",
                    "Attribute Unchanged Next Hop": "attributeUnchangedNextHop",
                    "Capability Dynamic": "capabilityDynamic",
                    "Capability ORF Prefix List Receive": "capabilityOrfPrefixListRecv",
                    "Capability ORF Prefix List Send": "capabilityOrfPrefixListSend",
                    "Default Originate": "defaultOriginate",
                    "Default Originate Route Map": "defaultOriginateRouteMap",
                    "Description": "description",
                    "Disable Connected Check": "disableConnectedCheck",
                    "Distribute List In": "distributeListIn",
                    "Distribute List Out": "distributeListOut",
                    "Dont Capability Negotiate": "dontCapabilityNegotiate",
                    "eBGP Multihop": "ebgpMultihop",
                    "Enforce Multihop": "enforceMultihop",
                    "Filter List In": "filterListIn",
                    "Filter List Out": "filterListOut",
                    "Local AS": "localAs",
                    "Local AS No Prepend": "localAsNoPrepend",
                    "Maximum Prefix": "maximumPrefix",
                    "Maximum Prefix Restart Interval": "maximumPrefixRestartIntv",
                    "Maximum Prefix Threshold": "maximumPrefixThreshold",
                    "Maximum Prefix Warning Only": "maximumPrefixWarningOnly",
                    "Neighbor": "neighbor",
                    "Next Hop Self": "nextHopSelf",
                    "No Activate": "noActivate",
                    "No Send Community Extended": "noSendCommunityExtended",
                    "No Send Community Standard": "noSendCommunityStandard",
                    "Override Capability": "overrideCapability",
                    "Passive": "passive",
                    "Password": "password",
                    "Prefix List In": "prefixListIn",
                    "Prefix List Out": "prefixListOut",
                    "Remove Private AS": "removePrivateAs",
                    "Route Map Export": "routeMapExport",
                    "Route Map Import": "routeMapImport",
                    "Route Map In": "routeMapIn",
                    "Route Map Out": "routeMapOut",
                    "Route Reflector Client": "routeReflectorClient",
                    "Route Server Client": "routeServerClient",
                    "Shutdown": "shutdown",
                    "Soft Reconfiguration Inbound": "softReconfigurationInbound",
                    "Timers Hold Time": "timersHoldTime",
                    "Timers Keep Alive": "timersKeepAlive",
                    "TTL Security Hops": "ttlSecurityHops",
                    "Unsuppress Map": "unsuppressMap",
                    "Update Source": "updateSource",
                    "Weight": "weight"}
        res_list = self.cli_get_all(commands)
        neighbours = res_list[0].split('Address Family .')
        table = []
        for rec in neighbours:
            table.append(self.process_vertical_table_data(commands[0][0], ['Address Family .' + rec, ], cli_keys))
        return table

    def get_table_bgp_neighbor_connections(self):
        """Get BGPNeighborConnection table.

        Returns:
            list[dict]:  table

        Examples::

            env.switch[1].ui.get_table_bgp_neighbor_connections()

        """
        self.enter_config_mode()
        commands = [['show ip bgp neighbor connection'], ]
        cli_keys = {"ASN": "asn",
                    "Advertisement Interval": "advertisementInterval",
                    "Interface ID": "ifId",
                    "IP Address": "ipAddress",
                    "Port": "port",
                    "Strict Capability Match": "strictCapabilityMatch",
                    "Timers Connect": "timersConnect"}
        res_list = self.cli_get_all(commands)
        neighbours = res_list[0].split('ASN')
        table = []
        for rec in neighbours:
            table.append(self.process_vertical_table_data(commands[0][0], ['ASN' + rec, ], cli_keys))
        return table

    def get_table_bgp_aggregate_address(self):
        """Get BGPAggregateAddress table.

        Returns:
            list[dict]:  table

        Examples::

            env.switch[1].ui.get_table_bgp_aggregate_address()

        """
        def _get_mask(mask):
            if mask == '255.255.255.0':
                return '24'
        commands = [['show ip bgp aggregate-address'], ]
        cli_keys = {"Address Family": "addrFamily",
                    "Address Family Cast": "addrFamilyCast",
                    "ASN": "asn",
                    "Network Address": "network",
                    "Network Mask": "network_mask",
                    "AS Set": "asSet",
                    "Summary Only": "summaryOnly"}
        res_list = self.cli_get_all(commands)
        neighbours = res_list[0].split('Address Family .')
        table = []
        for rec in neighbours:
            if rec:
                table.append(self.process_vertical_table_data(commands[0][0], ['Address Family .' + rec, ], cli_keys))
        for row in table:
            row['network'] = '/'.join([row['network'], _get_mask(row['network_mask'])])
            del row['network_mask']
        return table

    def get_table_bgp_confederation_peers(self):
        """Get BGPBgpConfederationPeers table.

        Returns:
            list[dict] table

        Examples::

            env.switch[1].ui.get_table_bgp_confederation_peers()

        """
        commands = [['show ip bgp confederation peers'], ]
        cli_keys = {"ASN": "asn",
                    "Peer ID": "peerId"}
        res_list = self.cli_get_all(commands)
        table = self.process_table_data(commands[0][0], res_list, cli_keys)
        for row in table:
            row['asn'] = int(row['asn'])
            row['peerId'] = int(row['peerId'])
        return table

    def get_table_bgp_distance_admin(self):
        """Get BGPDistanceAdmin table.

        Returns:
            list[dict]: table

        Examples::

            env.switch[1].ui.get_table_bgp_distance_admin()

        """
        commands = [['show ip bgp distance admin'], ]
        cli_keys = {"ASN": "asn",
                    "External Distance": "distExt",
                    "Internal Distance": "distInt",
                    "Local Distance": "distLocal"}
        res_list = self.cli_get_all(commands)
        neighbours = res_list[0].split('ASN .')
        table = []
        for rec in neighbours:
            table.append(self.process_vertical_table_data(commands[0][0], ['ASN .' + rec, ], cli_keys))
        return table

    def get_table_bgp_distance_network(self):
        """Get BGPDistanceNetwork table.

        Returns:
            list[dict]: table

        Examples::

            env.switch[1].ui.get_table_bgp_distance_network()

        """
        commands = [['show ip bgp distance network'], ]
        cli_keys = {"ASN": "asn",
                    "Network": "network",
                    "Administrative Distance": "adminDistance",
                    "Route Map": "routeMap"}
        res_list = self.cli_get_all(commands)
        neighbours = res_list[0].split('ASN .')
        table = []
        for rec in neighbours:
            table.append(self.process_vertical_table_data(commands[0][0], ['ASN .' + rec, ], cli_keys))
        return table

    def get_table_bgp_network(self):
        """Get BGPNetwork table.

        Returns:
            list[dict]:  table

        Examples::

            env.switch[1].ui.get_table_bgp_network()

        """
        def _get_mask(mask):
            if mask == '255.255.255.0':
                return '24'
        commands = [['show ip bgp network'], ]
        cli_keys = {"Address Family": "addrFamily",
                    "Address Family Cast": "addrFamilyCast",
                    "ASN": "asn",
                    "Network": "network",
                    "Mask": "network_mask",
                    "Backdoor": "backdoor",
                    "Route Map": "routeMap"}
        res_list = self.cli_get_all(commands)
        neighbours = res_list[0].split('Address Family .')
        table = []
        for rec in neighbours:
            if rec:
                table.append(self.process_vertical_table_data(commands[0][0], ['Address Family .' + rec, ], cli_keys))
        for row in table:
            row['network'] = '/'.join([row['network'], _get_mask(row['network_mask'])])
            del row['network_mask']
        return table

    def get_table_bgp_peer_group_members(self):
        """Get BGPPeerGroupMembers table.

        Returns:
            list[dict]: table

        Examples::

            env.switch[1].ui.get_table_bgp_peer_group_members()

        """
        commands = [['show ip bgp peer-group members'], ]
        cli_keys = {"Address Family": "addrFamily",
                    "Address Family Cast": "addrFamilyCast",
                    "ASN": "asn",
                    "Peer Group": "peerGroup",
                    "Peer Ip": "peerIp"}
        res_list = self.cli_get_all(commands)
        table = self.process_table_data(commands[0][0], res_list, cli_keys)
        return table

    def get_table_bgp_peer_groups(self):
        """Get BGPPeerGroups table

        Returns:
            list[dict]:  table

        Example:

            env.switch[1].ui.get_table_bgp_peer_groups()

        """
        commands = [['show ip bgp peer-group'], ]
        cli_keys = {"ASN": "asn",
                    "Peer Group": "peerGroup"}
        res_list = self.cli_get_all(commands)
        table = self.process_table_data(commands[0][0], res_list, cli_keys)
        return table

    def get_table_bgp_redistribute(self):
        """Get BGPRedistribute table.

        Returns:
            list[dict]: table

        Examples::

            env.switch[1].ui.get_table_bgp_redistribute()

        """
        commands = [['show ip bgp route-redistribute'], ]
        cli_keys = {"Address Family": "addrFamily",
                    "Address Family Cast": "addrFamilyCast",
                    "ASN": "asn",
                    "metric": "metric",
                    "Route Map": "routeMap",
                    "Source": "source"}
        res_list = self.cli_get_all(commands)
        table = self.process_table_data(commands[0][0], res_list, cli_keys)
        return table

# OVS configuration
    def create_ovs_bridge(self, bridge_name):
        """Create OvsBridges record.

        Args:
            bridge_name(str):  OVS bridge name

        Returns:
            None

        Examples::

            env.switch[1].ui.create_ovs_bridge('spp0')

        """
        self.enter_config_mode()
        commands = [['ovs bridge add %s' % (bridge_name, )], ]
        self.cli_set(commands)

    def get_table_ovs_bridges(self):
        """Get OvsBridges table.

        Returns:
            list[dict]:  table (list of dictionaries))

        Examples::

            env.switch[1].ui.get_table_ovs_bridges()

        """
        self.enter_config_mode()
        commands = [['show ovs bridges'], ]
        cli_keys = {'Bridge': 'bridgeId',
                    'Name': 'name',
                    'Type': 'type'}
        res_list = self.cli_get_all(commands)
        bridges = res_list.split('Controller')[0] + "Switch#"
        return self.process_vertical_table_data(commands[1][0], [bridges, ], cli_keys)

    def delete_ovs_bridge(self):
        """Delete OVS Bridge.

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_ovs_bridge()

        """
        self.enter_config_mode()
        commands = [['no ovs bridge'], ]
        self.cli_set(commands)

    def create_ovs_port(self, port, bridge_name):
        """Create OvsPorts record.

        Args:
            port(int):  port Id
            bridge_name(str):  OVS bridge name

        Returns:
            None

        Examples::

            env.switch[1].ui.create_ovs_port(1, 'spp0')

        """
        self.enter_config_mode()
        if port < MIN_LAG_ID:
            port_name = self.port_map[port]
        else:
            port_name = "port-channel %s" % (port, )
        commands = [['interface %s' % port_name], ['ovs port add %s' % (bridge_name, )]]
        self.cli_set(commands)

    def get_table_ovs_ports(self):
        """Get OvsPorts table.

        Returns:
            list[dict]:  table (list of dictionaries))

        Examples::

            env.switch[1].ui.get_table_ovs_ports()

        """
        self.enter_config_mode()
        commands = [['show ovs ports'], ]
        cli_keys = {'Port': 'portId',
                    'Bridge': 'bridgeId',
                    'Name': 'name',
                    'Type': 'type'}
        res_list = self.cli_get_all(commands)
        table = self.process_table_data(commands[0][0], res_list, cli_keys)
        for row in table:
            row['portId'] = int(row['portId'])
            row['bridgeId'] = int(row['bridgeId'])
        return table

    def get_table_ovs_rules(self):
        """Get OvsFlowRules table.

        Returns:
            list[dict]: table (list of dictionaries))

        Examples::

            env.switch[1].ui.get_table_ovs_rules()

        """
        self.enter_config_mode()
        commands = [['show ovs flows rule'], ]
        cli_keys = {'Flow': 'flowId',
                    'Bridge': 'bridgeId',
                    'Table': 'tableId',
                    'Enabled': 'enabled',
                    'Priority': 'priority'}
        res_list = self.cli_get_all(commands)
        table = self.process_table_data(commands[0][0], res_list, cli_keys)
        for row in table:
            row['flowId'] = int(row['flowId'])
            row['tableId'] = int(row['tableId'])
            row['priority'] = int(row['priority'])
        return table

    def create_ovs_bridge_controller(self, bridge_name, controller):
        """Create OvsControllers record.

        Args:
            bridge_name(str):  OVS bridge name
            controller(str):  controller address

        Returns:
            None

        Examples::

            env.switch[1].ui.create_ovs_bridge_controller("spp0", "tcp:127.0.0.1:6633")

        """
        self.enter_config_mode()
        commands = [['ovs bridge controller %s %s ' % (bridge_name, controller)], ]
        self.cli_set(commands)

    def get_table_ovs_controllers(self):
        """Get OvsControllers table.

        Returns:
            list[dict]:  table (list of dictionaries))

        Examples::

            env.switch[1].ui.get_table_ovs_controllers()

        """
        self.enter_config_mode()
        commands = [['show ovs bridges'], ]
        cli_keys = {'Controller': 'controller', }
        res_list = self.cli_get_all(commands)
        controllers = 'Controller' + res_list[0].split('Controller')[1]
        return self.process_table_data(commands[0][0], [controllers, ], cli_keys)

    def create_ovs_flow_rules(self, bridge_id, table_id, flow_id, priority, enabled):
        """Create OvsFlowRules table.

        Args:
            bridge_id(int):  OVS bridge ID
            table_id(int):  Table ID
            flow_id(int):  Flow ID
            priority(int):  Rule priority
            enabled(str):  Rule status

        Returns:
            None

        Examples::

            env.switch[1].ui.create_ovs_flow_rules(0, 0, 1, 2000, "Enabled")

        """
        self.enter_config_mode()
        commands = [['ovs flow %s %s %s %s' % ('spp' + str(bridge_id), flow_id, table_id, priority)], ]
        self.cli_set(commands)

    def delete_ovs_flow_rules(self, bridge_id, table_id, flow_id, priority):
        """Delete row from OvsFlowRules table.

        Args:
            bridge_id(int):  OVS bridge ID
            table_id(int):  Table ID
            flow_id(int):  Flow ID
            priority(int):  Rule priority

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_ovs_flow_rules(bridgeId, tableId, flowId, priority)

        Raises:
            UIException:  not implemented

        """
        raise UIException("Method is not implemented in CLI (ONS-904023, ONS-948468)")

    def configure_ovs_resources(self, **kwargs):
        """Configure OvsResources table.

        Args:
            **kwargs(dict): parameters to be configured:
                            "controllerRateLimit";
                            "vlansLimit";
                            "untaggedVlan";
                            "rulesLimit".

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_ovs_resources(rulesLimit=2000)

        """
        self.enter_config_mode()
        commands = []

        if 'rulesLimit' in kwargs:
            commands.append(["switchport rules-limit %s" % (kwargs['rulesLimit'], )])
        if 'untaggedVlan' in kwargs:
            commands.append(["switchport untagged-vlan %s" % (kwargs['untaggedVlan'], )])
        if 'vlansLimit' in kwargs:
            commands.append(["switchport vlans-limit %s" % (kwargs['vlansLimit'], )])

        self.cli_set(commands)

    def get_table_ovs_flow_actions(self):
        """Get OvsFlowActions table.

        Returns:
            list[dict]:  table (list of dictionaries))

        Examples::

            env.switch[1].ui.get_table_ovs_flow_actions()

        """
        self.enter_config_mode()
        commands = [['show ovs flows action'], ]
        cli_keys = {'Flow': 'flowId',
                    'Bridge': 'bridgeId',
                    'Table': 'tableId',
                    'Action': 'action',
                    'Param': 'param'}
        res_list = self.cli_get_all(commands)
        table = self.process_table_data(commands[0][0], res_list, cli_keys)
        for row in table:
            row['flowId'] = int(row['flowId'])
            row['tableId'] = int(row['tableId'])
        return table

    def create_ovs_flow_actions(self, bridge_id, table_id, flow_id, action, param, priority=2000):
        """Add row to OvsFlowActions table.

        Args:
            bridge_id(int):  OVS bridge ID
            table_id(int):  Table ID
            flow_id(int):  Flow ID
            priority(int):  Rule priority
            action(str):  Action name
            param(str):  Action parameter

        Returns:
            None

        Examples::

            env.switch[1].ui.create_ovs_flow_actions(0, 0, 1, 'Output', '25')

        """
        self.enter_config_mode()
        commands = [['ovs flow %s %s %s %s' % ('spp' + str(bridge_id), flow_id, table_id, priority)], ]
        self.cli_set(commands)
        if action == 'Output' or action == 'SetIpDscp' or action == 'SetQueue' or action == 'SetVlanVid' or action == 'SetVlanPcp':
            commands = [['action %s %s' % (action.lower(), param)], ]
        else:
            commands = [['action %s ' % action.lower()], ]

        self.cli_set(commands)

    def delete_ovs_flow_actions(self, bridge_id, table_id, flow_id, action, priority=2000):
        """Delete row from OvsFlowActions table.

        Args:
            bridge_id(int):  OVS bridge ID
            table_id(int):  Table ID
            flow_id(int):  Flow ID
            priority(int):  Rule priority
            action(str):  Action name

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_ovs_flow_actions(0, 0, 1, 'Output')

        """
        self.enter_config_mode()
        commands = [['ovs flow %s %s %s %s' % ('spp' + str(bridge_id), flow_id, table_id, priority)], ]
        self.cli_set(commands)

        commands = [['no action %s' % action.lower()], ]
        self.cli_set(commands)

    def get_table_ovs_flow_qualifiers(self):
        """Get OvsFlowQualifiers table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ovs_flow_qualifiers()

        """
        self.enter_config_mode()
        commands = [['show ovs flows expression'], ]
        cli_keys = {'Flow': 'flowId',
                    'Bridge': 'bridgeId',
                    'Table': 'tableId',
                    'Expressions': 'action',
                    'Data': 'data'}
        res_list = self.cli_get_all(commands)
        table = self.process_table_data(commands[0][0], res_list, cli_keys)
        for row in table:
            row['flowId'] = int(row['flowId'])
            row['tableId'] = int(row['tableId'])
        return table

    def create_ovs_flow_qualifiers(self, bridge_id, table_id, flow_id, field, data, priority=2000):
        """Add row to OvsFlowQualifiers table.

        Args:
            bridge_id(int):  OVS bridge ID
            table_id(int):  Table ID
            flow_id(int):  Flow ID
            priority(int):  Rule priority
            field(str):  Expression name
            data(str):  Expression data

        Returns:
            None

        Examples::

            env.switch[1].ui.create_ovs_flow_qualifiers(0, 0, i, 'EthSrc', '00:00:00:00:00:01')

        """
        self.enter_config_mode()
        commands = [['ovs flow %s %s %s %s' % ('spp' + str(bridge_id), flow_id, table_id, priority)], ]
        self.cli_set(commands)
        commands = [['expression %s %s' % (field.lower(), data)], ]
        self.cli_set(commands)

    def delete_ovs_flow_qualifiers(self, bridge_id, table_id, flow_id, field, priority=2000):
        """Delete row from OvsFlowQualifiers table.

        Args:
            bridge_id(int):  OVS bridge ID
            table_id(int):  Table ID
            flow_id(int):  Flow ID
            priority(int):  Rule priority
            field(str):  Expression name

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_ovs_flow_qualifiers(bridgeId, tableId, flowId, field)

        """
        self.enter_config_mode()
        commands = [['ovs flow %s %s %s %s' % ('spp' + str(bridge_id), flow_id, table_id, priority)], ]
        self.cli_set(commands)

        commands = [['no expression %s' % field.lower()], ]
        self.cli_set(commands)

# LLDP configuration

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
        lldp_params_map = {'messageFastTx': "fast-tx",
                           'messageTxHoldMultiplier': "holdtime",
                           'messageTxInterval': "timer",
                           'reinitDelay': "reinit",
                           'txCreditMax': "credits",
                           'txFastInit': "fast-init",
                           'locChassisIdSubtype': "loc-chassis-id-subtype"}

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in list(lldp_params_map.keys())}

        self.enter_config_mode()
        lldp_commands = []
        for param, value in params.items():
            lldp_commands.append(["lldp %s %s" % (lldp_params_map[param], value)])

        self.cli_set(lldp_commands)

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
        cli_keys = {'adminStatus': {"TxOnly": [["no lldp receive"], ["lldp transmit"]],
                                    'RxOnly': [["lldp receive"], ["no lldp transmit"]],
                                    'TxAndRx': [["lldp receive"], ["lldp transmit"]],
                                    'Disabled': [["no lldp receive"], ["no lldp transmit"]]},
                    'tlvManAddrTxEnable': 'lldp tlv-select management-address',
                    'tlvPortDescTxEnable': 'lldp tlv-select port-description',
                    'tlvSysCapTxEnable': 'lldp tlv-select system-capabilities',
                    'tlvSysDescTxEnable': 'lldp tlv-select system-description',
                    'tlvSysNameTxEnable': 'lldp tlv-select system-name'}

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in list(cli_keys.keys())}

        self.enter_config_mode()
        lldp_commands = []
        for port in ports:
            port_name = self.port_map[port]
            lldp_commands.append(["interface %s" % port_name])

            for param, value in params.items():
                # admin status in CLI is handled differently: both Tx or Rx mode can be banned or allowed
                if param == "adminStatus":
                    lldp_commands.extend(cli_keys[param][value])
                else:
                    # add 'no' command prefix to disable tlv
                    if value == "Disabled":
                        command_prefix = "no "
                    else:
                        command_prefix = ""
                    lldp_commands.append(["%s%s" % (command_prefix, cli_keys[param])])

            lldp_commands.append(["exit"])

        self.cli_set(lldp_commands)

    def get_table_lldp(self, param=None):
        """Get Lldp table.

        Args:
            param(str):  parameter name (optional)

        Returns:
            list[dict]|int|str: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_lldp()

        """
        self.exit_config_mode()
        cli_keys = {"Message Transmit Interval": 'messageTxInterval',
                    "Message Transmit Hold Multiplier": 'messageTxHoldMultiplier',
                    "Transmit Re-init Delay": 'reinitDelay',
                    "Maximum Transmit Credits": 'txCreditMax',
                    "Fast Transmission LLDPDUs count": 'txFastInit',
                    "Fast Transmission Interval": 'messageFastTx',
                    "Chassis ID": 'locChassisId',
                    "Chassis ID Subtype": 'locChassisIdSubtype',
                    "System Name": 'locSysName',
                    "System Description": 'locSysDesc',
                    "System Supported Capabilities": 'locSysCapSupported',
                    "System Enabled Capabilities": 'locSysCapEnabled',
                    "Last Remote Change Time": 'statsRemLastChangeTime',
                    "Total Remote Inserts": 'statsRemInserts',
                    "Total Remote Deletes": 'statsRemDeletes',
                    "Total Remote Drops": 'statsRemDrops',
                    "Total Remote Ageouts": 'statsRemAgeouts'}

        int_values = ["messageFastTx", "messageTxHoldMultiplier", "messageTxInterval", 'reinitDelay', 'txCreditMax',
                      'statsRemAgeouts', 'statsRemDeletes', 'statsRemDrops', 'statsRemInserts', 'statsRemLastChangeTime', 'txFastInit']

        enum_values = {"locSysCapEnabled": {"bridge, router": 20, "bridge": 4},
                       "locSysCapSupported": {"bridge, router": 20, "bridge": 4},
                       "locChassisIdSubtype": {"MacAddress": 4}}

        show_command = ['show lldp']
        res_list = self.switch.cli.cli_get_all([show_command])
        table = self.process_vertical_table_data(show_command[0], res_list, cli_keys)

        # convert string values to integer
        for key in table:
            if key in int_values:
                table[key] = int(table[key])
            elif key in enum_values:
                table[key] = enum_values[key][table[key]]

        if param is not None:
            return table[param]
        else:
            if not isinstance(table, list) and table:
                table = [table, ]

            return table

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
        self.exit_config_mode()
        cli_keys = {"Interface": 'portId',
                    "LLDP Port Name": 'locPortId',
                    "LLDP Port Subtype": 'locPortIdSubtype',
                    "Administrative Status": 'adminStatus',
                    "Port Description": 'locPortDesc',
                    "Port Description Transmit Enable": 'tlvPortDescTxEnable',
                    "System Name Transmit Enable": 'tlvSysNameTxEnable',
                    "System Description Transmit Enable": 'tlvSysDescTxEnable',
                    "System Capability Transmit Enable": 'tlvSysCapTxEnable',
                    "Management Address Transmit Enable": 'tlvManAddrTxEnable',
                    "Management Neighbors": 'mgmtNeighbors',
                    "Multiple Neighbors": 'multipleNeighbors',
                    "Port Neighbors": 'portNeighbors',
                    "Too Many Neighbors": 'tooManyNeighbors',
                    "Something Changed Local": 'somethingChangedLocal',
                    "Something Changed Remote": 'somethingChangedRemote'}

        int_values = ["locPortIdSubtype", "mgmtNeighbors", "multipleNeighbors", 'portNeighbors', 'somethingChangedLocal',
                      'somethingChangedRemote', 'tooManyNeighbors']

        def convert_srt_into_integer(table_row):
            """Convert string values to integer

            """
            for key in table_row.keys():
                if key in int_values:
                    table_row[key] = int(table_row[key])
            table_row["portId"] = self.name_to_portid_map[table_row["portId"]]

        if port is not None:
            port_name = self.port_map[port]
            show_command = ['show lldp interface %s' % port_name]
            res_list = self.switch.cli.cli_get_all([show_command])
            row = self.process_vertical_table_data(show_command[0], res_list, cli_keys)
            convert_srt_into_integer(row)

            if param is not None:
                return row[param]
            else:
                return row
        else:
            show_command = ['show lldp interface']
            res_list = self.switch.cli.cli_get_all([show_command])

            # split Lldp Ports table output into rows for procesing output with "process_vertical_table_data" method
            start = "Interface \.+.+\n"
            end = "Something Changed Remote \.+.+\n"
            table_rows = re.findall("%s%s%s" % (start, ".+\n" * (len(cli_keys) - 2), end), res_list[0])

            table = []
            for row in table_rows:
                if row.strip():
                    table_row = self.process_vertical_table_data(show_command[0], [row, ], cli_keys)
                    convert_srt_into_integer(table_row)
                    if table_row:
                        table.append(table_row)

            return table

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
        self.exit_config_mode()
        cli_keys = {"Interface": 'portId',
                    "RX Frames With Errors Discarded": 'statsRxFramesDiscardedTotal',
                    "RX Frames Errors": 'statsRxFramesInErrorsTotal',
                    "RX Frames Total": 'statsRxFramesTotal',
                    "RX TLVs Discarded": 'statsRxTLVsDiscardedTotal',
                    "RX TLVs Unrecognized": 'statsRxTLVsUnrecognizedTotal',
                    "RX Ageouts Total": 'statsRxAgeoutsTotal',
                    "TX Frames Total": 'statsTxFramesTotal'}

        def convert_srt_into_integer(table_row):
            """Convert string values to integer.

            """
            for key in table_row.keys():
                if key != 'portId':
                    table_row[key] = int(table_row[key])

        if port is not None:
            port_name = self.port_map[port]
            show_command = ['show lldp traffic interface %s' % port_name]
            res_list = self.switch.cli.cli_get_all([show_command])
            row = self.process_vertical_table_data(show_command[0], res_list, cli_keys)
            convert_srt_into_integer(row)

            if param is not None:
                return row[param]
            else:
                return row
        else:
            show_command = ['show lldp traffic']
            res_list = self.switch.cli.cli_get_all([show_command])

            # split Lldp Ports table output into rows for procesing output with "process_vertical_table_data" method
            start = "Interface \.+.+\n"
            end = "TX Frames Total \.+.+\n"
            table_rows = re.findall("%s%s%s" % (start, ".+\n" * (len(cli_keys) - 2), end), res_list[0])

            table = []
            for row in table_rows:
                if row.strip():
                    table_row = self.process_vertical_table_data(show_command[0], [row, ], cli_keys)
                    convert_srt_into_integer(table_row)
                    if table_row:
                        table.append(table_row)

            return table

    def get_table_lldp_remotes(self, port=None):
        """Get LldpRemotes table.

        Args:
            port(int):  port Id (optional)

        Returns:
            list[dict]: table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_table_lldp_remotes(1)

        """
        self.exit_config_mode()
        cli_keys = {"Local Interface": 'remLocalPortNum',
                    "Remote Index": 'remoteId',
                    "Remote Port": 'remPortId',
                    "Port Subtype": 'remPortIdSubtype',
                    "Chassis Subtype": 'remChassisIdSubtype',
                    "Chassis": 'remChassisId',
                    "MAC Address": 'remMacAddress',
                    "System Capability Supported": 'remSysCapSupported',
                    "System Capability Enabled": 'remSysCapEnabled',
                    "Port Description": 'remPortDesc',
                    "System Name": 'remSysName',
                    "System Description": 'remSysDesc'}

        int_values = ["remChassisIdSubtype", "remPortIdSubtype", 'remoteId']

        enum_values = {"remSysCapEnabled": {"bridge": 4, "bridge, router": 20, "N/A": 0},
                       "remSysCapSupported": {"bridge": 4, "bridge, router": 20, "bridge, access-point, router": 28, "N/A": 0}}
        #              "locChassisIdSubtype": {"MacAddress": 4}}

        def convert_command_output_into_table(res_list, row_start, row_end, show_command):
            """Convert cli command output into table.

            """
            # split Lldp Ports table output into rows for procesing output with "process_vertical_table_data" method
            table_rows = re.findall("%s%s%s" % (row_start, ".+\n" * (len(cli_keys) - 2), row_end), res_list[0])

            table = []
            for row in table_rows:
                if row.strip():
                    table_row = self.process_vertical_table_data(show_command[0], [row, ], cli_keys)
                    if table_row:
                        table.append(table_row)

            return table

        if port is not None:
            port_name = self.port_map[port]
            show_command = ['show lldp neighbors interface %s' % port_name]
        else:
            show_command = ['show lldp neighbors']

        res_list = self.cli_get_all([show_command], timeout=60)

        # Convert cli command output into table
        start = "Local Interface \.+.+\n"
        end = "System Description \.+.+\n"
        table = convert_command_output_into_table(res_list, start, end, show_command)

        # convert string values to integer
        for idx, value in enumerate(table):
            for key in int_values:
                table[idx][key] = int(table[idx][key])
            for key, enum_value in enum_values.items():
                table[idx][key] = enum_value[table[idx][key]]
            table[idx]["remLocalPortNum"] = self.name_to_portid_map[table[idx]["remLocalPortNum"]]

        return table

    def get_table_remotes_mgmt_addresses(self, port=None):
        """Get LldpRemotesMgmtAddresses table.

        Args:
            port(int):  port Id (optional)

        Returns:
            list[dict]: table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_table_remotes_mgmt_addresses(1)

        """
        self.exit_config_mode()
        cli_keys = {"Local Interface": 'remLocalPortNum',
                    "Address": 'remManAddr',
                    "Address Subtype": 'remManAddrSubtype',
                    "Address Interface ID": 'remManAddrIfId',
                    "Address Interface ID Subtype": 'remManAddrIfSubtype',
                    "Address OID": 'remManAddrOID'}
        if port is not None:
            port_name = self.port_map[port]
            show_command = ['show lldp neighbors interface %s' % port_name]

            res_list = self.switch.cli.cli_get_all([show_command])
            res_list = res_list[0].split('Learned management address configuration data on interface:')

            _table = self.process_table_data(show_command[0], [res_list[1], ], cli_keys, 2)
            for row in _table:
                row['remLocalPortNum'] = self.name_to_portid_map[row["remLocalPortNum"]]
                row['remManAddrIfId'] = int(row['remManAddrIfId'])
                if row['remManAddrIfSubtype'] == 'unknown':
                    row['remManAddrIfSubtype'] = 1
                elif row['remManAddrIfSubtype'] == 'if-index':
                    row['remManAddrIfSubtype'] = 2
                elif row['remManAddrIfSubtype'] == 'system-port-number':
                    row['remManAddrIfSubtype'] = 3
                if row['remManAddrOID'] == 'N/A':
                    row['remManAddrOID'] = ''
                if row['remManAddrSubtype'] == 'ipv4':
                    row['remManAddrSubtype'] = 1
        else:
            show_command = ['show lldp neighbors']
            res_list = self.switch.cli.cli_get_all([show_command])
            res_list = res_list[0].split('Learned management address configuration data on interface:')

            _table = self.process_table_data(show_command[0], [res_list[1], ], cli_keys, 2)
            for row in _table:
                row['remLocalPortNum'] = self.name_to_portid_map[row["remLocalPortNum"]]
                row['remManAddrIfId'] = int(row['remManAddrIfId'])
                if row['remManAddrIfSubtype'] == 'unknown':
                    row['remManAddrIfSubtype'] = 1
                elif row['remManAddrIfSubtype'] == 'if-index':
                    row['remManAddrIfSubtype'] = 2
                elif row['remManAddrIfSubtype'] == 'system-port-number':
                    row['remManAddrIfSubtype'] = 3
                if row['remManAddrOID'] == 'N/A':
                    row['remManAddrOID'] = ''
                if row['remManAddrSubtype'] == 'ipv4':
                    row['remManAddrSubtype'] = 1
        return _table

    def disable_lldp_on_device_ports(self, ports=None):
        """Disable Lldp on device ports (if port=None Lldp should be disabled on all ports).

        Args:
            ports(list[int]):  list of ports

        Returns:
            None

        Examples::

            env.switch[1].ui.disable_lldp_on_device_ports()

        """
        if ports is None:
            port_names = list(self.port_map.values())
        else:
            port_names = [port_name for port_id, port_name in self.port_map.items() if port_id in ports]

        # Set LLDP adminStatus to disabled for device ports
        self.enter_config_mode()
        lldp_commands = []
        in_ports = ",".join(port_names)
        lldp_commands.append(["interface range %s" % (in_ports, )])
        lldp_commands.append(["no lldp receive"])
        lldp_commands.append(["no lldp transmit"])

        self.cli_set(lldp_commands)

        # Verify that LLDP adminStatus was set to disabled for device ports
        lldp_ports = self.get_table_lldp_ports()
        for row in lldp_ports:
            if row["portId"] in port_names:
                assert row["adminStatus"] == "Disabled", "LLDP was not disabled for interface %s" % row["portId"]

# DCBX configuration

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
        self.enter_config_mode()
        dcb_commands = []
        for port in ports:
            port_name = self.port_map[port]
            dcb_commands.append(["interface %s" % port_name])
            if mode == 'Disabled':
                dcb_commands.append(["no dcb admin"])
            else:
                dcb_commands.append(["dcb admin enable"])

            dcb_commands.append(["exit"])

        self.cli_set(dcb_commands)

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

        Raises:
            ValueError:  Invalid tlv in tlv dcbx_tlvs list

        """
        tlv_map = {'tlvApplicationPriorityTxEnable': "app",
                   'tlvCongestionNotificationTxEnable': "cn",
                   'tlvEtsConfTxEnable': "ets-conf",
                   'tlvEtsRecoTxEnable': "ets-reco",
                   'tlvPfcTxEnable': "pfc"}

        self.enter_config_mode()
        dcb_commands = []
        if isinstance(dcbx_tlvs, list):
            try:
                cli_tlv_commands_list = ["dcb tx %s" % tlv_map[tlv] for tlv in dcbx_tlvs]
            except KeyError as err:
                raise ValueError("Invalid tlv '%s' transmitted in tlv dcbx_tlvs list" % err)
        elif isinstance(dcbx_tlvs, str) and dcbx_tlvs.lower() == "all":
            cli_tlv_commands_list = ["dcb tx all"]
        else:
            raise ValueError("Invalid DCBX tlvs specified %s" % dcbx_tlvs)

        if mode == "Disabled":
            cli_command_prefix = "no "
        else:
            cli_command_prefix = ""

        for port in ports:
            port_name = self.port_map[port]
            dcb_commands.append(["interface %s" % port_name])

            for cli_tlv_command in cli_tlv_commands_list:
                dcb_commands.append(["%s%s" % (cli_command_prefix, cli_tlv_command)])

            dcb_commands.append(["exit"])

        self.cli_set(dcb_commands)

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
        self.exit_config_mode()
        cli_keys = {"Interface": "portId",
                    "Administrative Status": 'adminStatus',
                    "PFC": 'tlvPfcTxEnable',
                    "ETS Conf": 'tlvEtsConfTxEnable',
                    "ETS Reco": 'tlvEtsRecoTxEnable',
                    "APP": 'tlvApplicationPriorityTxEnable',
                    "CN": 'tlvCongestionNotificationTxEnable',
                    "Multiple Peers Alarm": 'multiplePeers',
                    "Active Protocol Version": 'activeProtVersion',
                    "Administrative Protocol Version": 'adminProtVersion'}
        if port is not None:
            port_name = self.port_map[port]
            show_command = ['show dcb dcbx interface %s' % port_name]
            res_list = self.switch.cli.cli_get_all([show_command])
            row = self.process_vertical_table_data(show_command[0], res_list, cli_keys)
            if param is not None:
                return row[param]
            else:
                return row
        else:
            show_command = ['show dcb dcbx']
            res_list = self.switch.cli.cli_get_all([show_command])

            # split Dcbx Ports table output into rows for procesing output with "process_vertical_table_data" method
            start = "Interface \.+.+\n"
            end = "Administrative Protocol Version \.+.+\n"
            table_rows = re.findall("%s%s%s" % (start, ".+\n" * (len(cli_keys) - 2), end), res_list[0])

            table = []
            for row in table_rows:
                if row.strip():
                    table_row = self.process_vertical_table_data(show_command[0], [row, ], cli_keys)
                    if table_row:
                        table.append(table_row)

            return table

    def get_table_dcbx_app_ports(self, table_type="Admin", port=None):
        """Get DcbxAppPorts* table.

        Args:
            table_type(str):  "Admin", "Local"
            port(int):  port Id (optional)

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_dcbx_app_ports("Admin", 1)

        """
        self.exit_config_mode()
        assert table_type in ["Admin", "Local"], "Incorrect Dcbx App Ports table type specified: %s" % table_type

        if table_type == "Admin":
            command_suffix = "status"
            cli_keys = {'Interface': 'portId',
                        'Willing': 'willing'}
        else:
            command_suffix = "local status"
            cli_keys = {'Interface': 'portId',
                        'Willing': 'willing',
                        'Error Alarm': 'errorAlarm',
                        'Total TX TLVs': 'statsTxTLVs'}

        show_command = ['show dcb app {0}'.format(command_suffix)]
        res_list = self.switch.cli.cli_get_all([show_command])
        table = self.process_table_data(show_command[0], res_list, cli_keys, 2)

        for entry in table:
            entry['portId'] = int(self.name_to_portid_map[entry['portId']])
            entry['statsTxTLVs'] = int(entry['statsTxTLVs'])

        if port is not None:
            return [row for row in table if row["portId"] == port]
        else:
            return table

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
        self.exit_config_mode()
        assert table_type in ["Admin", "Local", "Remote"], "Incorrect Dcbx App Maps table type specified: %s" % table_type
        if table_type == "Admin":
            command_suffix = "map"
        else:
            command_suffix = "%s map" % table_type.lower()

        cli_keys = {'Interface': 'portId',
                    'Selector': 'selector',
                    'Protocol': 'protocol',
                    'Priority': 'priority'}

        show_command = ['show dcb app %s' % command_suffix]
        res_list = self.switch.cli.cli_get_all([show_command])
        table = self.process_table_data(show_command[0], res_list, cli_keys)

        # convert string values to int
        for entry in table:
            entry['priority'] = int(entry['priority'])
            entry['protocol'] = int(entry['protocol'])
            entry['portId'] = int(self.name_to_portid_map[entry['portId']])

        if port is not None:
            return [row for row in table if row["portId"] == port]
        else:
            return table

    def get_table_dcbx_app_remote(self, port=None):
        """Get DcbxAppRemotes table.

        Args:
            port(int):  port Id (optional)

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_dcbx_app_remote()

        """
        self.exit_config_mode()
        cli_keys = {'Interface': 'portId',
                    'Willing': 'willing',
                    'Error Alarm': 'errorAlarm',
                    'Total RX TLVs': 'statsTxTLVs'}

        show_command = ['show dcb app remote status']
        res_list = self.switch.cli.cli_get_all([show_command])
        table = self.process_table_data(show_command[0], res_list, cli_keys)

        for entry in table:
            if entry['errorAlarm'] != 'Cleared':
                entry['valid'] = 'Disabled'
            else:
                entry['valid'] = 'Enabled'
            entry['portId'] = int(self.name_to_portid_map[entry['portId']])

        if port is not None:
            return [row for row in table if row["portId"] == port]
        else:
            return table

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
        self.exit_config_mode()
        assert table_type in ["Local", "Remote"], "Incorrect Dcbx Pfc table type specified: %s" % table_type
        command_suffix = "%s" % table_type.lower()

        cli_keys = {'Interface': 'portId',
                    'Willing': 'willing',
                    'MBC': 'mbc',
                    'Capability': 'capability',
                    'Enabled': 'enabled',
                    'Error Alarm': 'errorAlarm',
                    'Total TX TLVs': 'statsTxTLVs'}

        show_command = ['show dcb pfc %s' % command_suffix]
        res_list = self.switch.cli.cli_get_all([show_command])
        table = self.process_table_data(show_command[0], res_list, cli_keys)

        # convert string values to int
        for idx, value in enumerate(table):
            table[idx]['capability'] = int(table[idx]['capability'])
            table[idx]['statsTxTLVs'] = int(table[idx]['statsTxTLVs'])
            table[idx]['portId'] = int(self.name_to_portid_map[table[idx]['portId']])

        if port is not None:
            return [row for row in table if row["portId"] == port]
        else:
            return table

    def get_table_dcbx_ets_ports(self, table_type='Admin', port=None):
        """Get DcbxEtsPorts* table.

        Args:
            port(int):  port Id (optional)
            table_type(str):  Table types "Admin"| "Local"

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_dcbx_ets_ports()

        """
        self.exit_config_mode()
        assert table_type in ["Admin", "Local"], "Incorrect Dcbx Ets Ports table type specified: %s" % table_type

        if table_type == 'Admin':
            cli_keys = {'Interface': 'portId',
                        'Willing': 'willing',
                        'CBS': 'cbs',
                        'Maximum TCs': 'maxTCs',
                        'Bandwidth': 'confBandwidth',
                        'Algorithm': 'confAlgorithm',
                        'Priority Assignment': 'confPriorityAssignment'}
            command_suffix = ""
        else:
            cli_keys = {'Interface': 'portId',
                        'Willing': 'willing',
                        'CBS': 'cbs',
                        'Maximum TCs': 'maxTCs',
                        'Error Alarm': 'confErrorAlarm',
                        'TX TLVs': 'confStatsTxTLVs',
                        'Bandwidth': 'confBandwidth',
                        'Algorithm': 'confAlgorithm',
                        'Priority Assignment': 'confPriorityAssignment'}
            command_suffix = table_type.lower()

        cli_keys_reco = {'Priority Assignment': 'recoPriorityAssignment',
                         'Algorithm': 'recoAlgorithm',
                         'Bandwidth': 'recoBandwidth'}
        show_command = ['show dcb ets-conf {}'.format(command_suffix)]
        res_list = self.switch.cli.cli_get_all([show_command])
        list_of_entries = res_list[0].split('  \r')[:-3]
        table = []
        for entry in list_of_entries:
            table.append(self.process_vertical_table_data(show_command[0], [entry], cli_keys))

        show_command_reco = ['show dcb ets-reco {}'.format(command_suffix)]
        res_list_reco = self.switch.cli.cli_get_all([show_command_reco])
        if table_type == 'Admin':
            table_reco = self.process_table_data(show_command_reco[0], res_list_reco, cli_keys_reco, header_rows=2)
        else:
            table_reco = []
            list_of_reco_entries = res_list[0].split('  \r')[:-3]
            for reco_entry in list_of_reco_entries:
                table_reco.append(self.process_vertical_table_data(show_command_reco[0], [reco_entry], cli_keys_reco))

        # convert string values to int
        not_configured = '-1,-1,-1,-1,-1,-1,-1,-1'
        for idx, entry in enumerate(table):
            entry['maxTCs'] = int(entry['maxTCs'])
            if entry['confBandwidth'] == 'Not Configured':
                entry['confBandwidth'] = not_configured
            if entry['confAlgorithm'] == 'Not Configured':
                entry['confAlgorithm'] = not_configured
            if entry['confPriorityAssignment'] == 'Not Configured':
                entry['confPriorityAssignment'] = not_configured
            if table_reco[idx]['recoPriorityAssignment'] == 'Not Configured':
                entry['recoPriorityAssignment'] = not_configured
            else:
                entry['recoPriorityAssignment'] = table_reco[idx]['recoPriorityAssignment']
            if table_reco[idx]['recoAlgorithm'] == 'Not Configured':
                entry['recoAlgorithm'] = not_configured
            else:
                entry['recoAlgorithm'] = table_reco[idx]['recoAlgorithm']
            if table_reco[idx]['recoBandwidth'] == 'Not Configured':
                entry['recoBandwidth'] = not_configured
            else:
                entry['recoBandwidth'] = table_reco[idx]['recoBandwidth']
            entry['portId'] = int(self.name_to_portid_map[entry['portId']])

        if port is not None:
            return [row for row in table if row["portId"] == port]
        else:
            return table

    def configure_application_priority_rules(self, ports, app_prio_rules, delete_params=False, update_params=False):
        """Configure Application Priority rules.

        Args:
            ports(list[int]):  list of ports
            app_prio_rules(list[dict]):  list of rules dictionaries
            delete_params(bool): if delete specified params or not
            update_params(bool): if update specified params or not

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_application_priority_rules([1, 2], [{"selector": 1, "protocol": 2, "priority":1}, ])

        """
        selector_map = {"Ethertype": "ethertype",
                        "Tcp": "tcp",
                        "TcpUdp": "tcp-udp",
                        "Udp": "udp"}

        self.enter_config_mode()
        dcb_commands = []
        for port in ports:
            port_name = self.port_map[port]
            dcb_commands.append(["interface %s" % port_name])

            # configure application priority rules for the port
            for rule in app_prio_rules:
                if delete_params:
                    dcb_commands.append(["no dcb app add %s %s" % (selector_map[rule["selector"]], rule["protocol"])])
                else:
                    dcb_commands.append(["dcb app add %s %s %s" % (selector_map[rule["selector"]], rule["protocol"], rule["priority"])])
            dcb_commands.append(["exit"])

        self.cli_set(dcb_commands)

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
        cli_keys = {"willing": "ets willing",
                    "cbs": "ets cbs",
                    "maxTCs": "ets max-tcs",
                    "confBandwidth": "ets-conf bandwidth",
                    "confPriorityAssignment": "ets-conf pri-assigment",
                    "confAlgorithm": "ets-conf algorithm",
                    "recoBandwidth": "ets-reco bandwidth",
                    "recoPriorityAssignment": "ets-reco pri-assigment",
                    "recoAlgorithm": "ets-reco algorithm"}

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in list(cli_keys.keys())}

        self.enter_config_mode()
        dcb_commands = []
        for port in ports:
            port_name = self.port_map[port]
            dcb_commands.append(["interface %s" % port_name])

            for param, value in params.items():
                command_prefix = ""
                # CLI command for setting Enabled/Disabled/-1,-1,-1,-1,-1,-1,-1,-1 ETS values doesn't require the value
                if value in ["Enabled", "Disabled", "-1,-1,-1,-1,-1,-1,-1,-1"]:
                    # add 'no' prefix to cli command for setting 'Disabled' value or resetting ETS params to default values
                    if value == "Disabled" or value == "-1,-1,-1,-1,-1,-1,-1,-1":
                        command_prefix = "no "

                    value = ""

                dcb_commands.append(["%sdcb %s %s" % (command_prefix, cli_keys[param], value)])

            dcb_commands.append(["exit"])

        self.cli_set(dcb_commands)

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
        cli_keys = {"cnpvSupported": "cnpv-supported",
                    "cnpvReady": "cnpv-ready"}

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in list(cli_keys.keys())}

        self.enter_config_mode()
        dcb_commands = []
        for port in ports:
            port_name = self.port_map[port]
            dcb_commands.append(["interface %s" % port_name])

            for param, value in params.items():
                dcb_commands.append(["dcb cn %s %s" % (cli_keys[param], value)])

            dcb_commands.append(["exit"])

        self.cli_set(dcb_commands)

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
        cli_keys = {"mbc": "mbc",
                    "enabled": "priority",
                    "willing": "willing"}

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in list(cli_keys.keys())}

        self.enter_config_mode()
        dcb_commands = []
        for port in ports:
            port_name = self.port_map[port]
            dcb_commands.append(["interface %s" % port_name])

            for param in params:
                dcb_commands.append(["dcb pfc %s" % (cli_keys[param])])

            dcb_commands.append(["exit"])

        self.cli_set(dcb_commands)

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
        cli_keys = {"willing": "willing"}

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in cli_keys}

        self.enter_config_mode()
        dcb_commands = []
        for port in ports:
            port_name = self.port_map[port]
            dcb_commands.append(["interface %s" % port_name])

            for param, value in params.items():
                command_prefix = ""
                if value == 'Disabled':
                    command_prefix = "no "
                dcb_commands.append(["{0}dcb app {1}".format(command_prefix, param)])

            dcb_commands.append(["exit"])

        self.cli_set(dcb_commands)

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
        self.exit_config_mode()
        cli_keys = {"Interface": 'portId',
                    "Remote Port": 'remoteId',
                    "Remote MAC Address": 'macAddress',
                    "Time Filter": 'timeMark',
                    "Valid Entry": 'valid'}

        def convert_sting_to_int(table_row):
            """"Convert string value to integer.

            """
            table_row["timeMark"] = int(table_row["timeMark"])
            table_row["remoteId"] = int(table_row["remoteId"])

            return table_row

        if port is not None:
            port_name = self.port_map[port]
            show_command = ['show dcb dcbx neighbors interface %s' % port_name]
            res_list = self.switch.cli.cli_get_all([show_command])
            row = self.process_table_data(show_command[0], res_list, cli_keys)
            if row:
                row = row[0]
                convert_sting_to_int(row)

            if param is not None:
                return row[param]
            else:
                return row
        else:
            show_command = ['show dcb dcbx neighbors']
            res_list = self.switch.cli.cli_get_all([show_command])
            table = self.process_table_data(show_command[0], res_list, cli_keys)
            table = [convert_sting_to_int(row) for row in table]

        for row in table:
            row['portId'] = int(self.name_to_portid_map[row['portId']] if 'e' in row['portId'] else row['portId'])

        return table

# UFD configuration

    def get_table_ufd_config(self):
        """Get UFDConfig table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ufd_config()

        """
        self.enter_config_mode()
        commands = [['show ufd'], ]
        cli_keys = {"Global UFD feature state": 'enable',
                    "Recovery delay time": 'holdOnTime'}
        res_list = self.cli_get_all(commands)
        table = [self.process_vertical_table_data(commands[0][0], [res_list[0], ], cli_keys)]
        table[0]['holdOnTime'] = int(table[0]['holdOnTime'])
        return table

    def configure_ufd(self, enable='Enabled', hold_on_time=None):
        """Modify UFDConfig table.

        Args:
            enable(str):  Enable or disable UFD
            hold_on_time(int):  hold on time

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_ufd(enable='Enabled')

        """
        self.enter_config_mode()
        commands = []
        if enable == 'Enabled':
            commands.append(['ufd enable'])
        if enable == 'Disabled':
            commands.append(['no ufd enable'])
        if hold_on_time:
            commands.append(['ufd recovery-delay %s' % (hold_on_time, )])

        self.cli_set(commands)

    def create_ufd_group(self, group_id, threshold=None, enable='Enabled'):
        """Create UFDGroups record.

        Args:
            group_id(int):  UFD group ID
            threshold(int):  group threshold
            enable(str):  Enable or disable UFD group

        Returns:
            None

        Examples::

            env.switch[1].ui.create_ufd_group(1)

        """
        self.enter_config_mode()
        commands = []
        if threshold:
            commands.append(['ufd %s threshold %s' % (group_id, threshold)])
        if enable == 'Enabled':
            commands.append(['ufd %s enable' % (group_id, )])

        self.cli_set(commands)

    def modify_ufd_group(self, group_id, threshold=None, enable=None):
        """Modify UFDGroups record.

        Args:
            group_id(int):  UFD group ID
            threshold(int):  group threshold
            enable(str):  Enable or disable UFD group

        Returns:
            None

        Examples::

            env.switch[1].ui.modify_ufd_group(1, enable='Disabled')

        """
        self.enter_config_mode()
        commands = []
        if enable:
            if enable == 'Enabled':
                commands.append(['ufd %s enable' % (group_id, )])
            if enable == 'Disabled':
                commands.append(['no ufd %s enable' % (group_id, )])
        if threshold:
            commands.append(['ufd %s threshold %s' % (group_id, threshold)])

        self.cli_set(commands)

    def delete_ufd_group(self, group_id):
        """Delete UFDGroups record.

        Args:
            group_id(int):  UFD group ID

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_ufd_group(2)

        """
        self.enter_config_mode()
        commands = [['no ufd %s' % (group_id, )], ]

        self.cli_set(commands)

    def _get_table_ufd_groups(self):
        """Get tables UFDGroups and UFDPorts2Groups.

        """
        self.enter_config_mode()
        commands = [['show ufd groups'], ]
        cli_keys = {"Group": 'groupId',
                    "Threshold": 'threshold',
                    "Enable": 'enable',
                    "Active Ports": 'active',
                    "Counter": 'counter',
                    "Failure Action": 'status',
                    "Interface": 'portId',
                    "Type": 'type',
                    "Status": 'status'}
        res_list = self.cli_get_all(commands)
        table_rows = res_list[0].split('Group .')
        table = []
        ports_table = []
        for row in table_rows[1:]:
            group = ('Group .' + row).split('Group interfaces')[0] + '\n'
            group_row = self.process_vertical_table_data(commands[0][0], [group, ], cli_keys)
            table.append(group_row)
            ports = row.split('Group interfaces:')[1] + '\nSwitch#'
            _ports_table = self.process_table_data(commands[0][0], [ports, ], cli_keys)
            for _row in _ports_table:
                _row['groupId'] = group_row['groupId']
            ports_table.extend(_ports_table)
        for row in table:
            row['groupId'] = int(row['groupId'])
            row['threshold'] = int(row['threshold'])
            row['active'] = int(row['active'])
            row['counter'] = int(row['counter'])
        for row in ports_table:
            row['groupId'] = int(row['groupId'])
            row['portId'] = int(row['portId'])
        return table, ports_table

    def get_table_ufd_groups(self):
        """Get UFDGroups table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ufd_groups()

        """
        table_groups, table_ports = self._get_table_ufd_groups()
        return table_groups

    def create_ufd_ports(self, ports, port_type, group_id):
        """Create UFDPorts2Groups record.

        Args:
            ports(list[int]):  list of ports
            port_type(str):  type of port
            group_id(int):  UFD group Id

        Returns:
            None

        Examples::

            env.switch[1].ui.create_ufd_ports([1, ], 'LtM' 2)

        """
        self.enter_config_mode()
        commands = []
        in_ports = ",".join([self.port_map[x] if x < MIN_LAG_ID else str(x) for x in ports])
        if 'e' in in_ports:
            commands.append(["interface range %s" % (in_ports, )])
        else:
            commands.append(["interface port-channel range %s" % (in_ports, )])
        commands.append(["ufd group %s %s" % (group_id, port_type.lower())])

        self.cli_set(commands)

    def delete_ufd_ports(self, ports, port_type, group_id):
        """Delete UFDPorts2Groups record.

        Args:
            ports(list[int]):  list of ports
            port_type(str):  type of port
            group_id(int):  UFD group Id

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_ufd_ports([1, ], 'LtM' 2)

        """
        self.enter_config_mode()
        commands = []
        in_ports = ",".join([self.port_map[x] if x < MIN_LAG_ID else str(x) for x in ports])
        if 'e' in in_ports:
            commands.append(["interface range %s" % (in_ports, )])
        else:
            commands.append(["interface port-channel range %s" % (in_ports, )])
        commands.append(["no ufd group %s %s" % (group_id, port_type.lower())])

        self.cli_set(commands)

    def get_table_ufd_ports(self):
        """Get UFDPorts2Groups table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ufd_ports()

        """
        table_groups, table_ports = self._get_table_ufd_groups()
        return table_ports

# QinQ configuration

    def configure_qinq_ports(self, ports, **kwargs):
        """Configure QinQ Ports.

        Args:
            ports(list[int]):  list of ports
            **kwargs(dict):  parameters to be modified:
                             "mode";
                             "tpid".

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_qinq_ports([1, ], tpid=2)

        """
        cli_keys = {"mode": {'ProviderStacked': "provider-stacked",
                             'ProviderMapped': "provider-mapped",
                             'CustomerStacked': "customer-stacked",
                             'CustomerMapped': "customer-mapped"},
                    "tpid": {33024: "customer",
                             34984: "service",
                             37120: "qinq"}}

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in list(cli_keys.keys())}

        qinq_commands = []
        for port in ports:
            if port >= MIN_LAG_ID:
                port_name = "port-channel %s" % (port, )
            else:
                port_name = self.port_map[port]
            qinq_commands.append(["interface %s" % port_name])

            if "tpid" not in list(params.keys()) and "mode" in list(params.keys()):
                mode_value = params["mode"]
                try:
                    set_value = cli_keys["mode"][mode_value]
                except KeyError:
                    set_value = mode_value
                qinq_commands.append(["switchport dot1qtunnel %s" % (set_value, )])
            elif "tpid" in list(params.keys()):
                tpid_value = params["tpid"]
                if "mode" not in list(params.keys()):
                    mode_value = self.get_table_qinq_ports(port=port, param="mode")
                else:
                    mode_value = params["mode"]

                qinq_commands.append(["switchport dot1qtunnel %s tpid %s" % (cli_keys["mode"][mode_value], cli_keys["tpid"][tpid_value])])

            qinq_commands.append(["exit"])

        self.enter_config_mode()
        self.cli_set(qinq_commands)

    def configure_qinq_vlan_stacking(self, ports, provider_vlan_id, provider_vlan_priority):
        """Configure QinQVlanStacking.

        Args:
            ports(list[int]):  list of ports
            provider_vlan_id(int):  provider vlan Id
            provider_vlan_priority(int):  provider vlan priority

        Returns:
            None

        Examples:

            env.switch[1].ui.configure_qinq_vlan_stacking([1, ], 2, 7)

        """
        self.enter_config_mode()
        qinq_commands = []
        for port in ports:
            if port < MIN_LAG_ID:
                qinq_commands.append(["interface %s" % (self.port_map[port], )])
            else:
                qinq_commands.append(["interface port-channel %s" % (port, )])
            qinq_commands.append(["encapsulation dot1q %s %s" % (provider_vlan_id, provider_vlan_priority)])
            qinq_commands.append(["exit"])

        self.cli_set(qinq_commands)

    def get_table_qinq_vlan_stacking(self):
        """Get QinQVlanStacking table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_qinq_vlan_stacking()

        """
        self.enter_config_mode()
        cli_keys = {"Interface": 'portId',
                    "Provider VLAN": 'providerVlanId',
                    "Provider VLAN Priority": 'providerVlanPriority'}

        show_command = ['show dot1q-tunnel encapsulation']
        res_list = self.switch.cli.cli_get_all([show_command])
        table = self.process_table_data(show_command[0], res_list, cli_keys)
        for row in table:
            row['portId'] = self.name_to_portid_map[row["portId"]]
            row['providerVlanId'] = int(row['providerVlanId'])
            row['providerVlanPriority'] = int(row['providerVlanPriority'])

        return table

    def configure_qinq_vlan_mapping(self, ports, customer_vlan_id, customer_vlan_priority, provider_vlan_id, provider_vlan_priority):
        """Configure QinQCustomerVlanMapping and QinQProviderVlanMapping.

        Args:
            ports(list[int]):  list of ports
            customer_vlan_id(int):  customer vlan Id
            customer_vlan_priority(int):  customer vlan priority
            provider_vlan_id(int):  provider vlan Id
            provider_vlan_priority(int):  provider vlan priority

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_qinq_vlan_mapping([1, ], 2, 7, 5, 6)

        """
        self.enter_config_mode()
        qinq_commands = []
        for port in ports:
            if port < MIN_LAG_ID:
                qinq_commands.append(["interface %s" % (self.port_map[port], )])
            else:
                qinq_commands.append(["interface port-channel %s" % (port, )])
            qinq_commands.append(["switchport vlan mapping %s %s %s %s" % (customer_vlan_id, customer_vlan_priority, provider_vlan_id, provider_vlan_priority)])
            qinq_commands.append(["exit"])

        self.cli_set(qinq_commands)

    def get_table_qinq_customer_vlan_mapping(self):
        """Get QinQCustomerVlanMapping table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_qinq_customer_vlan_mapping()

        """
        self.enter_config_mode()
        cli_keys = {"Interface": 'portId',
                    "Provider VLAN": 'providerVlanId',
                    "Customer VLAN": 'customerVlanId',
                    "Provider VLAN Priority": 'providerVlanPriority'}

        show_command = ['show dot1q-tunnel customer vlan mapping']
        res_list = self.switch.cli.cli_get_all([show_command])
        table = self.process_table_data(show_command[0], res_list, cli_keys)
        for row in table:
            row['portId'] = self.name_to_portid_map[row["portId"]]
            row['providerVlanId'] = int(row['providerVlanId'])
            row['customerVlanId'] = int(row['customerVlanId'])
            row['providerVlanPriority'] = int(row['providerVlanPriority'])

        return table

    def get_table_qinq_provider_vlan_mapping(self):
        """Get QinQProviderVlanMapping table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_qinq_provider_vlan_mapping()

        """
        self.enter_config_mode()
        cli_keys = {"Interface": 'portId',
                    "Provider VLAN": 'providerVlanId',
                    "Customer VLAN": 'customerVlanId',
                    "Customer VLAN Priority": 'customerVlanPriority'}

        show_command = ['show dot1q-tunnel customer vlan mapping']
        res_list = self.switch.cli.cli_get_all([show_command])
        table = self.process_table_data(show_command[0], res_list, cli_keys)
        for row in table:
            row['portId'] = self.name_to_portid_map[row["portId"]]
            row['providerVlanId'] = int(row['providerVlanId'])
            row['customerVlanId'] = int(row['customerVlanId'])
            row['customerVlanPriority'] = int(row['customerVlanPriority'])

        return table

    def get_table_qinq_ports(self, port=None, param=None):
        """Get QinQPorts table.

        Args:
            port(int):  port Id (optional)
            param(str):  parameter name (optional)

        Returns:
            list[dict]|int|str:  table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_table_qinq_ports()

        """
        self.exit_config_mode()
        cli_keys = {"Interface": 'portId',
                    "Mode": 'mode',
                    "TPID": 'tpid'}

        values_map = {'customer-mapped': 'CustomerMapped',
                      'customer-stacked': 'CustomerStacked',
                      'provider-mapped': 'ProviderMapped',
                      'provider-stacked': 'ProviderStacked',
                      'none': "None",
                      "customer": 33024,
                      "service": 34984,
                      "qinq": 37120}

        def convert_table_rows(table_row):
            """"Convert string value to integer.

            """
            table_row["mode"] = values_map[table_row["mode"]]
            table_row["tpid"] = values_map[table_row["tpid"]]
            table_row["portId"] = self.name_to_portid_map[table_row["portId"]]

            return table_row

        if port is not None:
            show_command = ['show dot1q-tunnel interface %s' % self.port_map[port]]
            res_list = self.switch.cli.cli_get_all([show_command])
            row = self.process_table_data(show_command[0], res_list, cli_keys)
            if row:
                row = convert_table_rows(row[0])

            if param is not None:
                return row[param]
            else:
                return row
        else:
            show_command = ['show dot1q-tunnel']
            res_list = self.switch.cli.cli_get_all([show_command])
            table = self.process_table_data(show_command[0], res_list, cli_keys)
            table = [convert_table_rows(row) for row in table]

            return table

# Errdisable configuration

    def get_table_errdisable_errors_config(self, app_name=None, app_error=None):
        """Get ErrdisableErrorsConfig table.

        Args:
            app_name(str):  application name
            app_error(str):  application error

        Returns:
            list[dict]|str:  table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_table_errdisable_errors_config()

        """
        self.exit_config_mode()
        show_command = ['show errdisable detect']
        cli_keys = {"Application": 'appName',
                    "Port Error Name": 'appError',
                    "Detection Status": 'enabled',
                    "Recovery Status": 'recovery'}
        res_list = self.switch.cli.cli_get_all([show_command])
        table = self.process_table_data(show_command[0], res_list, cli_keys)
        if app_name and app_error:
            for row in table:
                if (row['appName'] == app_name) and (row['appError'] == app_error):
                    return row
                else:
                    return False
        else:
            return table

    def get_table_errdisable_config(self):
        """Get ErrdisableConfig table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_errdisable_config()

        """
        self.exit_config_mode()
        show_command = ['show errdisable recovery']
        cli_keys = {"Interface recovery interval": 'recoveryInterval'}
        res_list = self.switch.cli.cli_get_all(show_command)
        table = [self.process_vertical_table_data(show_command[0][0], [res_list[0], ], cli_keys)]
        table[0]['recoveryInterval'] = int(table[0]['recoveryInterval'])
        return table

    def modify_errdisable_errors_config(self, detect=None, recovery=None, app_name=None, app_error=None):
        """Configure ErrdisableErrorsConfig table.

        Args:
            detect(str):  detect status
            recovery(str):  recovery status
            app_name(str):  application name
            app_error(str):  application error

        Returns:
            None

        Examples::

            env.switch[1].ui.modify_errdisable_errors_config(detect="Enabled", app_name='L2UfdControlApp', app_error='ufd')

        """
        self.enter_config_mode()
        commands = []
        if detect:
            if detect == 'Enabled':
                commands.append(['errdisable detect cause %s  %s' % (app_name, app_error, )])
            if detect == 'Disabled':
                commands.append(['no errdisable detect cause %s  %s' % (app_name, app_error, )])
        if recovery:
            if recovery == 'Enabled':
                commands.append(['errdisable recovery cause %s  %s' % (app_name, app_error, )])
            if recovery == 'Disabled':
                commands.append(['no errdisable recovery cause %s  %s' % (app_name, app_error, )])
        self.cli_set(commands)

    def modify_errdisable_config(self, interval=None):
        """Configure ErrdisableConfig table.

        Args:
            interval(int):  recovery interval

        Returns:
            None

        Examples::

            env.switch[1].ui.modify_errdisable_config(10)

        """
        self.enter_config_mode()
        commands = []
        if interval:
            commands.append(['errdisable recovery interval %s' % (interval, )])
        self.cli_set(commands)

    def get_errdisable_ports(self, port=None, app_name=None, app_error=None, param=None):
        """Get ErrdisablePorts table.

        Args:
            port(int):  port Id (optional)
            app_name(str):  application name (optional)
            app_error(str):  application error (optional)
            param(str):  parameter name (optional)

        Returns:
            list[dict]|int|str: table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_errdisable_ports()

        """
        self.exit_config_mode()
        cli_keys = {"Interface": "portId",
                    "Application Name": 'appName',
                    "Error Name": 'appError',
                    "Remaining Time": 'time'}
        show_command = ['show interface status errdisable']
        res_list = self.switch.cli.cli_get_all([show_command])
        table = self.process_table_data(show_command[0], res_list, cli_keys)
        if port and app_name and app_error:
            if port >= MIN_LAG_ID:
                port_name = port
            else:
                port_name = self.port_map[port]
            is_row_present = False
            for row in table:
                if (row['portId'] == str(port_name)) and (row['appName'] == app_name) and (row['appError'] == app_error):
                    is_row_present = True
                    if param:
                        return row[param]
                    else:
                        return row
            if not is_row_present:
                return []
        else:
            return table

# Mirroring configuration

    mirror_mode_mapping = {"Ingress": "rx",
                           "Egress": "tx",
                           "EgressOrg": "tx original",
                           "IngressAndEgress": "both",
                           "IngressAndEgressOrg": "both original",
                           "Redirect": "redirect"}

    reverse_mirror_mode_mapping = {v: k for k, v in mirror_mode_mapping.items()}

    def create_mirror_session(self, port, target, mode):
        """Configure PortsMirroring table.

        Args:
            port(int):  source port Id
            target(int):  target port Id
            mode(str):  mirroring mode

        Returns:
            None

        Examples::

            env.switch[1].ui.create_mirror_session(1, 2, 'Redirect')

        """
        self.enter_config_mode()
        if port >= MIN_LAG_ID:
            source = 'port-channel {}'.format(port)
        else:
            source = self.port_map[port]
        target = self.port_map[target]
        mode = self.mirror_mode_mapping[mode]
        commands = [['monitor source interface {}  destination interface {}  mode {}'.format(source, target, mode)]]
        self.cli_set(commands)

    def get_mirroring_sessions(self):
        """Get PortsMirroring table.

        Returns:
            list[dict]|int|str:  table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_mirroring_sessions()

        """
        cli_keys = {"Source interface": "sourcePortId",
                    "Destination interface": 'destinationPortId',
                    "Mode": 'mirroringMode'}
        res_list = self.switch.cli.cli_get_all([['show monitor']])
        table = self.process_table_data('show monitor', res_list, cli_keys)
        for row in table:
            row['sourcePortId'] = self.name_to_portid_map[row['sourcePortId']]
            row['destinationPortId'] = self.name_to_portid_map[row['destinationPortId']]
            row['mirroringMode'] = self.reverse_mirror_mode_mapping[row['mirroringMode']]
        return table

    def delete_mirroring_session(self, port, target, mode):
        """Delete mirroring session from the PortsMirroring table.

        Args:
            port(int):  source port Id
            target(int):  target port Id
            mode(str):  mirroring mode

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_mirroring_session(1, 2, 'Redirect')

        """
        self.enter_config_mode()
        if port >= MIN_LAG_ID:
            source = 'port-channel {}'.format(port)
        else:
            source = self.port_map[port]
        target = self.port_map[target]
        mode = self.mirror_mode_mapping[mode]
        commands = [['no monitor source interface {}  destination interface {}  mode {}'.format(source, target, mode)]]
        self.cli_set(commands)

# DHCP Relay configuration

    def create_dhcp_relay(self, iface_name='global', server_ip=None, fwd_iface_name=None):
        """Configure DhcpRelayAdmin or DhcpRelayV6Admin table.

        Args:
            iface_name(str):  VLAN inteface name
            server_ip(str):  DHCP Server IP address
            fwd_iface_name(str):  VLAN forward interface name (for IPv6 config only)

        Returns:
            None

        Examples::

            env.switch[1].ui.create_dhcp_relay(iface_name='global', server_ip='10.10.0.2')

        """
        self.enter_config_mode()
        if fwd_iface_name:
            if iface_name != 'global':
                commands = [['interface vlan %s' % int(iface_name.replace('IfVlan', ''))],
                            ['ipv6 dhcp relay server % fwd-interface %s' % (server_ip, fwd_iface_name)]]
            else:
                commands = [['ipv6 dhcp relay server % fwd-interface %s' % (server_ip, fwd_iface_name)], ]
        else:
            if iface_name != 'global':
                commands = [['interface vlan %s' % int(iface_name.replace('IfVlan', ''))],
                            ['ip dhcp relay server %s' % (server_ip, )]]
            else:
                commands = [['ip dhcp relay server %s' % (server_ip, )], ]
        self.cli_set(commands)

    def get_table_dhcp_relay(self, dhcp_relay_ipv6=False):
        """Return DhcpRelayAdmin or DhcpRelayV6Admin table

        Args:
            dhcp_relay_ipv6(bool):  is IPv6 config defined

        Returns:
            None

        Examples::

            env.switch[1].ui.get_table_dhcp_relay(dhcp_relay_ipv6=False)

        """
        self.exit_config_mode()

        if not dhcp_relay_ipv6:
            cli_keys = {"Administrative Mode": "adminMode",
                        "Global DHCP Relay Status": "adminMode",
                        "Interface": "ifName",
                        "DHCP Server IP Address": "serverIp"}

            self.exit_config_mode()
            show_commands = [['show ip dhcp relay conf interface'], ]
            res_list = self.switch.cli.cli_get_all(show_commands)
            _table = self.process_table_data(show_commands[0][0], res_list, cli_keys)

            show_commands = [['show ip dhcp relay conf'], ]
            _res_list = self.switch.cli.cli_get_all(show_commands)
            _table_global = self.process_table_data(show_commands[0][0], _res_list, cli_keys)
            for row in _table_global:
                row['ifName'] = 'global'

            return _table + _table_global

        else:
            cli_keys = {"Administrative Mode": "adminMode",
                        "DHCP Relay Administrative Status": "adminMode",
                        "Interface": "ifName",
                        "DHCPv6 Server IP Address": "serverIp",
                        "Forward Interface": "fwdIfName",
                        "Default Forward Interface Name": "fwdIfName", }

            self.exit_config_mode()
            show_commands = [['show ipv6 dhcp relay interface'], ]
            res_list = self.switch.cli.cli_get_all(show_commands)
            _table = self.process_table_data(show_commands[0][0], res_list, cli_keys)

            show_commands = [['show ipv6 dhcp relay'], ]
            _res_list = self.switch.cli.cli_get_all(show_commands)
            _table_global = self.process_table_data(show_commands[0][0], _res_list, cli_keys)
            for row in _table_global:
                row['ifName'] = 'global'

            return _table + _table_global

# VxLAN configuration

    def configure_tunneling_global(self, **kwargs):
        """Configure TunnelingGlobalAdmin table.

        Args:
            **kwargs(dict):  parameters to be modified:
                             "vnTag";
                             "vxlanInnerVlanProcessing";
                             "mode",
                             "vxlanDestUDPPort".

        Returns:
            None

        Examples::

            env.switch[1].ui.configure_tunneling_global()

        Raises:
            UIException:  not implemented

        """
        raise UIException("Functionality is not implemented completely via CLI")

    def create_tunnels(self, tunnel_id=None, destination_ip=None, vrf=0, encap_type=None):
        """Configure TunnelsAdmin table.

        Args:
            tunnel_id(int):  Tunnel ID
            destination_ip(str):  Destination IP address
            vrf(int):  Tunnel VRF
            encap_type(str):  Tunnel encapsulation type

        Returns:
            None

        Examples::

            env.switch[1].ui.create_tunnels(tunnel_id=records_count, destination_ip=ip_list, encap_type='VXLAN')

        Raises:
            UIException:  not implemented

        """
        raise UIException("Functionality is not implemented completely via CLI")

    def get_table_tunnels_admin(self):
        """Return TunnelsAdmin table.

        Returns:
            list[dict]:  table

        Examples::

            env.switch[1].ui.get_table_tunnels_admin()

        Raises:
            UIException:  not implemented

        """
        raise UIException("Functionality is not implemented completely via CLI")
