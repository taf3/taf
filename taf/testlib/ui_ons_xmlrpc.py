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

"""``ui_ons_xmlrpc.py``

`XMLRPC UI wrappers`

"""

import time
import socket
import operator
from collections import OrderedDict

import pytest

from . import helpers
from .ui_helpers import UiHelperMixin
from .ui_wrapper import UiInterface
from .custom_exceptions import UIException, SwitchException
from .xmlrpc_proxy import TimeoutServerProxy as xmlrpcProxy
from testlib import clicmd_ons


STAT_MAP = {
    "RxUcstPktsIPv4": "IfInUcastPkts",
    "RxUcstPktsIPv6": "IfInUcastPkts",
    "RxUcstPktsNonIP": "IfInUcastPkts",
    "TxUcstPktsIPv4": "IfOutUcastPkts",
}


class UiOnsXmlrpc(UiHelperMixin, UiInterface):
    """Class with XMLRPC wrappers.

    """

    def __init__(self, switch):
        self.switch = switch
        self.ris = {}
        self.areas = {}
        self.static_routes = {}
        self.switch.cli = clicmd_ons.CLICmd(
            self.switch.ipaddr, self.switch._sshtun_port,  # pylint: disable=protected-access
            self.switch.config['cli_user'],
            self.switch.config['cli_user_passw'],
            self.switch.config['cli_user_prompt'], self.switch.type)

    def connect(self):
        if self.switch._use_sshtun:  # pylint: disable=protected-access
            self.switch.open_sshtun()

    def disconnect(self):
        if self.switch.sshtun is not None:
            self.switch.close_sstun()

    def restart(self):
        try:
            server, port = self.switch.xmlproxy._ServerProxy__host.split(":")  # pylint: disable=protected-access
            xmlproxy_new = xmlrpcProxy("http://%s:%s/RPC2" % (server, port), timeout=1)
            xmlproxy_new.nb.Methods.rebootSystem()
            del xmlproxy_new
        except socket.timeout:
            pass

# Clear Config
    def clear_config(self):
        self.switch.xmlproxy.nb.clearConfig()
        self.ris = {}
        self.areas = {}

    def save_config(self):
        self.switch.xmlproxy.nb.saveConfig()

    def restore_config(self):
        self.switch.xmlproxy.nb.restoreConfig()

# Application Check
    def check_device_state(self):
        self.connect()
        assert self.switch.check_app_table()
        assert self.switch.xmlproxy.system.tablesReady() == 0

# Platform
    def get_table_platform(self):
        return self.switch.getprop_table('Platform')

# Syslog configuration
    def create_syslog(self, syslog_proto, syslog_ip, syslog_port, syslog_localport, syslog_transport, syslog_facility, syslog_severity):
        self.switch.setprop_row("SyslogRemotes", [syslog_proto, syslog_ip, syslog_port, syslog_localport, syslog_transport, syslog_facility, syslog_severity])
        self.switch.xmlproxy.nb.Methods.applySyslogConfig()

    def logs_add_message(self, level, message):
        """Add message into device logs.

        Args:
            level(str):  log severity
            message(str):  log message

        """
        self.switch.xmlproxy.tools.logMessage(level, message)

# Temperature information
    def get_temperature(self):
        """Get temperature from Sensors table.

        Returns:
            dict:  CPU temperature information (Sensors table)

        """
        sensor_table = self.switch.getprop_table('Sensors')
        temp_table = [x for x in sensor_table if 'Temp' in x['type']]
        return temp_table

# System information
    def get_memory(self, mem_type='usedMemory'):
        """Returns free cached/buffered memory from switch.

        Args:
            mem_type(str):  memory type

        Returns:
            float::  memory size

        """
        table = self.switch.xmlproxy.nb.Methods.getKPIData()
        mem_table = [x["value"] for x in table if x["indicator"] == mem_type]
        mem = float(mem_table[0])
        return mem

    def get_cpu(self):
        """Returns cpu utilization from switch.

        Returns:
            float:  cpu utilization from switch

        """
        table = self.switch.xmlproxy.nb.Methods.getKPIData()
        cpu_list = [x["value"] for x in table if x["subsystem"] == "Cpu" and x["value"] != "NaN"]
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
        return self.switch.getprop_table('Applications')

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
        row_id = self.switch.findprop('Applications', [1, 1, application])
        if row_id > 0:
            self.switch.setprop('Applications', 'logLevel', [row_id, loglevel])

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
        if 'enable' in kwargs:
            self.switch.setprop("SpanningTree", "globalEnable", [1, kwargs['enable']])
        if 'mode' in kwargs:
            self.switch.setprop("SpanningTree", "globalEnable", [1, 'Disabled'])
            self.switch.setprop("SpanningTree", "mode", [1, kwargs['mode']])
            self.switch.setprop("SpanningTree", "globalEnable", [1, 'Enabled'])
        if 'maxAge' in kwargs:
            self.switch.setprop("SpanningTree", "maxAge", [1, kwargs['maxAge']])
        if 'forwardDelay' in kwargs:
            self.switch.setprop("SpanningTree", "forwardDelay", [1, kwargs['forwardDelay']])
        if 'bridgePriority' in kwargs:
            self.switch.setprop("SpanningTree", "bridgePriority", [1, kwargs['bridgePriority']])
        if 'bpduGuard' in kwargs:
            self.switch.setprop("SpanningTree", "bpduGuard", [1, kwargs['bpduGuard']])
        if 'forceVersion' in kwargs:
            self.switch.setprop("SpanningTree", "forceVersion", [1, kwargs['forceVersion']])
        if 'mstpciName' in kwargs:
            self.switch.setprop("SpanningTree", "mstpciName", [1, kwargs['mstpciName']])

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
        self.switch.setprop_row("STPInstances", [instance, priority])

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
        if 'priority' in kwargs:
            self.switch.setprop("STPInstances", "bridgePriority", [instance + 1, kwargs['priority']])
        if 'vlan' in kwargs:
            self.switch.setprop_row("Vlans2STPInstance", [instance, kwargs['vlan']])

    def get_table_spanning_tree(self):
        """Get 'SpanningTree' table.

        Returns:
            list(dict): table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_spanning_tree()

        """
        return self.switch.getprop_table('SpanningTree')

    def get_table_spanning_tree_mst(self):
        """Get 'STPInstances' table

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_spanning_tree_mst()

        """
        return self.switch.getprop_table('STPInstances')

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
        _table = []
        if ports:
            for port in ports:
                _row_id = self.switch.findprop('MSTPPorts', [instance, port])
                _table.append(self.switch.getprop_row('MSTPPorts', _row_id))
        else:
            _table = self.switch.getprop_table('MSTPPorts')
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
        port_rows = self.switch.multicall([{"methodName": 'nb.MSTPPorts.find', "params": [[instance, x] for x in ports]}])
        errors = helpers.process_multicall(port_rows)
        assert len(errors) == 0, "Find methods failed with errors: %s" % [x["error"] for x in errors]

        if 'adminState' in kwargs:
            port_admin_params = [(int(x['result']), kwargs['adminState']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.MSTPPorts.set.adminState', "params": port_admin_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.MSTPPorts.set.adminState methods failed with errors: %s" % [x["error"] for x in errors]

        if 'portFast' in kwargs:
            portfast_params = [(int(x['result']), kwargs['portFast']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.MSTPPorts.set.portFast', "params": portfast_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.MSTPPorts.set.portFast methods failed with errors: %s" % [x["error"] for x in errors]

        if 'rootGuard' in kwargs:
            rootguard_params = [(int(x['result']), kwargs['rootGuard']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.MSTPPorts.set.rootGuard', "params": rootguard_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.MSTPPorts.set.rootGuard methods failed with errors: %s" % [x["error"] for x in errors]

        if 'bpduGuard' in kwargs:
            bpduguard_params = [(int(x['result']), kwargs['bpduGuard']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.MSTPPorts.set.bpduGuard', "params": bpduguard_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.MSTPPorts.set.bpduGuard methods failed with errors: %s" % [x["error"] for x in errors]

        if 'autoEdgePort' in kwargs:
            auto_edge_params = [(int(x['result']), kwargs['autoEdgePort']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.MSTPPorts.set.autoEdgePort', "params": auto_edge_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.MSTPPorts.set.autoEdgePort methods failed with errors: %s" % [x["error"] for x in errors]

        if 'adminPointToPointMAC' in kwargs:
            ptp_mac_params = [(int(x['result']), kwargs['adminPointToPointMAC']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.MSTPPorts.set.adminPointToPointMAC', "params": ptp_mac_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.MSTPPorts.set.adminPointToPointMAC methods failed with errors: %s" % [x["error"] for x in errors]

        if 'externalCost' in kwargs:
            cost_params = [(int(x['result']), kwargs['externalCost']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.MSTPPorts.set.externalCost', "params": cost_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.MSTPPorts.set.externalCost methods failed with errors: %s" % [x["error"] for x in errors]

        if 'internalCost' in kwargs:
            cost_params = [(int(x['result']), kwargs['internalCost']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.MSTPPorts.set.internalCost', "params": cost_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.MSTPPorts.set.internalCost methods failed with errors: %s" % [x["error"] for x in errors]

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
        port_rows = self.switch.multicall([{"methodName": 'nb.RSTPPorts.find', "params": [[x, ] for x in ports]}])
        errors = helpers.process_multicall(port_rows)
        assert len(errors) == 0, "Find methods failed with errors: %s" % [x["error"] for x in errors]

        if 'adminState' in kwargs:
            port_admin_params = [(int(x['result']), kwargs['adminState']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.RSTPPorts.set.adminState', "params": port_admin_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.RSTPPorts.set.adminState methods failed with errors: %s" % [x["error"] for x in errors]

        if 'portFast' in kwargs:
            portfast_params = [(int(x['result']), kwargs['portFast']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.RSTPPorts.set.portFast', "params": portfast_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.RSTPPorts.set.portFast methods failed with errors: %s" % [x["error"] for x in errors]

        if 'rootGuard' in kwargs:
            rootguard_params = [(int(x['result']), kwargs['rootGuard']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.RSTPPorts.set.rootGuard', "params": rootguard_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.RSTPPorts.set.rootGuard methods failed with errors: %s" % [x["error"] for x in errors]

        if 'bpduGuard' in kwargs:
            bpduguard_params = [(int(x['result']), kwargs['bpduGuard']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.RSTPPorts.set.bpduGuard', "params": bpduguard_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.RSTPPorts.set.bpduGuard methods failed with errors: %s" % [x["error"] for x in errors]

        if 'autoEdgePort' in kwargs:
            auto_edge_params = [(int(x['result']), kwargs['autoEdgePort']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.RSTPPorts.set.autoEdgePort', "params": auto_edge_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.RSTPPorts.set.autoEdgePort methods failed with errors: %s" % [x["error"] for x in errors]

        if 'adminPointToPointMAC' in kwargs:
            ptp_mac_params = [(int(x['result']), kwargs['adminPointToPointMAC']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.RSTPPorts.set.adminPointToPointMAC', "params": ptp_mac_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.RSTPPorts.set.adminPointToPointMAC methods failed with errors: %s" % [x["error"] for x in errors]

        if 'cost' in kwargs:
            cost_params = [(int(x['result']), kwargs['cost']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.RSTPPorts.set.cost', "params": cost_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.RSTPPorts.set.cost methods failed with errors: %s" % [x["error"] for x in errors]

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
        _table = []
        if ports:
            for port in ports:
                _row_id = self.switch.findprop('RSTPPorts', [port, ])
                _table.append(self.switch.getprop_row('RSTPPorts', _row_id))
        else:
            _table = self.switch.getprop_table('RSTPPorts')
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
        ports_table = self.switch.getprop_table('Ports')
        assert ports_table, "Ports table is empty on device %s" % \
                            (self.switch.xmlproxy._ServerProxy__host, )  # pylint: disable=protected-access
        # define multicall params for Ports.find method
        port_ids = [(x["portId"], ) for x in ports_table if x["operationalStatus"] != 'NotPresent' and
                    x["type"] == 'Physical' and
                    x["portId"] not in self.switch.mgmt_ports]

        port_rows = self.switch.multicall([{"methodName": 'nb.Ports.find', "params": port_ids}])
        errors = helpers.process_multicall(port_rows)
        assert len(errors) == 0, "Find methods failed with errors: %s" % [x["error"] for x in errors]

        # define multicall params for nb.Ports.set.adminMode method
        port_down_params = [(int(x['result']), "Down") for x in port_rows]

        results = self.switch.multicall([{"methodName": 'nb.Ports.set.adminMode', "params": port_down_params}])
        errors = helpers.process_multicall(results)
        if len(errors) > 0:
            # Process multicall params for nb.Ports.get.operationalStatus
            port_check_params = [(x["params"][0], ) for x in errors]
            statuses = self.switch.multicall([{"methodName": 'nb.Ports.get.operationalStatus', "params": port_check_params}])
            for row in errors:
                row["status"] = statuses[errors.index(row)]["result"]
            n_errors = [x for x in errors if x["status"] != 'NotPresent']
            assert len(n_errors) == 0, "Find methods failed with errors: %s" % [x["error"] for x in n_errors]

    def wait_all_ports_admin_disabled(self):
        """Wait for all ports into admin Down state.

        Notes:
            This method is used in helpers.set_all_ports_admin_disabled() for all functional test case.

        Returns:
            None

        """
        def _retry(ports_list):
            start_time = time.time()
            statuses = self.switch.multicall([{"methodName": 'nb.Ports.get.operationalStatus', "params": ports_list}])
            up_ports = [x["params"] for x in statuses if x["result"] == "Up"]
            end_time = time.time()
            while end_time < start_time + 30 and len(up_ports) > 0:
                time.sleep(1)
                statuses = self.switch.multicall([{"methodName": 'nb.Ports.get.operationalStatus', "params": up_ports}])
                up_ports = [x["params"] for x in statuses if x["result"] == "Up"]
                end_time = time.time()
            return up_ports

        ports_table = self.switch.getprop_table('Ports')
        # define multicall params for Ports.find method
        port_ids = [(x["portId"], ) for x in ports_table if x["operationalStatus"] not in {'NotPresent', 'Down'} and
                    x["type"] == 'Physical' and
                    x["portId"] not in self.switch.mgmt_ports]

        if port_ids:
            port_rows = self.switch.multicall([{"methodName": 'nb.Ports.find', "params": port_ids}])
            errors = helpers.process_multicall(port_rows)
            assert len(errors) == 0, "Find methods failed with errors: %s" % errors

            # define multicall params for nb.Ports.get.operationalStatus method
            port_get_params = [(int(x['result']), ) for x in port_rows]

            up_ports = _retry(port_get_params)

            attempts = 0

            while up_ports and attempts < 3:
                # retry: set adminMode in Up/Down
                # define multicall params for nb.Ports.set.adminMode method
                port_up_params = [(int(x[0]), "Up") for x in up_ports]

                results = self.switch.multicall([{"methodName": 'nb.Ports.set.adminMode', "params": port_up_params}])
                errors = helpers.process_multicall(results)
                time.sleep(2)
                port_down_params = [(int(x[0]), "Down") for x in up_ports]

                results = self.switch.multicall([{"methodName": 'nb.Ports.set.adminMode', "params": port_down_params}])
                errors = helpers.process_multicall(results)

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
        port_rows = self.switch.multicall([{"methodName": 'nb.Ports.find', "params": [[x, ] for x in ports]}])
        errors = helpers.process_multicall(port_rows)
        assert len(errors) == 0, "Find methods failed with errors: %s" % [x["error"] for x in errors]

        if 'pvid' in kwargs:
            port_pvid_params = [(int(x['result']), kwargs['pvid']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.Ports.set.pvid', "params": port_pvid_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.Ports.set.pvid methods failed with errors: %s" % [x["error"] for x in errors]
        if 'pvpt' in kwargs:
            port_pvpt_params = [(int(x['result']), kwargs['pvpt']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.Ports.set.pvpt', "params": port_pvpt_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.Ports.set.pvpt methods failed with errors: %s" % [x["error"] for x in errors]
        if 'adminMode' in kwargs:
            port_admin_params = [(int(x['result']), kwargs['adminMode']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.Ports.set.adminMode', "params": port_admin_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.Ports.set.adminMode methods failed with errors: %s" % [x["error"] for x in errors]
        if 'ingressFiltering' in kwargs:
            port_ingress_filter_params = [(int(x['result']), kwargs['ingressFiltering']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.Ports.set.ingressFiltering', "params": port_ingress_filter_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.Ports.set.ingressFiltering methods failed with errors: %s" % [x["error"] for x in errors]
        if 'maxFrameSize' in kwargs:
            port_frame_size_params = [(int(x['result']), kwargs['maxFrameSize']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.Ports.set.maxFrameSize', "params": port_frame_size_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.Ports.set.maxFrameSize methods failed with errors: %s" % [x["error"] for x in errors]
        if 'discardMode' in kwargs:
            port_discard_params = [(int(x['result']), kwargs['discardMode']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.Ports.set.discardMode', "params": port_discard_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.Ports.set.discardMode methods failed with errors: %s" % [x["error"] for x in errors]
        if 'cutThrough' in kwargs:
            port_cut_through_params = [(int(x['result']), kwargs['cutThrough']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.Ports.set.cutThrough', "params": port_cut_through_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.Ports.set.cutThrough methods failed with errors: %s" % [x["error"] for x in errors]
        if 'tx_cutThrough' in kwargs:
            pytest.fail("Configuring of tx_cutThrough attribute is not supported")
        if 'flowControl' in kwargs:
            port_flow_contr_params = [(int(x['result']), kwargs['flowControl']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.Ports.set.flowControl', "params": port_flow_contr_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.Ports.set.flowControl methods failed with errors: %s" % [x["error"] for x in errors]
        if 'speed' in kwargs:
            port_speed_params = [(int(x['result']), kwargs['speed']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.Ports.set.speed', "params": port_speed_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.Ports.set.speed methods failed with errors: %s" % [x["error"] for x in errors]
        if 'learnMode' in kwargs:
            port_learn_params = [(int(x['result']), kwargs['learnMode']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.Ports.set.learnMode', "params": port_learn_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.Ports.set.learnMode methods failed with errors: %s" % [x["error"] for x in errors]
        if 'macAddress' in kwargs:
            port_mac_params = [(int(x['result']), kwargs['macAddress']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.Ports.set.macAddress', "params": port_mac_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.Ports.set.macAddress methods failed with errors: %s" % [x["error"] for x in errors]
        if 'duplex' in kwargs:
            port_suplex_params = [(int(x['result']), kwargs['duplex']) for x in port_rows]
            results = self.switch.multicall([{"methodName": 'nb.Ports.set.duplex', "params": port_suplex_params}])
            errors = helpers.process_multicall(results)
            assert len(errors) == 0, "nb.Ports.set.duplex methods failed with errors: %s" % [x["error"] for x in errors]

    def get_table_ports(self, ports=None, all_params=False, ip_addr=True):
        """Get 'Ports' table.

        Args:
            ports(list):  list of port IDs.
            all_params(bool):  get additional port properties
            ip_addr(bool): get IP address

        Returns:
            list(dict): table (list of dictionaries)

        Notes:
            Return all table or information about particular ports.

        Examples::

            env.switch[1].ui.get_table_ports()
            env.switch[1].ui.get_table_ports([1, 2])

        """
        _table = []
        if ports is not None:
            for port in ports:
                _row_id = self.switch.findprop('Ports', [port, ])
                _table.append(self.switch.getprop_row('Ports', _row_id))
        else:
            _table = self.switch.getprop_table('Ports')
        return _table

    def get_port_configuration(self, port, expected_rcs=frozenset({0}), enabled_disabled_state=False, **kwargs):
        """Returns attribute value (int) for given port.

        Args:
            port(int | str):  port ID
            expected_rcs(int | set | list | frozenset):  expected return code
            enabled_disabled_state(bool):  Flag indicate to port state
            kwargs(dict):  Possible parameters

        Raises:
            ValueError
            SwitchException:  not implemented

        Returns:
            int | str:  port attribute value

        """
        raise SwitchException("Not implemented")

# Flow Confrol configuration
    def set_flow_control_type(self, ports=None, control_type=None, tx_mode='normal', tc=None):
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
            ports_table = self.switch.getprop_table('Ports')
            ports = [(x["portId"], ) for x in ports_table]

        for port in ports:
            row = self.switch.findprop("Ports", [port, ])
            self.switch.setprop("Ports", "flowControl", [row, control_type])
            if self.switch.getprop_row("Ports", row)["flowControl"] != control_type:
                raise UIException("Cannot set {0} flowControl for {1}".format(control_type, port))

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
        if vlans:
            # Add vlans using multicall
            vlan_params = [[x, "VLAN-%s" % (x, )] for x in vlans]
            calls = [{"methodName": 'nb.Vlans.addRow', "params": vlan_params}, ]
            res_list = self.switch.multicall(calls)
            errors = helpers.process_multicall(res_list)
            assert len(errors) == 0, "Vlans.addRow methods failed with errors: %s" % [x["error"] for x in errors]
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
        if vlans:
            # Delete vlan from port
            vlan_find_params = [[x, ] for x in vlans]
            calls = [{"methodName": 'nb.Vlans.find', "params": vlan_find_params}, ]
            res_list = self.switch.multicall(calls)
            errors = helpers.process_multicall(res_list)
            assert len(errors) == 0, "Vlans.find methods failed with errors: %s" % [x["error"] for x in errors]

            vlan_del_params = [[int(x['result']), ] for x in res_list]
            calls = [{"methodName": 'nb.Vlans.delRow', "params": vlan_del_params}, ]
            res_list = self.switch.multicall(calls)
            errors = helpers.process_multicall(res_list)
            assert len(errors) == 0, "Vlans.delRow methods failed with errors: %s" % [x["error"] for x in errors]
        else:
            raise UIException("List of vlans require")

    def get_table_vlans(self):
        """Get 'Vlans' table.

        Returns:
            list(dict): table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_vlans()

        """
        return self.switch.getprop_table('Vlans')

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
            UIException:  ports and vlans required

        """
        if vlans and ports:
            # Configure Ports2Vlans table
            p2v_params = [[x, y, tagged] for x in ports for y in vlans]
            i = 0
            step = 1000
            while i < len(p2v_params):
                calls = [{"methodName": 'nb.Ports2Vlans.addRow', "params": p2v_params[i:i + step]}, ]
                res_list = self.switch.multicall(calls)
                errors = helpers.process_multicall(res_list)
                assert len(errors) == 0, "Ports2Vlans.addRow methods failed with errors: %s" % [x["error"] for x in errors]
                i += step
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
            UIException:  ports and vlans required

        """
        # Delete vlan from port
        if vlans and ports:
            p2v_params = [[x, y] for x in ports for y in vlans]
            i = 0
            step = 1000
            while i < len(p2v_params):
                calls = [{"methodName": 'nb.Ports2Vlans.find', "params": p2v_params[i:i + step]}, ]
                res_list = self.switch.multicall(calls)
                errors = helpers.process_multicall(res_list)
                assert len(errors) == 0, "Ports2Vlans.find methods failed with errors: %s" % [x["error"] for x in errors]
                del_params = ([int(x['result']), ] for x in res_list)
                calls = [{"methodName": 'nb.Ports2Vlans.delRow', "params": del_params}, ]
                res_list = self.switch.multicall(calls)
                errors = helpers.process_multicall(res_list)
                assert len(errors) == 0, "Ports2Vlans.delRow methods failed with errors: %s" % [x["error"] for x in errors]
                i += step
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
        for row in self.get_table_ports2vlans():
            if row['vlanId'] in vlans and row['portId'] in ports:
                self.delete_vlan_ports(ports=[row['portId']], vlans=vlans)
        self.create_vlan_ports(ports=ports, vlans=vlans, tagged=tagged)

    def get_table_ports2vlans(self):
        """Get 'Ports2Vlans' table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ports2vlans()

        """
        table_port2vlan = self.switch.getprop_table('Ports2Vlans')

        # Add pvid field to vlan table
        table_port = self.switch.getprop_table('Ports')
        for entry in table_port2vlan:
            entry['pvid'] = any(int(row['portId']) == entry['portId'] and
                                int(row['pvid']) == entry['vlanId'] for row in table_port)

        return table_port2vlan

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

        """
        if not expressions:
            expressions = []
        if ports:
            in_ports = ",".join([str(x) for x in ports])
            # Configure ACL Expressions
            exp = 'OutPorts'
            if "Ingress" in rules[0][3]:
                exp = 'InPorts'
            exp_ids = set()
            for rule in rules:
                exp_ids.add(rule[1])
            for _id in exp_ids:
                expressions.append((_id, exp, '', in_ports))
        if expressions:
            calls = [{"methodName": 'nb.ACLExpressions.addRow', "params": expressions}, ]
            res_list = self.switch.multicall(calls)
            errors = helpers.process_multicall(res_list)
            assert len(errors) == 0, "ACLExpressions.addRow methods failed with errors: %s" % [x["error"] for x in errors]

        # Configure ACL Actions
        if actions:
            calls = [{"methodName": 'nb.ACLActions.addRow', "params": actions}, ]
            res_list = self.switch.multicall(calls)
            errors = helpers.process_multicall(res_list)
            assert len(errors) == 0, "ACLActions.addRow methods failed with errors: %s" % [x["error"] for x in errors]

        # Configure ACL Rules
        if rules:
            calls = [{"methodName": 'nb.ACLRules.addRow', "params": rules}, ]
            res_list = self.switch.multicall(calls)
            errors = helpers.process_multicall(res_list)
            assert len(errors) == 0, "ACLRules.addRow methods failed with errors: %s" % [x["error"] for x in errors]

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

        """
        # Delete ACL Rules
        if rule_ids:
            find_params = [[x, ] for x in rule_ids]
            calls = [{"methodName": 'nb.ACLRules.find', "params": find_params}, ]
            res_list = self.switch.multicall(calls)
            errors = helpers.process_multicall(res_list)
            assert len(errors) == 0, "ACLRules.find methods failed with errors: %s" % [x["error"] for x in errors]
            del_params = [[int(x['result']), ] for x in res_list]
            calls = [{"methodName": 'nb.ACLRules.delRow', "params": del_params}, ]
            res_list = self.switch.multicall(calls)
            errors = helpers.process_multicall(res_list)
            assert len(errors) == 0, "ACLRules.delRow methods failed with errors: %s" % [x["error"] for x in errors]
            # TODO: add InPorts expression deleting (cli like)
        if action_ids:
            actions = [x for x in self.switch.getprop_table('ACLActions') if x['actionId'] in [y[0] for y in action_ids]]
            find_params = [[x['actionId'], x['action']] for x in actions]
            calls = [{"methodName": 'nb.ACLActions.find', "params": find_params}, ]
            res_list = self.switch.multicall(calls)
            errors = helpers.process_multicall(res_list)
            assert len(errors) == 0, "ACLActions.find methods failed with errors: %s" % [x["error"] for x in errors]
            del_params = [[int(x['result']), ] for x in res_list]
            calls = [{"methodName": 'nb.ACLActions.delRow', "params": del_params}, ]
            res_list = self.switch.multicall(calls)
            errors = helpers.process_multicall(res_list)
            assert len(errors) == 0, "ACLActions.delRow methods failed with errors: %s" % [x["error"] for x in errors]
        if expression_ids:
            expressions = [x for x in self.switch.getprop_table('ACLExpressions') if x['expressionId'] in [y[0] for y in expression_ids]]
            find_params = [[x['expressionId'], x['field']] for x in expressions]
            calls = [{"methodName": 'nb.ACLExpressions.find', "params": find_params}, ]
            res_list = self.switch.multicall(calls)
            errors = helpers.process_multicall(res_list)
            assert len(errors) == 0, "ACLExpressions.find methods failed with errors: %s" % [x["error"] for x in errors]
            del_params = [[int(x['result']), ] for x in res_list]
            calls = [{"methodName": 'nb.ACLExpressions.delRow', "params": del_params}, ]
            res_list = self.switch.multicall(calls)
            errors = helpers.process_multicall(res_list)
            assert len(errors) == 0, "ACLExpressions.delRow methods failed with errors: %s" % [x["error"] for x in errors]

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
        if table in {'ACLStatistics', 'ACLExpressions', 'ACLActions', 'ACLRules'}:
            return self.switch.getprop_table(table)
        else:
            raise UIException("Wrong table name: {0}".format(table))

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
            UIException:  macs and vlans required, port must be int

        """
        if not isinstance(port, int):
            raise UIException('Ports must be type int')
        if not vlans:
            raise UIException('List of vlans require')
        if not macs:
            raise UIException('List of macs require')
        if isinstance(vlans, int):
            vlans = [vlans]
        if isinstance(macs, str):
            macs = [macs]
        fdb_params = []
        for _vlan in vlans:
            for _mac in macs:
                fdb_params.append((_mac, _vlan, port))
        calls = [{"methodName": 'nb.StaticMAC.addRow', "params": fdb_params}, ]
        res_list = self.switch.multicall(calls)
        errors = helpers.process_multicall(res_list)
        assert len(errors) == 0, "StaticMAC.addRow methods failed with errors: %s" % [x["error"] for x in errors]

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
            UIException:  mac and vlan required

        """
        if not vlan:
            raise UIException('VlanID required')
        if not mac:
            raise UIException('Mac required')

        row_index = self.switch.findprop("StaticMAC", [mac, vlan])
        self.switch.delprop_row("StaticMAC", row_index)

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
        if table == 'Fdb':
            _table = self.switch.getprop_table('Fdb')
        elif table == 'Static':
            _table = self.switch.getprop_table('StaticMAC')
        else:
            raise UIException('Table name required')

        return _table

    def clear_table_fdb(self):
        """Clear Fdb table.

        Returns:
            None

        Examples::

            env.switch[1].ui.clear_table_fdb()

        """
        self.switch.xmlproxy.nb.Methods.clearAllFdbEntries()

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
        sched_params = ['portId', 'schedMode', 'trustMode', 'schedWeight0', 'schedWeight1', 'schedWeight2', 'schedWeight3',
                        'schedWeight4', 'schedWeight5', 'schedWeight6', 'schedWeight7', 'cos0Bandwidth', 'cos1Bandwidth', 'cos2Bandwidth',
                        'cos3Bandwidth', 'cos4Bandwidth', 'cos5Bandwidth', 'cos6Bandwidth', 'cos7Bandwidth']

        if param is not None:
            assert param in sched_params, "Incorrect parameter transmitted to function: %s" % param

        def filter_qos_parameters(qos_ports_row):
            """Filter LLDP parameters.

            """
            return {key: value for key, value in qos_ports_row.items() if key in sched_params}

        if port is not None:
            if param is not None:
                return self.switch.getprop("PortsQoS", param, self.switch.findprop("PortsQoS", [port, ]))
            else:
                row = self.switch.getprop_row("PortsQoS", self.switch.findprop("PortsQoS", [port, ]))
                return filter_qos_parameters(row)
        else:
            table = self.switch.getprop_table("PortsQoS")
            return [filter_qos_parameters(row) for row in table]

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
        table = self.switch.getprop_table("PortsDot1p2CoS")
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
        for key in kwargs:
            if key.startswith("dotp"):
                priority = int(key.split("dotp")[1][0])
                row_id = self.switch.findprop("PortsDot1p2CoS", [-1, priority])
                self.switch.setprop("PortsDot1p2CoS", "CoS", [row_id, kwargs[key]])

    def configure_dscp_to_cos_mapping_global(self, **kwargs):
        """Configure global mapping of ingress DSCP value to CoS per switch.

        """
        keys = ["dotp", "dscp"]
        for key in kwargs:
            for value in keys:
                if key.startswith(value):
                    priority = int(key.split(value)[1][0])
                    row_id = self.switch.findprop("PortsDSCP2CoS", [-1, kwargs[key]])
                    assert self.switch.setprop("PortsDSCP2CoS", "CoS", [row_id, priority]) == 0

    def get_table_ports_dscp2cos(self):
        """Get PortsDSCP2CoS table.

        """
        table = self.switch.getprop_table("PortsDSCP2CoS")

        return table

    def configure_schedweight_to_cos_mapping(self, ports, **kwargs):
        """Configure schedWeight to CoS mapping.

        """
        self.configure_port_cos(ports=ports, **kwargs)

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
        ports = [self.switch.findprop("PortsQoS", [x, ]) for x in ports]
        calls = []
        for _port in ports:
            for _key in kwargs:
                if _key != 'index':
                    calls.append({"methodName": 'nb.PortsQoS.set.%s' % (_key, ), "params": [(_port, kwargs[_key]), ]})

        res_list = self.switch.multicall(calls)
        errors = helpers.process_multicall(res_list)
        assert len(errors) == 0, "PortsQoS configuration failed with errors: %s" % [x["error"] for x in errors]

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

        for cos in cos_list:
            assert cos in list(kwargs.keys()), "Not all eight CoS values transmitted for configuring CoS per port"

        for port in ports:
            for priority in range(8):
                self.switch.setprop_row("PortsDot1p2CoS", [port, priority, kwargs["dotp%sCoS" % priority]])

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
        cos_list = ["dotp%sCoS" % idx for idx in range(8)]

        for port in ports:
            for key, queue in kwargs.items():
                if key in cos_list:
                    priority = int(key.split("dotp")[1][0])
                    row_id = self.switch.findprop("PortsDot1p2CoS", [port, priority])
                    self.switch.setprop("PortsDot1p2CoS", "CoS", [row_id, kwargs[key]])

    def clear_per_port_dot1p_cos_mapping(self, ports, rx_attr_flag=False, dot1p=None):
        """Clear CoS per port mapping.

        """
        for port in ports:
            for pri in dot1p:
                assert self.switch.xmlproxy.nb.PortsDot1p2CoS.delRow(self.switch.findprop('PortsDot1p2CoS', [port, pri])) == 0

# Statistics configuration
    def map_stat_name(self, generic_name):
        """Get the UI specific stat name for given generic name.

        Args:
            generic_name(str): generic statistic name

        Returns:
            str: UI specific stat name

        """
        return STAT_MAP.get(generic_name, generic_name)

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

        Raises:
            UIException:  stat_name required

        """
        stat_name = self.map_stat_name(stat_name)
        if port == 'cpu':
            if not stat_name:
                raise UIException('stat_name require')
            else:
                return self.switch.xmlproxy.nb.Methods.getCpuStats(stat_name)
        elif port:
            row_id = self.switch.findprop("Statistics", [port, ])
            if not stat_name:
                return self.switch.getprop_row("Statistics", row_id)
            else:
                return self.switch.getprop("Statistics", stat_name, row_id)
        else:
            return self.switch.getprop_table("Statistics")

    def clear_statistics(self):
        """Clear Statistics.

        Returns:
            None

        Examples:

            env.switch[1].ui.clear_statistics()

        """
        self.switch.xmlproxy.nb.Methods.clearAllStats()

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
        if param is None:
            return self.switch.getprop_table("BridgeInfo")
        else:
            return self.switch.getprop("BridgeInfo", param, 1)

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
        if 'agingTime' in kwargs:
            self.switch.setprop("BridgeInfo", "agingTime", [
                1, kwargs['agingTime']])
        if 'defaultVlanId' in kwargs:
            row_id = self.switch.xmlproxy.nb.BridgeInfo.getFirst()
            self.switch.setprop("BridgeInfo", "defaultVlanId", [
                row_id, kwargs['defaultVlanId']])
        if 'macAddress' in kwargs:
            self.switch.setprop("BridgeInfo", "macAddress", [
                1, kwargs['macAddress']])

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
        # if not lag:
        #     raise UIException('Lag required')
        name = 'lag%s' % (lag, )
        key = lag if key is None else key
        assert self.switch.setprop_row('LagsAdmin', [lag, name, key, lag_type, hash_mode]) == 0

    def delete_lags(self, lags=None):
        """Delete LAG instance.

        Args:
            lags(list[int]):  list of LAG Ids

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_lags([3800, ])

        """
        find_params = [[lag_id, ] for lag_id in lags]
        calls = [{"methodName": 'nb.LagsAdmin.find', "params": find_params}, ]
        res_list = self.switch.multicall(calls)
        errors = helpers.process_multicall(res_list)
        assert len(errors) == 0, "LagsAdmin.find methods failed with errors: %s" % [x["error"] for x in errors]
        del_params = [[int(x['result']), ] for x in res_list]
        calls = [{"methodName": 'nb.LagsAdmin.delRow', "params": del_params}, ]
        res_list = self.switch.multicall(calls)
        errors = helpers.process_multicall(res_list)
        assert len(errors) == 0, "LagsAdmin.delRow methods failed with errors: %s" % [x["error"] for x in errors]

    def get_table_lags(self):
        """Get LagsAdmin table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_lags()

        """
        return self.switch.getprop_table('LagsAdmin')

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
        lag_row_id = self.switch.findprop("LagsAdmin", [lag, ])
        if key:
            assert self.switch.setprop("LagsAdmin", "actorAdminLagKey", [lag_row_id, key]) == 0
        if lag_type:
            assert self.switch.setprop("LagsAdmin", "lagControlType", [lag_row_id, lag_type]) == 0
        if hash_mode:
            assert self.switch.setprop("LagsAdmin", "hashMode", [lag_row_id, hash_mode]) == 0

    def get_table_link_aggregation(self):
        """Get LinkAggregation table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_link_aggregation()

        """
        return self.switch.getprop_table('LinkAggregation')

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
        if globalenable:
            assert self.switch.setprop("LinkAggregation", "globalEnable", [1, globalenable]) == 0

        if collectormaxdelay:
            assert self.switch.setprop("LinkAggregation", "collectorMaxDelay", [1, collectormaxdelay]) == 0

        if globalhashmode:
            assert self.switch.setprop("LinkAggregation", "globalHashMode", [1, globalhashmode]) == 0

        if priority:
            assert self.switch.setprop("LinkAggregation", "priority", [1, priority]) == 0

        if lacpenable:
            assert self.switch.setprop("LinkAggregation", "lacpEnable", [1, lacpenable]) == 0

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
        key = lag if key is None else key
        for port in ports:
            self.switch.setprop_row('Ports2LagAdmin',
                                    [port, lag, priority, key, aggregation, lag_mode, timeout,
                                     str(synchronization), str(collecting),
                                     str(distributing), str(defaulting), str(expired),
                                     partner_system, partner_syspri, partner_number, partner_key,
                                     partner_pri])

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
        for port in ports:
            row_index = self.switch.findprop("Ports2LagAdmin", [port, lag])
            self.switch.delprop_row("Ports2LagAdmin", row_index)

    def get_table_ports2lag(self):
        """Get Ports2LagAdmin table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ports2lag()

        """
        return self.switch.getprop_table('Ports2LagAdmin')

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
        row_id = self.switch.findprop("Ports2LagAdmin", [port, lag])
        if priority:
            assert self.switch.setprop("Ports2LagAdmin", "actorPortPriority", [row_id, priority]) == 0
        if key:
            assert self.switch.setprop("Ports2LagAdmin", "actorAdminPortKey", [row_id, key]) == 0
        if aggregation:
            assert self.switch.setprop("Ports2LagAdmin", "adminAggregation", [row_id, aggregation]) == 0
        if lag_mode:
            assert self.switch.setprop("Ports2LagAdmin", "adminActive", [row_id, lag_mode]) == 0
        if timeout:
            assert self.switch.setprop("Ports2LagAdmin", "adminTimeout", [row_id, timeout]) == 0
        if synchronization:
            assert self.switch.setprop("Ports2LagAdmin", "adminSynchronization", [row_id, synchronization]) == 0
        if collecting:
            assert self.switch.setprop("Ports2LagAdmin", "adminCollecting", [row_id, collecting]) == 0
        if distributing:
            assert self.switch.setprop("Ports2LagAdmin", "adminDistributing", [row_id, distributing]) == 0
        if defaulting:
            assert self.switch.setprop("Ports2LagAdmin", "adminDefaulted", [row_id, defaulting]) == 0
        if expired:
            assert self.switch.setprop("Ports2LagAdmin", "adminExpired", [row_id, expired]) == 0
        if partner_system:
            assert self.switch.setprop("Ports2LagAdmin", "partnerAdminSystem", [row_id, partner_system]) == 0
        if partner_syspri:
            assert self.switch.setprop("Ports2LagAdmin", "partnerAdminSystemPriority", [row_id, partner_syspri]) == 0
        if partner_number:
            assert self.switch.setprop("Ports2LagAdmin", "partnerAdminPortNumber", [row_id, partner_number]) == 0
        if partner_key:
            assert self.switch.setprop("Ports2LagAdmin", "partnerAdminKey", [row_id, partner_key]) == 0
        if partner_pri:
            assert self.switch.setprop("Ports2LagAdmin", "partnerAdminPortPriority", [row_id, partner_pri]) == 0

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
        table = self.switch.getprop_table("Ports2LagLocal")
        if lag:
            return [x for x in table if x['lagId'] == lag]

        return table

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
        table = self.switch.getprop_table("Ports2LagRemote")
        if lag:
            return [x for x in table if x['lagId'] == lag]

        return table

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
        if lag:
            lag_row_id = self.switch.findprop("LagsLocal", [lag, ])
            return [self.switch.getprop_row("LagsLocal", lag_row_id), ]
        else:
            return self.switch.getprop_table("LagsLocal")

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
        if lag:
            lag_row_id = self.switch.findprop("LagsRemote", [lag, ])
            return [self.switch.getprop_row("LagsRemote", lag_row_id), ]
        else:
            return self.switch.getprop_table("LagsRemote")

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
            UIException:  wrong unknown-action type

        """
        self.switch.setprop("IGMPSnoopingGlobalAdmin", "mode", [1, mode])
        if router_alert:
            self.switch.setprop("IGMPSnoopingGlobalAdmin", "routerAlertEnforced", [1, router_alert])
        if unknown_igmp_behavior:
            if unknown_igmp_behavior in ['Broadcast', 'Drop']:
                self.switch.setprop("IGMPSnoopingGlobalAdmin", "unknownIgmpBehavior", [1, unknown_igmp_behavior])
            else:
                raise UIException('Wrong unknown-action type %s' % (unknown_igmp_behavior, ))
        if query_interval:
            self.switch.setprop("IGMPSnoopingGlobalAdmin", "queryInterval", [1, query_interval])
        if querier_robustness:
            self.switch.setprop("IGMPSnoopingGlobalAdmin", "querierRobustness", [1, querier_robustness])

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
        for port in ports:
            row_id = self.switch.findprop("IGMPSnoopingPortsAdmin", [port, ])
            self.switch.setprop("IGMPSnoopingPortsAdmin", "igmpEnabled", [row_id, mode])
            if router_port_mode:
                self.switch.setprop("IGMPSnoopingPortsAdmin", "routerPortMode", [row_id, router_port_mode])

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
            UIException:  port, vlams and macs required

        """
        if not port:
            raise UIException('Port require')
        if not vlans:
            raise UIException('List of vlans require')
        if not macs:
            raise UIException('List of macs require')
        multicast_params = []
        for _vlan in vlans:
            for _mac in macs:
                multicast_params.append((_mac, _vlan, port))
        calls = [{"methodName": 'nb.StaticL2Multicast.addRow', "params": multicast_params}, ]
        res_list = self.switch.multicall(calls)
        errors = helpers.process_multicall(res_list)
        assert len(errors) == 0, "StaticL2Multicast.addRow methods failed with errors: %s" % [x["error"] for x in errors]

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
            UIException:  port, mac and vlan required

        """
        if not port:
            raise UIException('PortID required')
        if not vlan:
            raise UIException('VlanID required')
        if not mac:
            raise UIException('MAC required')

        row_index = self.switch.findprop("StaticL2Multicast", [port, mac, vlan])
        self.switch.delprop_row("StaticL2Multicast", row_index)

    def get_table_l2_multicast(self):
        """Get L2Multicast table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_l2_multicast()

        """
        return self.switch.getprop_table('L2Multicast')

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
        if param:
            return self.switch.getprop("IGMPSnoopingGlobalAdmin", param, 1)
        else:
            return self.switch.getprop_table("IGMPSnoopingGlobalAdmin")

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
        row_id = self.switch.findprop("IGMPSnoopingPortsOper", [port, ])
        if param:
            return self.switch.getprop("IGMPSnoopingPortsOper", param, row_id)
        else:
            return self.switch.getprop_row("IGMPSnoopingPortsOper", row_id)

    def clear_l2_multicast(self):
        """Clear L2Multicast table.

        Returns:
            None

        Examples::

            env.switch[1].ui.clear_l2_multicast()

        """
        self.switch.xmlproxy.nb.Methods.clearL2MulticastDynamicEntries()

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
        self.switch.setprop('Layer3', 'RoutingEnable', [1, routing])
        if ospf:
            self.switch.setprop("OSPFRouter", "ospfEnabled", [1, ospf])

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
        self.switch.setprop_row('RouteInterface', [vlan, ip, ip_type, bandwidth, mtu, status, vrf])
        row = self.switch.findprop('RouteInterface', [vlan, ip, bandwidth, mtu, vrf])
        ri = self.switch.getprop_row('RouteInterface', row)
        self.ris[ip] = ri

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
        row_id = self.switch.findprop("RouteInterface", [vlan, ip, bandwith, mtu, vrf])
        self.switch.delprop_row('RouteInterface', row_id)
        self.ris[ip] = {}

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
        row_id = self.switch.findprop("RouteInterface", [vlan, ip, self.ris[ip]['bandwidth'], self.ris[ip]['mtu'], self.ris[ip]['VRF']])
        if 'adminMode' in kwargs:
            self.switch.setprop('RouteInterface', 'adminMode', [row_id, kwargs['adminMode']])

    def get_table_route_interface(self):
        """Get RouteInterface table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_route_interface()

        """
        return self.switch.getprop_table('RouteInterface')

    def get_table_route(self, mode='ip'):
        """Get Route table.

        Args:
            mode(str):  'ip' or 'ipv6'

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_route()

        """
        return self.switch.getprop_table('Route')

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
        if garp:
            self.switch.setprop("ARPConfig", "AcceptGARP", [1, garp])
        if refresh_period:
            self.switch.setprop("ARPConfig", "RefreshPeriod", [1, refresh_period])
        if delay:
            self.switch.setprop("ARPConfig", "RequestDelay", [1, delay])
        if secure_mode:
            self.switch.setprop("ARPConfig", "SecureMode", [1, secure_mode])
        if age_time:
            self.switch.setprop("ARPConfig", "AgeTime", [1, age_time])
        if attemptes:
            self.switch.setprop("ARPConfig", "NumAttempts", [1, attemptes])

    def get_table_arp_config(self):
        """Get ARPConfig table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_arp_config()

        """
        return self.switch.getprop_table('ARPConfig')

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
        if_id = self.ris[network]['ifId']
        vrf = self.ris[network]['VRF']
        self.switch.setprop_row('StaticARP', [ip, mac, if_id, vrf])

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
        vrf = self.ris[network]['VRF']
        row_id = self.switch.findprop('StaticARP', [ip, vrf])
        self.switch.delprop_row('StaticARP', row_id)

    def get_table_arp(self, mode='arp'):
        """Get ARP table.

        Args:
            mode(str):  'arp' or 'ipv6 neigbor'

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_arp()

        """
        if mode == 'arp static':
            return self.switch.getprop_table('StaticARP')
        return self.switch.getprop_table('ARP')

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
        if_id = self.ris[network]['ifId']
        vrf = self.ris[network]['VRF']
        self.switch.setprop_row('StaticRoute', [ip, nexthop, if_id, vrf, distance])
        row = self.switch.findprop('StaticRoute', [ip, nexthop, vrf])
        self.static_routes[ip] = self.switch.getprop_row('StaticRoute', row)

    def delete_static_route(self, network):
        """Delete StaticRoute record.

        Args:
            network(str):  RouteInterface network

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_static_route('10.0.5.101/24')

        """
        vrf = self.static_routes[network]['VRF']
        nexthop = self.static_routes[network]['nexthop']
        self.switch.delprop_row('StaticRoute', self.switch.findprop('StaticRoute', [network, nexthop, vrf]))

    def get_table_static_route(self, mode='ip'):
        """Get StaticRoute table.

        Args:
            mode(str):  'ip' or 'ipv6'

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_static_route()

        """
        return self.switch.getprop_table('StaticRoute')

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
        if 'logAdjacencyChanges' in kwargs:
            self.switch.setprop("OSPFRouter", "logAdjacencyChanges", [1, kwargs['logAdjacencyChanges']])
        if 'routerId' in kwargs:
            self.switch.setprop("OSPFRouter", "routerId", [1, kwargs['routerId']])

    def get_table_ospf_router(self):
        """Get OSPFRouter table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ospf_router()

        """
        return self.switch.getprop_table("OSPFRouter")

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
        self.switch.setprop_row("OSPFAreas", [area, "Default", "Disabled", -1, "Disabled", "", "", "", "", "Disabled", "Candidate"])
        self.areas[area] = self.switch.getprop("OSPFAreas", "areaId", self.switch.findprop("OSPFAreas", [area, ]))

    def get_table_ospf_area(self):
        """Get OSPFAreas table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ospf_area()

        """
        return self.switch.getprop_table("OSPFAreas")

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
        area_id = self.areas[area]
        self.switch.setprop_row("OSPFNetworks2Area", [network, area_id, mode])

    def get_table_network_2_area(self):
        """Get OSPFNetworks2Area table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_network_2_area()

        """
        return self.switch.getprop_table("OSPFNetworks2Area")

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
        area_id = self.areas[area]
        self.switch.setprop_row("OSPFAreas2Ranges", [area_id, "Advertise", range_ip, range_mask, 100, "Enabled", substitute_ip, substitute_mask])

    def get_table_area_ranges(self):
        """Get OSPFAreas2Ranges table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_area_ranges()

        """
        return self.switch.getprop_table("OSPFAreas2Ranges")

    def create_route_redistribute(self, mode):
        """Create OSPFRouteRedistribute record.

        Args:
            mode(str):  redistribute mode

        Returns:
            None

        Examples::

            env.switch[1].ui.create_route_redistribute("Static")

        """
        self.switch.setprop_row("OSPFRouteRedistribute", [mode, -1, -1, -1])

    def get_table_route_redistribute(self):
        """Get OSPFRouteRedistribute table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_route_redistribute()

        """
        return self.switch.getprop_table("OSPFRouteRedistribute")

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
        if_id = self.ris[network]['ifId']
        self.switch.setprop_row("OSPFInterfaceMD5Keys", [if_id, key_id, key, ""])

    def get_table_interface_authentication(self):
        """Get OSPFInterfaceMD5Keys table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_interface_authentication()

        """
        return self.switch.getprop_table("OSPFInterfaceMD5Keys")

    def create_ospf_interface(self, vlan, network, dead_interval=40, hello_interval=5, network_type="Broadcast", hello_multiplier=3, minimal='Enabled',
                              priority=-1, retransmit_interval=-1):
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
        if_id = self.ris[network]['ifId']
        self.switch.setprop_row("OSPFInterface", [if_id, -1, dead_interval, minimal, hello_multiplier, hello_interval, network_type, 1, retransmit_interval, 1])

    def get_table_ospf_interface(self):
        """Get OSPFInterface table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_interface_authentication()

        """
        return self.switch.getprop_table("OSPFInterface")

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
        area_id = self.areas[area]
        self.switch.setprop_row("OSPFVirtLink", [area_id, link, "Enabled"])

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
        self.switch.setprop("BGPRouter", "asn", [1, asn]) == 0
        self.switch.setprop("BGPRouter", "bgpEnabled", [1, enabled]) == 0

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
        self.switch.setprop_row("BGPNeighbor2As", [asn, ip, remote_as])

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
        self.switch.setprop_row("BGPNeighbor", [asn, "Base", "Unicast", ip, "Disabled", 0, "Disabled", "Disabled", "Disabled",
                                                "Disabled", "Disabled", "Disabled", "Disabled", "DefOrigRouteMap", "UserDescription", "Enabled",
                                                "", "", "Disabled", -1, "Disabled", "filterListIn", "filterListOut", -1,
                                                "Disabled", -1, -1, -1, "Disabled", "Disabled", "Disabled", "Disabled", "", "", "",
                                                "Disabled", "routeMapIn", "routeMapOut", "routeMapImport", "routeMapExport", "Disabled", "Disabled", "Disabled",
                                                "Enabled", "Disabled", "Disabled", -1, -1, -1, "unsuppressMap", "updateSource", -1])

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
        self.switch.setprop_row("BGPNeighborConnection", [asn, ip, -1, -1, port, "Disabled", -1])

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
        self.switch.setprop_row("BGPBgp", [asn, "Base", "Unicast", "Enabled", "Disabled", "Enabled", "Enabled", "Enabled", "Disabled",
                                           "Enabled", "", -1, "Disabled", -1, -1, -1, -1, "Disabled", -1, "Disabled", "Disabled", "Enabled", "Enabled", 3600,
                                           "Enabled", "Disabled", router_id, -1])

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
        self.switch.setprop_row("BGPPeerGroups", [asn, name])

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
        self.switch.setprop_row("BGPPeerGroupMembers", [asn, "Base", "Unicast", name, ip])

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
        self.switch.setprop_row("BGPRedistribute", [asn, "Base", "Unicast", rtype, -1, ""])

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
        network = ip + '/24'
        self.switch.setprop_row("BGPNetwork", [asn, "Ipv4", "Unicast", network, "Disabled", route_map])

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
        network = ip + '/24'
        self.switch.setprop_row("BGPAggregateAddress", [asn, "Base", "Unicast", network, "Disabled", "Disabled"])

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
        self.switch.setprop_row("BGPBgpConfederationPeers", [asn, peers])

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
        network = ip + '/24'
        self.switch.setprop_row("BGPDistanceNetwork", [asn, network, distance, route_map])

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
        self.switch.setprop_row("BGPDistanceAdmin", [asn, ext_distance, int_distance, local_distance])

    def get_table_bgp_neighbor(self):
        """Get BGPNeighbour table.

        Returns:
            list[dict]: table

        Examples::

            env.switch[1].ui.get_table_bgp_neighbor()

        """
        return self.switch.getprop_table('BGPNeighbor')

    def get_table_bgp_neighbor_connections(self):
        """Get BGPNeighborConnection table.

        Returns:
            list[dict]:  table

        Examples::

            env.switch[1].ui.get_table_bgp_neighbor_connections()

        """
        return self.switch.getprop_table('BGPNeighborConnection')

    def get_table_bgp_aggregate_address(self):
        """Get BGPAggregateAddress table.

        Returns:
            list[dict]:  table

        Examples::

            env.switch[1].ui.get_table_bgp_aggregate_address()

        """
        return self.switch.getprop_table('BGPAggregateAddress')

    def get_table_bgp_confederation_peers(self):
        """Get BGPBgpConfederationPeers table.

        Returns:
            list[dict] table

        Examples::

            env.switch[1].ui.get_table_bgp_confederation_peers()

        """
        return self.switch.getprop_table('BGPBgpConfederationPeers')

    def get_table_bgp_distance_admin(self):
        """Get BGPDistanceAdmin table.

        Returns:
            list[dict]: table

        Examples::

            env.switch[1].ui.get_table_bgp_distance_admin()

        """
        return self.switch.getprop_table('BGPDistanceAdmin')

    def get_table_bgp_distance_network(self):
        """Get BGPDistanceNetwork table.

        Returns:
            list[dict]: table

        Examples::

            env.switch[1].ui.get_table_bgp_distance_network()

        """
        return self.switch.getprop_table('BGPDistanceNetwork')

    def get_table_bgp_network(self):
        """Get BGPNetwork table.

        Returns:
            list[dict]:  table

        Examples::

            env.switch[1].ui.get_table_bgp_network()

        """
        return self.switch.getprop_table('BGPNetwork')

    def get_table_bgp_peer_group_members(self):
        """Get BGPPeerGroupMembers table.

        Returns:
            list[dict]: table

        Examples::

            env.switch[1].ui.get_table_bgp_peer_group_members()

        """
        return self.switch.getprop_table('BGPPeerGroupMembers')

    def get_table_bgp_peer_groups(self):
        """Get BGPPeerGroups table

        Returns:
            list[dict]:  table

        Example:

            env.switch[1].ui.get_table_bgp_peer_groups()

        """
        return self.switch.getprop_table('BGPPeerGroups')

    def get_table_bgp_redistribute(self):
        """Get BGPRedistribute table.

        Returns:
            list[dict]: table

        Examples::

            env.switch[1].ui.get_table_bgp_redistribute()

        """
        return self.switch.getprop_table('BGPRedistribute')

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
        self.switch.setprop_row("OvsBridges", [0, bridge_name, "switchpp"]) == 0

    def get_table_ovs_bridges(self):
        """Get OvsBridges table.

        Returns:
            list[dict]:  table (list of dictionaries))

        Examples::

            env.switch[1].ui.get_table_ovs_bridges()

        """
        return self.switch.getprop_table("OvsBridges")

    def delete_ovs_bridge(self):
        """Delete OVS Bridge.

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_ovs_bridge()

        """
        self.switch.delprop_row("OvsBridges", 1) == 0

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
        self.switch.setprop_row("OvsPorts", [port, 0, "%s-%i" % (bridge_name, port), "switchpp"]) == 0

    def get_table_ovs_ports(self):
        """Get OvsPorts table.

        Returns:
            list[dict]:  table (list of dictionaries))

        Examples::

            env.switch[1].ui.get_table_ovs_ports()

        """
        return self.switch.getprop_table("OvsPorts")

    def get_table_ovs_rules(self):
        """Get OvsFlowRules table.

        Returns:
            list[dict]: table (list of dictionaries))

        Examples::

            env.switch[1].ui.get_table_ovs_rules()

        """
        return self.switch.getprop_table("OvsFlowRules")

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
        assert self.switch.setprop_row("OvsFlowRules", [bridge_id, table_id, flow_id, priority, enabled]) == 0, "Row is not added to OvsFlowRules table."

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

        """
        row_id = self.switch.findprop("OvsFlowRules", [bridge_id, table_id, flow_id, priority])
        assert self.switch.delprop_row("OvsFlowRules", row_id) == 0, "OVS Flow Rule is not deleted."

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
        self.switch.setprop_row("OvsControllers", [0, controller])

    def get_table_ovs_controllers(self):
        """Get OvsControllers table.

        Returns:
            list[dict]:  table (list of dictionaries))

        Examples::

            env.switch[1].ui.get_table_ovs_controllers()

        """
        return self.switch.getprop_table("OvsControllers")

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
        available_params = ['controllerRateLimit', 'vlansLimit', 'untaggedVlan', 'rulesLimit']

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in available_params}

        helpers.update_table_params(self.switch, "OvsResources", params, row_id=1, validate_updates=False)

    def get_table_ovs_flow_actions(self):
        """Get OvsFlowActions table.

        Returns:
            list[dict]:  table (list of dictionaries))

        Examples::

            env.switch[1].ui.get_table_ovs_flow_actions()

        """
        return self.switch.getprop_table("OvsFlowActions")

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
        assert self.switch.setprop_row("OvsFlowActions", [bridge_id, table_id, flow_id, action, param]) == 0, "Row is not added to OvsFlowActions table."

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
        row_id = self.switch.findprop("OvsFlowActions", [bridge_id, table_id, flow_id, action])
        assert self.switch.delprop_row("OvsFlowActions", row_id) == 0, "OVS Flow Rule is not deleted."

    def get_table_ovs_flow_qualifiers(self):
        """Get OvsFlowQualifiers table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ovs_flow_qualifiers()

        """
        return self.switch.getprop_table("OvsFlowQualifiers")

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
        assert self.switch.setprop_row("OvsFlowQualifiers", [bridge_id, table_id, flow_id, field, data]) == 0, "Row is not added to OvsFlowQualifiers table."

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
        row_id = self.switch.findprop("OvsFlowQualifiers", [bridge_id, table_id, flow_id, field])
        assert self.switch.delprop_row("OvsFlowQualifiers", row_id) == 0, "OVS Flow Rule is not deleted."

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
        available_params = ['messageFastTx', 'messageTxHoldMultiplier', 'messageTxInterval',
                            'reinitDelay', 'txCreditMax', 'txFastInit', 'locChassisIdSubtype']

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in available_params}

        helpers.update_table_params(self.switch, "Lldp", params, row_id=1, validate_updates=False)

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
        available_params = ['adminStatus', 'tlvManAddrTxEnable', 'tlvPortDescTxEnable',
                            'tlvSysCapTxEnable', 'tlvSysDescTxEnable', 'tlvSysNameTxEnable']

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in available_params}

        for port in ports:
            helpers.update_table_params(self.switch, "LldpPorts", params, [port, ], validate_updates=False)

    def get_table_lldp(self, param=None):
        """Get Lldp table.

        Args:
            param(str):  parameter name (optional)

        Returns:
            list[dict]|int|str: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_lldp()

        """
        if param is not None:
            return self.switch.getprop("Lldp", param, 1)
        else:
            return self.switch.getprop_table("Lldp")

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
        lldp_params = ['adminStatus', 'locPortId', 'tlvManAddrTxEnable', 'tlvSysNameTxEnable', 'multipleNeighbors', 'somethingChangedLocal',
                       'tlvPortDescTxEnable', 'mgmtNeighbors', 'somethingChangedRemote', 'tlvSysCapTxEnable', 'locPortIdSubtype',
                       'locPortDesc', 'portId', 'tooManyNeighbors', 'portNeighbors', 'tlvSysDescTxEnable']

        if param is not None:
            assert param in lldp_params, "Incorrect parameter transmitted to function: %s" % param

        def filter_lldp_parameters(lldp_ports_row):
            """Filter LLDP parameters"""
            return {key: value for key, value in lldp_ports_row.items() if key in lldp_params}

        # TODO: Split get LLDP table into two methods
        if port is not None:
            if param is not None:
                return self.switch.getprop("LldpPorts", param, self.switch.findprop("LldpPorts", [port, ]))
            else:
                row = self.switch.getprop_row("LldpPorts", self.switch.findprop("LldpPorts", [port, ]))
                return filter_lldp_parameters(row)
        else:
            table = self.switch.getprop_table("LldpPorts")
            for idx, value in enumerate(table):
                table[idx] = filter_lldp_parameters(table[idx])

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
        lldp_params = ['statsRxTLVsDiscardedTotal', 'statsTxFramesTotal', 'statsRxFramesTotal', 'statsRxAgeoutsTotal', 'portId',
                       'statsRxFramesInErrorsTotal', 'statsRxFramesDiscardedTotal', 'statsRxTLVsUnrecognizedTotal']

        if param is not None:
            assert param in lldp_params, "Incorrect parameter transmitted to function: %s" % param

        def filter_lldp_parameters(lldp_ports_row):
            """Filter LLDP parameters.

            """
            return {key: value for key, value in lldp_ports_row.items() if key in lldp_params}

        # TODO: Split get LLDP table into two methods
        if port is not None:
            if param is not None:
                return self.switch.getprop("LldpPorts", param, self.switch.findprop("LldpPorts", [port, ]))
            else:
                row = self.switch.getprop_row("LldpPorts", self.switch.findprop("LldpPorts", [port, ]))
                return filter_lldp_parameters(row)
        else:
            table = self.switch.getprop_table("LldpPorts")
            for idx, value in enumerate(table):
                table[idx] = filter_lldp_parameters(table[idx])

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
        lldp_remotes = self.switch.getprop_table("LldpRemotes")
        if port is not None:
            return [row for row in lldp_remotes if row["remLocalPortNum"] == port]
        else:
            return lldp_remotes

    def get_table_remotes_mgmt_addresses(self, port=None):
        """Get LldpRemotesMgmtAddresses table.

        Args:
            port(int):  port Id (optional)

        Returns:
            list[dict]: table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_table_remotes_mgmt_addresses(1)

        """
        lldp_remotes = self.switch.getprop_table("LldpRemotesMgmtAddresses")
        if port is not None:
            return [row for row in lldp_remotes if row["remLocalPortNum"] == port]
        else:
            return lldp_remotes

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
            ports = [row['portId'] for row in self.switch.getprop_table("Ports")]

        # Find row IDs
        params = [(port, ) for port in ports]
        find_results = self.switch.multicall([{'methodName': "nb.LldpPorts.find", 'params': params}, ])
        errors = helpers.process_multicall(find_results)
        assert len(errors) == 0, "LldpPorts.find methods failed with errors"

        # Set LLDP adminStatus to disabled for all ports
        disable_ports = [(int(find_res["result"]), "Disabled") for find_res in find_results]
        result = self.switch.multicall([{'methodName': "nb.LldpPorts.set.adminStatus", 'params': disable_ports}, ])
        errors = helpers.process_multicall(result)
        assert len(errors) == 0, "nb.LldpPorts.set.adminStatus method failed with errors"

        # Verify that LLDP adminStatus was set to disabled for all ports
        rows = [(value[0], ) for value in disable_ports]
        lldp_statuses = self.switch.multicall([{'methodName': "nb.LldpPorts.get.adminStatus", 'params': rows}, ])
        errors = helpers.process_multicall(result)
        assert len(errors) == 0, "nb.LldpPorts.set.adminStatus method failed with errors"
        assert all([status["result"] == "Disabled" for status in lldp_statuses]), "Lldp admin status was not set to Disabled for all ports"

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
        for port in ports:
            helpers.update_table_params(self.switch, "DcbxPorts", {'adminStatus': mode}, [port, ], validate_updates=False)

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
            ValueError:  invalid DCBX tlvs

        """
        all_dcbx_tlvs = ['tlvApplicationPriorityTxEnable', 'tlvCongestionNotificationTxEnable',
                         'tlvEtsConfTxEnable', 'tlvEtsRecoTxEnable', 'tlvPfcTxEnable']

        if isinstance(dcbx_tlvs, list):
            tlv_list = dcbx_tlvs
        elif isinstance(dcbx_tlvs, str) and dcbx_tlvs.lower() == "all":
            tlv_list = all_dcbx_tlvs
        else:
            raise ValueError("Invalid DCBX tlvs specified %s" % dcbx_tlvs)

        for port in ports:
            for tlv in tlv_list:
                helpers.update_table_params(self.switch, "DcbxPorts", {tlv: mode}, [port, ], validate_updates=False)

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
        if port is not None:
            if param is not None:
                return self.switch.getprop("DcbxPorts", param, self.switch.findprop("DcbxPorts", [port, ]))
            else:
                return self.switch.getprop_row("DcbxPorts", self.switch.findprop("DcbxPorts", [port, ]))
        else:
            return self.switch.getprop_table("DcbxPorts")

    def get_table_dcbx_app_remote(self, port=None):
        """Get DcbxAppRemotes table.

        Args:
            port(int):  port Id (optional)

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_dcbx_app_remote()

        """
        table = self.switch.getprop_table("DcbxAppRemotes")
        if port is not None:
            return [row for row in table if row["portId"] == port]
        else:
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
        assert table_type in ["Admin", "Local"], "Incorrect Dcbx App Ports table type specified: %s" % table_type

        table = self.switch.getprop_table("DcbxAppPorts%s" % table_type)
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
        assert table_type in ["Admin", "Local", "Remote"], "Incorrect Dcbx App Maps table type specified: %s" % table_type

        table = self.switch.getprop_table("DcbxAppMaps%s" % table_type)
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
        assert table_type in ["Local", "Remote"], "Incorrect Dcbx Pfc table type specified: %s" % table_type

        table = self.switch.getprop_table("DcbxPfcPorts%s" % table_type)
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
        assert table_type in ["Admin", "Local"], "Incorrect Dcbx Ets Ports table type specified: %s" % table_type

        table = self.switch.getprop_table("DcbxEtsPorts{}".format(table_type))
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
        for port in ports:
            for rule in app_prio_rules:
                if update_params:
                    helpers.update_table_params(self.switch, "DcbxAppMapsAdmin", {"priority": rule["priority"]}, [port, rule["selector"], rule['protocol']])
                elif delete_params:
                    row_id = self.switch.findprop("DcbxAppMapsAdmin", [port, rule['selector'], rule['protocol']])
                    assert self.switch.delprop_row("DcbxAppMapsAdmin", row_id) == 0, "Rule is not deleted"
                else:
                    assert self.switch.setprop_row("DcbxAppMapsAdmin", [port, rule["selector"], rule["protocol"], rule["priority"], ]) == 0, \
                        "Application Priority rule was not added"

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
        available_params = ["willing", "cbs", "maxTCs", "confBandwidth", "confPriorityAssignment", "confAlgorithm",
                            "recoBandwidth", "recoPriorityAssignment", "recoAlgorithm"]

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in available_params}

        for port in ports:
            helpers.update_table_params(self.switch, "DcbxEtsPortsAdmin", params, [port, ], validate_updates=False)

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
        available_params = ["cnpvSupported", "cnpvReady"]

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in available_params}

        for port in ports:
            helpers.update_table_params(self.switch, "DcbxCnPortsAdmin", params, [port, ], validate_updates=False)

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
        available_params = ["willing", ]

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in available_params}

        for port in ports:
            helpers.update_table_params(self.switch, "DcbxAppPortsAdmin", params, [port, ], validate_updates=False)

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
        available_params = ["mbc", "enabled", "willing"]

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in available_params}

        for port in ports:
            helpers.update_table_params(self.switch, "DcbxPfcPortsAdmin", params, [port, ], validate_updates=False)

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
        if port is not None:
            if param is not None:
                return self.switch.getprop("DcbxRemotes", param, self.switch.findprop("DcbxRemotes", [port, ]))
            else:
                return self.switch.getprop_row("DcbxRemotes", self.switch.findprop("DcbxRemotes", [port, ]))
        else:
            return self.switch.getprop_table("DcbxRemotes")

# UFD configuration

    def get_table_ufd_config(self):
        """Get UFDConfig table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ufd_config()

        """
        return self.switch.getprop_table("UFDConfig")

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
        assert self.switch.setprop('UFDConfig', 'enable', [1, enable]) == 0, "UFD can not be %s in general." % enable
        if hold_on_time:
            assert self.switch.setprop('UFDConfig', 'holdOnTime', [1, hold_on_time]) == 0, "UFD holdOnTime is not set to %s." % hold_on_time

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
        assert self.switch.setprop_row('UFDGroups', [group_id, threshold, enable]) == 0, "UFD group can not be created."

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
        row = self.switch.findprop('UFDGroups', [group_id])
        if enable:
            assert self.switch.setprop('UFDGroups', 'enable', [row, enable]) == 0, "UFD group can not be %s." % enable
        if threshold:
            assert self.switch.setprop('UFDGroups', 'threshold', [row, threshold]) == 0, "UFD threshold is not set to %s." % threshold

    def delete_ufd_group(self, group_id):
        """Delete UFDGroups record.

        Args:
            group_id(int):  UFD group ID

        Returns:
            None

        Examples::

            env.switch[1].ui.delete_ufd_group(2)

        """
        row = self.switch.findprop('UFDGroups', [group_id])
        assert self.switch.delprop_row('UFDGroups', row) == 0, "UFD group can not be deleted."

    def get_table_ufd_groups(self):
        """Get UFDGroups table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ufd_groups()

        """
        return self.switch.getprop_table("UFDGroups")

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
        params = [(int(x), port_type, group_id) for x in ports]
        results = self.switch.multicall([{"methodName": 'nb.UFDPorts2Groups.addRow', "params": params}])
        errors = helpers.process_multicall(results)
        assert len(errors) == 0, "nb.UFDPorts2Groups.addRow methods failed with errors: %s" % [x["error"] for x in errors]

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
        params = [(int(x), port_type, group_id) for x in ports]
        results = self.switch.multicall([{"methodName": 'nb.UFDPorts2Groups.find', "params": params}])
        errors = helpers.process_multicall(results)
        assert len(errors) == 0, "nb.UFDPorts2Groups.find methods failed with errors: %s" % [x["error"] for x in errors]

        del_params = [[int(x['result']), ] for x in results]
        calls = [{"methodName": 'nb.UFDPorts2Groups.delRow', "params": del_params}, ]
        results = self.switch.multicall(calls)
        errors = helpers.process_multicall(results)
        assert len(errors) == 0, "UFDPorts2Groups.delRow methods failed with errors: %s" % [x["error"] for x in errors]

    def get_table_ufd_ports(self):
        """Get UFDPorts2Groups table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_ufd_ports()

        """
        return self.switch.getprop_table("UFDPorts2Groups")

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
        available_params = ["mode", "tpid"]
        first = operator.itemgetter(0)
        ordered_params = OrderedDict(sorted(((k, v) for k, v in kwargs.items() if k in available_params), key=first))

        for port in ports:
            helpers.update_table_params(self.switch, "QinQPorts", ordered_params, [port, ], validate_updates=False)

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
        for port in ports:
            self.switch.setprop_row("QinQVlanStacking", [port, provider_vlan_id, provider_vlan_priority])

    def get_table_qinq_vlan_stacking(self):
        """Get QinQVlanStacking table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_qinq_vlan_stacking()

        """
        return self.switch.getprop_table("QinQVlanStacking")

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
        for port in ports:
            self.switch.setprop_row("QinQCustomerVlanMapping", [port, customer_vlan_id, provider_vlan_id, provider_vlan_priority])
            self.switch.setprop_row("QinQProviderVlanMapping", [port, provider_vlan_id, customer_vlan_id, customer_vlan_priority])

    def get_table_qinq_customer_vlan_mapping(self):
        """Get QinQCustomerVlanMapping table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_qinq_customer_vlan_mapping()

        """
        return self.switch.getprop_table("QinQCustomerVlanMapping")

    def get_table_qinq_provider_vlan_mapping(self):
        """Get QinQProviderVlanMapping table.

        Returns:
            list[dict]: table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_qinq_provider_vlan_mapping()

        """
        return self.switch.getprop_table("QinQProviderVlanMapping")

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
        if port is not None:
            if param is not None:
                return self.switch.getprop("QinQPorts", param, self.switch.findprop("QinQPorts", [port, ]))
            else:
                return self.switch.getprop_row("QinQPorts", self.switch.findprop("QinQPorts", [port, ]))
        else:
            return self.switch.getprop_table("QinQPorts")

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
        if app_name and app_error:
            row = self.switch.findprop('ErrdisableErrorsConfig', [app_name, app_error, ])
            return self.switch.getprop_row("ErrdisableErrorsConfig", row)
        else:
            return self.switch.getprop_table("ErrdisableErrorsConfig")

    def get_table_errdisable_config(self):
        """Get ErrdisableConfig table.

        Returns:
            list[dict]:  table (list of dictionaries)

        Examples::

            env.switch[1].ui.get_table_errdisable_config()

        """
        return self.switch.getprop_table("ErrdisableConfig")

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
        row = self.switch.findprop('ErrdisableErrorsConfig', [app_name, app_error, ])
        if detect:
            assert self.switch.setprop('ErrdisableErrorsConfig', 'enabled', [row, detect]) == 0, "ErrdisableErrorsConfig detection isn't set to %s" % detect
        if recovery:
            assert self.switch.setprop('ErrdisableErrorsConfig', 'recovery', [row, recovery]) == 0, "ErrdisableErrorsConfig recovery isn't set to %s" % recovery

    def modify_errdisable_config(self, interval=None):
        """Configure ErrdisableConfig table.

        Args:
            interval(int):  recovery interval

        Returns:
            None

        Examples::

            env.switch[1].ui.modify_errdisable_config(10)

        """
        if interval:
            assert self.switch.setprop('ErrdisableConfig', 'recoveryInterval', [1, interval]) == 0, "ErrdisableConfig interval isn't set to %s" % interval

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
        if port and app_name and app_error:
            row = self.switch.findprop('ErrdisablePorts', [port, app_name, app_error, ])
            if row != -1:
                if param:
                    return self.switch.getprop_row("ErrdisablePorts", param, row)
                else:
                    return self.switch.getprop_row("ErrdisablePorts", row)
            else:
                return []
        else:
            return self.switch.getprop_table("ErrdisablePorts")

# Mirroring configuration

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
        self.switch.setprop_row('PortsMirroring', [port, target, mode])

    def get_mirroring_sessions(self):
        """Get PortsMirroring table.

        Returns:
            list[dict]|int|str:  table (list of dictionaries) or value

        Examples::

            env.switch[1].ui.get_mirroring_sessions()

        """
        return self.switch.getprop_table('PortsMirroring')

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
        row_id = self.switch.findprop('PortsMirroring', [port, target, mode])
        self.switch.delprop_row("PortsMirroring", row_id)

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
        if fwd_iface_name:
            self.switch.setprop_row('DhcpRelayV6Admin', [iface_name, 'Enabled', server_ip, fwd_iface_name])
        else:
            self.switch.setprop_row('DhcpRelayAdmin', [iface_name, 'Enabled', server_ip])

    def get_table_dhcp_relay(self, dhcp_relay_ipv6=False):
        """Return DhcpRelayAdmin or DhcpRelayV6Admin table

        Args:
            dhcp_relay_ipv6(bool):  is IPv6 config defined

        Returns:
            None

        Examples::

            env.switch[1].ui.get_table_dhcp_relay(dhcp_relay_ipv6=False)

        """
        if dhcp_relay_ipv6:
            return self.switch.getprop_table('DhcpRelayV6Admin')
        else:
            return self.switch.getprop_table('DhcpRelayAdmin')

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

        """
        if 'vnTag' in kwargs:
            self.switch.setprop('TunnelingGlobalAdmin', 'vnTag', [1, kwargs['vnTag']])
        if 'vxlanInnerVlanProcessing' in kwargs:
            self.switch.setprop('TunnelingGlobalAdmin', 'vxlanInnerVlanProcessing', [1, kwargs['vxlanInnerVlanProcessing']])
        if 'mode' in kwargs:
            self.switch.setprop('TunnelingGlobalAdmin', 'mode', [1, kwargs['mode']])
        if 'vxlanDestUDPPort' in kwargs:
            self.switch.setprop('TunnelingGlobalAdmin', 'vxlanDestUDPPort', [1, kwargs['vxlanDestUDPPort']])

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

        """
        self.switch.setprop_row("TunnelsAdmin", [tunnel_id, destination_ip, vrf, encap_type])

    def get_table_tunnels_admin(self):
        """Return TunnelsAdmin table.

        Returns:
            list[dict]:  table

        Examples::

            env.switch[1].ui.get_table_tunnels_admin()

        """
        return self.switch.getprop_table("TunnelsAdmin")

    def create_invalid_ports(self, ports=None, num=1):
        """Creates port name if port id is passed say [Swop100, if 100 is passed as port id].

        Else creates port name with a value incremented to 10 to existing length of ports
        Ex[sw0p34 , currently sw0p24 is last port]

        Args:
            ports(iter()): list of port_ids to generate port_names for
            num(int): generate num new invalid ports

        """
        if ports is not None:
            port_ids = ports
        else:
            base = len(self.get_table_ports()) + 10
            # an invalid range will return an empty list and thus
            # an empty dict
            port_ids = [base + p for p in range(num)]
        return InvalidPortContext(self, port_ids)


class InvalidPortContext(object):
    """Class to create a invalid port.

    """
    def __init__(self, ui, ports):
        """"Initialize Invalidport class.

        Args:
            ui(UiOnsXmlrpc):  instance of switch
            ports(list):  port id of invalid port

        """
        super(InvalidPortContext, self).__init__()
        self.ports = ports
        self.ui = ui

    def __enter__(self):
        """

        Returns:
            list: list of ports

        """
        return self.ports

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Deletes invalid port created.

        """
        pass
