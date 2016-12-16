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

@file  ui_ons_xmlrpc.py

@summary  XMLRPC UI wrappers.
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
    "TxUcstPktsIPv4": "IfOutUcastPkts"
}


class UiOnsXmlrpc(UiHelperMixin, UiInterface):
    """
    @description  Class with XMLRPC wrappers
    """

    def __init__(self, switch):
        self.switch = switch
        self.ris = {}
        self.areas = {}
        self.static_routes = {}
        self.switch.cli = clicmd_ons.CLICmd(
                    self.switch.ipaddr, self.switch._sshtun_port,
                    self.switch.config['cli_user'],
                    self.switch.config['cli_user_passw'],
                    self.switch.config['cli_user_prompt'], self.switch.type)

    def connect(self):
        if self.switch._use_sshtun:
            self.switch.open_sshtun()

    def disconnect(self):
        if self.switch.sshtun is not None:
            self.switch.close_sstun()

    def restart(self):
        try:
            server, port = self.switch.xmlproxy._ServerProxy__host.split(":")
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::logs_add_message()
        """
        self.switch.xmlproxy.tools.logMessage(level, message)

# Temperature information
    def get_temperature(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_temperature()
        """
        sensor_table = self.switch.getprop_table('Sensors')
        temp_table = [x for x in sensor_table if 'Temp' in x['type']]
        return temp_table

# System information
    def get_memory(self, mem_type='usedMemory'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_memory()
        """
        table = self.switch.xmlproxy.nb.Methods.getKPIData()
        mem_table = [x["value"] for x in table if x["indicator"] == mem_type]
        mem = float(mem_table[0])
        return mem

    def get_cpu(self):
        """
        @brief UiInterface::get_cpu()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_applications()
        """
        return self.switch.getprop_table('Applications')

    def configure_application(self, application, loglevel):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_application()
        """
        row_id = self.switch.findprop('Applications', [1, 1, application])
        if row_id > 0:
            self.switch.setprop('Applications', 'logLevel', [row_id, loglevel])

# STP configuration
    def configure_spanning_tree(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_spanning_tree()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_stp_instance()
        """
        self.switch.setprop_row("STPInstances", [instance, priority])

    def configure_stp_instance(self, instance, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_stp_instance()
        """
        if 'priority' in kwargs:
            self.switch.setprop("STPInstances", "bridgePriority", [instance + 1, kwargs['priority']])
        if 'vlan' in kwargs:
            self.switch.setprop_row("Vlans2STPInstance", [instance, kwargs['vlan']])

    def get_table_spanning_tree(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_spanning_tree()
        """
        return self.switch.getprop_table('SpanningTree')

    def get_table_spanning_tree_mst(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_spanning_tree_mst()
        """
        return self.switch.getprop_table('STPInstances')

    def get_table_mstp_ports(self, ports=None, instance=0):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_mstp_ports()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_mstp_ports()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_rstp_ports()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_rstp_ports()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::set_all_ports_admin_disabled()
        """
        # define ports directly from the switch
        ports_table = self.switch.getprop_table('Ports')
        assert ports_table, "Ports table is empty on device %s" % (self.switch.xmlproxy._ServerProxy__host, )
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::wait_all_ports_admin_disabled()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_ports()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ports()
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
        """
        @brief  Returns attribute value (int) for given port
        @param  port:  port ID
        @type  port:  int | str
        @param  expected_rcs:  expected return code
        @type  expected_rcs:  int | set | list | frozenset
        @param  enabled_disabled_state:  Flag indicate to port state
        @type  enabled_disabled_state:  bool
        @param  kwargs:  Possible parameters
        @type  kwargs:  dict
        @raise  ValueError
        @raise  SwitchException:  not implemented
        @rtype:  int | str
        @return:  port attribute value
        """
        raise SwitchException("Not implemented")

# Flow Confrol configuration
    def set_flow_control_type(self, ports=None, control_type=None, tx_mode='normal', tc=None):
        """
        @copydoc  UiInterface::set_flow_control_type()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_vlans()
        @raise  UIException:  list of vlans required
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_vlans()
        @raise  UIException:  list of vlans required
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_vlans()
        """
        return self.switch.getprop_table('Vlans')

    def create_vlan_ports(self, ports=None, vlans=None, tagged='Tagged'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_vlan_ports()
        @raise  UIException:  ports and vlans required
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_vlan_ports()
        @raise  UIException:  ports and vlans required
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_vlan_ports()
        """
        for row in self.get_table_ports2vlans():
            if row['vlanId'] in vlans and row['portId'] in ports:
                self.delete_vlan_ports(ports=[row['portId']], vlans=vlans)
        self.create_vlan_ports(ports=ports, vlans=vlans, tagged=tagged)

    def get_table_ports2vlans(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ports2vlans()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_acl_name()
        """
        raise SwitchException("Not supported")

    def add_acl_rule_to_acl(self, acl_name=None, rule_id='', action=None, conditions=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::add_acl_rule_to_acl()
        """
        raise SwitchException("Not supported")

    def bind_acl_to_ports(self, acl_name=None, ports=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::bind_acl_to_ports()
        """
        raise SwitchException("Not supported")

    def unbind_acl(self, acl_name=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::unbind_acl()
        """
        raise SwitchException("Not supported")

    def create_acl(self, ports=None, expressions=None, actions=None, rules=None, acl_name='Test-ACL'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_acl()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_acl()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_acl()
        """
        if table in {'ACLStatistics', 'ACLExpressions', 'ACLActions', 'ACLRules'}:
            return self.switch.getprop_table(table)
        else:
            raise UIException("Wrong table name: {0}".format(table))

    def get_acl_names(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_acl_names()
        """
        raise SwitchException("Not supported")

# FDB configuration
    def create_static_macs(self, port=None, vlans=None, macs=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_static_macs()
        @raise  UIException:  macs and vlans required, port must be int
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_static_mac()
        @raise  UIException:  mac and vlan required
        """
        if not vlan:
            raise UIException('VlanID required')
        if not mac:
            raise UIException('Mac required')

        row_index = self.switch.findprop("StaticMAC", [mac, vlan])
        self.switch.delprop_row("StaticMAC", row_index)

    def get_table_fdb(self, table='Fdb'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_fdb()
        @raise  UIException:  table name required
        """
        if table == 'Fdb':
            _table = self.switch.getprop_table('Fdb')
        elif table == 'Static':
            _table = self.switch.getprop_table('StaticMAC')
        else:
            raise UIException('Table name required')

        return _table

    def clear_table_fdb(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::clear_table_fdb()
        """
        self.switch.xmlproxy.nb.Methods.clearAllFdbEntries()

# QoS configuration

    def get_table_ports_qos_scheduling(self, port=None, indexes=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ports_qos_scheduling()
        """
        sched_params = ['portId', 'schedMode', 'trustMode', 'schedWeight0', 'schedWeight1', 'schedWeight2', 'schedWeight3',
                        'schedWeight4', 'schedWeight5', 'schedWeight6', 'schedWeight7', 'cos0Bandwidth', 'cos1Bandwidth', 'cos2Bandwidth',
                        'cos3Bandwidth', 'cos4Bandwidth', 'cos5Bandwidth', 'cos6Bandwidth', 'cos7Bandwidth']

        if param is not None:
            assert param in sched_params, "Incorrect parameter transmitted to function: %s" % param

        def filter_qos_parameters(qos_ports_row):
            """Filter LLDP parameters"""
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ports_dot1p2cos()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_cos_global()
        """
        for key in kwargs:
            if key.startswith("dotp"):
                priority = int(key.split("dotp")[1][0])
                row_id = self.switch.findprop("PortsDot1p2CoS", [-1, priority])
                self.switch.setprop("PortsDot1p2CoS", "CoS", [row_id, kwargs[key]])

    def configure_dscp_to_cos_mapping_global(self, **kwargs):
        """
        @brief Configure global mapping of ingress DSCP value to CoS per switch
        """
        keys = ["dotp", "dscp"]
        for key in kwargs:
            for value in keys:
                if key.startswith(value):
                    priority = int(key.split(value)[1][0])
                    row_id = self.switch.findprop("PortsDSCP2CoS", [-1, kwargs[key]])
                    assert self.switch.setprop("PortsDSCP2CoS", "CoS", [row_id, priority]) == 0

    def get_table_ports_dscp2cos(self):
        """
        @brief Get PortsDSCP2CoS table
        """
        table = self.switch.getprop_table("PortsDSCP2CoS")

        return table

    def configure_schedweight_to_cos_mapping(self, ports, **kwargs):
        """
        @brief Configure schedWeight to CoS mapping
        """
        self.configure_port_cos(ports=ports, **kwargs)

    def configure_port_cos(self, ports=None, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_port_cos()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_dot1p_to_cos_mapping()
        """
        cos_list = ["dotp%sCoS" % idx for idx in range(8)]

        for cos in cos_list:
            assert cos in list(kwargs.keys()), "Not all eight CoS values transmitted for configuring CoS per port"

        for port in ports:
            for priority in range(8):
                self.switch.setprop_row("PortsDot1p2CoS", [port, priority, kwargs["dotp%sCoS" % priority]])

    def modify_dot1p_to_cos_mapping(self, ports, rx_attr_flag=False, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_dot1p_to_cos_mapping()
        """
        cos_list = ["dotp%sCoS" % idx for idx in range(8)]

        for port in ports:
            for key, queue in kwargs.items():
                if key in cos_list:
                    priority = int(key.split("dotp")[1][0])
                    row_id = self.switch.findprop("PortsDot1p2CoS", [port, priority])
                    self.switch.setprop("PortsDot1p2CoS", "CoS", [row_id, kwargs[key]])

    def clear_per_port_dot1p_cos_mapping(self, ports, rx_attr_flag=False, dot1p=None):
        """
        @brief Clear CoS per port mapping
        """
        for port in ports:
            for pri in dot1p:
                assert self.switch.xmlproxy.nb.PortsDot1p2CoS.delRow(self.switch.findprop('PortsDot1p2CoS', [port, pri])) == 0

# Statistics configuration
    def map_stat_name(self, generic_name):
        """
        @copydoc UiInterface::map_stat_name()
        """
        return STAT_MAP.get(generic_name, generic_name)

    def get_table_statistics(self, port=None, stat_name=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_statistics()
        @raise  UIException:  stat_name required
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::clear_statistics()
        """
        self.switch.xmlproxy.nb.Methods.clearAllStats()

# Bridge Info configuration
    def get_table_bridge_info(self, param=None, port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bridge_info()
        """
        if param is None:
            return self.switch.getprop_table("BridgeInfo")
        else:
            return self.switch.getprop("BridgeInfo", param, 1)

    def modify_bridge_info(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_bridge_info()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_lag()
        @raise  UIException:  lag required
        """
        # if not lag:
        #     raise UIException('Lag required')
        name = 'lag%s' % (lag, )
        key = lag if key is None else key
        assert self.switch.setprop_row('LagsAdmin', [lag, name, key, lag_type, hash_mode]) == 0

    def delete_lags(self, lags=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_lags()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lags()
        """
        return self.switch.getprop_table('LagsAdmin')

    def modify_lags(self, lag, key=None, lag_type=None, hash_mode=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_lags()
        """
        lag_row_id = self.switch.findprop("LagsAdmin", [lag, ])
        if key:
            assert self.switch.setprop("LagsAdmin", "actorAdminLagKey", [lag_row_id, key]) == 0
        if lag_type:
            assert self.switch.setprop("LagsAdmin", "lagControlType", [lag_row_id, lag_type]) == 0
        if hash_mode:
            assert self.switch.setprop("LagsAdmin", "hashMode", [lag_row_id, hash_mode]) == 0

    def get_table_link_aggregation(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_link_aggregation()
        """
        return self.switch.getprop_table('LinkAggregation')

    def modify_link_aggregation(self, globalenable=None, collectormaxdelay=None, globalhashmode=None, priority=None, lacpenable=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_link_aggregation()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_lag_ports()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_lag_ports()
        """
        for port in ports:
            row_index = self.switch.findprop("Ports2LagAdmin", [port, lag])
            self.switch.delprop_row("Ports2LagAdmin", row_index)

    def get_table_ports2lag(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ports2lag()
        """
        return self.switch.getprop_table('Ports2LagAdmin')

    def modify_ports2lag(self, port, lag, priority=None, key=None, aggregation=None, lag_mode=None, timeout=None, synchronization=None,
                         collecting=None, distributing=None, defaulting=None, expired=None, partner_system=None, partner_syspri=None,
                         partner_number=None, partner_key=None, partner_pri=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_ports2lag
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lags_local_ports()
        """
        table = self.switch.getprop_table("Ports2LagLocal")
        if lag:
            return [x for x in table if x['lagId'] == lag]

        return table

    def get_table_lags_remote_ports(self, lag=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lags_remote_ports()
        """
        table = self.switch.getprop_table("Ports2LagRemote")
        if lag:
            return [x for x in table if x['lagId'] == lag]

        return table

    def get_table_lags_local(self, lag=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lags_local()
        """
        if lag:
            lag_row_id = self.switch.findprop("LagsLocal", [lag, ])
            return [self.switch.getprop_row("LagsLocal", lag_row_id), ]
        else:
            return self.switch.getprop_table("LagsLocal")

    def get_table_lags_remote(self, lag=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lags_local()
        """
        if lag:
            lag_row_id = self.switch.findprop("LagsRemote", [lag, ])
            return [self.switch.getprop_row("LagsRemote", lag_row_id), ]
        else:
            return self.switch.getprop_table("LagsRemote")

# IGMP configuration
    def configure_igmp_global(self, mode='Enabled', router_alert=None, unknown_igmp_behavior=None, query_interval=None, querier_robustness=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_igmp_global()
        @raise  UIException:  wrong unknown-action type
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_igmp_per_ports()
        """
        for port in ports:
            row_id = self.switch.findprop("IGMPSnoopingPortsAdmin", [port, ])
            self.switch.setprop("IGMPSnoopingPortsAdmin", "igmpEnabled", [row_id, mode])
            if router_port_mode:
                self.switch.setprop("IGMPSnoopingPortsAdmin", "routerPortMode", [row_id, router_port_mode])

    def create_multicast(self, port, vlans, macs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_multicast()
        @raise  UIException:  port, vlams and macs required
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_multicast()
        @raise  UIException:  port, mac and vlan required
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_l2_multicast()
        """
        return self.switch.getprop_table('L2Multicast')

    def get_table_igmp_snooping_global_admin(self, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_igmp_snooping_global_admin()
        """
        if param:
            return self.switch.getprop("IGMPSnoopingGlobalAdmin", param, 1)
        else:
            return self.switch.getprop_table("IGMPSnoopingGlobalAdmin")

    def get_table_igmp_snooping_port_oper(self, port, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_igmp_snooping_port_oper()
        """
        row_id = self.switch.findprop("IGMPSnoopingPortsOper", [port, ])
        if param:
            return self.switch.getprop("IGMPSnoopingPortsOper", param, row_id)
        else:
            return self.switch.getprop_row("IGMPSnoopingPortsOper", row_id)

    def clear_l2_multicast(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::clear_l2_multicast()
        """
        self.switch.xmlproxy.nb.Methods.clearL2MulticastDynamicEntries()

# L3 configuration
    def configure_routing(self, routing='Enabled', ospf=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_routing()
        """
        self.switch.setprop('Layer3', 'RoutingEnable', [1, routing])
        if ospf:
            self.switch.setprop("OSPFRouter", "ospfEnabled", [1, ospf])

    def create_route_interface(self, vlan, ip, ip_type='InterVlan', bandwidth=1000, mtu=1500, status='Enabled', vrf=0, mode='ip'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_route_interface()
        """
        self.switch.setprop_row('RouteInterface', [vlan, ip, ip_type, bandwidth, mtu, status, vrf])
        row = self.switch.findprop('RouteInterface', [vlan, ip, bandwidth, mtu, vrf])
        ri = self.switch.getprop_row('RouteInterface', row)
        self.ris[ip] = ri

    def delete_route_interface(self, vlan, ip, bandwith=1000, mtu=1500, vrf=0, mode='ip'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_route_interface()
        """
        row_id = self.switch.findprop("RouteInterface", [vlan, ip, bandwith, mtu, vrf])
        self.switch.delprop_row('RouteInterface', row_id)
        self.ris[ip] = {}

    def modify_route_interface(self, vlan, ip, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_route_interface()
        """
        row_id = self.switch.findprop("RouteInterface", [vlan, ip, self.ris[ip]['bandwidth'], self.ris[ip]['mtu'], self.ris[ip]['VRF']])
        if 'adminMode' in kwargs:
            self.switch.setprop('RouteInterface', 'adminMode', [row_id, kwargs['adminMode']])

    def get_table_route_interface(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_route_interface()
        """
        return self.switch.getprop_table('RouteInterface')

    def get_table_route(self, mode='ip'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_route()
        """
        return self.switch.getprop_table('Route')

    def configure_arp(self, garp=None, refresh_period=None, delay=None, secure_mode=None, age_time=None, attemptes=None, arp_len=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_arp()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_arp_config()
        """
        return self.switch.getprop_table('ARPConfig')

    def create_arp(self, ip, mac, network, mode='arp'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_arp()
        """
        if_id = self.ris[network]['ifId']
        vrf = self.ris[network]['VRF']
        self.switch.setprop_row('StaticARP', [ip, mac, if_id, vrf])

    def delete_arp(self, ip, network, mode='arp'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_arp()
        """
        vrf = self.ris[network]['VRF']
        row_id = self.switch.findprop('StaticARP', [ip, vrf])
        self.switch.delprop_row('StaticARP', row_id)

    def get_table_arp(self, mode='arp'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_arp()
        """
        if mode == 'arp static':
            return self.switch.getprop_table('StaticARP')
        return self.switch.getprop_table('ARP')

    def create_static_route(self, ip, nexthop, network, distance=-1, mode='ip'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_static_route()
        """
        if_id = self.ris[network]['ifId']
        vrf = self.ris[network]['VRF']
        self.switch.setprop_row('StaticRoute', [ip, nexthop, if_id, vrf, distance])
        row = self.switch.findprop('StaticRoute', [ip, nexthop, vrf])
        self.static_routes[ip] = self.switch.getprop_row('StaticRoute', row)

    def delete_static_route(self, network):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_static_route()
        """
        vrf = self.static_routes[network]['VRF']
        nexthop = self.static_routes[network]['nexthop']
        self.switch.delprop_row('StaticRoute', self.switch.findprop('StaticRoute', [network, nexthop, vrf]))

    def get_table_static_route(self, mode='ip'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_static_route()
        """
        return self.switch.getprop_table('StaticRoute')

    def configure_ospf_router(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_ospf_router()
        """
        if 'logAdjacencyChanges' in kwargs:
            self.switch.setprop("OSPFRouter", "logAdjacencyChanges", [1, kwargs['logAdjacencyChanges']])
        if 'routerId' in kwargs:
            self.switch.setprop("OSPFRouter", "routerId", [1, kwargs['routerId']])

    def get_table_ospf_router(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ospf_router()
        """
        return self.switch.getprop_table("OSPFRouter")

    def create_ospf_area(self, area, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ospf_area()
        """
        self.switch.setprop_row("OSPFAreas", [area, "Default", "Disabled", -1, "Disabled", "", "", "", "", "Disabled", "Candidate"])
        self.areas[area] = self.switch.getprop("OSPFAreas", "areaId", self.switch.findprop("OSPFAreas", [area, ]))

    def get_table_ospf_area(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ospf_area()
        """
        return self.switch.getprop_table("OSPFAreas")

    def create_network_2_area(self, network, area, mode):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_network_2_area()
        """
        area_id = self.areas[area]
        self.switch.setprop_row("OSPFNetworks2Area", [network, area_id, mode])

    def get_table_network_2_area(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_network_2_area()
        """
        return self.switch.getprop_table("OSPFNetworks2Area")

    def create_area_ranges(self, area, range_ip, range_mask, substitute_ip, substitute_mask):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_area_ranges()
        """
        area_id = self.areas[area]
        self.switch.setprop_row("OSPFAreas2Ranges", [area_id, "Advertise", range_ip, range_mask, 100, "Enabled", substitute_ip, substitute_mask])

    def get_table_area_ranges(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_area_ranges()
        """
        return self.switch.getprop_table("OSPFAreas2Ranges")

    def create_route_redistribute(self, mode):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_route_redistribute()
        """
        self.switch.setprop_row("OSPFRouteRedistribute", [mode, -1, -1, -1])

    def get_table_route_redistribute(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_route_redistribute()
        """
        return self.switch.getprop_table("OSPFRouteRedistribute")

    def create_interface_md5_key(self, vlan, network, key_id, key):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_interface_md5_key()
        """
        if_id = self.ris[network]['ifId']
        self.switch.setprop_row("OSPFInterfaceMD5Keys", [if_id, key_id, key, ""])

    def get_table_interface_authentication(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_interface_authentication()
        """
        return self.switch.getprop_table("OSPFInterfaceMD5Keys")

    def create_ospf_interface(self, vlan, network, dead_interval=40, hello_interval=5, network_type="Broadcast", hello_multiplier=3, minimal='Enabled',
                              priority=-1, retransmit_interval=-1):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ospf_interface()
        """
        if_id = self.ris[network]['ifId']
        self.switch.setprop_row("OSPFInterface", [if_id, -1, dead_interval, minimal, hello_multiplier, hello_interval, network_type, 1, retransmit_interval, 1])

    def get_table_ospf_interface(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ospf_interface()
        """
        return self.switch.getprop_table("OSPFInterface")

    def create_area_virtual_link(self, area, link):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_area_virtual_link()
        """
        area_id = self.areas[area]
        self.switch.setprop_row("OSPFVirtLink", [area_id, link, "Enabled"])

# BGP configuration
    def configure_bgp_router(self, asn=65501, enabled='Enabled'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_bgp_router()
        """
        self.switch.setprop("BGPRouter", "asn", [1, asn]) == 0
        self.switch.setprop("BGPRouter", "bgpEnabled", [1, enabled]) == 0

    def create_bgp_neighbor_2_as(self, asn, ip, remote_as):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_neighbor_2_as()
        """
        self.switch.setprop_row("BGPNeighbor2As", [asn, ip, remote_as])

    def create_bgp_neighbor(self, asn=65501, ip='192.168.0.1'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_neighbor()
        """
        self.switch.setprop_row("BGPNeighbor", [asn, "Base", "Unicast", ip, "Disabled", 0, "Disabled", "Disabled", "Disabled",
                                                "Disabled", "Disabled", "Disabled", "Disabled", "DefOrigRouteMap", "UserDescription", "Enabled",
                                                "", "", "Disabled", -1, "Disabled", "filterListIn", "filterListOut", -1,
                                                "Disabled", -1, -1, -1, "Disabled", "Disabled", "Disabled", "Disabled", "", "", "",
                                                "Disabled", "routeMapIn", "routeMapOut", "routeMapImport", "routeMapExport", "Disabled", "Disabled", "Disabled",
                                                "Enabled", "Disabled", "Disabled", -1, -1, -1, "unsuppressMap", "updateSource", -1])

    def create_bgp_neighbor_connection(self, asn=65501, ip='192.168.0.1', port=179):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_neighbor_connection()
        """
        self.switch.setprop_row("BGPNeighborConnection", [asn, ip, -1, -1, port, "Disabled", -1])

    def create_bgp_bgp(self, asn=65501, router_id="1.1.1.1"):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_bgp()
        """
        self.switch.setprop_row("BGPBgp", [asn, "Base", "Unicast", "Enabled", "Disabled", "Enabled", "Enabled", "Enabled", "Disabled",
                                           "Enabled", "", -1, "Disabled", -1, -1, -1, -1, "Disabled", -1, "Disabled", "Disabled", "Enabled", "Enabled", 3600,
                                           "Enabled", "Disabled", router_id, -1])

    def create_bgp_peer_group(self, asn=65501, name="mypeergroup"):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_peer_group()
        """
        self.switch.setprop_row("BGPPeerGroups", [asn, name])

    def create_bgp_peer_group_member(self, asn=65501, name="mypeergroup", ip="12.1.0.2"):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_peer_group_member()
        """
        self.switch.setprop_row("BGPPeerGroupMembers", [asn, "Base", "Unicast", name, ip])

    def create_bgp_redistribute(self, asn=65501, rtype="OSPF"):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_redistribute()
        """
        self.switch.setprop_row("BGPRedistribute", [asn, "Base", "Unicast", rtype, -1, ""])

    def create_bgp_network(self, asn=65501, ip='10.0.0.0', mask='255.255.255.0', route_map='routeMap'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_network()
        """
        network = ip + '/24'
        self.switch.setprop_row("BGPNetwork", [asn, "Ipv4", "Unicast", network, "Disabled", route_map])

    def create_bgp_aggregate_address(self, asn=65501, ip='22.10.10.0', mask='255.255.255.0'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_aggregate_address()
        """
        network = ip + '/24'
        self.switch.setprop_row("BGPAggregateAddress", [asn, "Base", "Unicast", network, "Disabled", "Disabled"])

    def create_bgp_confederation_peers(self, asn=65501, peers=70000):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_confederation_peers()
        """
        self.switch.setprop_row("BGPBgpConfederationPeers", [asn, peers])

    def create_bgp_distance_network(self, asn=65501, ip="40.0.0.0/24", mask='255.255.255.0', distance=100, route_map='routeMap'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_distance_network()
        """
        network = ip + '/24'
        self.switch.setprop_row("BGPDistanceNetwork", [asn, network, distance, route_map])

    def create_bgp_distance_admin(self, asn=65501, ext_distance=100, int_distance=200, local_distance=50):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_distance_admin()
        """
        self.switch.setprop_row("BGPDistanceAdmin", [asn, ext_distance, int_distance, local_distance])

    def get_table_bgp_neighbor(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_neighbor()
        """
        return self.switch.getprop_table('BGPNeighbor')

    def get_table_bgp_neighbor_connections(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_neighbor_connections()
        """
        return self.switch.getprop_table('BGPNeighborConnection')

    def get_table_bgp_aggregate_address(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_aggregate_address()
        """
        return self.switch.getprop_table('BGPAggregateAddress')

    def get_table_bgp_confederation_peers(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_confederation_peers()
        """
        return self.switch.getprop_table('BGPBgpConfederationPeers')

    def get_table_bgp_distance_admin(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_distance_admin()
        """
        return self.switch.getprop_table('BGPDistanceAdmin')

    def get_table_bgp_distance_network(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_distance_network()
        """
        return self.switch.getprop_table('BGPDistanceNetwork')

    def get_table_bgp_network(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_network()
        """
        return self.switch.getprop_table('BGPNetwork')

    def get_table_bgp_peer_group_members(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_peer_group_members()
        """
        return self.switch.getprop_table('BGPPeerGroupMembers')

    def get_table_bgp_peer_groups(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_peer_groups()
        """
        return self.switch.getprop_table('BGPPeerGroups')

    def get_table_bgp_redistribute(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_redistribute()
        """
        return self.switch.getprop_table('BGPRedistribute')

# OVS configuration
    def create_ovs_bridge(self, bridge_name):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_bridge()
        """
        self.switch.setprop_row("OvsBridges", [0, bridge_name, "switchpp"]) == 0

    def get_table_ovs_bridges(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_bridges()
        """
        return self.switch.getprop_table("OvsBridges")

    def delete_ovs_bridge(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_ovs_bridge()
        """
        self.switch.delprop_row("OvsBridges", 1) == 0

    def create_ovs_port(self, port, bridge_name):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_port()
        """
        self.switch.setprop_row("OvsPorts", [port, 0, "%s-%i" % (bridge_name, port), "switchpp"]) == 0

    def get_table_ovs_ports(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_ports()
        """
        return self.switch.getprop_table("OvsPorts")

    def get_table_ovs_rules(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_rules()
        """
        return self.switch.getprop_table("OvsFlowRules")

    def create_ovs_flow_rules(self, bridge_id, table_id, flow_id, priority, enabled):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_flow_rules()
        """
        assert self.switch.setprop_row("OvsFlowRules", [bridge_id, table_id, flow_id, priority, enabled]) == 0, "Row is not added to OvsFlowRules table."

    def delete_ovs_flow_rules(self, bridge_id, table_id, flow_id, priority):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_ovs_flow_rules()
        """
        row_id = self.switch.findprop("OvsFlowRules", [bridge_id, table_id, flow_id, priority])
        assert self.switch.delprop_row("OvsFlowRules", row_id) == 0, "OVS Flow Rule is not deleted."

    def create_ovs_bridge_controller(self, bridge_name, controller):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_bridge_controller()
        """
        self.switch.setprop_row("OvsControllers", [0, controller])

    def get_table_ovs_controllers(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_controllers()
        """
        return self.switch.getprop_table("OvsControllers")

    def configure_ovs_resources(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_ovs_resources()
        """
        available_params = ['controllerRateLimit', 'vlansLimit', 'untaggedVlan', 'rulesLimit']

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in available_params}

        helpers.update_table_params(self.switch, "OvsResources", params, row_id=1, validate_updates=False)

    def get_table_ovs_flow_actions(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_flow_actions()
        """
        return self.switch.getprop_table("OvsFlowActions")

    def create_ovs_flow_actions(self, bridge_id, table_id, flow_id, action, param, priority=2000):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_flow_actions()
        """
        assert self.switch.setprop_row("OvsFlowActions", [bridge_id, table_id, flow_id, action, param]) == 0, "Row is not added to OvsFlowActions table."

    def delete_ovs_flow_actions(self, bridge_id, table_id, flow_id, action, priority=2000):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_ovs_flow_actions()
        """
        row_id = self.switch.findprop("OvsFlowActions", [bridge_id, table_id, flow_id, action])
        assert self.switch.delprop_row("OvsFlowActions", row_id) == 0, "OVS Flow Rule is not deleted."

    def get_table_ovs_flow_qualifiers(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_flow_qualifiers()
        """
        return self.switch.getprop_table("OvsFlowQualifiers")

    def create_ovs_flow_qualifiers(self, bridge_id, table_id, flow_id, field, data, priority=2000):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_flow_qualifiers()
        """
        assert self.switch.setprop_row("OvsFlowQualifiers", [bridge_id, table_id, flow_id, field, data]) == 0, "Row is not added to OvsFlowQualifiers table."

    def delete_ovs_flow_qualifiers(self, bridge_id, table_id, flow_id, field, priority=2000):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_ovs_flow_qualifiers()
        """
        row_id = self.switch.findprop("OvsFlowQualifiers", [bridge_id, table_id, flow_id, field])
        assert self.switch.delprop_row("OvsFlowQualifiers", row_id) == 0, "OVS Flow Rule is not deleted."

# LLDP configuration

    def configure_global_lldp_parameters(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_global_lldp_parameters()
        """
        available_params = ['messageFastTx', 'messageTxHoldMultiplier', 'messageTxInterval',
                            'reinitDelay', 'txCreditMax', 'txFastInit', 'locChassisIdSubtype']

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in available_params}

        helpers.update_table_params(self.switch, "Lldp", params, row_id=1, validate_updates=False)

    def configure_lldp_ports(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_lldp_ports()
        """
        available_params = ['adminStatus', 'tlvManAddrTxEnable', 'tlvPortDescTxEnable',
                            'tlvSysCapTxEnable', 'tlvSysDescTxEnable', 'tlvSysNameTxEnable']

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in available_params}

        for port in ports:
            helpers.update_table_params(self.switch, "LldpPorts", params, [port, ], validate_updates=False)

    def get_table_lldp(self, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lldp()
        """
        if param is not None:
            return self.switch.getprop("Lldp", param, 1)
        else:
            return self.switch.getprop_table("Lldp")

    def get_table_lldp_ports(self, port=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lldp_ports()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lldp_ports_stats()
        """
        lldp_params = ['statsRxTLVsDiscardedTotal', 'statsTxFramesTotal', 'statsRxFramesTotal', 'statsRxAgeoutsTotal', 'portId',
                       'statsRxFramesInErrorsTotal', 'statsRxFramesDiscardedTotal', 'statsRxTLVsUnrecognizedTotal']

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

    def get_table_lldp_remotes(self, port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lldp_remotes()
        """
        lldp_remotes = self.switch.getprop_table("LldpRemotes")
        if port is not None:
            return [row for row in lldp_remotes if row["remLocalPortNum"] == port]
        else:
            return lldp_remotes

    def get_table_remotes_mgmt_addresses(self, port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_remotes_mgmt_addresses()
        """
        lldp_remotes = self.switch.getprop_table("LldpRemotesMgmtAddresses")
        if port is not None:
            return [row for row in lldp_remotes if row["remLocalPortNum"] == port]
        else:
            return lldp_remotes

    def disable_lldp_on_device_ports(self, ports=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::disable_lldp_on_device_ports()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::set_dcb_admin_mode()
        """
        for port in ports:
            helpers.update_table_params(self.switch, "DcbxPorts", {'adminStatus': mode}, [port, ], validate_updates=False)

    def enable_dcbx_tlv_transmission(self, ports, dcbx_tlvs="all", mode="Enabled"):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::enable_dcbx_tlv_transmission()
        @raise  ValueError:  invalid DCBX tlvs
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_ports()
        """
        if port is not None:
            if param is not None:
                return self.switch.getprop("DcbxPorts", param, self.switch.findprop("DcbxPorts", [port, ]))
            else:
                return self.switch.getprop_row("DcbxPorts", self.switch.findprop("DcbxPorts", [port, ]))
        else:
            return self.switch.getprop_table("DcbxPorts")

    def get_table_dcbx_app_remote(self, port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_app_remote()
        """
        table = self.switch.getprop_table("DcbxAppRemotes")
        if port is not None:
            return [row for row in table if row["portId"] == port]
        else:
            return table

    def get_table_dcbx_app_ports(self, table_type="Admin", port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_app_ports()
        """
        assert table_type in ["Admin", "Local"], "Incorrect Dcbx App Ports table type specified: %s" % table_type

        table = self.switch.getprop_table("DcbxAppPorts%s" % table_type)
        if port is not None:
            return [row for row in table if row["portId"] == port]
        else:
            return table

    def get_table_dcbx_app_maps(self, table_type="Admin", port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_app_maps()
        """
        assert table_type in ["Admin", "Local", "Remote"], "Incorrect Dcbx App Maps table type specified: %s" % table_type

        table = self.switch.getprop_table("DcbxAppMaps%s" % table_type)
        if port is not None:
            return [row for row in table if row["portId"] == port]
        else:
            return table

    def get_table_dcbx_pfc(self, table_type="Local", port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_pfc()
        """
        assert table_type in ["Local", "Remote"], "Incorrect Dcbx Pfc table type specified: %s" % table_type

        table = self.switch.getprop_table("DcbxPfcPorts%s" % table_type)
        if port is not None:
            return [row for row in table if row["portId"] == port]
        else:
            return table

    def get_table_dcbx_ets_ports(self, table_type='Admin', port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_ets_ports()
        """
        assert table_type in ["Admin", "Local"], "Incorrect Dcbx Ets Ports table type specified: %s" % table_type

        table = self.switch.getprop_table("DcbxEtsPorts{}".format(table_type))
        if port is not None:
            return [row for row in table if row["portId"] == port]
        else:
            return table

    def configure_application_priority_rules(self, ports, app_prio_rules, delete_params=False, update_params=False):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_application_priority_rules()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_dcbx_ets()
        """
        available_params = ["willing", "cbs", "maxTCs", "confBandwidth", "confPriorityAssignment", "confAlgorithm",
                            "recoBandwidth", "recoPriorityAssignment", "recoAlgorithm"]

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in available_params}

        for port in ports:
            helpers.update_table_params(self.switch, "DcbxEtsPortsAdmin", params, [port, ], validate_updates=False)

    def configure_dcbx_cn(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_dcbx_cn()
        """
        available_params = ["cnpvSupported", "cnpvReady"]

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in available_params}

        for port in ports:
            helpers.update_table_params(self.switch, "DcbxCnPortsAdmin", params, [port, ], validate_updates=False)

    def configure_dcbx_app(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_dcbx_app()
        """
        available_params = ["willing", ]

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in available_params}

        for port in ports:
            helpers.update_table_params(self.switch, "DcbxAppPortsAdmin", params, [port, ], validate_updates=False)

    def configure_dcbx_pfc(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_dcbx_pfc()
        """
        available_params = ["mbc", "enabled", "willing"]

        # Select only allowed parameters for configuration
        params = {key: value for key, value in kwargs.items() if key in available_params}

        for port in ports:
            helpers.update_table_params(self.switch, "DcbxPfcPortsAdmin", params, [port, ], validate_updates=False)

    def get_table_dcbx_remotes(self, port=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_remotes()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ufd_config()
        """
        return self.switch.getprop_table("UFDConfig")

    def configure_ufd(self, enable='Enabled', hold_on_time=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_ufd()
        """
        assert self.switch.setprop('UFDConfig', 'enable', [1, enable]) == 0, "UFD can not be %s in general." % enable
        if hold_on_time:
            assert self.switch.setprop('UFDConfig', 'holdOnTime', [1, hold_on_time]) == 0, "UFD holdOnTime is not set to %s." % hold_on_time

    def create_ufd_group(self, group_id, threshold=None, enable='Enabled'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ufd_group()
        """
        assert self.switch.setprop_row('UFDGroups', [group_id, threshold, enable]) == 0, "UFD group can not be created."

    def modify_ufd_group(self, group_id, threshold=None, enable=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_ufd_group()
        """
        row = self.switch.findprop('UFDGroups', [group_id])
        if enable:
            assert self.switch.setprop('UFDGroups', 'enable', [row, enable]) == 0, "UFD group can not be %s." % enable
        if threshold:
            assert self.switch.setprop('UFDGroups', 'threshold', [row, threshold]) == 0, "UFD threshold is not set to %s." % threshold

    def delete_ufd_group(self, group_id):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_ufd_group()
        """
        row = self.switch.findprop('UFDGroups', [group_id])
        assert self.switch.delprop_row('UFDGroups', row) == 0, "UFD group can not be deleted."

    def get_table_ufd_groups(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ufd_groups()
        """
        return self.switch.getprop_table("UFDGroups")

    def create_ufd_ports(self, ports, port_type, group_id):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ufd_ports()
        """
        params = [(int(x), port_type, group_id) for x in ports]
        results = self.switch.multicall([{"methodName": 'nb.UFDPorts2Groups.addRow', "params": params}])
        errors = helpers.process_multicall(results)
        assert len(errors) == 0, "nb.UFDPorts2Groups.addRow methods failed with errors: %s" % [x["error"] for x in errors]

    def delete_ufd_ports(self, ports, port_type, group_id):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_ufd_ports()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ufd_ports()
        """
        return self.switch.getprop_table("UFDPorts2Groups")

# QinQ configuration

    def configure_qinq_ports(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_qinq_ports()
        """
        available_params = ["mode", "tpid"]
        first = operator.itemgetter(0)
        ordered_params = OrderedDict(sorted(((k, v) for k, v in kwargs.items() if k in available_params), key=first))

        for port in ports:
            helpers.update_table_params(self.switch, "QinQPorts", ordered_params, [port, ], validate_updates=False)

    def configure_qinq_vlan_stacking(self, ports, provider_vlan_id, provider_vlan_priority):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_qinq_vlan_stacking()
        """
        for port in ports:
            self.switch.setprop_row("QinQVlanStacking", [port, provider_vlan_id, provider_vlan_priority])

    def get_table_qinq_vlan_stacking(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_qinq_vlan_stacking()
        """
        return self.switch.getprop_table("QinQVlanStacking")

    def configure_qinq_vlan_mapping(self, ports, customer_vlan_id, customer_vlan_priority, provider_vlan_id, provider_vlan_priority):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_qinq_vlan_mapping()
        """
        for port in ports:
            self.switch.setprop_row("QinQCustomerVlanMapping", [port, customer_vlan_id, provider_vlan_id, provider_vlan_priority])
            self.switch.setprop_row("QinQProviderVlanMapping", [port, provider_vlan_id, customer_vlan_id, customer_vlan_priority])

    def get_table_qinq_customer_vlan_mapping(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_qinq_customer_vlan_mapping()
        """
        return self.switch.getprop_table("QinQCustomerVlanMapping")

    def get_table_qinq_provider_vlan_mapping(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_qinq_provider_vlan_mapping()
        """
        return self.switch.getprop_table("QinQProviderVlanMapping")

    def get_table_qinq_ports(self, port=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_qinq_ports()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_errdisable_errors_config()
        """
        if app_name and app_error:
            row = self.switch.findprop('ErrdisableErrorsConfig', [app_name, app_error, ])
            return self.switch.getprop_row("ErrdisableErrorsConfig", row)
        else:
            return self.switch.getprop_table("ErrdisableErrorsConfig")

    def get_table_errdisable_config(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_errdisable_config()
        """
        return self.switch.getprop_table("ErrdisableConfig")

    def modify_errdisable_errors_config(self, detect=None, recovery=None, app_name=None, app_error=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_errdisable_errors_config()
        """
        row = self.switch.findprop('ErrdisableErrorsConfig', [app_name, app_error, ])
        if detect:
            assert self.switch.setprop('ErrdisableErrorsConfig', 'enabled', [row, detect]) == 0, "ErrdisableErrorsConfig detection isn't set to %s" % detect
        if recovery:
            assert self.switch.setprop('ErrdisableErrorsConfig', 'recovery', [row, recovery]) == 0, "ErrdisableErrorsConfig recovery isn't set to %s" % recovery

    def modify_errdisable_config(self, interval=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_errdisable_config()
        """
        if interval:
            assert self.switch.setprop('ErrdisableConfig', 'recoveryInterval', [1, interval]) == 0, "ErrdisableConfig interval isn't set to %s" % interval

    def get_errdisable_ports(self, port=None, app_name=None, app_error=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_errdisable_ports()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_mirror_session()
        """
        self.switch.setprop_row('PortsMirroring', [port, target, mode])

    def get_mirroring_sessions(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_mirroring_sessions()
        """
        return self.switch.getprop_table('PortsMirroring')

    def delete_mirroring_session(self, port, target, mode):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_mirroring_session()
        """
        row_id = self.switch.findprop('PortsMirroring', [port, target, mode])
        self.switch.delprop_row("PortsMirroring", row_id)

# DHCP Relay configuration

    def create_dhcp_relay(self, iface_name='global', server_ip=None, fwd_iface_name=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_dhcp_relay()
        """
        if fwd_iface_name:
            self.switch.setprop_row('DhcpRelayV6Admin', [iface_name, 'Enabled', server_ip, fwd_iface_name])
        else:
            self.switch.setprop_row('DhcpRelayAdmin', [iface_name, 'Enabled', server_ip])

    def get_table_dhcp_relay(self, dhcp_relay_ipv6=False):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dhcp_relay()
        """
        if dhcp_relay_ipv6:
            return self.switch.getprop_table('DhcpRelayV6Admin')
        else:
            return self.switch.getprop_table('DhcpRelayAdmin')

# VxLAN configuration

    def configure_tunneling_global(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_tunneling_global()
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
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_tunnels()
        """
        self.switch.setprop_row("TunnelsAdmin", [tunnel_id, destination_ip, vrf, encap_type])

    def get_table_tunnels_admin(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_tunnels_admin()
        """
        return self.switch.getprop_table("TunnelsAdmin")

    def create_invalid_ports(self, ports=None, num=1):
        """

        @brief creates port name if port id is passed say [Swop100, if 100 is passed as port id]
        Else creates port name with a value incremented to 10 to existing length of ports
        Ex[sw0p34 , currently sw0p24 is last port]
        @param ports: list of port_ids to generate port_names for
        @type ports: iter()
        @param num: generate num new invalid ports
        @type num: int
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
    """
    @description  Class to create a invalid por
    """
    def __init__(self, ui, ports):
        """"

        @brief intialize Invalidport class
        @param  ui:  instance of switch
        @type  ui:  UiOnsXmlrpc
        @param  ports:  port id of invalid port
        @type  ports:  list
        """
        super(InvalidPortContext, self).__init__()
        self.ports = ports
        self.ui = ui

    def __enter__(self):
        """
        @return: list of ports
        @rtype: list
        """
        return self.ports

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        @brief deletes invalid port created
        """
        pass
