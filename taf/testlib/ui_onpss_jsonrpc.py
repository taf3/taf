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

@file  ui_onpss_jsonrpc.py

@summary  JSONRPC UI wrappers.
"""

import time
import urllib.parse

import jsonrpclib

from .ui_onpss_shell.ui_onpss_shell import UiOnpssShell
from .custom_exceptions import SwitchException, UIException
from testlib.linux import service_lib

# PSME NW Agent installation deploys a peculiar configuration
# of PVID and VLANs for ports that are specific to BDC-R (Bulldog Creek)
# and get enforced after reboot
# List of specific ports that is used for configuration
PSME_DEFAULT_PORTS_CONFIG = ["sw0p0", "sw0p25", "sw0p29", "sw0p33", "sw0p37", "sw0p39", "sw0p41",
                             "sw0p43", "enp0s20f0", "enp0s20f0.170", "enp0s20f0.4094", "00-sw0p33"]


class UiOnpssJsonrpc(UiOnpssShell):
    """
    @description  Class with JSONRPC wrappers
    """

    def __init__(self, switch):
        """
        @brief  Initialize UiOnpssJsonrpc class
        @param  switch:  Switch instance
        @type  switch:  SwitchGeneral
        """
        super(UiOnpssJsonrpc, self).__init__(switch)
        self.switch = switch
        self.host = switch.config['ip_host']
        # JSON-RPC listening port should be specified in environment
        # configuration file('env' folder under 'testcases/config') for appropriate device
        self.port = switch.config['json_port']
        self.rsa_server = "psme-rest-server"
        self.rsa_network = "psme-network"
        self.jsonrpc = None
        self.uuid_collections = {}

        # GAMI API doesn't support creating LAG without members
        # Initialize LAG map
        self.lags = []
        self.rest_server_service = service_lib.specific_service_manager_factory(
            "psme-rest-server", self.cli_send_command)
        self.network_agent_service = service_lib.specific_service_manager_factory(
            "psme-network", self.cli_send_command)

    def _get_subcomponents_uuid(self):
        """
        @brief  Get Manager subcomponents identifiers
        @raise  UIException:  incorrect reply
        @return:  None
        """
        self.uuid_collections = {"Manager": "", "Ports": {}}
        # get module uuid
        components = self.request("getManagerCollection", {})
        try:
            self.uuid_collections["Manager"] = components[0]["manager"]
            # get Switch UUID
            subcomponent = self.request("getCollection", {"component": self.uuid_collections["Manager"],
                                                          "name": "Switches"})
            self.uuid_collections.update({"Switch": subcomponent[0]["subcomponent"]})
            # get Ports UUID
            self._get_ports_uuid()
            # get VlanPort UUID
            self._get_vlans_uuid()
        except KeyError:
            raise UIException("PSME command 'getManagerCollection'/'getCollection' returned incorrect reply")
        if not self.uuid_collections:
            raise UIException("Switch subcomponents weren't found in Network Management Module")

    def _get_ports_uuid(self):
        """
        @brief  Get Ports identifiers
        @raise  UIException:  incorrect reply
        @return:  None
        """
        try:
            # get Ports collection
            ports_uuid = self.request("getCollection", {
                "component": self.uuid_collections["Switch"],
                "name": "Ports"
            })
            request_params = ({"port": p['subcomponent']} for p in ports_uuid)
            ports_info_request = {"method": "getEthernetSwitchPortInfo",
                                  "params": request_params}

            ports_info = self.multicall([ports_info_request])
            for p_uuid, p_info in zip(ports_uuid, ports_info):
                self.uuid_collections["Ports"].update({
                    self.parse_port_name(p_info["portIdentifier"]): {
                        "uuid": p_uuid["subcomponent"],
                        "Vlans": {},
                    }
                })
        except KeyError:
            raise UIException("PSME command 'getCollection'/'getEthernetSwitchPortInfo' returned incorrect reply")

    def _get_vlans_uuid(self):
        """
        @brief  Get VLAN identifiers for appropriate port
        @raise  UIException:  incorrect reply
        @return:  None
        """
        try:
            # get VLAN collection info for appropriate port
            for port_id, port_value in self.uuid_collections["Ports"].items():
                port_vlans_request = self.request("getCollection", {
                    "component": port_value["uuid"],
                    "name": "Vlans"
                })
                for vlan in port_vlans_request:
                    subcomponent = vlan["subcomponent"]
                    vlan_info = self.request("getPortVlanInfo", {
                        "portVlan": subcomponent
                    })
                    self.uuid_collections["Ports"][port_id]["Vlans"][
                        vlan_info["vlanId"]] = subcomponent
        except KeyError:
            raise UIException(
                "PSME command 'getCollection'/'getPortVlanInfo' returned incorrect reply")

    def connect(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::connect()
        """
        super(UiOnpssJsonrpc, self).connect()
        url = urllib.parse.urlunsplit(('http', '{0}:{1}'.format(self.host, self.port), '', '', ''))
        self.jsonrpc = jsonrpclib.ServerProxy(url)
        time.sleep(1)
        self._get_subcomponents_uuid()

    def disconnect(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::disconnect()
        """
        super(UiOnpssJsonrpc, self).disconnect()

    def restart(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::restart()
        """
        super(UiOnpssJsonrpc, self).restart()

    def request(self, method="", params=None):
        """
        @brief  Send and receive the JSON-RPC strings
        @param  method:  name of the method to be invoked
        @type  method:  str
        @param  params:  parameter values to be used during the invocation of the method
        @type  params:  dict
        @param  timeout:  timeout for socket operations
        @type  timeout:  int
        @raise  UIException:  error in reply
        @rtype:  dict | list
        @return:  Result of method
        """
        result = None
        if params is None:
            params = {}
        try:
            result = self.jsonrpc._request(method, params)
        except jsonrpclib.ProtocolError as err:
            message = "{0} command with parameters {1} returned error {2[0]}: {2[1]}".format(method, params, err.args[0])
            raise UIException(message)
        return result

    def multicall(self, calls_list):
        """
        @brief  Sends a list of commands
        @param calls_list:  List of dictionaries for necessary JSON-RPC calls
        @type  calls_list:  list(dict(("method",str),("params", list)))
        @raise  UIException:  incorrect key in call_list, error in reply
        @rtype:  list(int | boolean | list | dict)
        @return:  List of responses
        @par Example:
        @code
        env.switch[1].ui.multicall([{'method': 'getSwitchPortInfo', 'params': [{'component': '0', 'portIdentifier': 'sw0p1'},
                                                                               {'component': '0', 'portIdentifier': 'sw0p2'}]}, ])

        env.switch[1].ui.multicall([{'method': 'getSwitchInfo', 'params': [{'component': '0'}],
                                    {'method': 'getSwitchPortInfo', 'params': [{'component': '0', 'portIdentifier': 'sw0p1'},
                                                                               {'component': '0', 'portIdentifier': 'sw0p2'}]}, ])
        @endcode
        """
        multicall_list = []
        return_values = []
        batch = jsonrpclib.MultiCall(self.jsonrpc)
        # Generates a sequence of commands
        for row in calls_list:
            try:
                multicall_list.extend({"method": row["method"], "params": param}
                                      for param in row["params"])
            except KeyError as err:
                raise UIException("Incorrect key is transmitted in calls_list dictionary: {0}".format(err))
        for request in multicall_list:
            getattr(batch, request["method"])(**request["params"])

        # Executes a sequence of commands
        results = batch()

        # Verifies on error because result of execution is generator object
        # Iteration is necessary because multicall raises exceptions while iterating
        # and we need to collect the partial list in result_values in order to lookup the origin multicall method and params
        try:
            for res in results:
                return_values.append(res)
        except jsonrpclib.ProtocolError as err:
            method = multicall_list[len(return_values)]
            message = "{0[method]} command with parameters {0[params]} returned error {1[0]}: {1[1]}".format(method, err.args[0])
            raise UIException(message)

        assert len(return_values) == len(multicall_list), "Return values list has different length than multicall list"

        return return_values

    @staticmethod
    def check_params(reply, required_params):
        """
        @brief  Verify that reply contains required parameters
        @param  reply:  response to verify
        @type  reply:  dict
        @param  required_params:  required parameters
        @type  required_params:  list
        @raise  UIException:  reply doesn't contain required parameters
        @return:  None
        """
        if not set(required_params).issubset(set(reply.keys())):
            raise UIException("The required response parameters {0} were missing in {1}".format(required_params,
                                                                                                reply))

    def _restart_psme_agents(self):
        """
        @brief  Restarts PSME agents
        @return:  None
        """
        self.rest_server_service.restart(expected_rcs={0, 1, 3})
        self.network_agent_service.restart(expected_rcs={0, 1, 3})

# Clear Config
    def clear_config(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::clear_config()
        """
        # Exclude default PSME ports configuration from clearing networkd settings
        self.networkd.stop()
        self.networkd.clear_settings(exclude_ports=PSME_DEFAULT_PORTS_CONFIG)
        self.start_switchd()
        self.networkd.start()
        # Clear LLDP
        self.clear_lldp_config()
        # restart psme agent to clear non-existing uuid's
        # after performing 'fm10kdr -r' command
        self._restart_psme_agents()
        time.sleep(2)
        self._get_subcomponents_uuid()
        self.generate_port_name_mapping()

    def save_config(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::save_config()
        """
        raise UIException("Method isn't implemented")

    def restore_config(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::restore_config()
        """
        raise UIException("Method isn't implemented")

# Application Check
    def check_device_state(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::check_device_state()
        """
        super(UiOnpssJsonrpc, self).check_device_state()
        # Invoke "getSwitchInfo" method on the device
        end_time = time.time() + 15
        while time.time() < end_time:
            try:
                reply = self.request("getEthernetSwitchInfo", {
                    "switch": self.uuid_collections["Switch"]
                })
            except UIException:
                raise
            except Exception:
                continue
            if reply:
                self.check_params(reply, ["status", "location", "macAddress", "technology", "fruInfo", "oem", "collections"])
                return
        raise SwitchException("Device is not ready")

# Platform
#     def get_table_platform(self):
#         """
#         @copydoc  testlib::ui_wrapper::UiInterface::get_table_platform()
#         """
#         pass

# Syslog configuration
    def create_syslog(self, syslog_proto, syslog_ip, syslog_port, syslog_localport,
                      syslog_transport, syslog_facility, syslog_severity):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_syslog()
        """
        pass

    def logs_add_message(self, level, message):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::logs_add_message()
        """
        pass

# Temperature information
    def get_temperature(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_temperature()
        """
        pass

# System information
    def get_memory(self, mem_type='usedMemory'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_memory()
        """
        raise UIException("Method isn't implemented")

    def get_cpu(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_cpu()
        """
        raise UIException("Method isn't implemented")

# Applications configuration
    def get_table_applications(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_applications()
        """
        raise UIException("Method isn't implemented")

    def configure_application(self, application, loglevel):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_application()
        """
        raise UIException("Method isn't implemented")

# STP configuration
    def configure_spanning_tree(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_spanning_tree()
        """
        pass

    def create_stp_instance(self, instance, priority):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_stp_instance()
        """
        raise UIException("Method isn't implemented")

    def configure_stp_instance(self, instance, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_stp_instance()
        """
        raise UIException("Method isn't implemented")

    def get_table_spanning_tree(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_spanning_tree()
        """
        raise UIException("Method isn't implemented")

    def get_table_spanning_tree_mst(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_spanning_tree_mst()
        """
        raise UIException("Method isn't implemented")

    def get_table_mstp_ports(self, ports=None, instance=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_mstp_ports()
        """
        raise UIException("Method isn't implemented")

    def modify_mstp_ports(self, ports, instance=0, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_mstp_ports()
        """
        raise UIException("Method isn't implemented")

    def modify_rstp_ports(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_rstp_ports()
        """
        raise UIException("Method isn't implemented")

    def get_table_rstp_ports(self, ports=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_rstp_ports()
        """
        raise UIException("Method isn't implemented")

# Ports configuration
#     def set_all_ports_admin_disabled(self):
#         """
#         @copydoc  testlib::ui_wrapper::UiInterface::set_all_ports_admin_disabled()
#         """
#         raise UIException("Method isn't implemented")
#
#     def wait_all_ports_admin_disabled(self):
#         """
#         @copydoc  testlib::ui_wrapper::UiInterface::wait_all_ports_admin_disabled()
#         """
#         raise UIException("Method isn't implemented")
#
#     def check_device_status(self, dev=None, dev_status=None):
#         """
#         @copydoc  testlib::ui_wrapper::UiInterface::check_device_status()
#         """
#         raise UIException("Method isn't implemented")
#
#     def read_ports(self, port, **kwargs):
#         """
#         @copydoc  testlib::ui_wrapper::UiInterface::read_ports()
#         """
#         raise UIException("Method isn't implemented")

    def modify_ports(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_ports()
        """
        for port_id in ports:

            try:
                port = self.uuid_collections["Ports"][port_id]["uuid"]
            except KeyError:
                raise UIException("No port found.")

            port_attr = kwargs.copy()
            params = {"component": port,
                      "attributes": {}}
            try:
                admin_mode = port_attr.pop("adminMode")
                params["attributes"]["administrativeState"] = admin_mode
                port_info = self.request("getEthernetSwitchPortInfo", {
                    "port": port
                })
                if port_info["portClass"] == "Logical":
                    lag_members = self.request("getCollection", {
                        "component": port,
                        "name": "Members"
                    })
                    request_params = ({"component": member["subcomponent"],
                                       "attributes": {"administrativeState": admin_mode}}
                                      for member in lag_members)
                    self.multicall([{"method": "setComponentAttributes",
                                     "params": request_params}])
            except KeyError:
                pass
            try:
                params["attributes"]["frameSize"] = port_attr.pop("maxFrameSize")
            except KeyError:
                pass
            try:
                params["attributes"]["autoSense"] = port_attr.pop("autoNegotiate")
            except KeyError:
                pass
            try:
                vlan_id = port_attr.pop("pvid")
                try:
                    vlan_uuid = self.uuid_collections["Ports"][port_id]["Vlans"][vlan_id]
                    params["attributes"]["defaultVlan"] = vlan_uuid
                except KeyError:
                    raise UIException("VLAN {0} wasn't found in: {1}".format(vlan_id, list(self.uuid_collections["Ports"][port_id]["Vlans"].keys())))
            except KeyError:
                pass
            try:
                params["attributes"]["linkSpeedMbps"] = port_attr.pop("speed")
            except KeyError:
                pass

            self.request("setComponentAttributes", params)
            if port_attr:
                super(UiOnpssJsonrpc, self).modify_ports(ports=[port_id], **port_attr)

    @staticmethod
    def parse_port_name(port_name):
        """
        @brief  Returns port ID.
        @param  port_name:  port name
        @type  ports_name:  str
        @rtype:  int
        @return:  port ID
        """
        try:
            port_id = int(port_name.lstrip("sw0p"))
        except ValueError:
            port_id = port_name
        return port_id

    def get_table_ports(self, ports=None, all_params=False):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ports()
        """
        if ports:
            ports_uuid = (self.uuid_collections["Ports"][p]["uuid"] for p in ports)
        else:
            ports_uuid = (port["uuid"] for port in self.uuid_collections["Ports"].values())
        request_params = ({"port": p} for p in ports_uuid)
        ports_info_request = {"method": "getEthernetSwitchPortInfo",
                              "params": request_params}
        ports_info = self.multicall([ports_info_request])
        port_table = []
        for port in ports_info:
            try:
                # Temporary added settings with None value since
                # RSA does not support them yet.
                port_attr = {"macAddress": port["macAddress"],
                             "adminMode": port["administrativeState"],
                             "operationalStatus": port["operationalState"],
                             "speed": port["linkSpeedMbps"],
                             "portId": self.parse_port_name(port["portIdentifier"]),
                             "name": port["portIdentifier"],
                             "maxFrameSize": port["frameSize"],
                             "ip_addr": port["ipv4Address"],
                             "tx_cutThrough": None,
                             "cutThrough": None,
                             "duplex": None,
                             "flowControl": None,
                             "pvpt": None,
                             "master": None,
                             "type": port["portClass"]}
            except KeyError as err:
                raise UIException("Command 'getEthernetSwitchPortInfo' returned incorrect reply: {0}".format(port))
            else:
                port_table.append(port_attr)

        return port_table

# Ustack configuration
    def start_ustack_with_given_mesh_ports(self, mesh_ports=tuple(), dbglevel=0):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::start_ustack_with_given_mesh_ports()
        """
        raise UIException("Method isn't implemented")

# Vlan configuration
    def create_vlans(self, vlans=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_vlans()
        """
        # Add VLAN command is optional and may not be implemented
        pass

    def delete_vlans(self, vlans=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_vlans()
        """
        # Delete VLAN command is optional and may not be implemented
        pass

    def get_table_vlans(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_vlans()
        """
        raise UIException("Method isn't implemented")

    def create_vlan_ports(self, ports=None, vlans=None, tagged='Tagged'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_vlan_ports()
        """
        tagged_map = {'tagged': True, 'untagged': False}
        tagged = tagged.lower()
        if ports is not None and vlans is not None:
            try:
                tagged_value = tagged_map[tagged]
            except KeyError:
                raise UIException('Invalid argument for tagged type, {0}.'.format(tagged))
            else:
                for port in ports:
                    params = ({"port": self.uuid_collections["Ports"][port]["uuid"],
                               "vlanId": v,
                               "tagged": tagged_value,
                               "vlanName": "",
                               "oem": {},
                               } for v in vlans)
                    vlan_uuid = self.multicall([{"method": "addPortVlan",
                                                 "params": params}])
                    # update Vlans uuid
                    for vlan in vlan_uuid:
                        vlan_info = self.request("getPortVlanInfo", {"portVlan": vlan["portVlan"]})
                        self.uuid_collections["Ports"][port]["Vlans"].update({vlan_info["vlanId"]: vlan["portVlan"]})
        else:
            raise UIException("List of vlans and ports required")

    def delete_vlan_ports(self, ports=None, vlans=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_vlan_ports()
        """
        if ports is not None and vlans is not None:
            ports = set(ports)
            vlans = set(vlans)
            for port in ports:
                try:
                    vlan_uuids = self.uuid_collections["Ports"][port]["Vlans"]
                except KeyError:
                    raise UIException('No port found.')
                for vlan in vlans:
                    try:
                        params = {"portVlan": vlan_uuids[vlan],
                                  "oem": {}}
                        self.request("deletePortVlan", params)
                        self.uuid_collections["Ports"][port]["Vlans"].pop(vlan)
                    except KeyError:
                        raise UIException('No VLAN found.')
        else:
            raise UIException("List of vlans and ports required")

    def modify_vlan_ports(self, ports=None, vlans=None, tagged='Tagged'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_vlan_ports()
        """
        if ports is not None and vlans is not None:
            # Convert to set as finding membership in set is much faster than list
            vlans = set(vlans)
            ports = set(ports)
            table_vlan = self.get_table_ports2vlans()

            vlans_found = (r for r in table_vlan if r['vlanId']in vlans)
            vlans_and_ports_found = [r for r in vlans_found if r['portId'] in ports]
            for row in vlans_and_ports_found:
                self.delete_vlan_ports(ports=[row['portId']], vlans=[row['vlanId']])

            self.create_vlan_ports(ports=ports, vlans=vlans, tagged=tagged)

            for vlan in vlans_and_ports_found:
                if vlan["pvid"]:
                    self.modify_ports(ports=[vlan["portId"]], pvid=vlan["vlanId"])
        else:
            raise UIException("List of vlans and ports required")

    def get_table_ports2vlans(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ports2vlans()
        """
        tagged_map = {True: "Tagged", False: "Untagged"}
        vlan_table = []

        for port in self.uuid_collections["Ports"]:
            for vlan in self.uuid_collections["Ports"][port]["Vlans"]:
                vlan_info = self.request("getPortVlanInfo", {
                    "portVlan": self.uuid_collections["Ports"][port]["Vlans"][vlan]
                })
                port_info = self.request("getEthernetSwitchPortInfo", {
                    "port": self.uuid_collections["Ports"][port]["uuid"]
                })
                pvid = port_info["defaultVlan"] == self.uuid_collections["Ports"][port]["Vlans"][vlan]
                try:
                    vlan_table.append({"vlanId": vlan,
                                       "portId": port,
                                       "tagged": tagged_map[vlan_info["tagged"]],
                                       "pvid": pvid})
                except KeyError:
                    raise UIException('Invalid argument for tagged type, {0}.'.format(vlan_info["tagged"]))

        return vlan_table

# ACL configuration
    def create_acl(self, ports=None, expressions=None, actions=None, rules=None, acl_name='Test-ACL'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_acl()
        """
        raise UIException("Method isn't implemented")

    def delete_acl(self, ports=None, expression_ids=None, action_ids=None, rule_ids=None, acl_name=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_acl()
        """
        raise UIException("Method isn't implemented")

    def get_table_acl(self, table, acl_name=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_acl()
        """
        raise UIException("Method isn't implemented")

# FDB configuration
    def create_static_macs(self, port=None, vlans=None, macs=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_static_macs()
        """
        raise UIException("Method isn't implemented")

    def delete_static_mac(self, port=None, vlan=None, mac=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_static_mac()
        """
        raise UIException("Method isn't implemented")

    # def get_table_fdb(self, table='Fdb'):
    #     """
    #     @copydoc  testlib::ui_wrapper::UiInterface::get_table_fdb()
    #     """
    #     raise UIException("Method isn't implemented")

    def clear_table_fdb(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::clear_table_fdb()
        """
        raise UIException("Method isn't implemented")

# QoS configuration
    def get_table_ports_qos_scheduling(self, port=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ports_qos_scheduling()
        """
        raise UIException("Method isn't implemented")

    def get_table_ports_dot1p2cos(self, port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ports_dot1p2cos()
        """
        raise UIException("Method isn't implemented")

    def configure_cos_global(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_cos_global()
        """
        raise UIException("Method isn't implemented")

    def configure_port_cos(self, ports=None, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_port_cos()
        """
        raise UIException("Method isn't implemented")

    def create_dot1p_to_cos_mapping(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_dot1p_to_cos_mapping()
        """
        raise UIException("Method isn't implemented")

    def modify_dot1p_to_cos_mapping(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_dot1p_to_cos_mapping()
        """
        raise UIException("Method isn't implemented")

# Statistics configuration
#     def get_table_statistics(self, port=None, stat_name=None):
#         """
#         @copydoc  testlib::ui_wrapper::UiInterface::get_table_statistics()
#         """
#         raise UIException("Method isn't implemented")
#
#     def clear_statistics(self):
#         """
#         @copydoc  testlib::ui_wrapper::UiInterface::clear_statistics()
#         """
#         raise UIException("Method isn't implemented")

# Bridge Info configuration
    def get_table_bridge_info(self, param=None, port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bridge_info()
        """
        raise UIException("Method isn't implemented")

    def modify_bridge_info(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_bridge_info()
        """
        raise UIException("Method isn't implemented")

# LAG configuration
    def create_lag(self, lag=None, key=None, lag_type='Static', hash_mode='None'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_lag()
        """
        # GAMI API doesn't support creating LAG without members
        lag_info = {
            'lagControlType': lag_type,
            'lagId': lag,
            'hashMode': hash_mode,
            'name': 'lag3801',
            'actorAdminLagKey': key
        }
        self.lags.append(lag_info)
        # Add value to lag_map if it isn't there
        self.lag_map.setdefault(lag, str(lag))
        self.name_to_lagid_map.setdefault(str(lag), lag)

    def delete_lags(self, lags=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_lags()
        """
        # GAMI API doesn't support deleting LAG without members
        for lag in lags:
            try:
                record = next(idx for idx, x in enumerate(self.lags) if x['lagId'] == lag)
                del self.lags[record]
                # Delete value to lag_map
                self.lag_map.pop(lag)
                self.name_to_lagid_map.pop(str(lag))
            except IndexError:
                pass

    def get_table_lags(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lags()
        """
        # GAMI API doesn't support getting LAG without members
        return self.lags

    def get_table_link_aggregation(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_link_aggregation()
        """
        raise UIException("Method isn't implemented")

    def modify_link_aggregation(self, globalenable=None, collectormaxdelay=None,
                                globalhashmode=None, priority=None, lacpenable=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_link_aggregation()
        """
        raise UIException("Method isn't implemented")

    def create_lag_ports(self, ports, lag, priority=1, key=None, aggregation='Multiple',
                         lag_mode='Passive', timeout='Long', synchronization=False,
                         collecting=False, distributing=False, defaulting=False, expired=False,
                         partner_system='00:00:00:00:00:00', partner_syspri=32768,
                         partner_number=1, partner_key=0, partner_pri=32768):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_lag_ports()
        """
        if ports is not None and lag is not None:
            # Adds members to existing LAG
            if lag in self.uuid_collections["Ports"]:
                params = {
                    "port": self.uuid_collections["Ports"][lag]["uuid"],
                    "oem": {},
                    "members": [self.uuid_collections["Ports"][p]["uuid"] for p in ports]
                }
                self.request("addEthernetSwitchPortMembers", params)
            # Creates new LAG
            else:
                params = {
                    "switch": self.uuid_collections["Switch"],
                    "portIdentifier": str(lag),
                    "type": "LinkAggregation",
                    "mode": "LinkAggregationStatic",
                    "members": [self.uuid_collections["Ports"][p]["uuid"] for p in ports],
                    "oem": {}
                }
                self.request("addEthernetSwitchPort", params)
                # update Ports uuid
                self._get_subcomponents_uuid()
        else:
            raise UIException("List of ports and LAG Id are required")

    def delete_lag_ports(self, ports, lag):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_lag_ports()
        """
        if ports is not None and lag is not None:
            table_ports2lag = self.get_table_ports2lag()
            lag_found = (l for l in table_ports2lag if l["lagId"] == lag)
            ports_found = set([p["portId"] for p in lag_found])
            # Deletes LAG
            if ports_found == set(ports):
                params = {
                    "port": self.uuid_collections["Ports"][lag]["uuid"],
                    "oem": {}
                }
                self.request("deleteEthernetSwitchPort", params)
                # update Ports uuid
                self._get_subcomponents_uuid()
            # Removes members from existing LAG
            else:
                params = {
                    "port": self.uuid_collections["Ports"][lag]["uuid"],
                    "oem": {},
                    "members": [self.uuid_collections["Ports"][p]["uuid"] for p in ports]
                }
                self.request("deleteEthernetSwitchPortMembers", params)
        else:
            raise UIException("List of ports and LAG Id are required")

    def get_table_ports2lag(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ports2lag()
        """
        table_ports2lag = []
        ports_uuid = ({"port": port["uuid"]} for port in
                      self.uuid_collections["Ports"].values())
        ports_info = self.multicall([{"method": "getEthernetSwitchPortInfo",
                                      "params": ports_uuid}])

        for port_info in ports_info:
            if port_info["portClass"] == "Logical":
                lad_id = self.parse_port_name(port_info["portIdentifier"])
                lag_uuid = self.uuid_collections["Ports"][lad_id]["uuid"]
                lag_members = self.request("getCollection", {
                    "component": lag_uuid,
                    "name": "Members"
                })
                members_uuid = ({"port": port["subcomponent"]} for port in lag_members)
                members_info = self.multicall([{"method": "getEthernetSwitchPortInfo",
                                                "params": members_uuid}])
                lags_info = ({"lagId": lad_id, "actorPortPriority": None,
                              "portId": self.parse_port_name(member["portIdentifier"])
                              } for member in members_info)
                for lag_info in lags_info:
                    table_ports2lag.append(lag_info)
        return table_ports2lag

    def get_table_lags_local(self, lag=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lags_local()
        """
        raise UIException("Method isn't implemented")

    def get_table_lags_local_ports(self, lag=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lags_local_ports()
        """
        raise UIException("Method isn't implemented")

    def get_table_lags_remote_ports(self, lag=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lags_remote_ports()
        """
        raise UIException("Not implemented")

# IGMP configuration
    def configure_igmp_global(self, mode='Enabled', router_alert=None, unknown_igmp_behavior=None,
                              query_interval=None, querier_robustness=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_igmp_global()
        """
        raise UIException("Method isn't implemented")

    def configure_igmp_per_ports(self, ports, mode='Enabled', router_port_mode=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_igmp_per_ports()
        """
        raise UIException("Method isn't implemented")

    def create_multicast(self, port, vlans, macs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_multicast()
        """
        raise UIException("Method isn't implemented")

    def delete_multicast(self, port=None, vlan=None, mac=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_multicast()
        """
        raise UIException("Method isn't implemented")

    def get_table_l2_multicast(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_l2_multicast()
        """
        raise UIException("Method isn't implemented")

    def get_table_igmp_snooping_global_admin(self, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_igmp_snooping_global_admin()
        """
        raise UIException("Method isn't implemented")

    def get_table_igmp_snooping_port_oper(self, port, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_igmp_snooping_port_oper()
        """
        raise UIException("Method isn't implemented")

    def clear_l2_multicast(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::clear_l2_multicast()
        """
        raise UIException("Method isn't implemented")

# L3 configuration
    def configure_routing(self, routing='Enabled', ospf=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_routing()
        """
        raise UIException("Method isn't implemented")

    def create_route_interface(self, vlan, ip, ip_type='InterVlan', bandwidth=1000, mtu=1500,
                               status='Enabled', vrf=0, mode='ip'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_route_interface()
        """
        raise UIException("Method isn't implemented")

    def delete_route_interface(self, vlan, ip, bandwith=1000, mtu=1500, vrf=0, mode='ip'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_route_interface()
        """
        raise UIException("Method isn't implemented")

    def modify_route_interface(self, vlan, ip, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_route_interface()
        """
        raise UIException("Method isn't implemented")

    def get_table_route_interface(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_route_interface()
        """
        raise UIException("Method isn't implemented")

    def get_table_route(self, mode='ip'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_route()
        """
        raise UIException("Method isn't implemented")

    def configure_arp(self, garp=None, refresh_period=None, delay=None, secure_mode=None,
                      age_time=None, attemptes=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_arp()
        """
        raise UIException("Method isn't implemented")

    def get_table_arp_config(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_arp_config()
        """
        raise UIException("Method isn't implemented")

    def create_arp(self, ip, mac, network, mode='arp'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_arp()
        """
        raise UIException("Method isn't implemented")

    def delete_arp(self, ip, network, mode='arp'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_arp()
        """
        raise UIException("Method isn't implemented")

    def get_table_arp(self, mode='arp'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_arp()
        """
        raise UIException("Method isn't implemented")

    def create_static_route(self, ip, nexthop, network, distance=-1, mode='ip'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_static_route()
        """
        raise UIException("Method isn't implemented")

    def delete_static_route(self, network):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_static_route()
        """
        raise UIException("Method isn't implemented")

    def get_table_static_route(self, mode='ip'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_static_route()
        """
        raise UIException("Method isn't implemented")

    def configure_ospf_router(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_ospf_router()
        """
        raise UIException("Method isn't implemented")

    def get_table_ospf_router(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ospf_router()
        """
        raise UIException("Method isn't implemented")

    def create_ospf_area(self, area, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ospf_area()
        """
        raise UIException("Method isn't implemented")

    def get_table_ospf_area(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ospf_area()
        """
        raise UIException("Method isn't implemented")

    def create_network_2_area(self, network, area, mode):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_network_2_area()
        """
        raise UIException("Method isn't implemented")

    def get_table_network_2_area(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_network_2_area()
        """
        raise UIException("Method isn't implemented")

    def create_area_ranges(self, area, range_ip, range_mask, substitute_ip, substitute_mask):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_area_ranges()
        """
        raise UIException("Method isn't implemented")

    def get_table_area_ranges(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_area_ranges()
        """
        raise UIException("Method isn't implemented")

    def create_route_redistribute(self, mode):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_route_redistribute()
        """
        raise UIException("Method isn't implemented")

    def get_table_route_redistribute(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_route_redistribute()
        """
        raise UIException("Method isn't implemented")

    def create_interface_md5_key(self, vlan, network, key_id, key):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_interface_md5_key()
        """
        raise UIException("Method isn't implemented")

    def get_table_interface_authentication(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_interface_authentication()
        """
        raise UIException("Method isn't implemented")

    def create_ospf_interface(self, vlan, network, dead_interval=40, hello_interval=5,
                              network_type="Broadcast", hello_multiplier=3, minimal='Enabled',
                              priority=-1, retransmit_interval=-1):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ospf_interface()
        """
        raise UIException("Method isn't implemented")

    def get_table_ospf_interface(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ospf_interface()
        """
        raise UIException("Method isn't implemented")

    def create_area_virtual_link(self, area, link):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_area_virtual_link()
        """
        raise UIException("Method isn't implemented")

# BGP configuration
    def configure_bgp_router(self, asn=65501, enabled='Enabled'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_bgp_router()
        """
        raise UIException("Method isn't implemented")

    def create_bgp_neighbor_2_as(self, asn, ip, remote_as):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_neighbor_2_as()
        """
        raise UIException("Method isn't implemented")

    def create_bgp_neighbor(self, asn=65501, ip='192.168.0.1'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_neighbor()
        """
        raise UIException("Method isn't implemented")

    def create_bgp_neighbor_connection(self, asn=65501, ip='192.168.0.1', port=179):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_neighbor_connection()
        """
        raise UIException("Method isn't implemented")

    def create_bgp_bgp(self, asn=65501, router_id="1.1.1.1"):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_bgp()
        """
        raise UIException("Method isn't implemented")

    def create_bgp_peer_group(self, asn=65501, name="mypeergroup"):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_peer_group()
        """
        raise UIException("Method isn't implemented")

    def create_bgp_peer_group_member(self, asn=65501, name="mypeergroup", ip="12.1.0.2"):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_peer_group_member()
        """
        raise UIException("Method isn't implemented")

    def create_bgp_redistribute(self, asn=65501, rtype="OSPF"):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_redistribute()
        """
        raise UIException("Method isn't implemented")

    def create_bgp_network(self, asn=65501, ip='10.0.0.0', mask='255.255.255.0',
                           route_map='routeMap'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_network()
        """
        raise UIException("Method isn't implemented")

    def create_bgp_aggregate_address(self, asn=65501, ip='22.10.10.0', mask='255.255.255.0'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_aggregate_address()
        """
        raise UIException("Method isn't implemented")

    def create_bgp_confederation_peers(self, asn=65501, peers=70000):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_confederation_peers()
        """
        raise UIException("Method isn't implemented")

    def create_bgp_distance_network(self, asn=65501, ip="40.0.0.0/24", mask='255.255.255.0',
                                    distance=100, route_map='routeMap'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_distance_network()
        """
        raise UIException("Method isn't implemented")

    def create_bgp_distance_admin(self, asn=65501, ext_distance=100, int_distance=200,
                                  local_distance=50):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_distance_admin()
        """
        raise UIException("Method isn't implemented")

    def get_table_bgp_neighbor(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_neighbor()
        """
        raise UIException("Method isn't implemented")

    def get_table_bgp_neighbor_connections(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_neighbor_connections()
        """
        raise UIException("Method isn't implemented")

    def get_table_bgp_aggregate_address(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_aggregate_address()
        """
        raise UIException("Method isn't implemented")

    def get_table_bgp_confederation_peers(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_confederation_peers()
        """
        raise UIException("Method isn't implemented")

    def get_table_bgp_distance_admin(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_distance_admin()
        """
        raise UIException("Method isn't implemented")

    def get_table_bgp_distance_network(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_distance_network()
        """
        raise UIException("Method isn't implemented")

    def get_table_bgp_network(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_network()
        """
        raise UIException("Method isn't implemented")

    def get_table_bgp_peer_group_members(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_peer_group_members()
        """
        raise UIException("Method isn't implemented")

    def get_table_bgp_peer_groups(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_peer_groups()
        """
        raise UIException("Method isn't implemented")

    def get_table_bgp_redistribute(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_redistribute()
        """
        raise UIException("Method isn't implemented")

# OVS configuration
    def create_ovs_bridge(self, bridge_name):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_bridge()
        """
        raise UIException("Method isn't implemented")

    def get_table_ovs_bridges(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_bridges()
        """
        raise UIException("Method isn't implemented")

    def delete_ovs_bridge(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_ovs_bridge()
        """
        raise UIException("Method isn't implemented")

    def create_ovs_port(self, port, bridge_name):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_port()
        """
        raise UIException("Method isn't implemented")

    def get_table_ovs_ports(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_ports()
        """
        raise UIException("Method isn't implemented")

    def get_table_ovs_rules(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_rules()
        """
        raise UIException("Method isn't implemented")

    def create_ovs_bridge_controller(self, bridge_name, controller):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_bridge_controller()
        """
        raise UIException("Method isn't implemented")

    def get_table_ovs_controllers(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_controllers()
        """
        raise UIException("Method isn't implemented")

    def create_ovs_flow_rules(self, bridge_id, table_id, flow_id, priority, enabled):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_flow_rules()
        """
        raise UIException("Method isn't implemented")

    def delete_ovs_flow_rules(self, bridge_id, table_id, flow_id, priority):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_ovs_flow_rules()
        """
        raise UIException("Method isn't implemented")

    def configure_ovs_resources(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_ovs_resources()
        """
        raise UIException("Method isn't implemented")

    def get_table_ovs_flow_actions(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_flow_actions()
        """
        raise UIException("Method isn't implemented")

    def create_ovs_flow_actions(self, bridge_id, table_id, flow_id, action, param, priority=2000):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_flow_actions()
        """
        raise UIException("Method isn't implemented")

    def delete_ovs_flow_actions(self, bridge_id, table_id, flow_id, action, priority=2000):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_ovs_flow_actions()
        """
        raise UIException("Method isn't implemented")

    def get_table_ovs_flow_qualifiers(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_flow_qualifiers()
        """
        raise UIException("Method isn't implemented")

    def create_ovs_flow_qualifiers(self, bridge_id, table_id, flow_id, field, data,
                                   priority=2000):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_flow_qualifiers()
        """
        raise UIException("Method isn't implemented")

    def delete_ovs_flow_qualifiers(self, bridge_id, table_id, flow_id, field, priority=2000):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_ovs_flow_qualifiers()
        """
        raise UIException("Method isn't implemented")

# LLDP configuration
    def configure_global_lldp_parameters(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_global_lldp_parameters()
        """
        raise UIException("Method isn't implemented")

    def configure_lldp_ports(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_lldp_ports()
        """
        raise UIException("Method isn't implemented")

    def get_table_lldp(self, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lldp()
        """
        raise UIException("Method isn't implemented")

    def get_table_lldp_ports(self, port=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lldp_ports()
        """
        raise UIException("Method isn't implemented")

    def get_table_lldp_ports_stats(self, port=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lldp_ports_stats()
        """
        raise UIException("Method isn't implemented")

    def get_table_lldp_remotes(self, port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lldp_remotes()
        """
        raise UIException("Method isn't implemented")

    def get_table_remotes_mgmt_addresses(self, port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_remotes_mgmt_addresses()
        """
        raise UIException("Method isn't implemented")

    def disable_lldp_on_device_ports(self, ports=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::disable_lldp_on_device_ports()
        """
        raise UIException("Method isn't implemented")

# DCBX configuration
    def set_dcb_admin_mode(self, ports, mode='Enabled'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::set_dcb_admin_mode()
        """
        raise UIException("Method isn't implemented")

    def enable_dcbx_tlv_transmission(self, ports, dcbx_tlvs="all", mode="Enabled"):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::enable_dcbx_tlv_transmission()
        """
        raise UIException("Method isn't implemented")

    def get_table_dcbx_ports(self, port=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_ports()
        """
        raise UIException("Method isn't implemented")

    def get_table_dcbx_app_maps(self, table_type="Admin", port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_app_maps()
        """
        raise UIException("Method isn't implemented")

    def configure_application_priority_rules(self, ports, app_prio_rules, delete_params=False, update_params=False):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_application_priority_rules()
        """
        raise UIException("Method isn't implemented")

    def configure_dcbx_ets(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_dcbx_ets()
        """
        raise UIException("Method isn't implemented")

    def configure_dcbx_cn(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_dcbx_cn()
        """
        raise UIException("Method isn't implemented")

    def configure_dcbx_pfc(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_dcbx_pfc()
        """
        raise UIException("Method isn't implemented")

    def configure_dcbx_app(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_dcbx_app()
        """
        raise UIException("Method isn't implemented")

    def get_table_dcbx_remotes(self, port=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_remotes()
        """
        raise UIException("Method isn't implemented")

    def get_table_dcbx_pfc(self, table_type="Local", port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_pfc()
        """
        raise UIException("Method isn't implemented")

# UFD configuration
    def get_table_ufd_config(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ufd_config()
        """
        raise UIException("Method isn't implemented")

    def configure_ufd(self, enable='Enabled', hold_on_time=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_ufd()
        """
        raise UIException("Method isn't implemented")

    def create_ufd_group(self, group_id, threshold=None, enable='Enabled'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ufd_group()
        """
        raise UIException("Method isn't implemented")

    def modify_ufd_group(self, group_id, threshold=None, enable=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_ufd_group()
        """
        raise UIException("Method isn't implemented")

    def delete_ufd_group(self, group_id):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_ufd_group()
        """
        raise UIException("Method isn't implemented")

    def get_table_ufd_groups(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ufd_groups()
        """
        raise UIException("Method isn't implemented")

    def create_ufd_ports(self, ports, port_type, group_id):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ufd_ports()
        """
        raise UIException("Method isn't implemented")

    def delete_ufd_ports(self, ports, port_type, group_id):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_ufd_ports()
        """
        raise UIException("Method isn't implemented")

    def get_table_ufd_ports(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ufd_ports()
        """
        raise UIException("Method isn't implemented")

# QinQ configuration
    def configure_qinq_ports(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_qinq_ports()
        """
        raise UIException("Method isn't implemented")

    def configure_qinq_vlan_stacking(self, ports, provider_vlan_id, provider_vlan_priority):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_qinq_vlan_stacking()
        """
        raise UIException("Method isn't implemented")

    def get_table_qinq_vlan_stacking(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_qinq_vlan_stacking()
        """
        raise UIException("Method isn't implemented")

    def configure_qinq_vlan_mapping(self, ports, customer_vlan_id, customer_vlan_priority,
                                    provider_vlan_id, provider_vlan_priority):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_qinq_vlan_mapping()
        """
        raise UIException("Method isn't implemented")

    def get_table_qinq_customer_vlan_mapping(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_qinq_customer_vlan_mapping()
        """
        raise UIException("Method isn't implemented")

    def get_table_qinq_provider_vlan_mapping(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_qinq_provider_vlan_mapping()
        """
        raise UIException("Method isn't implemented")

    def get_table_qinq_ports(self, port=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_qinq_ports()
        """
        raise UIException("Method isn't implemented")

# Errdisable configuration
    def get_table_errdisable_errors_config(self, app_name=None, app_error=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_errdisable_errors_config()
        """
        raise UIException("Method isn't implemented")

    def get_table_errdisable_config(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_errdisable_config()
        """
        raise UIException("Method isn't implemented")

    def modify_errdisable_errors_config(self, detect=None, recovery=None, app_name=None,
                                        app_error=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_errdisable_errors_config()
        """
        raise UIException("Method isn't implemented")

    def modify_errdisable_config(self, interval=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_errdisable_config()
        """
        raise UIException("Method isn't implemented")

    def get_errdisable_ports(self, port=None, app_name=None, app_error=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_errdisable_ports()
        """
        raise UIException("Method isn't implemented")

# Mirroring configuration
    def create_mirror_session(self, port, target, mode):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_mirror_session()
        @raise  UIException:  not implemented
        """
        raise UIException("Method isn't implemented")

    def get_mirroring_sessions(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_mirroring_sessions()
        @raise  UIException:  not implemented
        """
        raise UIException("Not implemented")

    def delete_mirroring_session(self, port, target, mode):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_mirroring_session()
        @raise  UIException:  not implemented
        """
        raise UIException("Not implemented")

# DHCP Relay configuration
    def create_dhcp_relay(self, iface_name='global', server_ip=None, fwd_iface_name=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_dhcp_relay()
        """
        raise UIException("Method isn't implemented")

    def get_table_dhcp_relay(self, dhcp_relay_ipv6=False):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dhcp_relay()
        """
        raise UIException("Method isn't implemented")

# VxLAN configuration
    def configure_tunneling_global(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_tunneling_global()
        """
        raise UIException("Method isn't implemented")

    def create_tunnels(self, tunnel_id=None, destination_ip=None, vrf=0, encap_type=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_tunnels()
        """
        raise UIException("Method isn't implemented")

    def get_table_tunnels_admin(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_tunnels_admin()
        """
        raise UIException("Method isn't implemented")
