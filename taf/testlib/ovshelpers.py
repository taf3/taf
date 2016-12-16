#! /usr/bin/env python
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

@file  ovshelpers.py

@summary  Helpers functions for OVS test suites.
"""

import time

from . import loggers

# create logger for module
mod_logger = loggers.module_logger(name=__name__)


def set_ovs_config_with_controller(ports, switch, controller):
    """
    @brief  Set OVS configuration on Switch
    @param  ports:  Links information
    @type  ports:  dict
    @param  switch:  switch
    @type  switch:  SwitchGeneral
    @param  controller:  Controller
    @type  controller:  OvsControllerGeneralMixin
    @return: None
    """
    switch.ui.create_ovs_bridge(bridge_name="spp0")
    controller_ip = "tcp:%s:%s" % (controller.ipaddr, controller.cport, )
    switch.ui.create_ovs_bridge_controller("spp0", controller_ip)
    for port in ports:
        if port[0] != "tg1":
            for link_id in ports[port]:
                try:
                    switch.ui.get_table_ovs_ports()[ports[port][link_id]]
                except Exception:
                    switch.ui.create_ovs_port(int(ports[port][link_id]), bridge_name="spp0")
    # Wait until configuration is applied and connection to Controller is established
    time.sleep(6)


def set_ovs_complex_config_with_controller(ports, switch, sw_id, controller):
    """
    @brief  Set OVS configuration on Switch
    @param  ports:  Links information
    @type  ports:  dict
    @param  switch:  switch
    @type  switch:  SwitchGeneral
    @param  sw_id:  id of switch in complex setup on which OVS is configured
    @type  sw_id:  int
    @param  controller:  Controller
    @type  controller:  OvsControllerGeneralMixin
    @return: None
    """
    switch.ui.create_ovs_bridge(bridge_name="spp0")
    controller_ip = "tcp:%s:%s" % (controller.ipaddr, str(controller.cport), )
    switch.ui.create_ovs_bridge_controller("spp0", controller_ip)
    for port in ports:
        if port[0] != "tg1" and (port[0] == "sw%d" % (sw_id, )):
            for link_id in ports[port]:
                try:
                    switch.ui.get_table_ovs_ports()[ports[port][link_id]]
                except Exception:
                    switch.ui.create_ovs_port(int(ports[port][link_id]), bridge_name="spp0")
    # Wait until configuration is applied and connection to Controller is established
    time.sleep(6)


def add_flow_via_controller(qualifiers, action, controller, name=None, dpid=None):
    """
    @brief  Add flow to OVS bridge via Controller
    @param  qualifiers:  flow qualifiers
    @type  qualifiers:  str
    @param  action:  flow actions
    @type  action:  str
    @param  controller:  Controller
    @type  controller:  OvsControllerGeneralMixin
    @param  name:  flow name
    @type  name:  name
    @type  dpid:  Get process ID
    @type  dpid:  bool
    @return: None
    """
    flow_command = "flow_add"
    flow = "%s %s" % (qualifiers, action, )
    if not name:
        name = 'flow1'
    if controller.name == 'nox':
        controller.setprop(flow_command, [flow_command, flow])
    elif controller.name == 'floodlight':
        if not dpid:
            dpid = controller.getprop('get_dpid', '')
            mod_logger.info('Switch dpid: %s' % (dpid, ))
        controller.setprop(flow_command, [dpid, flow, name])
    elif controller.name == 'oftest':
        controller.setprop(flow_command, [flow])


def delete_flow_via_controller(qualifiers, controller, name=None):
    """
    @brief  Delete flow from OVS bridge via Controller
    @param  qualifiers:  flow qualifiers
    @type  qualifiers:  str
    @param  controller:  Controller
    @type  controller:  OvsControllerGeneralMixin
    @param  name:  flow name
    @type  name:  name
    @return: None
    """
    flow_command = "flow_delete"
    flow = qualifiers
    if not name:
        name = 'flow1'
    if controller.name == 'nox':
        controller.setprop(flow_command, [flow_command, flow])
    elif controller.name == 'floodlight':
        controller.setprop(flow_command, ['flow_delete', name])
    elif controller.name == 'oftest':
        controller.setprop(flow_command, [flow])


def create_packet_definition(packet_to_send):
    """
    @brief  Create packet definition to send
    @param  packet_to_send:  dictionary with specified packet type and fields with values
    @type  packet_to_send:  dict
    @rtype:  tuple(dict)
    @return: packet_definition
    """
    source_mac = "00:00:00:00:00:01"
    destination_mac = "00:00:00:00:00:02"
    source_ip = "10.10.10.1"
    destination_ip = "10.10.10.2"
    source_ip6 = 'fe80::214:f2ff:fe07:af0'
    destination_ip6 = 'ff02::1'
    sport = 1
    dport = 2
    tos = 4
    if packet_to_send["type"] == "ip":
        packet_definition = ({"Ether": {"dst": destination_mac, "src": source_mac, "type": 0x0800}},
                             {"IP": {"dst": destination_ip, "src": source_ip, "tos": tos}},
                             {"TCP": {}})
    elif packet_to_send["type"] == "tagged_ip":
        packet_definition = ({"Ether": {"dst": destination_mac, "src": source_mac, "type": 0x8100}},
                             {"Dot1Q": {"vlan": packet_to_send["vlan"],
                                        "prio": packet_to_send["priority"]}},
                             {"IP": {"dst": destination_ip, "src": source_ip, "tos": tos}})
    elif packet_to_send["type"] == "tcp":
        packet_definition = ({"Ether": {"dst": destination_mac, "src": source_mac, "type": 0x0800}},
                             {"IP": {"dst": destination_ip, "src": source_ip, "tos": tos}},
                             {"TCP": {"sport": sport, "dport": dport}})
    elif packet_to_send["type"] == "udp":
        packet_definition = ({"Ether": {"dst": destination_mac, "src": source_mac, "type": 0x0800}},
                             {"IP": {"dst": destination_ip, "src": source_ip, "tos": tos}},
                             {"UDP": {"sport": sport, "dport": dport}})
    elif packet_to_send["type"] == "double_tagged_ip":
        packet_definition = ({"Ether": {"dst": destination_mac, "src": source_mac, "type": 0x8100}},
                             {"Dot1Q": {"vlan": packet_to_send["outer_vlan"], "type": 0x8100,
                                        "prio": packet_to_send["outer_priority"]}},
                             {"Dot1Q": {"vlan": packet_to_send["inner_vlan"], "type": 0x0800,
                                        "prio": packet_to_send["inner_priority"]}},
                             {"IP": {"dst": destination_ip, "src": source_ip, "tos": tos}})
    elif packet_to_send["type"] == "arp":
        packet_definition = (
            {"Ether": {"src": source_mac, "dst": 'FF:FF:FF:FF:FF:FF', "type": 0x0806}},
            {"ARP": {"op": 1, "hwsrc": source_mac,
                     "psrc": source_ip, "pdst": destination_ip}},)
    elif packet_to_send["type"] == "arp_reply_tagged":
        packet_definition = ({"Ether": {"src": source_mac, "dst": destination_mac, "type": 0x8100}},
                             {"Dot1Q": {"vlan": 2}},
                             {"ARP": {"op": 2, "hwsrc": source_mac, "hwdst": destination_mac,
                                      "pdst": destination_ip, "psrc": source_ip}}, )
    elif packet_to_send["type"] == "icmp":
        packet_definition = ({"Ether": {"dst": destination_mac, "src": source_mac, "type": 0x0800}},
                             {"IP": {"dst": destination_ip, "src": source_ip, "proto": 1}},
                             {"ICMP": {"type": 8, "code": 0}})
    elif packet_to_send["type"] == "ipv6":
        packet_definition = ({"Ether": {"dst": destination_mac, "src": source_mac, "type": 0x86dd}},
                             {"IPv6": {"dst": destination_ip6, "src": source_ip6, "version": 6,
                                       "hlim": 255, "plen": 64, "tc": 225}})
    elif packet_to_send["type"] == "tcp6":
        packet_definition = ({"Ether": {"dst": destination_mac, "src": source_mac, "type": 0x86dd}},
                             {"IPv6": {"dst": destination_ip6, "src": source_ip6, "version": 6,
                                       "hlim": 255, "tc": 224, "nh": 6}},
                             {"TCP": {"sport": sport, "dport": dport}})
    elif packet_to_send["type"] == "udp6":
        packet_definition = ({"Ether": {"dst": destination_mac, "src": source_mac, "type": 0x86dd}},
                             {"IPv6": {"dst": destination_ip6, "src": source_ip6, "version": 6,
                                       "hlim": 255, "tc": 224, "nh": 17}},
                             {"UDP": {"sport": sport, "dport": dport}})
    elif packet_to_send["type"] == "icmp6":
        packet_definition = ({"Ether": {"dst": destination_mac, "src": source_mac, "type": 0x86dd}},
                             {"IPv6": {"dst": destination_ip6, "src": source_ip6, "version": 6,
                                       "hlim": 255, "tc": 224, "nh": 1}},
                             {"ICMP": {"type": 8, "code": 0}})
    return packet_definition


def set_ovs_test_preconditions(ports, test_preconditions, switch, controller):
    """
    @brief  Set test preconditions, e.g. flows
    @param  ports:  ports
    @type  ports:  dict
    @param  test_preconditions:  test preconditions
    @type  test_preconditions:  tuple
    @param  switch:  switch
    @type  switch:  SwitchGeneral
    @param  controller:  Controller
    @type  controller:  OvsControllerGeneralMixin
    @return: None
    """
    if isinstance(test_preconditions, tuple):
        for i, v in enumerate(test_preconditions):
            name = "flow%d" % (i + 1, )
            # configure actions string (if output port is in actions)
            if "output" in test_preconditions[i][1]:
                action = test_preconditions[i][1].split(",")
                for j, k in enumerate(action):
                    if "output" in action[j]:
                        port_id = int(action[j][action[j].find(":") + 1:])
                        action[j] = "output:%d" % (int(ports[('sw1', 'tg1')][port_id], ))
                action_string = ",".join(action)
                test_preconditions[i][1] = action_string
            if "enqueue" in test_preconditions[i][1]:
                action = test_preconditions[i][1].split(",")
                for j, l in enumerate(action):
                    if "enqueue" in action[j]:
                        port_id = int(action[j].split(":")[1])
                        action[j] = "enqueue:%d:%s" % (
                            int(ports[('sw1', 'tg1')][port_id]), action[j].split(":")[2], )
                action_string = ",".join(action)
                test_preconditions[i][1] = action_string
            if "in_port" in test_preconditions[i][0]:
                qualifiers = test_preconditions[i][0].split(",")
                for j, g in enumerate(qualifiers):
                    if "in_port" in qualifiers[j]:
                        port_id = int(qualifiers[j][qualifiers[j].find("=") + 1:])
                        qualifiers[j] = "in_port=%d" % (int(ports[('sw1', 'tg1')][port_id], ))
                qualifiers_string = ",".join(qualifiers)
                test_preconditions[i][0] = qualifiers_string
                add_flow_via_controller(test_preconditions[i][0], test_preconditions[i][1],
                                        controller, name)
            else:
                add_flow_via_controller(test_preconditions[i][0], test_preconditions[i][1],
                                        controller, name)
        # Wait until Controller sends flow to Switch"
        time.sleep(5)


def set_ovs_complex_test_preconditions(ports, test_preconditions, switch, controller, dpid=None):
    """
    @brief  Set test preconditions, e.g. flows
    @param  ports:  ports
    @type  ports:  dict
    @param  test_preconditions:  test preconditions
    @type  test_preconditions:  tuple
    @param  switch:  switch
    @type  switch:  SwitchGeneral
    @param  controller:  Controller
    @type  controller:  OvsControllerGeneralMixin
    @type  dpid:  Get process ID
    @type  dpid:  bool
    @return  None
    """
    if isinstance(test_preconditions, tuple):
        for i, v in enumerate(test_preconditions):
            name = "flow%d" % (i + 1, )
            # configure actions string (if output port is in actions)
            if "output" in test_preconditions[i][1]:
                action = test_preconditions[i][1].split(",")
                for j, k in enumerate(action):
                    if "output" in action[j]:
                        action[j] = "output:%d" % (int(
                            ports[(action[j].split(":")[1], action[j].split(":")[2])][
                                int(action[j].split(":")[3])]), )
                action_string = ",".join(action)
                test_preconditions[i][1] = action_string
            if "enqueue" in test_preconditions[i][1]:
                action = test_preconditions[i][1].split(",")
                for j, l in enumerate(action):
                    if "enqueue" in action[j]:
                        action[j] = "enqueue:%d:%s" % \
                                    (int(ports[(action[j].split(":")[1], action[j].split(":")[2])][
                                        int(action[j].split(":")[3])]),
                                     action[j].split(":")[4])
                action_string = ",".join(action)
                test_preconditions[i][1] = action_string
            if "in_port" in test_preconditions[i][0]:
                qualifiers = test_preconditions[i][0].split(",")
                for j, g in enumerate(qualifiers):
                    if "in_port" in qualifiers[j]:
                        port_string = qualifiers[j].split("=")[1]
                        qualifiers[j] = "in_port=%d" % (int(
                            ports[(port_string.split(":")[0], port_string.split(":")[1])][
                                int(port_string.split(":")[2])]), )
                qualifiers_string = ",".join(qualifiers)
                test_preconditions[i][0] = qualifiers_string
                add_flow_via_controller(test_preconditions[i][0], test_preconditions[i][1],
                                        controller, name=name, dpid=dpid)
            else:
                add_flow_via_controller(test_preconditions[i][0], test_preconditions[i][1],
                                        controller, name=name, dpid=dpid)
        # Wait until Controller sends flow to Switch"
        time.sleep(5)
