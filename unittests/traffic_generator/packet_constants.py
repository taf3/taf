# Copyright (c) 2017, Intel Corporation.
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

"""``packet_constants.py``

`Packet constants`

"""

# Constants for different packet fields
SRC_MAC = "00:00:20:00:10:02"
DST_MAC = "00:00:00:33:33:33"
BROADCAT_MAC = "ff:ff:ff:ff:ff:ff"
ETHER_TYPE_ARP = 0x0806
ETHER_TYPE_IP = 0x0800
ETHER_TYPE_IP6 = 0x86DD
ETHER_TYPE_LLDP = 0x88cc
ETHER_TYPE_TUNNELING = 0x9100
ETHER_TYPE_PBRIDGE = 0x88A8
ETHER_TYPE_8021Q = 0x8100
ETHER_TYPE_EFC = 0x8808
VLAN_1 = 5
VLAN_2 = 18
DOT1Q_PRIO_1 = 1
DOT1Q_PRIO_2 = 2
DOT1Q_DEFAULT_CFI = 0
PAUSE_CODE = 0x0001
PFC_CODE = 0x0101
PAUSE_TIME = 3
PFC_MS = 0
PFC_LS = [0, 1, 0, 1, 1, 1, 0, 1]
PFC_TIME = [0, 1, 0, 20, 3, 40, 3, 500]
IP4_VERSION_FIELD = 4
IP_PROTO_IP = 0
IP_PROTO_ICMP = 1
IP_PROTO_UDP = 17
IP_PROTO_TCP = 6
IP_PROTO_IGMP = 2
IP_TOS = 255
IP_FLAGS = 2
IP_TTL = 64
IP_SRC = "20.0.10.2"
IP_DST = "10.10.10.1"
IP_OPTS_TYPE = 20
IP_OPTS_BODY = b"\xff\xff"
IGMP_TYPE = 17
TCP_FLAGS = 1
ICMP_ECHO_TYPE = 8
UDP_DPORT = 23
UDP_SPORT = 23


# Packet definitions
PACKET_DEFINITION = ({"Ethernet": {"dst": BROADCAT_MAC, "src": "00:00:00:00:00:02"}},
                     {"IP": {"p": IP_PROTO_UDP}},
                     {"UDP": {}},
                     )

PACKET_DEFS = [
    ({"Ethernet": {"dst": BROADCAT_MAC, "src": "00:00:00:00:00:02"}}, {"IP": {"p": IP_PROTO_UDP}}, {"UDP": {}}),
    ({"Ethernet": {"dst": BROADCAT_MAC, "src": "00:00:00:00:00:03"}}, {"IP": {"p": IP_PROTO_ICMP}}, {"ICMP": {}}),
    ({"Ethernet": {"dst": BROADCAT_MAC, "src": "00:00:00:00:00:04"}}, {"IP": {}}, {"TCP": {}}),
]

ARP = ({"Ethernet": {"src": SRC_MAC, "dst": DST_MAC, "type": ETHER_TYPE_ARP}},
       {"ARP": {"sha": SRC_MAC, "spa": "1.1.1.1", "tha": "00:00:00:00:00:00", "tpa": "1.1.1.2"}},
       )

DOT1Q = ({"Ethernet": {"src": SRC_MAC, "dst": DST_MAC}},
         {"Dot1Q": {"vid": VLAN_1}},
         )

IP6 = ({"Ethernet": {"src": '00:00:0a:00:02:08', "dst": "00:01:12:12:34:12", "type": ETHER_TYPE_IP6}},
       {"IP6": {"src": "2000::1:2", "dst": "2000::2:2", "nxt": IP_PROTO_TCP}},
       {"TCP": {}},
       )

QINQ = ({"Ethernet": {"src": SRC_MAC, "dst": DST_MAC}},
        {"Dot1Q": {"vid": VLAN_1, "type": ETHER_TYPE_TUNNELING, "prio": DOT1Q_PRIO_1}},
        {"Dot1Q": {"vid": VLAN_2, "prio": DOT1Q_PRIO_2}},
        {"IP": {"src": IP_SRC, "dst": IP_DST, "p": IP_PROTO_UDP}},
        {"UDP": {"dport": UDP_DPORT, "sport": UDP_SPORT}},
        )

PAUSE = ({"Ethernet": {"dst": DST_MAC, "src": SRC_MAC, "type": ETHER_TYPE_EFC}},
         {"FlowControl": {"opcode": PAUSE_CODE}}, {"Pause": {"ptime": PAUSE_TIME}},
         )

PFC = ({"Ethernet": {"dst": DST_MAC, "src": SRC_MAC, "type": ETHER_TYPE_EFC}},
       {"FlowControl": {"opcode": PFC_CODE}},
       {"PFC": {"ls_list": PFC_LS, "time_list": PFC_TIME}},
       )

ETH_IP_UDP = ({"Ethernet": {"src": SRC_MAC, "dst": DST_MAC}},
              {"IP": {"src": IP_SRC, "dst": IP_DST, "p": IP_PROTO_UDP}},
              {"UDP": {"dport": UDP_DPORT, "sport": UDP_SPORT}},
              )

ETH_IP_TCP = ({"Ethernet": {"src": SRC_MAC, "dst": DST_MAC}},
              {"IP": {"src": IP_SRC, "dst": IP_DST}},
              {"TCP": {}},
              )

ETH_IP_ICMP = ({"Ethernet": {"src": SRC_MAC, "dst": DST_MAC}},
               {"IP": {"src": IP_SRC, "dst": IP_DST, "p": IP_PROTO_ICMP}},
               {"ICMP": {"type": ICMP_ECHO_TYPE}},
               {"ICMP.Echo": {"id": 3, "seq": 20}},
               )

ETH_IP_IGMP = ({"Ethernet": {"src": SRC_MAC, "dst": DST_MAC}},
               {"Dot1Q": {"vid": VLAN_1}},
               {"IP": {"src": IP_SRC, "dst": IP_DST, "tos": IP_TOS, "id": 2, "flags": IP_FLAGS, "offset": 0,
                       "opts": [{"type": IP_OPTS_TYPE, "len": 4, "body_bytes": IP_OPTS_BODY}], "p": IP_PROTO_IGMP}},
               {"IGMP": {"type": IGMP_TYPE, "maxresp": 23, "group": '10.0.2.5'}},
               )

IP_TCP = ({"IP": {"src": IP_SRC, "dst": IP_DST, "flags": IP_FLAGS}},
          {"TCP": {"flags": TCP_FLAGS}},
          )

DOT1Q_IP_ICMP = ({"Ethernet": {"src": SRC_MAC, "dst": DST_MAC}},
                 {"Dot1Q": {"vid": VLAN_1}},
                 {"IP": {"src": IP_SRC, "dst": IP_DST, "p": IP_PROTO_ICMP}},
                 {"ICMP": {}}, {"ICMP.Echo": {}},
                 )

DOT1Q_IP_UDP = ({"Ethernet": {"src": SRC_MAC, "dst": DST_MAC}},
                {"Dot1Q": {"vid": VLAN_1}},
                {"IP": {"src": IP_SRC, "dst": IP_DST, "tos": IP_TOS, "p": IP_PROTO_UDP}},
                {"UDP": {"dport": UDP_DPORT, "sport": UDP_SPORT}},
                )

DOT1Q_IP_TCP = ({"Ethernet": {"src": SRC_MAC, "dst": DST_MAC}},
                {"Dot1Q": {"vid": VLAN_1}},
                {"IP": {"src": IP_SRC, "dst": IP_DST}},
                {"TCP": {}},
                )

DOT1Q_ARP = ({"Ethernet": {"src": SRC_MAC, "dst": DST_MAC, "type": ETHER_TYPE_ARP}},
             {"Dot1Q": {"vid": VLAN_1}},
             {"ARP": {"sha": SRC_MAC, "spa": "1.1.1.1", "tha": "00:00:00:00:00:00", "tpa": "1.1.1.2"}},
             )

DOT1Q_IP6 = ({"Ethernet": {"dst": "00:00:00:01:02:03", "src": "00:00:00:03:02:01", 'type': ETHER_TYPE_IP6}},
             {"Dot1Q": {"vid": VLAN_1, "prio": DOT1Q_PRIO_1}},
             {"IP6": {"src": "2001:db8:1:2:60:8ff:fe52:f9d8", "dst": "2001:db8:1:2:60:8ff:fe52:f9d9", "nxt": IP_PROTO_TCP}},
             {"TCP": {}})

STP = ({"Dot3": {"src": "00:00:00:11:11:11", "dst": DST_MAC}},
       {"LLC": {"dsap": 66, "ssap": 66, "ctrl": 3}},
       {"STP": {"proto": 0, "version": 0}},
       )

RSTP = ({"Dot3": {"src": "00:00:00:11:11:11", "dst": DST_MAC}},
        {"LLC": {"dsap": 66, "ssap": 66, "ctrl": 3}},
        {"STP": {"proto": 0, "version": 2}},
        )

MSTP = ({"Dot3": {"dst": "01:80:c2:00:00:00", "src": "00:00:00:11:11:11"}},
        {"LLC": {"dsap": 66, "ssap": 66, "ctrl": 3}},
        {"STP": {"proto": 0, "version": 3, "bpdutype": 2, "bpduflags": 126, "rootid": 7 * 4096,
                 "rootmac": "00:00:00:11:11:11", "pathcost": 0, "bridgeid": 7 * 4096,
                 "bridgemac": "00:00:00:11:11:11", "portid": 128 + 1, "age": 0.0, "maxage": 20.0,
                 "hellotime": 2.0, "fwddelay": 15.0, "mcidselect": 0,
                 "mcidname": "Switch++ Configuration", "mcidrev": 17,
                 "mcidcfgd": b"\xac6\x17\x7fP(<\xd4\xb88!\xd8\xab&\xdeb",
                 "cistpathcost": 0, "cistbridgeid": 7 * 4096, "cistbridgemac": "00:00:00:11:11:11",
                 "cistrhops": 20}},
        )

MSTI_BPDU = ({"MstiConfigMsg": {"agree": 0, "fwd": 1, "lrn": 1, "prole": 3, "prop": 0, "tchng": 0,
                                "rootid": 7 * 4096 + 1, "rootmac": "00:00:00:11:11:11",
                                "pathcost": 0, "bprio": 0, "pprio": 8, "rhops": 20}},
             )

LLDP = ({"Ethernet": {"dst": "01:80:c2:00:00:0e", "src": "00:12:12:13:13:45", "type": ETHER_TYPE_LLDP}},
        {"LLDP": {
            "tlvlist": [
                 {"LLDPChassisId": {"type": 1, "length": 7, "subtype": "MAC address", "macaddr": "00:12:12:13:13:45"}},
                 {"LLDPPortId": {"type": 2, "length": 4, "subtype": "Interface alias", "value": 'ge0'}},
                 {"LLDPTTL": {"type": 3, "length": 2, "seconds": 65535}},
                 {"LLDPPortDescription": {"type": 4, "length": 0, "value": ""}},
                 {"LLDPSystemName": {"type": 5, "length": 10, "value": '<sys-name>'}},
                 {"LLDPSystemDescription": {"type": 6, "length": 10, "value": '<sys-desc>'}},
                 {"LLDPSystemCapabilities": {"type": 7, "length": 4, "capabilities": 4, "enabled": 4}},
                 {'LLDPManagementAddress': {'type': 8, 'length': 12, 'addrlen': 5, 'addrsubtype': 1,
                                            'ipaddr': '01.01.01.01', 'ifsubtype': 2, 'ifnumber': 1001, 'oidlen': 0,
                                            'oid': ''}},
                 {"LLDPDUEnd": {"type": 0, "length": 0}},
            ]}})
