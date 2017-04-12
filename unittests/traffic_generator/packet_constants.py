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
LLDP_DST_MAC = "01:80:C2:00:00:0E"
LACP_DST_MAC = "01:80:C2:00:00:02"
BROADCAT_MAC = "ff:ff:ff:ff:ff:ff"
ETHER_TYPE_ARP = 0x0806
ETHER_TYPE_IP = 0x0800
ETHER_TYPE_IP6 = 0x86DD
ETHER_TYPE_LLDP = 0x88cc
ETHER_TYPE_TUNNELING = 0x9100
ETHER_TYPE_PBRIDGE = 0x88A8
ETHER_TYPE_8021Q = 0x8100
ETHER_TYPE_EFC = 0x8808
ETHER_TYPE_LLDP = 0x88CC
ETHER_TYPE_LACP = 0x8809
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
LLDP_MAC_SUBTYPE = 4
LLDP_CAPAB_BRIDGE = 4

LLDP_DCBX_OUI = 0x80c2
LLDP_CHASSIS_ID_TLV_TYPE = 1
LLDP_PORT_ID_TLV_TYPE = 2
LLDP_TTL_TLV_TYPE = 3
LLDP_PORT_DESCR_TLV_TYPE = 4
LLDP_SYS_NAME_TLV_TYPE = 5
LLDP_SYS_DESCR_TLV_TYPE = 6
LLDP_SYS_CAPAB_TLV_TYPE = 7
LLDP_MAN_ADDR_TLV_TYPE = 8
LLDP_DCBX_TYPE = 127
LLDP_PORT_ID_INTERFACE_SUBTYPE = 1
LLDP_PORT_ID_INTERFACE_VALUE = b'ge0'
LLDP_TTL_SECONDS = 40
LLDP_SYS_NAME_TLV_VALUE = b"<sys-name>"
LLDP_SYS_DESCR_TLV_VALUE = b"<sys-desc>"
LLDP_EMPTY_VALUE = b""
LLDP_MANAGMENT_INTERFACE_INDEX_SUBTYPE = 2
LLDP_MANAGMENT_INTERFACE_INDEX_NUMBER = 1001
LLDP_MANAGMENT_IPV4_ADDR_SUBTYPE = 1
DCBX_CONFIG_SUBTYPE = 9
DCBX_RECOMEND_SUBTYPE = 10
DCBX_PRIORITY_SUBTYPE = 11
DCBX_PRIORITY_LIST = [0, 1, 2, 3, 3, 3, 3, 3]
DCBX_TCBANDWITH_LIST = [50, 50, 0, 0, 0, 0, 0, 0]
DCBX_TCAASSIGMENT_LIST = [2, 2, 2, 2, 2, 2, 2, 2]
DCBX_PFCENABLE_LIST = [0, 0, 0, 0, 0, 0, 0, 0]
DCBX_WILLING = 1
DCBX_CBS = 1
DCBX_MAXTCS = 3
DCBX_APP_PRIORITY = 0
DCBX_APP_PROTOCOL_ID_1 = 884
DCBX_APP_PROTOCOL_ID_2 = 53
DCBX_APP_SEL_1 = 2
DCBX_APP_SEL_2 = 3
LACP_SUBTYPE = 1
LACP_VERSION = 1
LACP_SYS_PORT_PRIO = 32768
LACP_KEY = 0
LACP_ACTOR_TYPE = 1
LACP_ACTOR_LEN = 20
LACP_ACTOR_PORT = 2
LACP_ACTOR_PARTENER_RESERVED = b"\x00" * 3
LACP_PARTNER_TYPE = 2
LACP_PARTNER_LEN = 20
LACP_PARTNER_PORT = 1
LACP_COLLECTOR_TYPE = 3
LACP_COLLECTOR_LEN = 16
LACP_COLLECTOR_MAXDELAY = 10
LACP_COLLECTOR_RESERVED_VAL = b"\x00" * 12
LACP_TERMINATOR_TYPE = 0
LACP_TERMINATOR_LEN = 0
LACP_RESERVED_VAL = b"\x00" * 50
ENABLE = 1
DISABLE = 0


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

# IPv6 Payload Length ("dlen" for pypacker.IP6) is not auto-updated and should be specified manually
# for Ixia should be include CRC 4 bytes
IP6 = ({"Ethernet": {"src": '00:00:0a:00:02:08', "dst": "00:01:12:12:34:12", "type": ETHER_TYPE_IP6}},
       {"IP6": {"src": "2000::1:2", "dst": "2000::2:2", "nxt": IP_PROTO_TCP, "dlen": 24}},
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

# IPv6 Payload Length ("dlen" for pypacker.IP6) is not auto-updated and should be specified manually
# for Ixia should be include CRC 4 bytes
DOT1Q_IP6 = ({"Ethernet": {"dst": "00:00:00:01:02:03", "src": "00:00:00:03:02:01", 'type': ETHER_TYPE_IP6}},
             {"Dot1Q": {"vid": VLAN_1, "prio": DOT1Q_PRIO_1}},
             {"IP6": {"src": "2001:db8:1:2:60:8ff:fe52:f9d8", "dst": "2001:db8:1:2:60:8ff:fe52:f9d9",
                      "nxt": IP_PROTO_TCP, "dlen": 24}},
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

LLDP_CHASSIS_ID_TLV = {"LLDPChassisId": {"tlv_type": LLDP_CHASSIS_ID_TLV_TYPE, "subtype": LLDP_MAC_SUBTYPE,
                                         "value_s": SRC_MAC},
                       }

LLDP_PORT_ID_TLV = {"LLDPPortId": {"tlv_type": LLDP_PORT_ID_TLV_TYPE, "subtype": LLDP_PORT_ID_INTERFACE_SUBTYPE,
                                   "value": LLDP_PORT_ID_INTERFACE_VALUE},
                    }

LLDP_TTL_TLV = {"LLDPTTL": {"tlv_type": LLDP_TTL_TLV_TYPE, "seconds": LLDP_TTL_SECONDS}}

LLDP_PORT_DESCR_TLV = {"LLDPPortDescription": {"tlv_type": LLDP_PORT_DESCR_TLV_TYPE, "value": LLDP_EMPTY_VALUE}}

LLDP_SYS_NAME_TLV = {"LLDPSystemName": {"tlv_type": LLDP_SYS_NAME_TLV_TYPE, "value": LLDP_SYS_NAME_TLV_VALUE}}

LLDP_SYS_DESCR_TLV = {"LLDPSystemDescription": {"tlv_type": LLDP_SYS_DESCR_TLV_TYPE, "value": LLDP_SYS_DESCR_TLV_VALUE}}

LLDP_SYS_CAPAB_TLV = {"LLDPSystemCapabilities": {"enabled": LLDP_CAPAB_BRIDGE,
                                                 "tlv_type": LLDP_SYS_CAPAB_TLV_TYPE,
                                                 "capabilities": LLDP_CAPAB_BRIDGE,
                                                 },
                      }

LLDP_MAN_ADDR_TLV = {"LLDPManagementAddress": {"tlv_type": LLDP_MAN_ADDR_TLV_TYPE, "addrsubtype": LLDP_MANAGMENT_IPV4_ADDR_SUBTYPE,
                                               "addrval_s": IP_SRC, "ifsubtype": LLDP_MANAGMENT_INTERFACE_INDEX_SUBTYPE,
                                               "ifnumber": LLDP_MANAGMENT_INTERFACE_INDEX_NUMBER,
                                               "oid": LLDP_EMPTY_VALUE}}

DCBX_CONFIG_TLV = {"DCBXConfiguration": {"tlv_type": LLDP_DCBX_TYPE, "oui": LLDP_DCBX_OUI,
                                         "subtype": DCBX_CONFIG_SUBTYPE, "willing": DCBX_WILLING,
                                         "cbs": DCBX_CBS, "maxtcs": DCBX_MAXTCS,
                                         "priority_list": DCBX_PRIORITY_LIST,
                                         "tcbandwith_list": DCBX_TCBANDWITH_LIST,
                                         "tsaassigment_list": DCBX_TCAASSIGMENT_LIST,
                                         },
                   }

DCBX_RECOMENDATION_TLV = {"DCBXRecommendation": {"tlv_type": LLDP_DCBX_TYPE, "oui": LLDP_DCBX_OUI,
                                                 "subtype": DCBX_RECOMEND_SUBTYPE,
                                                 "priority_list": DCBX_PRIORITY_LIST,
                                                 "tcbandwith_list": DCBX_TCBANDWITH_LIST,
                                                 "tsaassigment_list": DCBX_TCAASSIGMENT_LIST,
                                                 },
                          }

DCBX_PRIORITY_TLV = {"DCBXPriorityBasedFlowControlConfiguration": {"tlv_type": LLDP_DCBX_TYPE,
                                                                   "oui": LLDP_DCBX_OUI,
                                                                   "subtype": DCBX_PRIORITY_SUBTYPE,
                                                                   "willing": DCBX_WILLING,
                                                                   "mbc": DCBX_CBS,
                                                                   "pfcenable_list": DCBX_PFCENABLE_LIST,
                                                                   },
                     }

DCBX_APP_PRIO_TLV = {"DCBXApplicationPriority": {"tlv_type": LLDP_DCBX_TYPE, "oui": LLDP_DCBX_OUI,
                                                 "apppriotable": [
                                                     {"DCBXApplicationPriorityTable": {"priority": DCBX_APP_PRIORITY,
                                                                                       "protocolid": DCBX_APP_PROTOCOL_ID_1,
                                                                                       "sel": DCBX_APP_SEL_1,
                                                                                       },
                                                      },
                                                     {"DCBXApplicationPriorityTable": {"priority": DCBX_APP_PRIORITY,
                                                                                       "protocolid": DCBX_APP_PROTOCOL_ID_2,
                                                                                       "sel": DCBX_APP_SEL_1,
                                                                                       },
                                                      },
                                                 ]}}

LLDP_END_TLV = {"LLDPDUEnd": {}}

LLDP = ({"Ethernet": {"dst": LLDP_DST_MAC, "src": SRC_MAC, "type": ETHER_TYPE_LLDP}},
        {"LLDP": {"tlvlist": [LLDP_CHASSIS_ID_TLV, LLDP_PORT_ID_TLV, LLDP_TTL_TLV,
                              LLDP_PORT_DESCR_TLV, LLDP_SYS_NAME_TLV, LLDP_SYS_DESCR_TLV,
                              LLDP_SYS_CAPAB_TLV, LLDP_MAN_ADDR_TLV, LLDP_END_TLV,
                              ],
                  },
         })

LLDP_DCBX = ({"Ethernet": {"dst": LLDP_DST_MAC, "src": SRC_MAC, "type": ETHER_TYPE_LLDP}},
             {"LLDP": {"tlvlist": [LLDP_CHASSIS_ID_TLV, LLDP_PORT_ID_TLV, LLDP_TTL_TLV,
                                   LLDP_PORT_DESCR_TLV, LLDP_SYS_NAME_TLV, LLDP_SYS_DESCR_TLV,
                                   DCBX_CONFIG_TLV, DCBX_RECOMENDATION_TLV, DCBX_PRIORITY_TLV,
                                   LLDP_END_TLV,
                                   ],
                       },
              })

LLDP_DCBX_APP_PRIO = ({"Ethernet": {"dst": LLDP_DST_MAC, "src": SRC_MAC, "type": ETHER_TYPE_LLDP}},
                      {'LLDP': {"tlvlist": [LLDP_CHASSIS_ID_TLV, LLDP_PORT_ID_TLV, LLDP_TTL_TLV,
                                            LLDP_PORT_DESCR_TLV, LLDP_SYS_NAME_TLV, LLDP_SYS_DESCR_TLV,
                                            LLDP_SYS_CAPAB_TLV, DCBX_APP_PRIO_TLV, LLDP_END_TLV,
                                            ],
                                },
                       })

LACP_ACTOR_TLV = {"LACPActorInfoTlv": {"type": LACP_ACTOR_TYPE, "len": LACP_PARTNER_LEN,
                                       "sysprio": LACP_SYS_PORT_PRIO, "sys_s": SRC_MAC,
                                       "key": LACP_KEY, "portprio": LACP_SYS_PORT_PRIO,
                                       "port": LACP_ACTOR_PORT, "expired": ENABLE,
                                       "defaulted": DISABLE, "distribute": ENABLE,
                                       "collect": DISABLE, "synch": ENABLE, "aggregate": DISABLE,
                                       "timeout": ENABLE, "activity": ENABLE,
                                       "reserved": LACP_ACTOR_PARTENER_RESERVED,
                                       }}

LACP_PARTNER_TLV = {"LACPPartnerInfoTlv": {"type": LACP_PARTNER_TYPE, "len": LACP_PARTNER_LEN,
                                           "sysprio": LACP_SYS_PORT_PRIO, "sys_s": SRC_MAC,
                                           "key": LACP_KEY, 'portprio': LACP_SYS_PORT_PRIO,
                                           "port": LACP_PARTNER_PORT, "expired": ENABLE,
                                           "defaulted": DISABLE, "distribute": ENABLE,
                                           "collect": DISABLE, "synch": ENABLE, "aggregate": ENABLE,
                                           "timeout": DISABLE, "activity": ENABLE,
                                           "reserved": LACP_ACTOR_PARTENER_RESERVED,
                                           }}

LACP_COLLECTOR_TLV = {"LACPCollectorInfoTlv": {"type": LACP_COLLECTOR_TYPE, "len": LACP_COLLECTOR_LEN,
                                               "maxdelay": LACP_COLLECTOR_MAXDELAY,
                                               "reserved": LACP_COLLECTOR_RESERVED_VAL}}

LACP_TERMINATOR_TLV = {"LACPTerminatorTlv": {"type": LACP_TERMINATOR_TYPE, "len": LACP_TERMINATOR_LEN}}

LACP_RESERVED_TLV = {"LACPReserved": {"reserved": LACP_RESERVED_VAL}}

LACP = ({"Ethernet": {"dst": LACP_DST_MAC, "src": SRC_MAC, "type": ETHER_TYPE_LACP}},
        {"LACP": {"subtype": LACP_SUBTYPE, "version": LACP_VERSION,
                  "tlvlist": [LACP_ACTOR_TLV, LACP_PARTNER_TLV,
                              LACP_COLLECTOR_TLV, LACP_TERMINATOR_TLV,
                              LACP_RESERVED_TLV,
                              ],
                  },
         })
