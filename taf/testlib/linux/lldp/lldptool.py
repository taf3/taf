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

"""``lldptool.py``

"""

import argparse
import os

import sys
import re
import pprint
from collections import defaultdict

LLDPAD_SERVICE = "lldpad"   # this is "boot.lldpad" on SLES
LLDPAD_PATH = "/usr/sbin/lldpad"   # this is "boot.lldpad" on SLES
LLDPTOOL = "lldptool"
LLDPAD_CONFIG_FILE = "/var/lib/lldpad/lldpad.conf"

class TlvNames(object):
    CHASSIS_ID = "Chassis ID TLV"
    PORT_ID = "Port ID TLV"
    TIME_TO_LIVE = "Time to Live TLV"
    PORT_DESCRIPTION = "Port Description TLV"
    SYSTEM_NAME = "System Name TLV"
    SYSTEM_DESCRIPTION = "System Description TLV"
    SYSTEM_CAPABILITIES = "System Capabilities TLV"
    MANAGEMENT_ADDRESS = "Management Address TLV"
    LLDP_MED_CAPABILITIES = "LLDP-MED Capabilities TLV"
    LLDP_MED_HARDWARE_REVISION = "LLDP-MED Hardware Revision TLV"
    LLDP_MED_FIRMWARE_REVISION = "LLDP-MED Firmware Revision TLV"
    LLDP_MED_SOFTWARE_REVISION = "LLDP-MED Software Revision TLV"
    LLDP_MED_SERIAL_NUMBER = "LLDP-MED Serial Number TLV"
    LLDP_MED_MANUFACTURER_NAME = "LLDP-MED Manufacturer Name TLV"
    LLDP_MED_MODEL_NAME = "LLDP-MED Model Name TLV"
    LLDP_MED_ASSET_ID = "LLDP-MED Asset ID TLV"
    MAC_PHY_CONFIGURATION_STATUS = "MAC/PHY Configuration Status TLV"
    LINK_AGGREGATION = "Link Aggregation TLV"
    MAXIMUM_FRAME_SIZE = "Maximum Frame Size TLV"
    EVB_DRAFT_0_2_CONFIGURATION = "EVB draft 0.2 Configuration TLV"
    IEEE_8021QAZ_ETS_CONFIGURATION = "IEEE 8021QAZ ETS Configuration TLV"
    IEEE_8021QAZ_PFC = "IEEE 8021QAZ PFC TLV"
    CEE_DCBX = "CEE DCBX TLV"
    END_OF_LLDPDU = "End of LLDPDU TLV"

lldptool_tni = """
Chassis ID TLV
\tIPv4: 10.0.0.150
Port ID TLV
\tIfname: Te 0/13
Time to Live TLV
\t120
Port Description TLV
\tTe 0/13
System Name TLV
\tbroc150_jack
System Description TLV
\tCEE Switch
System Capabilities TLV
\tSystem capabilities:  Bridge, Router
\tEnabled capabilities: Bridge
Management Address TLV
\tIPv4: 10.0.0.150
Unknown interface subtype: 0
CEE DCBX TLV
\tControl TLV:
\t  SeqNo: 1, AckNo: 3
\tPriority Groups TLV:
\t  Enabled, Not Willing, No Error
\t  PGID Priorities:  0:[0,1,5,7] 1:[3] 2:[4] 3:[2] 4:[6]
\t  PGID Percentages: 0:20% 1:10% 2:40% 3:20% 4:10% 5:0% 6:0% 7:0%
\t  Number of TC's supported: 8
\tPriority Flow Control TLV:
\t  Enabled, Not Willing, No Error
\t  PFC enabled priorities: 2, 3, 4, 6
\t  Number of TC's supported: 8
\tApplication TLV:
\t  Enabled, Not Willing, No Error
\t  Ethertype: 0x8906, Priority Map: 0x04
\t  TCP/UDP Port: 0x0cbc, Priority Map: 0x10
\tUnknown DCBX sub-TLV: 0000800080
\tUnknown DCBX sub-TLV: 0000800180
End of LLDPDU TLV
"""

cee_sub_tlv = """
CEE DCBX TLV
\tControl TLV:
\t  SeqNo: 1, AckNo: 3
\tPriority Groups TLV:
\t  Enabled, Not Willing, No Error
\t  PGID Priorities:  0:[0,1,5,7] 1:[3] 2:[4] 3:[2] 4:[6]
\t  PGID Percentages: 0:20% 1:10% 2:40% 3:20% 4:10% 5:0% 6:0% 7:0%
\t  Number of TC's supported: 8
\tPriority Flow Control TLV:
\t  Enabled, Not Willing, No Error
\t  PFC enabled priorities: 2, 3, 4, 6
\t  Number of TC's supported: 8
\tApplication TLV:
\t  Enabled, Not Willing, No Error
\t  Ethertype: 0x8906, Priority Map: 0x04
\t  TCP/UDP Port: 0x0cbc, Priority Map: 0x10
\tUnknown DCBX sub-TLV: 0000800080
\tUnknown DCBX sub-TLV: 0000800180
"""

lldptool_ti = """Chassis ID TLV
\tMAC: 00:1b:21:87:ac:7d
Port ID TLV
\tMAC: 00:1b:21:87:ac:7d
Time to Live TLV
\t120
CEE DCBX TLV
\tControl TLV:
\t  SeqNo: 8, AckNo: 2
\tPriority Groups TLV:
\t  Enabled, Willing, No Error
\t  PGID Priorities:  0:[0] 1:[1] 2:[2] 3:[3] 4:[4] 5:[5] 6:[6] 7:[7]
\t  PGID Percentages: 0:13% 1:13% 2:13% 3:13% 4:12% 5:12% 6:12% 7:12%
\t  Number of TC's supported: 8
\tPriority Flow Control TLV:
\t  Enabled, Willing, No Error
\t  PFC enabled priorities: none
\t  Number of TC's supported: 8
\tApplication TLV:
\t  Enabled, Willing, No Error
\t  Ethertype: 0x8906, Priority Map: 0x08
\t  TCP/UDP Port: 0x0cbc, Priority Map: 0x10
\t  Ethertype: 0x8914, Priority Map: 0x0f
End of LLDPDU TLV
"""

ieee_lldptool_tni = ieee_lldptool_ti = """Chassis ID TLV
\tMAC: a0:36:9f:0b:3f:9c
Port ID TLV
\tMAC: a0:36:9f:0b:3f:9c
Time to Live TLV
\t120
IEEE 8021QAZ ETS Configuration TLV
\t Willing: no
\t CBS: not supported
\t MAX_TCS: 4
\t PRIO_MAP: 0:0 1:0 2:1 3:1 4:2 5:2 6:3 7:3
\t TC Bandwidth: 25% 25% 25% 25% 0% 0% 0% 0%
\t TSA_MAP: 0:ets 1:ets 2:ets 3:ets 4:strict 5:strict 6:strict 7:strict
IEEE 8021QAZ ETS Recommendation TLV
\t PRIO_MAP:  0:0 1:0 2:1 3:1 4:2 5:2 6:3 7:3
\t TC Bandwidth: 25% 25% 25% 25% 0% 0% 0% 0%
\t TSA_MAP: 0:ets 1:ets 2:ets 3:ets 4:strict 5:strict 6:strict 7:strict
IEEE 8021QAZ PFC TLV
\t Willing: no
\t MACsec Bypass Capable: no
\t PFC capable traffic classes: 4
\t PFC enabled: 1 2 5 7
IEEE 8021QAZ APP TLV
\tApp#0:
\t Priority: 2
\t Sel: 2
\t {S}TCP Port: 3260

\tApp#1:
\t Priority: 5
\t Sel: 1
\t Ethertype: 0x8906

End of LLDPDU TLV
"""

lldptool_tni_with_oid = """
Chassis ID TLV
\tMAC: 5c:26:0a:f1:c5:73
Port ID TLV
\tIfname: Te1/0/2
Time to Live TLV
\t120
Port Description TLV
\tTe1/0/2
System Name TLV
\tpowerconnect-155
System Description TLV
\tPowerconnect 8024, 4.2.0.4, VxWorks 6.6
System Capabilities TLV
\tSystem capabilities:  Bridge, Router
\tEnabled capabilities: Bridge
Management Address TLV
\tIPv4: 10.0.0.155
\tIfindex: 145
\tOID: 1.3.6.1.4.1.674.10895.3023
CEE DCBX TLV
\tControl TLV:
\t  SeqNo: 1, AckNo: 2
\tPriority Flow Control TLV:
\t  Enabled, Not Willing, No Error
\t  PFC enabled priorities: 3, 4
\t  Number of TC's supported: 2
\tPriority Groups TLV:
\t  Enabled, Not Willing, No Error
\t  PGID Priorities:  0:[0,1,2,5,6,7] 1:[3] 2:[4]
\t  PGID Percentages: 0:25% 1:30% 2:45% 3:0% 4:0% 5:0% 6:0% 7:0%
\t  Number of TC's supported: 3
\tApplication TLV:
\t  Enabled, Not Willing, No Error
\t  TCP/UDP Port: 0x0cbc, Priority Map: 0x10
\t  Ethertype: 0x8906, Priority Map: 0x08
End of LLDPDU TLV
"""

unknown_tlvs = """\
CEE DCBX TLV
\tControl TLV:
\t  SeqNo: 1, AckNo: 16777216
\tApplication TLV:
\t  Enabled, Not Willing, No Error
\t  Ethertype: 0x8906, Priority Map: 0x08
\tPriority Flow Control TLV:
\t  Enabled, Not Willing, No Error
\t  PFC enabled priorities: 3
\t  Number of TC's supported: 8
\tPriority Groups TLV:
\t  Enabled, Not Willing, No Error
\t  PGID Priorities:  0:[0,1,2,4,5,6,7] 1:[3]
\t  PGID Percentages: 0:50% 1:50% 2:0% 3:0% 4:0% 5:0% 6:0% 7:0%
\t  Number of TC's supported: 2
Unidentified Org Specific TLV
\tOUI: 0x000142, Subtype: 1, Info: 01
Unidentified Org Specific TLV
\tOUI: 0x0080c2, Subtype: 1, Info: 0001
End of LLDPDU TLV
"""

lldptool_tni_evb_med = """\
Chassis ID TLV
\tMAC: 90:e2:ba:75:27:08
Port ID TLV
\tMAC: 90:e2:ba:75:27:08
Time to Live TLV
\t120
System Capabilities TLV
\tSystem capabilities:  Station Only
\tEnabled capabilities: Station Only
LLDP-MED Capabilities TLV
\tDevice Type:  class1
\tCapabilities: LLDP-MED, Inventory
LLDP-MED Hardware Revision TLV
\tA09
LLDP-MED Firmware Revision TLV
\t3.0.0
LLDP-MED Software Revision TLV
\t3.11.0-15-generic
LLDP-MED Serial Number TLV
\t44454C4C-5700-1037-8035-B2C04F47
LLDP-MED Manufacturer Name TLV
\tDell Inc.
LLDP-MED Model Name TLV
\tPowerEdge R710
LLDP-MED Asset ID TLV
\t2W75GQ1
MAC/PHY Configuration Status TLV
\tAuto-negotiation supported and enabled
\tPMD auto-negotiation capabilities: 0x8001
\tMAU type: Unknown [0x0000]
EVB draft 0.2 Configuration TLV
\tsupported forwarding mode: (0x80) standard 802.1Q
\tsupported capabilities: (0x7) RTE ECP VDP
\tconfigured forwarding mode: (00)
\tconfigured capabilities: (00)
\tno. of supported VSIs: 0000
\tno. of configured VSIs: 0000
\tRTE: 15

IEEE 8021QAZ ETS Configuration TLV
\t Willing: yes
\t CBS: not supported
\t MAX_TCS: 8
\t PRIO_MAP: 0:0 1:0 2:0 3:0 4:0 5:0 6:0 7:0
\t TC Bandwidth: 0% 0% 0% 0% 0% 0% 0% 0%
\t TSA_MAP: 0:strict 1:strict 2:strict 3:strict 4:strict 5:strict 6:strict 7:strict
IEEE 8021QAZ PFC TLV
\t Willing: yes
\t MACsec Bypass Capable: no
\t PFC capable traffic classes: 8
\t PFC enabled: none
End of LLDPDU TLV
"""

COLON_SPLIT_NO_WHITESPACE_RE = re.compile(r"\s*([^:]+)\s*:\s*(.*)\s*")


def comma_sep_ints(s):
    # autodetect int base because we may get 0x04
    return tuple(int(p, 0) for p in s.split(','))


def yes_no_to_bool(s):
    return s == 'yes'


def tsa_value(s):
    key_vals = find_all_colon_key_vals(s)
    return dict((int(k), v) for k, v in key_vals)


def up2tc_value(s):
    key_vals = find_all_colon_key_vals(s)
    return dict((int(k), int(v)) for k, v in key_vals)


class State(object):

    def __init__(self, parser):
        self.parser = parser


class Start(State):

    def tlv(self, l):
        self.parser.tlv_state.set_tlv_type(l)
        self.parser.state = self.parser.tlv_state

    def non_tlv(self, l):
        # save error TLV
        self.parser.tlv_list.append((l, None))
        return self

    def tlv_data(self, _):
        self.parser.state = self.parser.error_state

    def end_tlv(self, l):
        self.parser.tlv_list.append((l, None))
        self.parser.state = self.parser.end_state


class TLV(State):

    def __init__(self, parser):
        State.__init__(self, parser)
        self.tlv_type = None
        self.name = None

    def set_tlv_type(self, l):
        self.name = l

    def tlv(self, _):
        self.tlv_type = None
        self.parser.state = self.parser.error_state

    def non_tlv(self, _):
        self.tlv_type = None
        self.parser.state = self.parser.error_state

    def tlv_data(self, l):
        self.parser.tlv_data_state.start_tlv(self.name, l)
        self.parser.state = self.parser.tlv_data_state

    def end_tlv(self, _):
        self.parser.state = self.parser.error_state


class TLVData(State):

    def __init__(self, parser):
        State.__init__(self, parser)
        self.tlv_type = None
        self.tlv_values = None

    def start_tlv(self, name, l):
        self.tlv_type = name
        self.tlv_values = [l]

    def tlv(self, l):
        self.parser.add_tlv((self.tlv_type, self.tlv_values))
        self.tlv_type = l
        self.tlv_values = []
        self.parser.state = self.parser.tlv_data_state

    def non_tlv(self, l):
        self.parser.add_tlv((self.tlv_type, self.tlv_values))
        self.tlv_type = None
        self.tlv_values = []
        self.parser.tlv_list.append((l, None))
        self.parser.state = self.parser.start_state

    def tlv_data(self, l):
        self.tlv_values.append(l)

    def end_tlv(self, l):
        self.parser.add_tlv((self.tlv_type, self.tlv_values))
        self.tlv_type = None
        self.tlv_values = []
        self.parser.tlv_list.append((l, None))
        self.parser.state = self.parser.end_state


class ErrorState(State):
    pass


class EndState(State):
    pass


class Parser(object):

    def __init__(self, tlv_handlers):
        self.tlv_handlers = tlv_handlers
        self.tlv_list = []
        self.start_state = Start(self)
        self.tlv_state = TLV(self)
        self.tlv_data_state = TLVData(self)
        self.error_state = ErrorState(self)
        self.end_state = EndState(self)
        self.state = self.start_state

    # be careful we use \n
    TLV_RE = re.compile(r"^(\S" "[^\n]+)TLV")
    TLV_DATA_RE = re.compile(r"^\s+" "([^\n]+)")
    NON_TLV_RE = re.compile(r"^(\S" "[^\n]+)(?!TLV)")
    END_TLV_RE = re.compile("^End of LLDPDU TLV")

    def add_tlv(self, tlv):
        res = self.tlv_handlers.get(tlv[0], subtype_handler)(tlv[1])
        self.tlv_list.append((tlv[0], res))

    def parse(self, lines):
        self.state = self.start_state
        self.tlv_list = []
        # import pdb ; pdb.set_trace()
        if len(sys.argv) > 1 and sys.argv[1] == "rpdb":
            import rpdb2
            rpdb2.start_embedded_debugger('foo', True, True)

        if isinstance(lines, str):
            lines = lines.splitlines()

        for l in lines:
            if self.state == self.error_state:
                raise SyntaxError(l)
            elif self.state == self.end_state:
                return self.tlv_list
            elif self.END_TLV_RE.match(l):
                self.state.end_tlv(l)
            elif self.TLV_RE.match(l):
                self.state.tlv(l)
            elif self.NON_TLV_RE.match(l):
                self.state.non_tlv(l)
            elif self.TLV_DATA_RE.match(l):
                self.state.tlv_data(l)
        if self.state == self.end_state:
            return self.tlv_list
        else:
            raise SyntaxError("EOF without End of LLDPDU TLV")


def control_tlv_handler(val):
    values = {}
    for line in val:
        values.update(
            [COLON_SPLIT_NO_WHITESPACE_RE.search(v).groups() for v in line.split(',')])
    return values


def parse_enabled_willing_error(val):
    enabled, willing, error = [s.strip() for s in val.split(',')]
    values = {'Enable': (enabled == 'Enabled'),
              'Willing': (willing == 'Willing'),
              'Errors': error}
    return values


def pgid_priorities(pgid_prios):
    pgids = re.findall(r'(\d):\[([^]]+)\]', pgid_prios)
    pgid_map = dict((int(k), (int(sp) for sp in v.split(',')))
                    for k, v in pgids)
    up2tc = {}
    for tc, ups in pgid_map.items():
        for up in ups:
            up2tc[up] = tc
    return up2tc


def pgid_percentages(pgid_percents):
    percentages = re.findall(r'\d:(\d+)%', pgid_percents)
    return tuple(int(p) for p in percentages)


def priority_group_tlv_handler(val):
    handlers = {
        'PGID Priorities': pgid_priorities,
        'PGID Percentages': pgid_percentages,
        "Number of TC's supported": int
    }
    values = {}
    values.update(parse_enabled_willing_error(val[0]))
    for v in val[1:]:
        tlv_name, tlv_val = v.split(":", 1)
        values[tlv_name] = handlers[tlv_name](tlv_val)
    return values


def priority_flow_control_tlv_handler(val):
    handlers = {
        'PFC enabled priorities': priority_flow_control_enabled_handler,
        "Number of TC's supported": int
    }
    values = {}
    values.update(parse_enabled_willing_error(val[0]))
    for v in val[1:]:
        tlv_name, tlv_val = v.split(":", 1)
        values[tlv_name] = handlers[tlv_name](tlv_val)
    return values


def priority_flow_control_enabled_handler(pfc_enabled):
    enabled_prios = dict((up, False) for up in range(8))
    enabled_prios.update((int(
        p.strip()), True) for p in pfc_enabled.split(",") if 'none' not in p)
    return enabled_prios


def ieee_priority_flow_control_enabled_handler(pfc_enabled):
    enabled_prios = dict((up, False) for up in range(8))
    enabled_prios.update((int(
        p.strip()), True) for p in pfc_enabled.split() if 'none' not in p)
    return enabled_prios


def application_tlv_handler(val):
    # Application TLV:
    #   Enabled, Not Willing, No Error
    #   Ethertype: 0x8906, Priority Map: 0x04
    #   TCP/UDP Port: 0x0cbc, Priority Map: 0x10
    handlers = {
        'Ethertype': int_auto_base,
        'TCP/UDP Port': int_auto_base,
    }
    values = {}
    values.update(parse_enabled_willing_error(val[0]))
    selectors = defaultdict(dict)
    for app in val[1:]:
        selector, priority_map = [tuple(
            s.strip() for s in v.split(':', 1)) for v in app.split(',')]
        # values[selector].
        converted_selector = (selector[0], handlers[selector[0]](selector[1]))
        selectors[converted_selector] = int(priority_map[1], 16)
        # if selector[0] == "Ethertype" and selector[1] == '0x8906':
        #    pass
        # elif selector[0] == "TCP/UDP Port" and selector[1] == '0x0cbc':
        #    pass
    values['Applications'] = dict(selectors)
    return values

SUB_TLV_HANDLERS = {
    'Control TLV:': control_tlv_handler,
    'Priority Groups TLV:': priority_group_tlv_handler,
    'Priority Flow Control TLV:': priority_flow_control_tlv_handler,
    'Application TLV:': application_tlv_handler,
}


class CEESubTLVParser(object):

    def __init__(self, tlv_handlers=None):
        if tlv_handlers is None:
            self.tlv_handlers = SUB_TLV_HANDLERS
        else:
            self.tlv_handlers = tlv_handlers
        self.tlv_list = []
        self.start_state = Start(self)
        self.tlv_state = TLV(self)
        self.tlv_data_state = TLVData(self)
        self.error_state = ErrorState(self)
        self.end_state = EndState(self)
        self.state = self.start_state

    # be careful mixing \t and \s
    TLV_RE = re.compile("^(?:\t| {8})" r"\S" "[^\n]+TLV")
    TLV_DATA_RE = re.compile("^(?:\t| {8})" r"\s+\S" "[^\n]+")

    def add_tlv(self, tlv):
        res = self.tlv_handlers.get(tlv[0], subtype_handler)(tlv[1])
        self.tlv_list.append((tlv[0], res))

    def parse(self, lines):
        self.state = self.start_state
        self.tlv_list = []

        # raw text TLV for already split into lines
        if os.linesep in lines:
            lines = lines.splitlines()

        for l in lines:
            if self.state == self.error_state:
                raise SyntaxError(l)
            elif self.TLV_RE.match(l):
                # use lstrip() because we just use the re for matching and
                # discard the groups
                self.state.tlv(l.lstrip())
            elif self.TLV_DATA_RE.match(l):
                self.state.tlv_data(l.lstrip())
        # fake an end tlv
        self.state.end_tlv('')
        return self.tlv_list[:-1]


class IEEEAppTLVParser(object):

    def __init__(self, tlv_handlers=None):
        if tlv_handlers is None:
            self.tlv_handlers = {}
        else:
            self.tlv_handlers = tlv_handlers
        self.tlv_list = []
        self.start_state = Start(self)
        self.tlv_state = TLV(self)
        self.tlv_data_state = TLVData(self)
        self.error_state = ErrorState(self)
        self.end_state = EndState(self)
        self.state = self.start_state

        # be careful mixing \t and \s
        self.tlv_re = re.compile("^(?:\t| {8})" r"App#\d+:")
        self.tlv_data_re = re.compile("^(?:\t| {8})" r"\s+\S" "[^\n]+")

    def add_tlv(self, tlv):
        res = self.tlv_handlers.get(tlv[0], subtype_handler)(tlv[1])
        # TODO: We have a loop in the parser, so it is adding duplicates
        # for now prevent appending duplicates
        if res:
            if (tlv[0], res) not in self.tlv_list:
                self.tlv_list.append((tlv[0], res))

    def parse(self, lines):
        self.state = self.start_state

        # raw text TLV for already split into lines
        if '\n' in lines:
            lines = lines.splitlines()

        for l in lines:
            if self.state == self.error_state:
                raise SyntaxError(l)
            elif self.tlv_re.match(l):
                self.state.tlv(l.lstrip())
            elif self.tlv_data_re.match(l):
                self.state.tlv_data(l.lstrip())
            # fake an end tlv
        self.state.end_tlv('')
        return [tlv for tlv in self.tlv_list[:-1] if tlv[1] is not None]


def non_subtype_handler(tlvs):
    return [t.strip() for t in tlvs]


def subtype_handler(tlvs):
    """

    Args:
        tlvs

    Returns:
        list: list of subtype, value pairs

    """
    values = []
    for tlv in tlvs:
        if ':' in tlv:
            values.append([s.strip() for s in tlv.split(':', 1)])
        else:
            values.append(tlv.strip())
    return values


def sub_tlv_as_dict_handler_factory(sub_tlv_handlers):
    def save_tlvs_as_dict(tlvs):
        values = {}
        for tlv in tlvs:
            if ':' in tlv:
                name, value = COLON_SPLIT_NO_WHITESPACE_RE.search(tlv).groups()
                converted_value = sub_tlv_handlers.get(
                    name, lambda x: x)(value)
                values[name] = converted_value
            else:
                v = tlv.strip()
                values[v] = v
        return values

    return save_tlvs_as_dict

IEEE_PFC_HANDLERS = {
    "PFC enabled": ieee_priority_flow_control_enabled_handler,
    "PFC capable traffic classes": int,
    "Willing": yes_no_to_bool,
    "MACsec Bypass Capable": yes_no_to_bool,
}


def cee_sub_tlv_handler_into_list(val):
    p = CEESubTLVParser()
    return p.parse(val)


def cee_sub_tlv_handler(val):
    p = CEESubTLVParser()
    return dict(p.parse(val))


def ieee_app_tlv_handler(val):
    p = IEEEAppTLVParser()
    return dict(p.parse(val))

TLV_HANDLERS = {
    TlvNames.SYSTEM_NAME: non_subtype_handler,
    TlvNames.SYSTEM_DESCRIPTION: non_subtype_handler,
    TlvNames.PORT_DESCRIPTION: non_subtype_handler,
    TlvNames.CEE_DCBX: cee_sub_tlv_handler,
    'IEEE 8021QAZ ETS Configuration TLV': sub_tlv_as_dict_handler_factory({}),
    'IEEE 8021QAZ ETS Recommendation TLV': sub_tlv_as_dict_handler_factory({}),
    'IEEE 8021QAZ PFC TLV': sub_tlv_as_dict_handler_factory(IEEE_PFC_HANDLERS),
    'IEEE 8021QAZ APP TLV': IEEEAppTLVParser().parse,
}


def parse_into_list(s):
    p = Parser(TLV_HANDLERS)
    return p.parse(s)


def parse(s):
    p = Parser(TLV_HANDLERS)
    return dict(p.parse(s))


def int_auto_base(n):
    """Convert string to an int, automatically detecting the base.

    """
    return int(n, base=0)


class AppCollector(object):

    def __init__(self):
        super(AppCollector, self).__init__()
        self.apps = {}

    def __call__(self, *args, **kwargs):
        self.apps[comma_sep_ints(args[0])] = True
        return self.apps


SET_FIELD_NAMES_TRANSFORM = {
    'enableTx': "advertise",
}


def parse_set(s):
    set_fields = {
        'enabled': priority_flow_control_enabled_handler,
        'willing': yes_no_to_bool,
        'enableTx': yes_no_to_bool,
        'tsa': tsa_value,
        'up2tc': up2tc_value,
        'tcbw': comma_sep_ints,
        'app': AppCollector(),
    }

    parser = argparse.ArgumentParser(prog="lldptool")
    parser.add_argument(
        "-g", action="store", default=False, dest="bridge_scope")
    parser.add_argument("-n", choices=("nb", "ncb", "nntpmrb",
                                     "nearest_bridge",
                                     "neareast_customer_bridge",
                                     "nearest_nontpmr_bridge"),
                      dest="neighboor")
    parser.add_argument(
        "-T", action="store_true", default=False, dest="set_tlv")
    parser.add_argument(
        "-t", action="store_true", default=False, dest="get_tlv")
    parser.add_argument(
        "-L", action="store_true", default=False, dest="set_lldp")
    parser.add_argument(
        "-l", action="store_true", default=False, dest="get_lldp")
    parser.add_argument(
        "-r", action="store_true", default=False, dest="raw_client")
    parser.add_argument(
        "-R", action="store_true", default=False, dest="only_raw_client")
    parser.add_argument(
        "-c", action="store_true", default=False, dest="query_config")
    parser.add_argument("-i", action="store", dest="interface")
    parser.add_argument("-V", action="store", dest="tlvid")
    opts = parser.parse_args(s.split())
    args = s[1:]
    # by default set max_tcs to 8, we can't even set it on the command line
    vals = {'max_tcs': 8, "interface": opts.interface}
    if not opts.query_config:
        for name, val in (t.split('=') for t in args):
            vals[SET_FIELD_NAMES_TRANSFORM.get(
                # TODO: AppCollector needs to be cleared
                # TODO: can we have multiple for every field?
                name, name)] = set_fields[name](val)
    return vals


def tlv_name_to_python_const(t):
    return re.sub("_TLV$", "", re.sub("[ ./-]", "_", t.upper()))


test_parse = [
    ('Chassis ID TLV', [['IPv6', 'fe80::92e2:baff:fe75:2708']]),
    ('Port ID TLV', [['MAC', '90:e2:ba:75:27:08']]),
    ('Time to Live TLV', ['120']),
    ('Port Description TLV', ['Interface   6 as eth4']),
    ('System Name TLV', ['terminator13']),
    ('System Description TLV',
     [
         'Linux terminator13 3.11.0-15-generic #25~precise1-Ubuntu SMP '
         'Thu Jan 30 17:39:31 UTC 2014 x86_64']),
    ('System Capabilities TLV',
     [['System capabilities', 'Station Only'],
      ['Enabled capabilities', 'Station Only']]),
    ('Management Address TLV',
     [['IPv6', 'fe80::92e2:baff:fe75:2708'], ['Ifindex', '6']]),
    ('LLDP-MED Capabilities TLV',
     [['Device Type', 'class1'], ['Capabilities', 'LLDP-MED, Inventory']]),
    ('LLDP-MED Hardware Revision TLV', ['A09']),
    ('LLDP-MED Firmware Revision TLV', ['3.0.0']),
    ('LLDP-MED Software Revision TLV', ['3.11.0-15-generic']),
    ('LLDP-MED Serial Number TLV', ['44454C4C-5700-1037-8035-B2C04F47']),
    ('LLDP-MED Manufacturer Name TLV', ['Dell Inc.']),
    ('LLDP-MED Model Name TLV', ['PowerEdge R710']),
    ('LLDP-MED Asset ID TLV', ['2W75GQ1']),
    ('MAC/PHY Configuration Status TLV',
     ['Auto-negotiation supported and enabled',
      ['PMD auto-negotiation capabilities', '0x8001'],
      ['MAU type', 'Unknown [0x0000]']]),
    ('Link Aggregation TLV',
     ['Aggregation not capable',
      'Currently not aggregated',
      ['Aggregated Port ID', '0']]),
    ('Maximum Frame Size TLV', ['1518']),
    ('IEEE 8021QAZ ETS Configuration TLV',
     {'CBS': 'not supported',
      'MAX_TCS': '8',
      'PRIO_MAP': '0:0 1:0 2:0 3:0 4:0 5:0 6:0 7:0 ',
      'TC Bandwidth': '0% 0% 0% 0% 0% 0% 0% 0% ',
      'TSA_MAP': '0:strict 1:strict 2:strict 3:strict 4:strict 5:strict '
                 '6:strict 7:strict ',
      'Willing': 'yes'}),
    ('IEEE 8021QAZ PFC TLV',
     {'MACsec Bypass Capable': False,
      'PFC capable traffic classes': 8,
      'PFC enabled': {0: False,
                      1: False,
                      2: False,
                      3: False,
                      4: False,
                      5: False,
                      6: False,
                      7: False},
      'Willing': True}),
    ('End of LLDPDU TLV', None)]


if __name__ == '__main__':
    # print parse("    Chassis ID TLV\nTLV\n")
    _p = Parser(TLV_HANDLERS)
    try:
        with open(sys.argv[1]) as infile:
            pprint.pprint(_p.parse(infile.read()))
    except (IndexError, IOError) as e:
        # pprint.pprint(_p.parse(lldptool_ti))
        # pprint.pprint(_p.parse(ieee_lldptool_ti))
        # pprint.pprint(_p.parse(lldptool_tni))
        # pprint.pprint(_p.parse(lldptool_tni_with_oid))
        # pprint.pprint(_p.parse(lldptool_tni_evb_med))
        # for _t, _v in _p.parse(lldptool_tni_with_oid):
        #     print '%s = "%s"' % (tlv_name_to_python_const(_t), _t)
        for _t, _v in test_parse:
            print('%s = "%s"' % (tlv_name_to_python_const(_t), _t))
    # p = CEESubTLVParser({})
    # pprint.pprint(_p.parse(cee_sub_tlv))

lldp_parser = Parser(TLV_HANDLERS)


def find_all_colon_key_vals(s):
    return re.findall(r'(\d):(\w+)', s)
