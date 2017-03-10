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

"""``lldp.py``

"""

from enum import IntEnum

from . import lldptool


class Lldp(object):

    def __init__(self, run_command):
        super(Lldp, self).__init__()
        self.run_command = run_command

    def set_adminstatus(self, port_name, status):
        cmd = "{lldptool} {command} -i {interface} adminstatus={enableTx}".format(
            lldptool=lldptool.LLDPTOOL,
            command="set-lldp",
            interface=port_name,
            enableTx=status
        )
        self.run_command(cmd)

    def get_adminstatus(self, port_name):
        cmd = "{lldptool} {command} -i {interface} adminStatus".format(
            lldptool=lldptool.LLDPTOOL,
            command="get-lldp",
            interface=port_name
        )
        stdout, stderr, exit_status = self.run_command(cmd)

        return stdout

    def set_enable_tx(self, port_name, tlv, enable_tx):
        cmd = "{lldptool} {command} -i {interface} -V {tlv} {enableTx}".format(
            lldptool=lldptool.LLDPTOOL, command="set-tlv",
            interface=port_name, tlv=tlv,
            enableTx=enable_tx
        )
        self.run_command(cmd)

    def _get_lldp_tlvs_list(self, show_command):
        """

        Args:
            show_command(str): lldptool show-tlv command

        Returns:
            list: list of tlvs

        """
        # quiet=True to avoid exception on ret_code != exit_status
        stdout, stderr, exit_status = self.run_command(show_command, expected_rcs={0, 1})
        # import rpdb2; rpdb2.start_embedded_debugger('foo', True, True)
        if exit_status == 0 and stdout:
            # success
            tlvs = lldptool.lldp_parser.parse(stdout)
            # self.switch.cli.suite_logger.debug(pprint.pformat(tlvs))
            return tlvs
        else:
            # if there is an error return an empty list instead of
            # raising anything, we will fail when trying to verify
            return []

    def get_local_tlvs(self, port_name):
        cmd = '{lldptool} {command} -i {interface}'.format(
            lldptool=lldptool.LLDPTOOL,
            command="get-tlv",
            interface=port_name)
        tlvs = self._get_lldp_tlvs_list(cmd)
        return tlvs

    def get_remote_tlvs(self, port_name):
        cmd = '{lldptool} {command} -n -i {interface}'.format(
            lldptool=lldptool.LLDPTOOL,
            command="get-tlv",
            interface=port_name)
        tlvs = self._get_lldp_tlvs_list(cmd)
        return tlvs

    def clear_settings(self):
        self.run_command("systemctl stop {0}".format(lldptool.LLDPAD_SERVICE))
        # we have to remove config file to clear the config
        self.run_command("rm -f {0}".format(lldptool.LLDPAD_CONFIG_FILE))
        # the shared memory segement stores CEE vs. IEEE and other state, clear it
        self.run_command("{0} -s".format(lldptool.LLDPAD_PATH))
        self.run_command("systemctl start {0}".format(lldptool.LLDPAD_SERVICE))


class ManAddrSubTypes(IntEnum):
    OTHER = 0
    IPV4 = 1
    IPV6 = 2
    NSAP = 3
    HDLC = 4
    BBN1822 = 5
    ALL802 = 6
    E163 = 7
    E164 = 8
    F69 = 9
    X121 = 10
    IPX = 11
    APPLETALK = 12
    DECNETIV = 13
    BANYANVINES = 14
    E164WITHNSAP = 15
    DNS = 16
    DISTINGUISHEDNAME = 17
    ASNUMBER = 18
    XTPOVERIPV4 = 19
    XTPOVERIPV6 = 20
    XTPNATIVEMODEXTP = 21
    FIBRECHANNELWWPN = 22
    FIBRECHANNELWWNN = 23
    GWID = 24
    AFI = 25
    RESERVED = 65535


class ManAddrIfSubTypes(IntEnum):
    UNKNOWN = 1
    IFINDEX = 2
    SYS_PORT_NUM = 3


class ChassisIdSubTypes(IntEnum):
    RESERVED = 0
    CHASSIS_COMPONENT = 1
    INTERFACE_ALIAS = 2
    PORT_COMPONENT = 3
    MAC_ADDRESS = 4
    NETWORK_ADDRESS = 5
    INTERFACE_NAME = 6
    LOCALLY_ASSIGNED = 7


class PortIdSubTypes(IntEnum):
    RESERVED = 0
    INTERFACE_ALIAS = 1
    PORT_COMPONENT = 2
    MAC_ADDRESS = 3
    NETWORK_ADDRESS = 4
    INTERFACE_NAME = 5
    AGENT_CIRCUIT_ID = 6
    LOCALLY_ASSIGNED = 7

# dict because we do string lookup
SYS_CAPABILITIES = {
    "Other": 0x01,
    "Repeater": 0x02,
    "Bridge": 0x04,
    "WLAN Access Point": 0x08,
    "Router": 0x10,
    "Telephone": 0x20,
    "DOCSIS cable device": 0x40,
    "Station Only": 0x80,
}
