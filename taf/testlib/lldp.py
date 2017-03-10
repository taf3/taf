# Copyright (c) 2015 - 2017, Intel Corporation.
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

import re

from .linux import lldp


class Tlv(object):

    @staticmethod
    def get_simple_tlv_row(row_name, value):
        # zero lenght values return an empty list, convert to ''
        return {row_name: value[0] if value else ''}

    @staticmethod
    def get_tlv_from_list(tlvs, predicate):
        # chain all the tlvs together
        """

        Args:
            tlvs(list): list tlvs
            predicate(function): predicate function

        Returns:
            list

        """
        return next(val for t, val in tlvs if predicate(t))

    @staticmethod
    def get_local_port_tlv_row(tlv):
        """

        Args:
            tlv(list): list or dict of the port TLV

        Returns:
            dict: remMan style dict

        """
        row = {}
        # have to use elif because of endswith substring matching
        for subtype, value in tlv:
            if subtype.endswith("MAC"):
                row['PortIdSubtype'] = \
                    lldp.PortIdSubTypes.MAC_ADDRESS
            elif subtype.endswith("IPv4"):
                row['PortIdSubtype'] = \
                    lldp.PortIdSubTypes.NETWORK_ADDRESS
            elif subtype.endswith("IPv6"):
                row['PortIdSubtype'] = \
                    lldp.PortIdSubTypes.NETWORK_ADDRESS
            elif subtype.startswith("Network Address Type"):
                row['PortIdSubtype'] = \
                    lldp.PortIdSubTypes.NETWORK_ADDRESS
                row['PortId'] = value
            elif subtype == 'Interface Alias':
                row['PortIdSubtype'] = \
                    lldp.PortIdSubTypes.INTERFACE_ALIAS
            elif subtype == 'Port Component':
                row['PortIdSubtype'] = \
                    lldp.PortIdSubTypes.PORT_COMPONENT
            elif subtype == 'Ifname':
                row['PortIdSubtype'] = \
                    lldp.PortIdSubTypes.INTERFACE_NAME
            elif subtype == 'Local':
                row['PortIdSubtype'] = \
                    lldp.PortIdSubTypes.LOCALLY_ASSIGNED
            elif subtype == 'Agent Circuit ID':
                row['PortIdSubtype'] = \
                    lldp.PortIdSubTypes.AGENT_CIRCUIT_ID
            elif subtype == 'Bad Port ID':
                # use None to indicate invalid
                row['PortIdSubtype'] = None
            row['PortId'] = value
        return row

    @staticmethod
    def get_local_chassis_tlv_row(tlv):
        """

        Args:
            tlv(list): list or dict of the chassis TLV

        Returns:
            dict: row style dict

        """
        row = {}
        for subtype, value in tlv:
            if subtype.endswith("MAC"):
                row['ChassisIdSubtype'] = \
                    lldp.ChassisIdSubTypes.MAC_ADDRESS
            elif subtype.endswith("IPv4"):
                row['ChassisIdSubtype'] = \
                    lldp.ChassisIdSubTypes.NETWORK_ADDRESS
            elif subtype.endswith("IPv6"):
                row['ChassisIdSubtype'] = \
                    lldp.ChassisIdSubTypes.NETWORK_ADDRESS
            elif subtype.startswith("Network Address Type"):
                row['ChassisIdSubtype'] = \
                    lldp.ChassisIdSubTypes.NETWORK_ADDRESS
                row['ChassisId'] = value
            elif subtype == 'Chassis Component':
                row['ChassisIdIfIdSubtype'] = \
                    lldp.ChassisIdSubTypes.CHASSIS_COMPONENT
            elif subtype == 'IfAlias':
                row['ChassisIdIfIdSubtype'] = \
                    lldp.ChassisIdSubTypes.INTERFACE_ALIAS
            elif subtype == 'Port Component':
                row['ChassisIdIfIdSubtype'] = \
                    lldp.ChassisIdSubTypes.PORT_COMPONENT
            elif subtype == 'Ifname':
                row['ChassisIdIfIdSubtype'] = \
                    lldp.ChassisIdSubTypes.INTERFACE_NAME
            elif subtype == 'Local':
                row['ChassisIdIfIdSubtype'] = \
                    lldp.ChassisIdSubTypes.LOCALLY_ASSIGNED
            elif subtype == 'Bad Chassis ID':
                # use None to indicate invalid
                row['ChassisIdIfIdSubtype'] = None
            row['ChassisId'] = value
        return row

    @staticmethod
    def get_local_cap_tlv_row(tlv):
        """

        Args:
            tlv(list): list or dict of the port TLV

        Returns:
            dict: row style dict

        """
        row = {}
        # have to use elif because of endswith substring matching
        for subtype, value in tlv:
            cap_strings = (s.strip() for s in value.split(','))
            sys_cap = sum(lldp.SYS_CAPABILITIES[c] for c in cap_strings)
            if subtype == "System capabilities":
                row['SysCapSupported'] = sys_cap
            elif subtype == "Enabled capabilities":
                row['SysCapEnabled'] = sys_cap
        return row

    @staticmethod
    def get_port_tlv_row(tlv):
        """

        Args:
            tlv(list): list or dict of the port TLV

        Returns:
            dict: row style dict

        """
        row = {}
        # have to use elif because of endswith substring matching
        for subtype, value in tlv:
            if subtype.endswith("MAC"):
                row['remPortIdSubtype'] = \
                    lldp.PortIdSubTypes.MAC_ADDRESS
            elif subtype.endswith("IPv4"):
                row['remPortIdSubtype'] = \
                    lldp.PortIdSubTypes.NETWORK_ADDRESS
            elif subtype.endswith("IPv6"):
                row['remPortIdSubtype'] = \
                    lldp.PortIdSubTypes.NETWORK_ADDRESS
            elif subtype.startswith("Network Address Type"):
                row['remPortIdSubtype'] = \
                    lldp.PortIdSubTypes.NETWORK_ADDRESS
                row['remPortId'] = value
            elif subtype == 'Interface Alias':
                row['remPortIdSubtype'] = \
                    lldp.PortIdSubTypes.INTERFACE_ALIAS
            elif subtype == 'Port Component':
                row['remPortIdSubtype'] = \
                    lldp.PortIdSubTypes.PORT_COMPONENT
            elif subtype == 'Ifname':
                row['remPortIdSubtype'] = \
                    lldp.PortIdSubTypes.INTERFACE_NAME
            elif subtype == 'Local':
                row['remPortIdSubtype'] = \
                    lldp.PortIdSubTypes.LOCALLY_ASSIGNED
            elif subtype == 'Agent Circuit ID':
                row['remPortIdSubtype'] = \
                    lldp.PortIdSubTypes.AGENT_CIRCUIT_ID
            elif subtype == 'Bad Port ID':
                # use None to indicate invalid
                row['remPortIdSubtype'] = None
            row['remPortId'] = value
        return row

    @staticmethod
    def get_sys_cap_tlv_row(tlv):
        """

        Args:
            tlv(list): list or dict of the port TLV

        Returns:
            dict: row style dict

        """
        row = {}
        # have to use elif because of endswith substring matching
        for subtype, value in tlv:
            cap_strings = (s.strip() for s in value.split(','))
            sys_cap = sum(lldp.SYS_CAPABILITIES[c] for c in cap_strings)
            if subtype == "System capabilities":
                row['remSysCapSupported'] = sys_cap
            elif subtype == "Enabled capabilities":
                row['remSysCapEnabled'] = sys_cap
        return row

    @staticmethod
    def get_chassis_tlv_row(tlv):
        """

        Args:
            tlv(list): list or dict of the chassis TLV

        Returns:
            dict: remMan style dict

        """
        row = {}
        for subtype, value in tlv:
            if subtype.endswith("MAC"):
                row['remChassisIdSubtype'] = \
                    lldp.ChassisIdSubTypes.MAC_ADDRESS
            elif subtype.endswith("IPv4"):
                row['remChassisIdSubtype'] = \
                    lldp.ChassisIdSubTypes.NETWORK_ADDRESS
            elif subtype.endswith("IPv6"):
                row['remChassisIdSubtype'] = \
                    lldp.ChassisIdSubTypes.NETWORK_ADDRESS
            elif subtype.startswith("Network Address Type"):
                row['remChassisIdSubtype'] = \
                    lldp.ChassisIdSubTypes.NETWORK_ADDRESS
                row['remChassisId'] = value
            elif subtype == 'Chassis Component':
                row['remChassisIdIfIdSubtype'] = \
                    lldp.ChassisIdSubTypes.CHASSIS_COMPONENT
            elif subtype == 'IfAlias':
                row['remChassisIdIfIdSubtype'] = \
                    lldp.ChassisIdSubTypes.INTERFACE_ALIAS
            elif subtype == 'Port Component':
                row['remChassisIdIfIdSubtype'] = \
                    lldp.ChassisIdSubTypes.PORT_COMPONENT
            elif subtype == 'Ifname':
                row['remChassisIdIfIdSubtype'] = \
                    lldp.ChassisIdSubTypes.INTERFACE_NAME
            elif subtype == 'Local':
                row['remChassisIdIfIdSubtype'] = \
                    lldp.ChassisIdSubTypes.LOCALLY_ASSIGNED
            elif subtype == 'Bad Chassis ID':
                # use None to indicate invalid
                row['remChassisIdIfIdSubtype'] = None
            row['remChassisId'] = value
        return row

    @staticmethod
    def get_mgmt_row(tlv):
        """

        Args:
            tlv(list): list or dict of the mgmt TLV sub-tlvs

        Returns:
            dict: remMan style dict

        """
        row = {
            # default '' for OID because it might not be present
            'remManAddrOID': '',
            }
        for sub_tlv, value in tlv:
            if sub_tlv.endswith("OID"):
                row['remManAddrOID'] = value
            if sub_tlv.endswith("MAC"):
                row['remManAddrSubtype'] = lldp.ManAddrSubTypes.ALL802
                row['remManAddr'] = value
            elif sub_tlv.endswith("IPv4"):
                row['remManAddrSubtype'] = lldp.ManAddrSubTypes.IPV4
                row['remManAddr'] = value
            elif sub_tlv.endswith("IPv6"):
                row['remManAddrSubtype'] = lldp.ManAddrSubTypes.IPV6
                row['remManAddr'] = value
            elif sub_tlv.startswith("Network Address Type"):
                # convert to int for test cases
                subtype = int(re.search(r'Network Address Type (\d+)',
                                    sub_tlv).group(1))
                row['remManAddrSubtype'] = subtype
                row['remManAddr'] = value
            elif sub_tlv == 'Ifindex':
                row['remManAddrIfSubtype'] = \
                    lldp.ManAddrIfSubTypes.IFINDEX
                row['remManAddrIfId'] = int(value)
            elif sub_tlv == 'System port number':
                row['remManAddrIfSubtype'] = \
                    lldp.ManAddrIfSubTypes.SYS_PORT_NUM
                row['remManAddrIfId'] = int(value)
            elif sub_tlv == 'Unknown interface subtype':
                row['remManAddrIfSubtype'] = \
                    lldp.ManAddrIfSubTypes.UNKNOWN
                row['remManAddrIfId'] = int(value)
            elif sub_tlv == 'Bad interface numbering subtype':
                # use None to indicate invalid
                row['remManAddrIfSubtype'] = None
                row['remManAddrIfId'] = int(value)
        return row
