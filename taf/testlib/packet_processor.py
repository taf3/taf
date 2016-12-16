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

@file  packet_processor.py

@summary  Packet processor specific functionality.
"""
#TODO: Intagrate Pypacker into methods assemble, assemble_fragmented_packets, packet_fragment, packet_dictionary, check_packet_field_multilayer

import struct

import codecs
import pypacker
from pypacker.layer12 import ethernet
from pypacker.layer12 import arp
from pypacker.layer12 import llc
from pypacker.layer3 import ip
from pypacker.layer3 import ip6
from pypacker.layer3 import icmp
from pypacker.layer4 import tcp
from pypacker.layer4 import udp
from functools import reduce

from . import loggers
from .custom_exceptions import PypackerException

class PacketProcessor(object):
    """
    @description  This class contents only one method to build packet from tuple of dictionaries.
    """

    class_logger = loggers.ClassLogger()

    flt_patterns = {
        "ARP": {'ptrn1': ["08 06", "00 00", "12"], 'mt1': "matchUser", 'cfp': "pattern1"},
        "notARP": {'ptrn1': ["08 06", "00 00", "12"], 'mt1': "matchUser", 'cfp': "notPattern1"},
        "Dot1Q.ARP": {'ptrn1': ["81 00 00 00 08 06", "00 00 FF FF 00 00", "12"], 'mt1': "matchUser", 'cfp': "pattern1"},
        "Dot1Q": {'ptrn1': None, 'mt1': "matchVlan", 'cfp': "pattern1"},
        "IP": {'ptrn1': ["08 00", "00 00", "12"], 'mt1': "matchUser", 'cfp': "pattern1"},
        "IPv6": {'ptrn1': ["86 dd", "00 00", "12"], 'mt1': "matchUser", 'cfp': "pattern1"},
        "notIP": {'ptrn1': ["08 00", "00 00", "12"], 'mt1': "matchUser", 'cfp': "notPattern1"},
        "Dot1Q.IP": {'ptrn1': ["81 00 00 00 08 00", "00 00 FF FF 00 00", "12"], 'mt1': "matchUser", 'cfp': "pattern1"},
        "Dot1Q.IPv6": {'ptrn1': ["81 00 00 00 86 dd", "00 00 FF FF 00 00", "12"], 'mt1': "matchUser", 'cfp': "pattern1"},
        "STP": {'ptrn1': ["42 42 03 00 00", "00 00 00 00 00", "14"], 'mt1': "matchUser", 'cfp': "pattern1"},
        "LLDP": {'ptrn1': ["01 80 c2 00 00 0e 00 00 00 00 00 00 88 cc", "00 00 00 00 00 00 FF FF FF FF FF FF 00 00", "0"], 'mt1': "matchUser",
                 'cfp': "pattern1"},
        "notSTP": {'ptrn1': ["42 42 03 00 00", "00 00 00 00 00", "14"], 'mt1': "matchUser", 'cfp': "notPattern1"},
        "TCP": {'ptrn1': ["08 00 00 00 00 00 00 00 00 00 00 06", "00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                'mt1': "matchUser", 'cfp': "pattern1"},
        "Dot1Q.TCP": {'ptrn1': ["81 00 00 00 08 00 00 00 00 00 00 00 00 00 00 06", "00 00 FF FF 00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                      'mt1': "matchUser", 'cfp': "pattern1"},
        "UDP": {'ptrn1': ["08 00 00 00 00 00 00 00 00 00 00 11", "00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                'mt1': "matchUser", 'cfp': "pattern1"},
        "notUDP": {'ptrn1': ["08 00 00 00 00 00 00 00 00 00 00 11", "00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                   'mt1': "matchUser", 'cfp': "notPattern1"},
        "Dot1Q.UDP": {'ptrn1': ["81 00 00 00 08 00 00 00 00 00 00 00 00 00 00 11", "00 00 FF FF 00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                      'mt1': "matchUser", 'cfp': "pattern1"},
        "ICMP": {'ptrn1': ["08 00 00 00 00 00 00 00 00 00 00 01", "00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                 'mt1': "matchUser", 'cfp': "pattern1"},
        "ICMPv6": {'ptrn1': ["86 dd 00 00 00 00 00 00 00 00 00 01", "00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                   'mt1': "matchUser", 'cfp': "pattern1"},
        "Dot1Q.ICMP": {'ptrn1': ["81 00 00 00 08 00 00 00 00 00 00 00 00 00 00 01", "00 00 FF FF 00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                       'mt1': "matchUser", 'cfp': "pattern1"},
        "Dot1Q.ICMPv6": {'ptrn1': ["81 00 00 00 86 dd 00 00 00 00 00 00 00 00 00 01", "00 00 FF FF 00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                         'mt1': "matchUser", 'cfp': "pattern1"},
        "PAUSE": {'ptrn1': ["88 08", "00 00", "12"], 'mt1': "matchUser", 'cfp': "pattern1"},
        "BOOTP": {'ptrn1': ["08 00", "00 00", "42"], 'mt1': "matchUser", 'cfp': "pattern1"},
    }

    def _build_trex_packet(self, packet_definition, adjust_size=True, required_size=64):
        """
        @brief  Builds trex packet based on provided packet definition.
        @param  packet_definition:  Packet representation (tuple of dictionaries of dictionaries)
        @type  packet_definition:  tuple(dict)
        @param  adjust_size:  If set to True packet size will be increased to 60 bytes (CRC not included)
        @type  adjust_size:  bool
        @param  required_size:  Size (in bytes) of the result packet
        @type  required_size:  int
        @rtype:  trex.Packet
        @return:  trex.packet or list of pypacker packets (if fragsize defined)
        @par Example:
        @code{.py}
        packet_definition = ({"Ether": {"dst": "00:80:C2:00:00:00", "src": "00:00:00:00:00:02"}},
                             {"Dot1Q": {"vlan": 4}},
                             {"IP": {}})
        packet=env.tg[1]._build_trex_packet(packet_definition)
        @endcode
        """
        import trex_stl_lib.api as TApi

        def _value_repr(value):
            """
            @brief  Check if value contains layers.
            """
            if isinstance(value, (list, tuple)):
                return type(value)(list(map(_value_repr, value)))
            elif isinstance(value, dict):
                return _trex_layer(value)
            else:
                return value

        def _trex_layer(layer_dict):
            """
            @brief  Return trex Packet object built according to definition.
            """
            layer_name = list(layer_dict.keys())[0]
            sl = getattr(TApi, layer_name)()
            field_list = [_fl.name for _fl in sl.fields_desc]
            fields = layer_dict[layer_name]
            list([setattr(sl, f, _value_repr(fields[f])) for f in [f for f in field_list if f in fields]])
            return sl

        # Converting packet_definition to trex.Packet.
        packet = reduce(lambda a, b: a / b, list(map(_trex_layer, packet_definition)))

        # Adjust packet size with padding.
        if adjust_size:
            packet_length = len(packet)
            if packet_length < required_size:
                packet.add_payload(b"\x00" * (required_size - packet_length))
            elif packet_length > required_size and required_size < 60:
                self.class_logger.warning("required_size is less than actual size. Packet will be cut off.")
                packet_string = bytes(packet)
                packet_string = packet_string[0:required_size]
                packet = TApi.Ether(packet_string)

        return packet

    def __get_pypacker_layer(self, layer):
        if layer in ["Ethernet", "ARP", "LLC", "STP"]:
            return getattr(getattr(pypacker.layer12, layer.lower()), layer)
        elif layer in ["IP", "IP6", "ICMP", "IGMP"]:
            return getattr(getattr(pypacker.layer3, layer.lower()), layer)
        elif layer in ["TCP", "UDP"]:
            return getattr(getattr(pypacker.layer4, layer.lower()), layer)

    # TODO: adjust_size=True must cut off all packets to required_size, include packet greater 64
    def _build_pypacker_packet(self, packet_definition, adjust_size=True, required_size=64):
        """
        @brief  Builds pypacker packet based on provided packet definition.
        @param  packet_definition:  Packet representation (tuple of dictionaries of dictionaries)
        @type  packet_definition:  tuple(dict)
        @param  adjust_size:  If set to True packet size will be increased to 60 bytes (CRC not included)
        @type  adjust_size:  bool
        @param  required_size:  Size (in bytes) of the result packet
        @type  required_size:  int
        @rtype:  pypacker.Packet
        @return:  pypacker.packet or list of pypacker packets (if fragsize defined)
        @par Example:
        @code{.py}
        packet_definition = ({"Ethernet": {"dst": "00:80:C2:00:00:00", "src": "00:00:00:00:00:02"}},
                             {"Dot1Q": {"vlan": 4}},
                             {"IP": {}})
        packet=env.tg[1]._build_pypacker_packet(packet_definition)
        @endcode
        """

        def _value_repr(packet, field, value):
            """
            @brief  Check if value contains layers.
            """
            if getattr(packet, '{0}_s'.format(field), None):
                setattr(packet, '{0}_s'.format(field), value)
            else:
                setattr(packet, field, value)

        def _pypacker_layer(layer_dict):
            """
            @brief  Return pypacker Packet object built according to definition.
            """
            layer_name = list(layer_dict.keys())[0]
            # Handle inner pypacker class e.g. icmp.ICMP.Echo
            if '.' in layer_name:
                layer, inner_layer = layer_name.split('.')
                pypacker_layer = self.__get_pypacker_layer(layer)
                sl = getattr(pypacker_layer, inner_layer)()
            else:
                pypacker_layer = self.__get_pypacker_layer(layer_name)
                if pypacker_layer:
                    sl = pypacker_layer()
                # Skip undefined layers e.g. Dot1Q
                else:
                    return None
            field_list = (_fl.strip('_') for _fl in sl._header_field_names)
            fields = layer_dict[layer_name]
            list([_value_repr(sl, f, fields[f]) for f in [f for f in field_list if f in fields]])

            return sl

        # Converting packet_definition to pypacker.Packet.
        packet = reduce(lambda a, b: a + b, list(map(_pypacker_layer, packet_definition)))
        # Handle Dot1Q layer in packet_definition
        # TODO: Add handling of priority and CFI fields. Also check ability to build QinQ
        for layer in packet_definition:
            try:
                dot1q_definition = layer["Dot1Q"]

                pypacker_vlan = struct.pack("!H", pypacker.layer12.ethernet.ETH_TYPE_8021Q) + \
                                struct.pack("!H", dot1q_definition["vlan"])
                packet.vlan = pypacker_vlan
                if packet._bodytypename:
                    next_layer =packet._bodytypename.upper()
                    next_layer_type = getattr(pypacker.layer12.ethernet, "ETH_TYPE_{0}".format(next_layer))
                else:
                    next_layer_type = 0
                packet.type = next_layer_type
            except KeyError:
                pass

        # Adjust packet size with padding.
        if adjust_size:
            packet_length = len(packet)
            if packet_length < required_size:
                packet.padding = b"\x00" * (required_size - packet_length)
            # TODO: Check that packet can be created less then 64 bytes via Pypacker
            elif packet_length > required_size and required_size < 60:
                self.class_logger.warning("required_size is less than actual size. Packet will be cut off.")
                packet_string = packet.bin()
                packet_string = packet_string[0:required_size]
                packet = pypacker.layer12.ethernet.Ethernet(packet_string)

        return packet

    def check_packet_field(self, packet=None, layer=None, field=None, value=None):
        """
        @brief  Check if specified field is present (for specified layer) and checks if field value matches specified value.
        @param  packet:  Packet to analyze
        @type  packet:  pypacker.Packet
        @param  layer:  Layer to analyze
        @type  layer:  str
        @param  field:  Field to look for
        @type  field:  str
        @param  value:  Filed value to compare (may be different types, depending on field)
        @type  value:  str, int
        @rtype:  bool
        @return:  True or False
        @par Example:
        @code{.py}
        assert check_packet_field(packet=pypacker_packet, layer="Dot1Q", field="prio", value=4)
        assert check_packet_field(packet=pypacker_packet, layer="Dot1Q", field="type")
        @endcode
        """
        try:
            if layer == "Dot1Q":
                try:
                    vlan_number = struct.unpack('!HH', getattr(packet, field))[1]
                    if value:
                        return vlan_number == value
                    else:
                        return True
                except TypeError:
                    return False
            else:
                pypacker_layer = self.__get_pypacker_layer(layer)
                packet_layer = packet[pypacker_layer]
                if field is not None:
                    packet_value = getattr(packet_layer, field)
                    if value is not None:
                        if isinstance(packet_value, bytes):
                            return getattr(packet_layer, '{0}_s'.format(field)) == value
                        else:
                            return packet_value == value
                return True
        except AttributeError:
            return False

    @staticmethod
    def check_packet_field_multilayer(packet=None, layer=None, field=None, value=None):
        """
        @brief  Check two if specified field is present (for specified layer) and checks if field value matches specified value.
        @param  packet:  Packet to analyze
        @type  packet:  pypacker.Packet
        @param  layer:  Layer to analyze
        @type  layer:  str
        @param  field:  Field to look for
        @type  field:  str
        @param  value:  Filed value to compare (may be different types, depending on field)
        @type  value:  str, int
        @rtype:  bool
        @return:  True or False
        @par Example:
        @code{.py}
        assert check_packet_field_multilayer(packet=pypacker_packet, layer="Dot1Q", field="prio", value=4)
        assert check_packet_field_multilayer(packet=pypacker_packet, layer="Dot1Q", field="type")
        @endcode
        """
        if value is not None:
            try:
                index = 1
                pack = packet[getattr(pypacker, layer):index]
                while pack:
                    packet_value = pack.fields[field]
                    if isinstance(packet_value, bytes) and packet_value.decode("utf-8") == value:
                        return True
                    elif packet_value == value:
                        return True
                    else:
                        index += 1
                        pack = packet[getattr(pypacker, layer):index]
                return False
            except Exception:
                return False
        else:
            try:
                value = packet.getlayer(getattr(pypacker, layer)).fields[field]
                return True
            except Exception:
                return False

    def get_packet_field(self, packet=None, layer=None, field=None):
        """
        @brief  Returns field value (for specified layer) from specified packet.
        @param  packet:  Packet to analyze
        @type  packet:  pypacker.Packet
        @param  layer:  Layer to analyze
        @type  layer:  str
        @param  field:  Field to look for
        @type  field:  str
        @raise  PypackerException:  unknown layer or field
        @rtype:  int, str
        @return:  value (may be different types, depending on field)
        @par Example:
        @code{.py}
        value = get_packet_field(packet=pypacker_packet, layer="Dot1Q", field="vlan")
        @endcode
        """
        try:
            pypacker_layer = self.__get_pypacker_layer(layer)
            packet_layer = packet[pypacker_layer]
        except AttributeError:
            message = "Layer {0} is not defined.".format(layer)
            raise PypackerException(message)

        if packet_layer is None:
            message = "Layer {0} is not defined.".format(layer)
            raise PypackerException(message)

        try:
            result = getattr(packet_layer, field)
            if isinstance(result, bytes) and field == "vlan":
                result = struct.unpack('!HH', getattr(packet_layer, field))[1]
            elif isinstance(result, bytes):
                result = getattr(packet_layer, '{0}_s'.format(field))
        except AttributeError:
            message = "Field {0} is not defined in {1}.".format(field, layer)
            raise PypackerException(message)

        # verify that field is defined in correct layer
        if field in [_fl.strip('_') for _fl in pypacker_layer._header_field_names]:
            return result.decode('UTF-8') if isinstance(result, bytes) else result
        else:
            message = "Field {0} is defined in other layers.".format(field)
            raise PypackerException(message)

    def get_packet_layer(self, packet=None, layer=None, output_format="pypacker"):
        """
        @brief  Returns packet layer in pypacker or hex format.
        @param  packet:  Packet to analyze
        @type  packet:  pypacker.Packet
        @param  layer:  Layer to analyze
        @type  layer:  str
        @param  output_format:  Output format - "pypacker" or "hex" or "bytes_array"
        @type  output_format:  str
        @rtype:  pypacker.Packet, str
        @return:  pypacker.Packet or str
        @par  Example:
        @code{.py}
        packet_definition = ({"Ethernet": {"dst": "00:80:C2:00:00:00", "src": "00:00:00:00:00:02"}}, {"Dot1Q": {"vlan": 4}}, {"IP": {}})
        pypacker_packet = _build_pypacker_packet(packet_definition)
        ip_layer_hex = get_packet_layer(packet=pypacker_packet, layer="IP", output_format="hex")
        assert ip_layer_hex[-8:] == '7f000001'
        @endcode
        """
        try:
            pypacker_layer = self.__get_pypacker_layer(layer)
            layer = packet[pypacker_layer]
            if output_format == "pypacker":
                return layer
            hex_repr = codecs.encode(layer.bin(), "hex_codec").decode('utf-8')
            if output_format == "hex":
                return hex_repr
            if output_format == "bytes_array":
                hexbytes = []
                for i in range(0, len(hex_repr), 2):
                    hexbytes.append(int(hex_repr[i:i + 2], 16))
                return hexbytes
        except Exception:
            return None

    # TODO: remove recursion
    def packet_dictionary(self, packet):
        """
        @brief  Get packet dictionary from pypacker.Packet
        @param  packet:  pypacker packet
        @type  packet:  pypacker.Packet
        @rtype;  dict
        @return  dictionary created from pypacker.Packet
        @par  Example:
        @code{.py}
        p = pypacker.Ethernet(dst="ff:ff:ff:ff:ff:ff", src="90:e6:ba:c3:17:13", type=0x806)/
            pypacker.ARP(hwtype=0x1, ptype=0x800, hwlen=6, plen=4,
                      op=1, hwsrc="90:e6:ba:c3:17:13", psrc="172.20.20.175", hwdst="00:00:00:00:00:00", pdst="172.20.20.211")/
            pypacker.Padding(load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        pd = PacketProcessor().packet_dictionary(p)
        assert pd == ({'Ether': {'src': '90:e6:ba:c3:17:13', 'dst': 'ff:ff:ff:ff:ff:ff', 'type': 2054}},
                      {'ARP': {'hwdst': '00:00:00:00:00:00', 'ptype': 2048, 'hwtype': 1, 'psrc': '172.20.20.175',
                               'plen': 4, 'hwlen': 6, 'pdst': '172.20.20.211', 'hwsrc': '90:e6:ba:c3:17:13', 'op': 1}},
                      {'Padding': {'load': '\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'}})
        @endcode
        """
        def xr(x):
            repr_x = repr(x)
            if "\\x" in repr_x:
                return eval(repr_x.replace("\\x", "\\\\x"))
            else:
                return x

        packet_list = []
        if not isinstance(packet, pypacker.Packet):
            return packet
        payl = packet.copy()
        while payl:
            layer_dict = {}
            class_name = payl.__class__.__name__
            layer_dict[class_name] = payl.fields
            for key in layer_dict[class_name]:
                if isinstance(layer_dict[class_name][key], str):
                    layer_dict[class_name][key] = "".join(map(xr, layer_dict[class_name][key]))
                elif isinstance(layer_dict[class_name][key], list):
                    for indx in range(len(layer_dict[class_name][key])):
                        sub_layer = self.packet_dictionary(layer_dict[class_name][key][indx])
                        if isinstance(sub_layer, tuple):
                            layer_dict[class_name][key][indx] = sub_layer[0]
                        else:
                            layer_dict[class_name][key][indx] = sub_layer
            packet_list.append(layer_dict)
            payl = payl.payload
        return tuple(packet_list)

    def packet_fragment(self, packet, adjust_size=True, required_size=64, fragsize=None):
        """
        @brief  Method for packet fragmentation
        @param  packet:  Packet to be fragmented
        @type  packet:  pypacker.Packet
        @param  adjust_size:  If set to True packet size will be increased to 60 bytes
        @type  adjust_size:  bool
        @param  required_size:  Size (in bytes) of the result packet
        @type  required_size:  int
        @param  fragsize:  length of each fragment
        @type  fragsize:  int
        @rtype:  list[pypacker.Packet]
        @return:  list of pypacker.Packets - fragments of received packet
        """
        if isinstance(packet, tuple) or isinstance(packet, list):
            packet = self._build_pypacker_packet(packet, adjust_size, required_size)

        if fragsize is not None:
            fragments = pypacker.fragment(packet, fragsize)
            return fragments
        else:
            return [packet, ]

    def assemble_fragmented_packets(self, packets):
        """
        @brief  Method for assembling packets from fragments in packet list
        @param  packets:  List of fragmened packets
        @type  packets:  list[pypacker.Packet]
        @rtype:  list[pypacker.Packet]
        @return:  List of assembled packets
        """
        data = []
        while len(packets) > 0:
            pack = packets[0]
            if self.get_packet_field(pack, 'IP', 'frag') == 0 and self.get_packet_field(pack, 'IP', 'flags') == 0:
                packets.pop(packets.index(pack))
                data.append(pack)
            else:
                pack = self.assemble(packets, self.get_packet_field(pack, 'IP', 'id'))
                data.extend(pack)
        return data

    def assemble(self, packets, packet_id):
        """
        @brief  Method for finding fragments and packet assembling by packet["IP"].id value
        @param  packets:  List of packets
        @type  packets:  list[pypacker.Packet]
        @param  packet_id:  Packet IP.id value
        @type  packet_id:  int
        @rtype:  list[pypacker.Packet]
        @return:  List with assembled packet
        """
        packet = None
        # Get all packets with packet_id
        data = [x for x in packets if self.get_packet_field(x, 'IP', 'id') == packet_id]
        # Sorted packets by frag
        data = sorted(data, key=lambda x: self.get_packet_field(x, 'IP', 'frag'))
        for pack in data:
            packets.pop(packets.index(pack))
        # Delete duplicated fragments:
        fragments = data[:]
        counter = 0
        while counter < len(fragments):
            fragment = fragments[counter]
            frag = self.get_packet_field(fragment, 'IP', 'frag')
            same_frags = [x for x in fragments if self.get_packet_field(x, 'IP', 'frag') == frag]
            if len(same_frags) > 1:
                same_frags = sorted(same_frags, key=lambda x: x.time)
                for i in range(1, len(same_frags)):
                    fragments.pop(fragments.index(same_frags[i]))
            counter += 1
        # Remove Padding (checksumm) from fragments:
        for pack in fragments:
            if pack.lastlayer().__class__.__name__ == 'Padding':
                pack.set_field('Padding', 'load', '')
        # Check first fragment:
        if self.get_packet_field(fragments[0], 'IP', 'frag') != 0 or self.get_packet_field(fragments[0], 'IP', 'flags') != 1:
            self.class_logger.warning("First fragment is wrong")
            return data
        # Check last fragment:
        if self.get_packet_field(fragments[len(fragments) - 1], 'IP', 'frag') == 0 or self.get_packet_field(fragments[len(fragments) - 1], 'IP', 'flags') != 0:
            self.class_logger.warning("Last fragment is wrong")
            return data
        # Check fragments for overlapping:
        check_list = [(self.get_packet_field(x, 'IP', 'frag'), len(getattr(x.getlayer(getattr(pypacker, 'IP')), 'payload'))) for x in fragments]
        for i in range(1, len(check_list)):
            prev = check_list[i - 1][0] * 8 + check_list[i - 1][1]
            current = check_list[i][0] * 8
            if prev > current:
                self.class_logger.warning("Fragment %s is overlapped with fragment %s" % (i, i + 1))
                return data
            if prev < current:
                self.class_logger.warning("Fragment is missed between fragments %s and %s" % (i, i + 1))
                return data
        # Assembly fragmented packet
        for pack in fragments:
            if packet is None:
                packet = pack
            else:
                packet.getlayer(getattr(pypacker, 'Raw')).load += pack.getlayer(getattr(pypacker, 'Raw')).load
            packet.getlayer(getattr(pypacker, 'IP')).flags = 0
        # Delete packet checksum and len (pypacker rewrites these values)
        payl = packet.payload
        while payl:
            try:
                del payl.chksum
                del payl.len
            except AttributeError:
                pass
            except Exception as err:
                self.class_logger.warning("Error while processing packet %s" % err)
            payl = payl.payload
        return [packet, ]
