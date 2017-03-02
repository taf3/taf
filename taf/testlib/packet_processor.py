"""
@copyright Copyright (c) 2011 - 2017, Intel Corporation.

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

import codecs
from functools import reduce
from contextlib import suppress

import pytest
import pypacker
from pypacker.layer3 import ip
from pypacker.layer12 import ethernet

from . import loggers
from .custom_exceptions import PypackerException


class PacketProcessor(object):
    """
    @description  This class contents only one method to build packet from tuple of dictionaries.
    """

    class_logger = loggers.ClassLogger()
    inner_classes = ["Echo", "Unreach", "Redirect", "Error", "TooBig", "TimeExceed", "ParamProb"]
    flt_patterns = {
        "ARP": {'ptrn1': ["08 06", "00 00", "12"], 'mt1': "matchUser", 'cfp': "pattern1",
                'lfilter': lambda x: getattr(x, 'arp', None) and not x.vlan},
        "notARP": {'ptrn1': ["08 06", "00 00", "12"], 'mt1': "matchUser", 'cfp': "notPattern1",
                   'lfilter': lambda x: not getattr(x, 'arp', None) or x.vlan},
        "Dot1Q.ARP": {'ptrn1': ["81 00 00 00 08 06", "00 00 FF FF 00 00", "12"], 'mt1': "matchUser", 'cfp': "pattern1",
                      'lfilter': lambda x: getattr(x, 'arp', None) and x.vlan},
        "Dot1Q": {'ptrn1': None, 'mt1': "matchVlan", 'cfp': "pattern1",
                  'lfilter': lambda x: x.vlan != []},
        "IP": {'ptrn1': ["08 00", "00 00", "12"], 'mt1': "matchUser", 'cfp': "pattern1",
               'lfilter': lambda x: getattr(x, 'ip', None) and not x.vlan},
        "IPv6": {'ptrn1': ["86 dd", "00 00", "12"], 'mt1': "matchUser", 'cfp': "pattern1",
                 'lfilter': lambda x: getattr(x, 'ip6', None) and not x.vlan},
        "notIP": {'ptrn1': ["08 00", "00 00", "12"], 'mt1': "matchUser", 'cfp': "notPattern1",
                  'lfilter': lambda x: not getattr(x, 'ip', None) or x.vlan},
        "Dot1Q.IP": {'ptrn1': ["81 00 00 00 08 00", "00 00 FF FF 00 00", "12"], 'mt1': "matchUser", 'cfp': "pattern1",
                     'lfilter': lambda x: getattr(x, 'ip', None) and x.vlan},
        "Dot1Q.IPv6": {'ptrn1': ["81 00 00 00 86 dd", "00 00 FF FF 00 00", "12"], 'mt1': "matchUser", 'cfp': "pattern1",
                       'lfilter': lambda x: getattr(x, 'ip6', None) and x.vlan},
        "STP": {'ptrn1': ["42 42 03 00 00", "00 00 00 00 00", "14"], 'mt1': "matchUser", 'cfp': "pattern1"},
        "LLDP": {'ptrn1': ["01 80 c2 00 00 0e 00 00 00 00 00 00 88 cc", "00 00 00 00 00 00 FF FF FF FF FF FF 00 00", "0"], 'mt1': "matchUser",
                 'cfp': "pattern1"},
        "notSTP": {'ptrn1': ["42 42 03 00 00", "00 00 00 00 00", "14"], 'mt1': "matchUser", 'cfp': "notPattern1"},
        "TCP": {'ptrn1': ["08 00 00 00 00 00 00 00 00 00 00 06", "00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                'mt1': "matchUser", 'cfp': "pattern1",
                'lfilter': lambda x: getattr(x, 'ip', None) and getattr(x.ip, 'tcp', None) and not x.vlan},
        "Dot1Q.TCP": {'ptrn1': ["81 00 00 00 08 00 00 00 00 00 00 00 00 00 00 06", "00 00 FF FF 00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                      'mt1': "matchUser", 'cfp': "pattern1",
                      'lfilter': lambda x: getattr(x, 'ip', None) and getattr(x.ip, 'tcp', None) and x.vlan},
        "UDP": {'ptrn1': ["08 00 00 00 00 00 00 00 00 00 00 11", "00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                'mt1': "matchUser", 'cfp': "pattern1",
                'lfilter': lambda x: getattr(x, 'ip', None) and getattr(x.ip, 'udp', None) and not x.vlan},
        "notUDP": {'ptrn1': ["08 00 00 00 00 00 00 00 00 00 00 11", "00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                   'mt1': "matchUser", 'cfp': "notPattern1",
                   'lfilter': lambda x: getattr(x, 'ip', None) and not getattr(x.ip, 'udp', None) and x.vlan},
        "Dot1Q.UDP": {'ptrn1': ["81 00 00 00 08 00 00 00 00 00 00 00 00 00 00 11", "00 00 FF FF 00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                      'mt1': "matchUser", 'cfp': "pattern1",
                      'lfilter': lambda x: getattr(x, 'ip', None) and getattr(x.ip, 'udp', None) and x.vlan},
        "ICMP": {'ptrn1': ["08 00 00 00 00 00 00 00 00 00 00 01", "00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                 'mt1': "matchUser", 'cfp': "pattern1",
                 'lfilter': lambda x: getattr(x, 'ip', None) and getattr(x.ip, 'icmp', None) and not x.vlan},
        "ICMPv6": {'ptrn1': ["86 dd 00 00 00 00 00 00 00 00 00 01", "00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                   'mt1': "matchUser", 'cfp': "pattern1",
                   'lfilter': lambda x: getattr(x, 'ip6', None) and getattr(x.ip, 'icmp6', None) and not x.vlan},
        "Dot1Q.ICMP": {'ptrn1': ["81 00 00 00 08 00 00 00 00 00 00 00 00 00 00 01", "00 00 FF FF 00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                       'mt1': "matchUser", 'cfp': "pattern1",
                       'lfilter': lambda x: getattr(x, 'ip', None) and getattr(x.ip, 'icmp', None) and x.vlan},
        "Dot1Q.ICMPv6": {'ptrn1': ["81 00 00 00 86 dd 00 00 00 00 00 00 00 00 00 01", "00 00 FF FF 00 00 FF FF FF FF FF FF FF FF FF 00", "12"],
                         'mt1': "matchUser", 'cfp': "pattern1",
                         'lfilter': lambda x: getattr(x, 'ip6', None) and getattr(x.ip, 'icmp6', None) and x.vlan},
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
                             {"Dot1Q": {"vid": 4}},
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
                self.class_logger.warning("required_size is less than actual size. Packet will be cut off")
                packet_string = bytes(packet)
                packet_string = packet_string[0:required_size]
                packet = TApi.Ether(packet_string)

        return packet

    def _get_pypacker_layer(self, layer):
        """
        @brief  Get Pypacker protocol object
        @param  layer:  Protocol name e.g IP, ICMP.Echo
        @type  layer:  str
        @rtype:  pypacker.Packet
        @return:  return Pypacker object
        """
        if '.' not in layer:
            if layer in ["Ethernet", "ARP", "LLC", "STP"]:
                return getattr(getattr(pypacker.layer12, layer.lower()), layer)
            elif layer in ["IP", "IP6", "ICMP", "IGMP"]:
                return getattr(getattr(pypacker.layer3, layer.lower()), layer)
            elif layer in ["TCP", "UDP"]:
                return getattr(getattr(pypacker.layer4, layer.lower()), layer)
            elif layer == "FlowControl":
                return getattr(getattr(pypacker.layer12, "flow_control"), layer)
            elif layer in ["Pause", "PFC"]:
                return getattr(getattr(getattr(pypacker.layer12, "flow_control"), "FlowControl"), layer)
        # Handle inner pypacker class e.g. icmp.ICMP.Echo
        else:
            layer, inner_layer = layer.split('.')
            pypacker_layer = self._get_pypacker_layer(layer)
            return getattr(pypacker_layer, inner_layer)

    @staticmethod
    def _get_pypacker_layer_fields(packet):
        """
        @brief  Get packet fields
        @param  packet:  pypacker packet
        @type  packet:  pypacker.Packet
        @rtype  set
        @return  set of packet fields
        """
        # Get header fields
        fields = {field.strip('_') for field in packet._header_field_names if not field.endswith("_s")}
        # Get subfields that value is less than 1 byte
        sub_fields = {f for f, v in packet.__class__.__dict__.items() if isinstance(v, property) and not f.endswith("_s")}
        return fields.union(sub_fields)

    def _build_pypacker_packet(self, packet_definition, adjust_size=True, required_size=64):
        """
        @brief  Builds pypacker packet based on provided packet definition.
        @param  packet_definition:  Packet representation (tuple of dictionaries of dictionaries)
        @type  packet_definition:  tuple(dict)
        @param  adjust_size:  If set to True packet size will be increased to 64 bytes for Pypacker TG (CRC is included)
                              and to 60 bytes for Ixia TG without CRC.
                              Otherwise Ixia TG will add 4 bytes(CRC), Pypacker TG will not add CRC.
        @type  adjust_size:  bool
        @param  required_size:  Size (in bytes) of the result packet
        @type  required_size:  int
        @rtype:  pypacker.Packet
        @return:  pypacker.packet or list of pypacker packets (if fragsize defined)
        @par Example:
        @code{.py}
        packet_definition = ({"Ethernet": {"dst": "00:80:C2:00:00:00", "src": "00:00:00:00:00:02"}},
                             {"Dot1Q": {"vid": 4}},
                             {"IP": {}})
        packet=env.tg[1]._build_pypacker_packet(packet_definition)
        @endcode
        """

        def _pypacker_layer(layer_dict):
            """
            @brief  Return pypacker Packet object built according to definition.
            """
            layer_name = next(iter(layer_dict))
            pypacker_layer = self._get_pypacker_layer(layer_name)
            if pypacker_layer:
                sl = pypacker_layer()
            # Skip undefined layers e.g. Dot1Q
            else:
                return None

            for field, value in layer_dict[layer_name].items():
                if getattr(sl, '{0}_s'.format(field), None):
                    setattr(sl, '{0}_s'.format(field), value)
                else:
                    setattr(sl, field, value)

            return sl

        # Converting packet_definition to pypacker.Packet.
        packet = reduce(lambda a, b: a + b, map(_pypacker_layer, packet_definition))
        # Handle Dot1Q layer and IP options in packet_definition
        for layer in packet_definition:
            with suppress(KeyError):
                dot1q_definition = layer["Dot1Q"]
                pypacker_vlan = ethernet.Dot1Q(**dot1q_definition)
                packet.vlan.append(pypacker_vlan)
            with suppress(KeyError):
                opts = layer["IP"]["opts"]
                packet.ip.opts = [ip.IPOptMulti(**opt) for opt in opts]

        # Adjust packet size with padding.
        if adjust_size:
            packet_length = len(packet)
            if packet_length < required_size:
                loss_bytes = required_size - packet_length
                try:
                    packet.padding = b"\x00" * (loss_bytes + len(packet.padding))
                except AttributeError:
                    packet.upper_layer.body_bytes = b"\x00" * loss_bytes
            # packet length cannot be less 14 bytes for Ethernet layer due to pypacker behavior
            elif packet_length > required_size and required_size < 60:
                self.class_logger.warning("required_size is less than actual size. Packet will be cut off")
                packet_string = packet.bin()
                packet_string = packet_string[:required_size]
                packet = ethernet.Ethernet(packet_string)

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
        assert check_packet_field(packet=pypacker_packet, layer="S-Dot1Q", field="prio", value=4)
        assert check_packet_field(packet=pypacker_packet, layer="S-Dot1Q", field="type")
        @endcode
        """
        try:
            packet_value = self.get_packet_field(packet, layer, field)
            if value is None:
                return True
            elif packet_value == value:
                return True
            else:
                return False
        except PypackerException:
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
        value = get_packet_field(packet=pypacker_packet, layer="S-Dot1Q", field="vid")
        @endcode
        """
        tag_id = {"S-Dot1Q": 0, "C-Dot1Q": 1}
        try:
            with suppress(KeyError):
                layer_tag = tag_id[layer]
                vlan_tags = self.get_packet_field(packet, "Ethernet", "vlan")
                try:
                    return getattr(vlan_tags[layer_tag], field)
                except IndexError:
                    raise PypackerException("VLAN tag is not defined")

            packet_layer = self.get_packet_layer(packet, layer)
            if packet_layer is None:
                message = "Layer {0} is not defined".format(layer)
                raise PypackerException(message)
            with suppress(AttributeError):
                return getattr(packet_layer, '{0}_s'.format(field))
            return getattr(packet_layer, field)
        except AttributeError:
            message = "Field {0} is not defined in {1}".format(field, layer)
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
        packet_definition = ({"Ethernet": {"dst": "00:80:C2:00:00:00", "src": "00:00:00:00:00:02"}},
                            {"Dot1Q": {"vid": 4}}, {"IP": {}})
        pypacker_packet = _build_pypacker_packet(packet_definition)
        ip_layer_hex = get_packet_layer(packet=pypacker_packet, layer="IP", output_format="hex")
        assert ip_layer_hex[-8:] == '7f000001'
        @endcode
        """
        try:
            pypacker_layer = self._get_pypacker_layer(layer)
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

    def packet_dictionary(self, packet):
        """
        @brief  Get packet dictionary from pypacker.Packet
        @param  packet:  pypacker packet
        @type  packet:  pypacker.Packet
        @rtype;  dict
        @return  dictionary created from pypacker.Packet
        @par  Example:
        @code{.py}
        p = ethernet.Ethernet(dst_s="ff:ff:ff:ff:ff:ff", src_s="90:e6:ba:c3:17:13", type=0x806)/
            arp.ARP(hrd=0x1, pro=0x800, hln=6, pln=4,
                      op=1, sha="90:e6:ba:c3:17:13", spa="172.20.20.175", tha="00:00:00:00:00:00", tpa="172.20.20.211")
        pd = PacketProcessor().packet_dictionary(p)
        assert pd == ({'Ethernet': {'src': '90:e6:ba:c3:17:13', 'dst': 'ff:ff:ff:ff:ff:ff', 'type': 2054}},
                      {'ARP': {'tha': '00:00:00:00:00:00', 'pro': 2048, 'hrd': 1, 'spa': '172.20.20.175',
                               'pln': 4, 'hln': 6, 'tpa': '172.20.20.211', 'sha': '90:e6:ba:c3:17:13', 'op': 1}})
        @endcode
        """
        packet_def = []
        vlans = []
        opts = []
        for layer in packet:
            class_name = layer.__class__.__name__
            # Handle inner pypacker class e.g. icmp.ICMP.Echo, icmp6.ICMP6.Echo
            if class_name in self.inner_classes:
                # get main class ICMP + echo
                class_name = "{0}.{1}".format(next(iter(layer_dict)), class_name)
            fields = self._get_pypacker_layer_fields(layer)
            layer_dict = {class_name: {}}
            for field in fields:
                if field == "vlan" and self.get_packet_field(packet, "Ethernet", "vlan"):
                    for vlan in self.get_packet_field(packet, "Ethernet", "vlan"):
                        vlans.append({"Dot1Q": {f: getattr(vlan, f) for f in self._get_pypacker_layer_fields(vlan)}})
                elif field == "opts" and class_name in ["IP", "IP6"]:
                    pypacker_opts = self.get_packet_field(packet, class_name, "opts")[:]
                    opts_fields = {"len", "type", "body_bytes"}
                    opts.append({f: getattr(opt, f) for opt in pypacker_opts for f in opts_fields})
                    layer_dict[class_name][field] = opts
                elif field != "padding":
                    layer_dict[class_name][field] = self.get_packet_field(layer, class_name, field)
            packet_def.append(layer_dict)
            if class_name == "Ethernet" and vlans:
                packet_def.extend(vlans)
        return tuple(packet_def)

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
        pytest.skip("Packet fragmentation is not integrated yet")

    def assemble_fragmented_packets(self, packets):
        """
        @brief  Method for assembling packets from fragments in packet list
        @param  packets:  List of fragmened packets
        @type  packets:  list[pypacker.Packet]
        @rtype:  list[pypacker.Packet]
        @return:  List of assembled packets
        """
        pytest.skip("Packet fragmentation is not integrated yet")
