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

@file test_pp.py

@summary Packet Processor's unittests.
"""

import pytest

from testlib import dev_ixia
from testlib.custom_exceptions import PypackerException


IXIA_CONFIG = {"name": "IXIA", "entry_type": "tg", "instance_type": "ixiahl", "id": 1, "ip_host": "10.166.44.250",
               "ports": [[1, 6, 13]]}


@pytest.fixture(scope="session")
def traffic_generator(request):
    tg = dev_ixia.Ixia(IXIA_CONFIG, request.config.option)
    request.addfinalizer(tg.destroy)
    tg.create()

    return tg


@pytest.fixture
def tgs(request, traffic_generator):
    traffic_generator.cleanup()
    if traffic_generator.type == "ixiahl":
        iface = traffic_generator.ports[0]
        chassis, card, port = iface
        traffic_generator.tcl("ixClearPortStats %(chassis)s %(card)s %(port)s; \
                               port get %(chassis)s %(card)s %(port)s; \
                               port config -rxTxMode gigLoopback; \
                               port config -loopback portLoopback; \
                               port set %(chassis)s %(card)s %(port)s; \
                               port write %(chassis)s %(card)s %(port)s" %
                              {'chassis': chassis, 'card': card, 'port': port})
    return traffic_generator


class TestPacket(object):

    packet_definition = ({"Ethernet": {"dst": "ff:ff:ff:ff:ff:ff", "src": "00:00:00:00:00:02"}}, {"IP": {"p": 17}}, {"UDP": {}},)
    packet_defs = [({"Ethernet": {"dst": "ff:ff:ff:ff:ff:ff", "src": "00:00:00:00:00:02"}}, {"IP": {"p": 17}}, {"UDP": {}},),
                   ({"Ethernet": {"dst": "ff:ff:ff:ff:ff:ff", "src": "00:00:00:00:00:03"}}, {"IP": {"p": 1}}, {"ICMP": {}},),
                   ({"Ethernet": {"dst": "ff:ff:ff:ff:ff:ff", "src": "00:00:00:00:00:04"}}, {"IP": {}}, {"TCP": {}},)]

    pack_dot1q_ip_udp = ({"Ether": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                         {"Dot1Q": {"vlan": 5}},
                         {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1"}},
                         {"UDP": {"dport": 23, "sport": 23}},
                         )

    pack_dot1q_ip_tcp = ({"Ether": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                         {"Dot1Q": {"vlan": 5}},
                         {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1"}},
                         {"TCP": {}},
                         )

    pack_dot1q_ip_icmp = ({"Ether": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                          {"Dot1Q": {"vlan": 5}},
                          {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1"}},
                          {"ICMP": {}},
                          )

    pack_dot1q_arp = ({"Ether": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                      {"Dot1Q": {"vlan": 5}},
                      {"ARP": {"hwsrc": "00:00:20:00:10:02", "psrc": "1.1.1.1", "hwdst": "00:00:00:00:00:00", "pdst": "1.1.1.2"}},
                      )

    pack_ip_icmp = ({"Ethernet": {"src": "00:00:20:00:10:01", "dst": "00:00:00:33:33:33", "type": 0x0800}},
                    {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "p": 1}},
                    {"ICMP": {}},
                    )

    pack_ip_udp = ({"Ether": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x0800}},
                   {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1"}},
                   {"UDP": {}},
                   )

    pack_ip_tcp = ({"Ether": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x0800}},
                   {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1"}},
                   {"TCP": {}},
                   )

    pack_arp = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x0806}},
                {"ARP": {"sha": "00:00:20:00:10:02", "spa": "1.1.1.1", "tha": "00:00:00:00:00:00", "tpa": "1.1.1.2"}},
                )

    pack_dot1q = ({"Ether": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                  {"Dot1Q": {"vlan": 5}},
                  )

    pack_qinq = ({"Ether": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                 {"Dot1Q": {"vlan": 5, "type": 0x8100}},
                 {"Dot1Q": {"vlan": 15}},
                 {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1"}},
                 {"UDP": {"dport": 23, "sport": 23}},
                 )

    pack_stp = ({"Dot3": {"src": "00:00:00:11:11:11", "dst": "00:00:00:33:33:33"}},
                {"LLC": {"dsap": 66, "ssap": 66, "ctrl": 3}},
                {"STP": {"proto": 0, "version": 0}},
                )

    pack_rstp = ({"Dot3": {"src": "00:00:00:11:11:11", "dst": "00:00:00:33:33:33"}},
                 {"LLC": {"dsap": 66, "ssap": 66, "ctrl": 3}},
                 {"STP": {"proto": 0, "version": 2}},
                 )

    pack_mstp = ({"Dot3": {"dst": "01:80:c2:00:00:00", "src": "00:00:00:11:11:11"}},
                 {"LLC": {"dsap": 66, "ssap": 66, "ctrl": 3}},
                 {"STP": {"proto": 0, "version": 3, "bpdutype": 2, "bpduflags": 126, "rootid": 7 * 4096,
                          "rootmac": "00:00:00:11:11:11", "pathcost": 0, "bridgeid": 7 * 4096,
                          "bridgemac": "00:00:00:11:11:11", "portid": 128 + 1, "age": 0.0, "maxage": 20.0,
                          "hellotime": 2.0, "fwddelay": 15.0, "mcidselect": 0,
                          "mcidname": "Switch++ Configuration", "mcidrev": 17,
                          "mcidcfgd": "\xac6\x17\x7fP(<\xd4\xb88!\xd8\xab&\xdeb",
                          "cistpathcost": 0, "cistbridgeid": 7 * 4096, "cistbridgemac": "00:00:00:11:11:11",
                          "cistrhops": 20}})
    # Initial dictionary with packet field values for MSTP with MSTI BPDU
    pack_msti = ({"MstiConfigMsg": {"agree": 0, "fwd": 1, "lrn": 1, "prole": 3, "prop": 0, "tchng": 0,
                                    "rootid": 7 * 4096 + 1, "rootmac": "00:00:00:11:11:11",
                                    "pathcost": 0, "bprio": 0, "pprio": 8, "rhops": 20}}, )

    pack_lldp = ({"Ether": {"dst": "01:80:c2:00:00:0e", "src": "00:12:12:13:13:45", "type": 0x88cc}},
                 {"LLDP": {"tlvlist": [{"LLDPChassisId": {"type": 1, "length": 7, "subtype": "MAC address", "macaddr": "00:12:12:13:13:45"}},
                                       {"LLDPPortId": {"type": 2, "length": 4, "subtype": "Interface alias", "value": 'ge0'}},
                                       {"LLDPTTL": {"type": 3, "length": 2, "seconds": 65535}},
                                       {"LLDPPortDescription": {"type": 4, "length": 0, "value": ""}},
                                       {"LLDPSystemName": {"type": 5, "length": 10, "value": '<sys-name>'}},
                                       {"LLDPSystemDescription": {"type": 6, "length": 10, "value": '<sys-desc>'}},
                                       {"LLDPSystemCapabilities": {"type": 7, "length": 4, "capabilities": 4, "enabled": 4}},
                                       {'LLDPManagementAddress': {'type': 8, 'length': 12, 'addrlen': 5, 'addrsubtype': 1,
                                                                  'ipaddr': '01.01.01.01', 'ifsubtype': 2, 'ifnumber': 1001, 'oidlen': 0, 'oid': ''}},
                                       {"LLDPDUEnd": {"type": 0, "length": 0}}]}})

    pack_ipv6 = ({"Ether": {"src": '00:00:0a:00:02:08', "dst": "00:01:12:12:34:12"}}, {"IP6": {"src": '2000::1:2', "dst": '2000::2:2'}})

    pack_dot1q_ipv6 = ({"Ether": {"dst": "00:00:00:01:02:03", "src": "00:00:00:03:02:01", 'type': 0x8100}},
                       {"Dot1Q": {"vlan": 2, "prio": 1}}, {"IPv6": {"src": "2001:db8:1:2:60:8ff:fe52:f9d8"}}, {"TCP": {}})

    def _check_packets_data(self, deff1, deff2):
        """ Check 2 packet definitions """
        for layer1 in deff1:
            l_name = list(layer1.keys())[0]
            layer2 = deff2[deff1.index(layer1)]
            if l_name not in list(layer2.keys()):
                print("l_name ", l_name)
                return False
            for field1 in list(layer1[l_name].keys()):
                print("field1 ", field1)
                print("layer2", layer2[l_name])
                if field1 not in list(layer2[l_name].keys()):
                    return False
                if isinstance(layer1[l_name][field1], list):
                    res = self._check_packets_data(layer1[l_name][field1], layer1[l_name][field1])
                    if res is False:
                        return False
                elif layer1[l_name][field1] != layer1[l_name][field1]:
                    return False
        return True

    def test_check_packet_field_1(self, tgs):
        packet = tgs._build_pypacker_packet(self.pack_ip_icmp)
        for layer_dict in self.pack_ip_icmp:
            layer_name = list(layer_dict.keys())[0]
            for field, value in layer_dict[layer_name].items():
                assert tgs.check_packet_field(packet=packet, layer=layer_name)
                assert tgs.check_packet_field(packet=packet, layer=layer_name, field=field)
                assert tgs.check_packet_field(packet=packet, layer=layer_name, field=field, value=value)

    def test_packet_with_empty_layer(self, tgs):
        """
        @brief  Test building packet with empty layer
        """
        empty_layer = ({"Ethernet": {"dst": "11:11:11:11:11:11", "src": "22:22:22:22:22:22"}},
                       {"IP": {}})

        packet = tgs._build_pypacker_packet(empty_layer)

        assert tgs.get_packet_layer(packet, "IP") is not None

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_pproc_packet_field_setting(self, tgs):
        """ Check packet field setting """
        fragments = tgs.packet_fragment(self.pack_ip_icmp, required_size=200)
        assert len(fragments) == 1
        src = '12:34:56:78:98:76'
        fragments[0].set_field('Ether', 'src', src)
        assert src == tgs.get_packet_field(fragments[0], 'Ether', 'src')
        load = 'abcdefg'
        fragments[0].set_field('Raw', 'load', load)
        assert load == tgs.get_packet_field(fragments[0], 'Raw', 'load')

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_assembling_dot1q_icmp_packet_1(self, tgs):
        """ Check assembling of Dot1Q.ICMP fragmented packet """
        iface = tgs.ports[0]

        stream_id_1 = tgs.set_stream(self.pack_dot1q_ip_icmp, count=1,
                                     required_size=1000, fragsize=200, iface=iface)

        tgs.start_sniff([iface, ], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tgs.send_stream(stream_id_1)
        data = tgs.stop_sniff([iface, ])

        # helpers.print_sniffed_data_brief(data)

        data_1 = tgs.assemble_fragmented_packets(data[iface])

        # helpers.print_sniffed_data_brief({"lo": data_1})

        # Verify that fragmented packet is assembled
        assert len(data_1) == 1

        # Send assembled packet
        pac = data_1[0]

        tgs.streams[stream_id_1]['packet'] = pac

        tgs.start_sniff([iface, ], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tgs.send_stream(stream_id_1)
        data = tgs.stop_sniff([iface, ])

        # Verify that assembled packet has len = 996
        assert len(data[iface][0]) == 996

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_assembling_dot1q_icmp_packet_2(self, tgs):
        """ Check assembling of Dot1Q.ICMP fragmented packet. Overlapped fragments"""
        iface = tgs.ports[0]

        stream_id_1 = tgs.set_stream(self.pack_dot1q_ip_icmp, count=1,
                                     required_size=1000, fragsize=200, iface=iface)

        tgs.streams[stream_id_1]['packet'][2][pypacker.layer3.ip.IP].frag = \
            tgs.streams[stream_id_1]['packet'][2][pypacker.layer3.ip.IP].frag - 1

        tgs.start_sniff([iface, ], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tgs.send_stream(stream_id_1)
        data = tgs.stop_sniff([iface, ])

        # helpers.print_sniffed_data_brief(data)

        data_1 = tgs.assemble_fragmented_packets(data[iface])

        # helpers.print_sniffed_data_brief({"lo": data_1})

        # Verify that fragmented packet is assembled
        assert len(data_1) == 5

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_assembling_dot1q_icmp_packet_3(self, tgs):
        """Check assembling of Dot1Q.ICMP fragmented packet. Missed fragment 1"""
        iface = tgs.ports[0]

        stream_id_1 = tgs.set_stream(self.pack_dot1q_ip_icmp, count=1,
                                     required_size=1000, fragsize=200, iface=iface)

        tgs.streams[stream_id_1]['packet'].pop(0)

        tgs.start_sniff([iface, ], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tgs.send_stream(stream_id_1)
        data = tgs.stop_sniff([iface, ])

        # helpers.print_sniffed_data_brief(data)

        data_1 = tgs.assemble_fragmented_packets(data[iface])

        # helpers.print_sniffed_data_brief({"lo": data_1})

        # Verify that fragmented packet is assembled
        assert len(data_1) == 4

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_assembling_dot1q_icmp_packet_4(self, tgs):
        """Check assembling of Dot1Q.ICMP fragmented packet. Wrong frag in Fragment 1"""
        iface = tgs.ports[0]

        stream_id_1 = tgs.set_stream(self.pack_dot1q_ip_icmp, count=1,
                                     required_size=1000, fragsize=200, iface=iface)

        tgs.streams[stream_id_1]['packet'][0][pypacker.layer3.ip.IP].frag = 1

        tgs.start_sniff([iface, ], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tgs.send_stream(stream_id_1)
        data = tgs.stop_sniff([iface, ])

        # helpers.print_sniffed_data_brief(data)

        data_1 = tgs.assemble_fragmented_packets(data[iface])

        # helpers.print_sniffed_data_brief({"lo": data_1})

        # Verify that fragmented packet is assembled
        assert len(data_1) == 5

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_assembling_dot1q_icmp_packet_5(self, tgs):
        """Check assembling of Dot1Q.ICMP fragmented packet. Wrong flags in Fragment 1"""
        iface = tgs.ports[0]

        stream_id_1 = tgs.set_stream(self.pack_dot1q_ip_icmp, count=1,
                                     required_size=1000, fragsize=200, iface=iface)

        tgs.streams[stream_id_1]['packet'][0][pypacker.layer3.ip.IP].flags = 0

        tgs.start_sniff([iface, ], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tgs.send_stream(stream_id_1)
        data = tgs.stop_sniff([iface, ])

        # helpers.print_sniffed_data_brief(data)

        data_1 = tgs.assemble_fragmented_packets(data[iface])

        # helpers.print_sniffed_data_brief({"lo": data_1})

        # Verify that fragmented packet is assembled
        assert len(data_1) == 5

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_assembling_dot1q_icmp_packet_6(self, tgs):
        """Check assembling of Dot1Q.ICMP fragmented packet. Missed last fragment"""
        iface = tgs.ports[0]

        stream_id_1 = tgs.set_stream(self.pack_dot1q_ip_icmp, count=1,
                                     required_size=1000, fragsize=200, iface=iface)

        tgs.streams[stream_id_1]['packet'].pop(4)

        tgs.start_sniff([iface, ], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tgs.send_stream(stream_id_1)
        data = tgs.stop_sniff([iface, ])

        # helpers.print_sniffed_data_brief(data)

        data_1 = tgs.assemble_fragmented_packets(data[iface])

        # helpers.print_sniffed_data_brief({"lo": data_1})

        # Verify that fragmented packet is assembled
        assert len(data_1) == 4

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_assembling_dot1q_icmp_packet_7(self, tgs):
        """Check assembling of Dot1Q.ICMP fragmented packet. Wrong frag in last fragment"""
        iface = tgs.ports[0]

        stream_id_1 = tgs.set_stream(self.pack_dot1q_ip_icmp, count=1,
                                     required_size=1000, fragsize=200, iface=iface)

        tgs.streams[stream_id_1]['packet'][4][pypacker.layer3.ip.IP].frag = 0

        tgs.start_sniff([iface, ], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tgs.send_stream(stream_id_1)
        data = tgs.stop_sniff([iface, ])

        # helpers.print_sniffed_data_brief(data)

        data_1 = tgs.assemble_fragmented_packets(data[iface])

        # helpers.print_sniffed_data_brief({"lo": data_1})

        # Verify that fragmented packet is assembled
        assert len(data_1) == 5

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_assembling_dot1q_icmp_packet_8(self, tgs):
        """Check assembling of Dot1Q.ICMP fragmented packet. Wrong flags in last fragment"""
        iface = tgs.ports[0]

        stream_id_1 = tgs.set_stream(self.pack_dot1q_ip_icmp, count=1,
                                     required_size=1000, fragsize=200, iface=iface)

        tgs.streams[stream_id_1]['packet'][4][pypacker.layer3.ip.IP].flags = 1

        tgs.start_sniff([iface, ], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tgs.send_stream(stream_id_1)
        data = tgs.stop_sniff([iface, ])

        # helpers.print_sniffed_data_brief(data)

        data_1 = tgs.assemble_fragmented_packets(data[iface])

        # helpers.print_sniffed_data_brief({"lo": data_1})

        # Verify that fragmented packet is assembled
        assert len(data_1) == 5

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_assembling_dot1q_icmp_packet_9(self, tgs):
        """Check assembling of Dot1Q.ICMP fragmented packet. Missed fragment after 2"""
        iface = tgs.ports[0]

        stream_id_1 = tgs.set_stream(self.pack_dot1q_ip_icmp, count=1,
                                     required_size=1000, fragsize=200, iface=iface)

        tgs.streams[stream_id_1]['packet'].pop(2)

        tgs.start_sniff([iface, ], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tgs.send_stream(stream_id_1)
        data = tgs.stop_sniff([iface, ])

        # helpers.print_sniffed_data_brief(data)

        data_1 = tgs.assemble_fragmented_packets(data[iface])

        # helpers.print_sniffed_data_brief({"lo": data_1})

        # Verify that fragmented packet is assembled
        assert len(data_1) == 4

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_assembling_dot1q_icmp_packet_10(self, tgs):
        """Check assembling of Dot1Q.ICMP fragmented packet. Duplicate fragment 2"""
        iface = tgs.ports[0]

        stream_id_1 = tgs.set_stream(self.pack_dot1q_ip_icmp, count=1,
                                     required_size=1000, fragsize=200, iface=iface)

        pack_2 = tgs.streams[stream_id_1]['packet'][2]
        pack_2.time = pack_2.time + 1
        tgs.streams[stream_id_1]['packet'].append(pack_2)

        tgs.start_sniff([iface, ], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tgs.send_stream(stream_id_1)
        data = tgs.stop_sniff([iface, ])

        # helpers.print_sniffed_data_brief(data)

        data_1 = tgs.assemble_fragmented_packets(data[iface])

        # helpers.print_sniffed_data_brief({"lo": data_1})

        # Verify that fragmented packet is assembled
        assert len(data_1) == 1

        # Send assembled packet
        pac = data_1[0]

        tgs.streams[stream_id_1]['packet'] = pac

        tgs.start_sniff([iface, ], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tgs.send_stream(stream_id_1)
        data = tgs.stop_sniff([iface, ])

        # Verify that assembled packet has len = 996
        assert len(data[iface][0]) == 996

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_assembling_dot1q_icmp_packet_11(self, tgs):
        """Check assembling of Dot1Q.ICMP fragmented packet. Two packets"""
        iface = tgs.ports[0]

        stream_id_1 = tgs.set_stream(self.pack_dot1q_ip_icmp, count=1,
                                     required_size=1000, fragsize=200, iface=iface)
        stream_id_2 = tgs.set_stream(self.pack_dot1q_ip_icmp, count=1,
                                     required_size=1200, fragsize=100, iface=iface)

        for pac in tgs.streams[stream_id_2]['packet']:
            pac[pypacker.layer3.ip.IP].id = 2

        tgs.start_sniff([iface, ], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tgs.send_stream(stream_id_1)
        tgs.send_stream(stream_id_2)
        data = tgs.stop_sniff([iface, ])

        # helpers.print_sniffed_data_brief(data)

        data_1 = tgs.assemble_fragmented_packets(data[iface])

        # helpers.print_sniffed_data_brief({"lo": data_1})

        # Verify that fragmented packet is assembled
        assert len(data_1) == 2

        # Send assembled packet
        pac_1 = data_1[0]
        pac_2 = data_1[1]

        tgs.streams[stream_id_1]['packet'] = pac_1
        tgs.streams[stream_id_2]['packet'] = pac_2

        tgs.start_sniff([iface, ], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tgs.send_stream(stream_id_1)
        tgs.send_stream(stream_id_2)
        data = tgs.stop_sniff([iface, ])

        assert len(data[iface][0]) == 996
        assert len(data[iface][1]) == 1196

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_assembling_dot1q_icmp_packet_12(self, tgs):
        """Check assembling of Dot1Q.ICMP fragmented packet. Four packets (fragmented and not)"""
        iface = tgs.ports[0]

        stream_id_1 = tgs.set_stream(self.pack_dot1q_ip_icmp, count=1,
                                     required_size=1000, fragsize=200, iface=iface)
        stream_id_2 = tgs.set_stream(self.pack_dot1q_ip_icmp, count=1,
                                     required_size=1200, fragsize=100, iface=iface)
        stream_id_3 = tgs.set_stream(self.pack_dot1q_ip_icmp, count=1,
                                     required_size=500, iface=iface)
        stream_id_4 = tgs.set_stream(self.pack_dot1q_ip_icmp, count=1,
                                     required_size=800, iface=iface)

        for pac in tgs.streams[stream_id_2]['packet']:
            pac[pypacker.layer3.ip.IP].id = 2

        tgs.streams[stream_id_3]['packet'][pypacker.layer3.ip.IP].id = 3
        tgs.streams[stream_id_4]['packet'][pypacker.layer3.ip.IP].id = 4

        tgs.start_sniff([iface, ], sniffing_time=8, filter_layer='Dot1Q.ICMP')
        tgs.send_stream(stream_id_1)
        tgs.send_stream(stream_id_2)
        tgs.send_stream(stream_id_3)
        tgs.send_stream(stream_id_4)
        data = tgs.stop_sniff([iface, ])

        # helpers.print_sniffed_data_brief(data)

        data_1 = tgs.assemble_fragmented_packets(data[iface])

        # helpers.print_sniffed_data_brief({"lo": data_1})

        # Verify that fragmented packet is assembled
        assert len(data_1) == 4

        # Send assembled packet
        pac_1 = data_1[0]
        pac_2 = data_1[1]
        pac_3 = data_1[2]
        pac_4 = data_1[3]

        tgs.streams[stream_id_1]['packet'] = pac_1
        tgs.streams[stream_id_2]['packet'] = pac_2
        tgs.streams[stream_id_3]['packet'] = pac_3
        tgs.streams[stream_id_4]['packet'] = pac_4

        tgs.start_sniff([iface, ], sniffing_time=8, filter_layer='Dot1Q.ICMP')
        tgs.send_stream(stream_id_1)
        tgs.send_stream(stream_id_2)
        tgs.send_stream(stream_id_3)
        tgs.send_stream(stream_id_4)
        data = tgs.stop_sniff([iface, ])

        assert len(data[iface][0]) == 996
        assert len(data[iface][1]) == 1196
        assert len(data[iface][2]) == 496
        assert len(data[iface][3]) == 796

    def test_get_packet_field_negative_1(self, tgs):
        """ Verify that method get_packet_field returns Error message when layer is not defined in packet(1). """

        packet = ({"IP": {"src": "20.0.10.2", "dst": "10.10.10.1"}}, {"TCP": {}})
        packet_pypacker = tgs._build_pypacker_packet(packet)
        with pytest.raises(PypackerException) as excepinfo:
            tgs.get_packet_field(packet=packet_pypacker, layer="Ethernet")
        exception_message = excepinfo.value.parameter
        # verify expected result
        result = "Layer Ethernet is not defined."
        assert exception_message == result

    def test_get_packet_field_negative_2(self, tgs):
        """ Verify that method get_packet_field returns Error message when layer is not defined in packet(2). """

        packet = ({"IP": {"src": "20.0.10.2", "dst": "10.10.10.1"}}, {"TCP": {}})
        packet_pypacker = tgs._build_pypacker_packet(packet)
        with pytest.raises(PypackerException) as excepinfo:
            tgs.get_packet_field(packet=packet_pypacker, layer="Ip")
        exception_message = excepinfo.value.parameter
        # verify expected result
        result = "Layer Ip is not defined."
        assert exception_message == result

    def test_get_packet_field_negative_3(self, tgs):
        """ Verify that method get_packet_field returns Error message when field is not defined in packet(1). """

        packet = ({"IP": {"src": "20.0.10.2", "dst": "10.10.10.1"}}, {"TCP": {}})
        packet_pypacker = tgs._build_pypacker_packet(packet)
        with pytest.raises(PypackerException) as excepinfo:
            tgs.get_packet_field(packet=packet_pypacker, layer="IP", field="Src")
        exception_message = excepinfo.value.parameter
        # verify expected result
        result = "Field Src is not defined in IP."
        assert exception_message == result

    def test_get_packet_field_4(self, tgs):
        """ Verify that method get_packet_field returns correct value(4). """

        packet = ({"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "off": 1}}, {"TCP": {"flags": 0}})
        packet_pypacker = tgs._build_pypacker_packet(packet)
        flag = tgs.get_packet_field(packet=packet_pypacker, layer="IP", field="off")
        # verify expected result
        assert flag == 1

    def test_get_packet_field_1(self, tgs):
        """ Verify that method get_packet_field returns correct value(1). """

        packet = ({"IP": {"src": "20.0.10.2", "dst": "10.10.10.1"}}, {"TCP": {}})
        packet_pypacker = tgs._build_pypacker_packet(packet)
        ttl = tgs.get_packet_field(packet=packet_pypacker, layer="IP", field="ttl")
        # verify expected result
        assert ttl == 64

    def test_get_packet_field_2(self, tgs):
        """ Verify that method get_packet_field returns correct value(2). """

        packet = ({"IP": {"src": "20.0.10.2", "dst": "10.10.10.1"}}, {"TCP": {}})
        packet_pypacker = tgs._build_pypacker_packet(packet)
        proto = tgs.get_packet_field(packet=packet_pypacker, layer="IP", field="p")
        # verify expected result
        assert proto == 6

    def test_get_packet_field_3(self, tgs):
        """ Verify that method get_packet_field returns correct value(3). """

        packet = ({"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "off": 0}}, {"TCP": {"flags": 1}})
        packet_pypacker = tgs._build_pypacker_packet(packet)
        flag = tgs.get_packet_field(packet=packet_pypacker, layer="IP", field="off")
        # verify expected result
        assert flag == 0

    @pytest.mark.skip("Pypacker does not support")
    def test_set_field(self, tgs):
        """ Verify that method set_field sets correct field value. """

        packet = ({"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "flags": 0}}, {"TCP": {"flags": 1}})
        packet_pypacker = tgs._build_pypacker_packet(packet)
        packet_pypacker.set_field('IP', 'src', '10.10.10.10')
        assert tgs.get_packet_field(packet=packet_pypacker, layer="IP", field="src") == '10.10.10.10'
        # negative scenarious: not existing layer
        with pytest.raises(AttributeError):
            packet_pypacker.set_field('Ether', 'src', '11:11:11:11:11:11')
        assert tgs.get_packet_layer(packet, "Ether") is None
        # negative scenarious: wrong field value
        with pytest.raises(Exception):
            packet_pypacker.set_field('IP', 'src', '11:11:11:11:11:11')
        assert tgs.get_packet_field(packet=packet_pypacker, layer="IP", field="src") == '10.10.10.10'
        # negative scenarious: wrong field name
        packet_pypacker.set_field('IP', 'hwsrc', '11:11:11:11:11:11')
        with pytest.raises(PypackerException):
            tgs.get_packet_field(packet=packet_pypacker, layer="IP", field="hwsrc")

    @pytest.mark.skip("Pypacker does not support")
    def test_get_lcount(self, tgs):
        """ Verify that method get_lcount returns correct count of layers. """

        packet = ({"Dot1Q": {"vlan": 1}}, {"Dot1Q": {"vlan": 2}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "flags": 0}}, {"TCP": {"flags": 1}})
        packet_pypacker = tgs._build_pypacker_packet(packet)
        assert packet_pypacker.get_lcount('Dot1Q') == 2
        assert packet_pypacker.get_lcount('IP') == 1
        assert packet_pypacker.get_lcount('Ether') == 0
        # negative scenarious: not existing layer
        assert packet_pypacker.get_lcount('dot') == 0

    @pytest.mark.skip("Pypacker does not support")
    def test_get_lfield(self, tgs):
        """ Verify that method get_lfield returns correct value. """

        packet = ({"Dot1Q": {"vlan": 1}}, {"Dot1Q": {"vlan": 2}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "flags": 0}}, {"TCP": {"flags": 1}})
        packet_pypacker = tgs._build_pypacker_packet(packet)
        assert packet_pypacker.get_lfield('Dot1Q', 'vlan') == 1
        assert packet_pypacker.get_lfield('Dot1Q', 'vlan', l_id=2) == 2
        assert packet_pypacker.get_lfield('IP', 'src') == '20.0.10.2'
        assert packet_pypacker.get_lfield('Ether', 'src') is None
        # negative scenarious: not existing layer
        assert packet_pypacker.get_lfield('dot', 'src') is None
        # negative scenarious: not existing field
        assert packet_pypacker.get_lfield('IP', 'vlan') is None

    @pytest.mark.skip("Pypacker does not support")
    def test_rechecksum(self, tgs):
        """ Verify that method rechecksum returns correct value. """

        packet = ({"Dot1Q": {"vlan": 1}}, {"Dot1Q": {"vlan": 2}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "flags": 0}}, {"TCP": {"flags": 1}})
        packet_pypacker = tgs._build_pypacker_packet(packet)
        ip_chksum = packet_pypacker.get_lfield('IP', 'chksum')
        tcp_chksum = packet_pypacker.get_lfield('TCP', 'chksum')
        assert packet_pypacker.rechecksum('IP') == ip_chksum
        assert packet_pypacker.rechecksum('TCP') == tcp_chksum
        # negative scenarious: not existing layer
        assert packet_pypacker.rechecksum('dot') is None
