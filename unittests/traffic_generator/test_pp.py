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

"""``test_pp.py``

`Packet Processor's unittests`

"""

import pytest

from testlib.custom_exceptions import PypackerException
from .packet_constants import (ETH_IP_ICMP, DOT1Q_IP_ICMP,
                               IP_TCP, PACKET_DEFS, IP_FLAGS,
                               IP4_VERSION_FIELD, IP_TTL, IP_PROTO_TCP)


class TestPacketProcessor(object):

    def test_check_packet_field_1(self, tg):
        packet = tg._build_pypacker_packet(ETH_IP_ICMP)
        verification_params = ((layer, field, value) for p in ETH_IP_ICMP for layer in p for (field, value) in p[layer].items())
        for layer, field, value in verification_params:
            assert tg.check_packet_field(packet=packet, layer=layer, field=field, value=value)

    def test_packet_with_empty_layer(self, tg):
        """Test building packet with empty layer.

        """
        packet = tg._build_pypacker_packet(PACKET_DEFS[2])

        assert tg.get_packet_layer(packet, "IP") is not None

    def test_pproc_packet_field_setting(self, tg):
        """Check packet field setting.

        """
        fragments = tg.packet_fragment(ETH_IP_ICMP, required_size=200)
        assert len(fragments) == 1
        src = '12:34:56:78:98:76'
        fragments[0].set_field('Ether', 'src', src)
        assert src == tg.get_packet_field(fragments[0], 'Ether', 'src')
        load = 'abcdefg'
        fragments[0].set_field('Raw', 'load', load)
        assert load == tg.get_packet_field(fragments[0], 'Raw', 'load')

    def test_assembling_dot1q_icmp_packet_1(self, tg):
        """Check assembling of Dot1Q.ICMP fragmented packet.

        """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(DOT1Q_IP_ICMP, count=1,
                                    required_size=1000, fragsize=200, iface=iface)

        tg.start_sniff([iface], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tg.send_stream(stream_id_1)
        data = tg.stop_sniff([iface])
        data_1 = tg.assemble_fragmented_packets(data[iface])
        # Verify that fragmented packet is assembled
        assert len(data_1) == 1

        # Send assembled packet
        pac = data_1[0]

        tg.streams[stream_id_1]['packet'] = pac

        tg.start_sniff([iface], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tg.send_stream(stream_id_1)
        data = tg.stop_sniff([iface])

        # Verify that assembled packet has len = 996
        assert len(data[iface][0]) == 996

    def test_assembling_dot1q_icmp_packet_2(self, tg):
        """ Check assembling of Dot1Q.ICMP fragmented packet. Overlapped fragments.

        """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(DOT1Q_IP_ICMP, count=1,
                                    required_size=1000, fragsize=200, iface=iface)

        offset = tg.get_packet_field(tg.streams[stream_id_1]['packet'][2], "IP", "offset")
        tg.streams[stream_id_1]['packet'][2].ip.offset = offset - 1

        tg.start_sniff([iface], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tg.send_stream(stream_id_1)
        data = tg.stop_sniff([iface])
        data_1 = tg.assemble_fragmented_packets(data[iface])

        # Verify that fragmented packet is assembled
        assert len(data_1) == 5

    def test_assembling_dot1q_icmp_packet_3(self, tg):
        """Check assembling of Dot1Q.ICMP fragmented packet. Missed fragment 1.

        """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(DOT1Q_IP_ICMP, count=1,
                                    required_size=1000, fragsize=200, iface=iface)

        tg.streams[stream_id_1]['packet'].pop(0)

        tg.start_sniff([iface], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tg.send_stream(stream_id_1)
        data = tg.stop_sniff([iface])
        data_1 = tg.assemble_fragmented_packets(data[iface])

        # Verify that fragmented packet is assembled
        assert len(data_1) == 4

    def test_assembling_dot1q_icmp_packet_4(self, tg):
        """Check assembling of Dot1Q.ICMP fragmented packet. Wrong frag in Fragment 1.

        """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(DOT1Q_IP_ICMP, count=1,
                                    required_size=1000, fragsize=200, iface=iface)

        tg.streams[stream_id_1]['packet'][0].ip.offset = 1

        tg.start_sniff([iface], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tg.send_stream(stream_id_1)
        data = tg.stop_sniff([iface])
        data_1 = tg.assemble_fragmented_packets(data[iface])

        # Verify that fragmented packet is assembled
        assert len(data_1) == 5

    def test_assembling_dot1q_icmp_packet_5(self, tg):
        """Check assembling of Dot1Q.ICMP fragmented packet. Wrong flags in Fragment 1.

        """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(DOT1Q_IP_ICMP, count=1,
                                    required_size=1000, fragsize=200, iface=iface)

        tg.streams[stream_id_1]['packet'][0].ip.offset = 0

        tg.start_sniff([iface], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tg.send_stream(stream_id_1)
        data = tg.stop_sniff([iface])
        data_1 = tg.assemble_fragmented_packets(data[iface])

        # Verify that fragmented packet is assembled
        assert len(data_1) == 5

    def test_assembling_dot1q_icmp_packet_6(self, tg):
        """Check assembling of Dot1Q.ICMP fragmented packet. Missed last fragment.

        """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(DOT1Q_IP_ICMP, count=1,
                                    required_size=1000, fragsize=200, iface=iface)

        tg.streams[stream_id_1]['packet'].pop(4)

        tg.stop_sniff([iface], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tg.send_stream(stream_id_1)
        data = tg.stop_sniff([iface])
        data_1 = tg.assemble_fragmented_packets(data[iface])

        # Verify that fragmented packet is assembled
        assert len(data_1) == 4

    def test_assembling_dot1q_icmp_packet_7(self, tg):
        """Check assembling of Dot1Q.ICMP fragmented packet. Wrong frag in last fragment.

        """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(DOT1Q_IP_ICMP, count=1,
                                    required_size=1000, fragsize=200, iface=iface)

        tg.streams[stream_id_1]['packet'][4].ip.offset = 0

        tg.stop_sniff([iface], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tg.send_stream(stream_id_1)
        data = tg.stop_sniff([iface])
        data_1 = tg.assemble_fragmented_packets(data[iface])

        # Verify that fragmented packet is assembled
        assert len(data_1) == 5

    def test_assembling_dot1q_icmp_packet_8(self, tg):
        """Check assembling of Dot1Q.ICMP fragmented packet. Wrong flags in last fragment.

        """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(DOT1Q_IP_ICMP, count=1,
                                    required_size=1000, fragsize=200, iface=iface)

        tg.streams[stream_id_1]['packet'][4].ip.offset = 1

        tg.stop_sniff([iface], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tg.send_stream(stream_id_1)
        data = tg.stop_sniff([iface])
        data_1 = tg.assemble_fragmented_packets(data[iface])

        # Verify that fragmented packet is assembled
        assert len(data_1) == 5

    def test_assembling_dot1q_icmp_packet_9(self, tg):
        """Check assembling of Dot1Q.ICMP fragmented packet. Missed fragment after 2.

        """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(DOT1Q_IP_ICMP, count=1,
                                    required_size=1000, fragsize=200, iface=iface)

        tg.streams[stream_id_1]['packet'].pop(2)

        tg.stop_sniff([iface], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tg.send_stream(stream_id_1)
        data = tg.stop_sniff([iface])
        data_1 = tg.assemble_fragmented_packets(data[iface])

        # Verify that fragmented packet is assembled
        assert len(data_1) == 4

    def test_assembling_dot1q_icmp_packet_10(self, tg):
        """Check assembling of Dot1Q.ICMP fragmented packet. Duplicate fragment 2.

        """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(DOT1Q_IP_ICMP, count=1,
                                    required_size=1000, fragsize=200, iface=iface)

        pack_2 = tg.streams[stream_id_1]['packet'][2]
        pack_2.time += 1
        tg.streams[stream_id_1]['packet'].append(pack_2)

        tg.stop_sniff([iface], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tg.send_stream(stream_id_1)
        data = tg.stop_sniff([iface])
        data_1 = tg.assemble_fragmented_packets(data[iface])

        # Verify that fragmented packet is assembled
        assert len(data_1) == 1

        # Send assembled packet
        pac = data_1[0]

        tg.streams[stream_id_1]['packet'] = pac

        tg.stop_sniff([iface], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tg.send_stream(stream_id_1)
        data = tg.stop_sniff([iface])

        # Verify that assembled packet has len = 996
        assert len(data[iface][0]) == 996

    def test_assembling_dot1q_icmp_packet_11(self, tg):
        """Check assembling of Dot1Q.ICMP fragmented packet. Two packets.

        """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(DOT1Q_IP_ICMP, count=1,
                                    required_size=1000, fragsize=200, iface=iface)
        stream_id_2 = tg.set_stream(DOT1Q_IP_ICMP, count=1,
                                    required_size=1200, fragsize=100, iface=iface)

        for pac in tg.streams[stream_id_2]['packet']:
            pac.ip.id = 2

        tg.stop_sniff([iface], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tg.send_stream(stream_id_1)
        tg.send_stream(stream_id_2)
        data = tg.stop_sniff([iface])
        data_1 = tg.assemble_fragmented_packets(data[iface])

        # Verify that fragmented packet is assembled
        assert len(data_1) == 2

        # Send assembled packet
        pac_1 = data_1[0]
        pac_2 = data_1[1]

        tg.streams[stream_id_1]['packet'] = pac_1
        tg.streams[stream_id_2]['packet'] = pac_2

        tg.stop_sniff([iface], sniffing_time=5, filter_layer='Dot1Q.ICMP')
        tg.send_stream(stream_id_1)
        tg.send_stream(stream_id_2)
        data = tg.stop_sniff([iface])

        assert len(data[iface][0]) == 996
        assert len(data[iface][1]) == 1196

    def test_assembling_dot1q_icmp_packet_12(self, tg):
        """Check assembling of Dot1Q.ICMP fragmented packet. Four packets (fragmented and not).

        """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(DOT1Q_IP_ICMP, count=1,
                                    required_size=1000, fragsize=200, iface=iface)
        stream_id_2 = tg.set_stream(DOT1Q_IP_ICMP, count=1,
                                    required_size=1200, fragsize=100, iface=iface)
        stream_id_3 = tg.set_stream(DOT1Q_IP_ICMP, count=1,
                                    required_size=500, iface=iface)
        stream_id_4 = tg.set_stream(DOT1Q_IP_ICMP, count=1,
                                    required_size=800, iface=iface)

        for pac in tg.streams[stream_id_2]['packet']:
            pac.ip.id = 2

        tg.streams[stream_id_3]['packet'].ip.id = 3
        tg.streams[stream_id_4]['packet'].ip.id = 4

        tg.stop_sniff([iface], sniffing_time=8, filter_layer='Dot1Q.ICMP')
        tg.send_stream(stream_id_1)
        tg.send_stream(stream_id_2)
        tg.send_stream(stream_id_3)
        tg.send_stream(stream_id_4)
        data = tg.stop_sniff([iface])
        data_1 = tg.assemble_fragmented_packets(data[iface])

        # Verify that fragmented packet is assembled
        assert len(data_1) == 4

        # Send assembled packet
        pac_1 = data_1[0]
        pac_2 = data_1[1]
        pac_3 = data_1[2]
        pac_4 = data_1[3]

        tg.streams[stream_id_1]['packet'] = pac_1
        tg.streams[stream_id_2]['packet'] = pac_2
        tg.streams[stream_id_3]['packet'] = pac_3
        tg.streams[stream_id_4]['packet'] = pac_4

        tg.stop_sniff([iface], sniffing_time=8, filter_layer='Dot1Q.ICMP')
        tg.send_stream(stream_id_1)
        tg.send_stream(stream_id_2)
        tg.send_stream(stream_id_3)
        tg.send_stream(stream_id_4)
        data = tg.stop_sniff([iface])

        assert len(data[iface][0]) == 996
        assert len(data[iface][1]) == 1196
        assert len(data[iface][2]) == 496
        assert len(data[iface][3]) == 796

    def test_get_packet_field_negative_1(self, tg):
        """Verify that method get_packet_field returns Error message when layer is not defined in packet(1).

        """
        packet_pypacker = tg._build_pypacker_packet(IP_TCP)
        with pytest.raises(PypackerException) as excepinfo:
            tg.get_packet_field(packet=packet_pypacker, layer="Ethernet")
        exception_message = excepinfo.value.parameter
        # verify expected result
        result = "Layer Ethernet is not defined"
        assert exception_message == result

    def test_get_packet_field_negative_2(self, tg):
        """Verify that method get_packet_field returns Error message when layer is not defined in packet(2).

        """
        packet_pypacker = tg._build_pypacker_packet(IP_TCP)
        with pytest.raises(PypackerException) as excepinfo:
            tg.get_packet_field(packet=packet_pypacker, layer="Ip")
        exception_message = excepinfo.value.parameter
        # verify expected result
        result = "Layer Ip is not defined"
        assert exception_message == result

    def test_get_packet_field_negative_3(self, tg):
        """Verify that method get_packet_field returns Error message when field is not defined in packet(1).

        """
        packet_pypacker = tg._build_pypacker_packet(IP_TCP)
        with pytest.raises(PypackerException) as excepinfo:
            tg.get_packet_field(packet=packet_pypacker, layer="IP", field="Src")
        exception_message = excepinfo.value.parameter
        # verify expected result
        result = "Field Src is not defined in IP"
        assert exception_message == result

    def test_get_packet_field_4(self, tg):
        """Verify that method get_packet_field returns correct value(4).

        """
        packet_pypacker = tg._build_pypacker_packet(IP_TCP)
        flag = tg.get_packet_field(packet=packet_pypacker, layer="IP", field="flags")
        # verify expected result
        assert flag == IP_FLAGS

    def test_get_packet_field_1(self, tg):
        """Verify that method get_packet_field returns correct value(1).

        """
        packet_pypacker = tg._build_pypacker_packet(IP_TCP)
        ttl = tg.get_packet_field(packet=packet_pypacker, layer="IP", field="ttl")
        # verify expected result
        assert ttl == IP_TTL

    def test_get_packet_field_2(self, tg):
        """Verify that method get_packet_field returns correct value(2).

        """
        packet_pypacker = tg._build_pypacker_packet(IP_TCP)
        proto = tg.get_packet_field(packet=packet_pypacker, layer="IP", field="p")
        # verify expected result
        assert proto == IP_PROTO_TCP

    def test_get_packet_field_3(self, tg):
        """Verify that method get_packet_field returns correct value(3).

        """
        packet_pypacker = tg._build_pypacker_packet(IP_TCP)
        version = tg.get_packet_field(packet=packet_pypacker, layer="IP", field="v")
        # verify expected result
        assert version == IP4_VERSION_FIELD

    @pytest.mark.skip("Pypacker does not support")
    def test_set_field(self, tg):
        """Verify that method set_field sets correct field value.

        """
        packet = ({"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "flags": 0}}, {"TCP": {"flags": 1}})
        packet_pypacker = tg._build_pypacker_packet(packet)
        packet_pypacker.set_field('IP', 'src', '10.10.10.10')
        assert tg.get_packet_field(packet=packet_pypacker, layer="IP", field="src") == '10.10.10.10'
        # negative scenarious: not existing layer
        with pytest.raises(AttributeError):
            packet_pypacker.set_field('Ether', 'src', '11:11:11:11:11:11')
        assert tg.get_packet_layer(packet, "Ether") is None
        # negative scenarious: wrong field value
        with pytest.raises(Exception):
            packet_pypacker.set_field('IP', 'src', '11:11:11:11:11:11')
        assert tg.get_packet_field(packet=packet_pypacker, layer="IP", field="src") == '10.10.10.10'
        # negative scenarious: wrong field name
        packet_pypacker.set_field('IP', 'hwsrc', '11:11:11:11:11:11')
        with pytest.raises(PypackerException):
            tg.get_packet_field(packet=packet_pypacker, layer="IP", field="hwsrc")

    @pytest.mark.skip("Pypacker does not support")
    def test_get_lcount(self, tg):
        """Verify that method get_lcount returns correct count of layers.

        """
        packet = ({"Dot1Q": {"vlan": 1}}, {"Dot1Q": {"vlan": 2}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "flags": 0}}, {"TCP": {"flags": 1}})
        packet_pypacker = tg._build_pypacker_packet(packet)
        assert packet_pypacker.get_lcount('Dot1Q') == 2
        assert packet_pypacker.get_lcount('IP') == 1
        assert packet_pypacker.get_lcount('Ether') == 0
        # negative scenarious: not existing layer
        assert packet_pypacker.get_lcount('dot') == 0

    @pytest.mark.skip("Pypacker does not support")
    def test_get_lfield(self, tg):
        """Verify that method get_lfield returns correct value.

        """
        packet = ({"Dot1Q": {"vlan": 1}}, {"Dot1Q": {"vlan": 2}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "flags": 0}}, {"TCP": {"flags": 1}})
        packet_pypacker = tg._build_pypacker_packet(packet)
        assert packet_pypacker.get_lfield('Dot1Q', 'vlan') == 1
        assert packet_pypacker.get_lfield('Dot1Q', 'vlan', l_id=2) == 2
        assert packet_pypacker.get_lfield('IP', 'src') == '20.0.10.2'
        assert packet_pypacker.get_lfield('Ether', 'src') is None
        # negative scenarious: not existing layer
        assert packet_pypacker.get_lfield('dot', 'src') is None
        # negative scenarious: not existing field
        assert packet_pypacker.get_lfield('IP', 'vlan') is None

    @pytest.mark.skip("Pypacker does not support")
    def test_rechecksum(self, tg):
        """Verify that method rechecksum returns correct value.

        """
        packet = ({"Dot1Q": {"vlan": 1}}, {"Dot1Q": {"vlan": 2}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "flags": 0}}, {"TCP": {"flags": 1}})
        packet_pypacker = tg._build_pypacker_packet(packet)
        ip_chksum = packet_pypacker.get_lfield('IP', 'chksum')
        tcp_chksum = packet_pypacker.get_lfield('TCP', 'chksum')
        assert packet_pypacker.rechecksum('IP') == ip_chksum
        assert packet_pypacker.rechecksum('TCP') == tcp_chksum
        # negative scenarious: not existing layer
        assert packet_pypacker.rechecksum('dot') is None
