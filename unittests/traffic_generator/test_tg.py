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

"""``test_tg.py``

`Traffic generator's unittests`

"""

import time
import copy
import random
from collections import namedtuple

import pytest

from testlib.custom_exceptions import PypackerException
from .packet_constants import (PACKET_DEFINITION, PACKET_DEFS,
                               ARP, DOT1Q, IP6, QINQ, STP, RSTP,
                               MSTP, MSTI_BPDU, LLDP, PAUSE, PFC,
                               ETH_IP_ICMP, ETH_IP_UDP, ETH_IP_TCP,
                               ETH_IP_IGMP, DOT1Q_PRIO_1, DOT1Q_PRIO_2,
                               DOT1Q_IP_UDP, DOT1Q_IP_ICMP, DOT1Q_IP_TCP,
                               DOT1Q_ARP, DOT1Q_IP6, ETHER_TYPE_EFC,
                               ETHER_TYPE_PBRIDGE, ETHER_TYPE_IP,
                               ETHER_TYPE_8021Q, ETHER_TYPE_TUNNELING,
                               SRC_MAC, DST_MAC, BROADCAT_MAC, IP_SRC, IP_DST,
                               DOT1Q_DEFAULT_CFI, VLAN_1, PAUSE_CODE,
                               PFC_CODE, PAUSE_TIME, PFC_LS, PFC_TIME,
                               PFC_MS, IP_PROTO_IP)


@pytest.mark.unittests
class TestTGs(object):

    @staticmethod
    def verify_packets_data(initial_packet_def, received_packet_def):
        """Check 2 packet definitions.

        """

        initial_packet_layers = [layer for p in initial_packet_def for layer in p]
        received_packet_layers = [layer for p in received_packet_def for layer in p]
        assert initial_packet_layers == received_packet_layers, \
            "Sent packet layers {0} do not match with received {1}".format(initial_packet_layers, received_packet_layers)

        layer_param = namedtuple("layer_param", ("layer", "field", "value"))
        initial_packet_params = (layer_param(layer, field, value) for p in initial_packet_def for layer in p
                                 for (field, value) in p[layer].items())

        received_packet_params = [layer_param(layer, field, value) for p in received_packet_def for layer in p
                                  for (field, value) in p[layer].items()]

        for init_param in initial_packet_params:
            assert init_param in received_packet_params, \
                "Field '{packet.field}' with value {packet.value} from " \
                "layer '{packet.layer}' is not found in received packet".format(packet=init_param)

    def test_stream(self, tg):
        """Verify that send stream send exact packets count.

        """
        iface = tg.ports[0]
        packet_count = 100
        src_mac = PACKET_DEFINITION[0]["Ethernet"]["src"]
        stream_id = tg.set_stream(PACKET_DEFINITION, count=packet_count,
                                  iface=iface, adjust_size=True, required_size=1450)
        tg.start_sniff([iface], sniffing_time=2, src_filter=src_mac)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

    def test_single_packet(self, tg):
        """Single packet.

        """
        time_stamp = time.time()
        stream_id = tg.set_stream(PACKET_DEFINITION, count=1, iface=tg.ports[0])
        print("Stream set time %2.6fs." % (time.time() - time_stamp))

        time_stamp = time.time()
        tg.send_stream(stream_id)
        print("Packet send time %2.6fs." % (time.time() - time_stamp))

    def test_single_stream(self, tg):
        """Single stream.

        """
        stream_id = tg.set_stream(PACKET_DEFINITION, count=5, inter=1, iface=tg.ports[0], adjust_size=True)
        time_stamp = time.time()
        tg.start_streams([stream_id])
        print("Time to start stream %2.6fs." % (time.time() - time_stamp))
        tg.stop_streams([stream_id])

    def test_multistreams_and_multifaces(self, tg):
        """Multiple streams and multiple ifaces.

        """
        stream_list = []
        for packet_definition, port in zip(PACKET_DEFS, tg.ports):
            stream_id = tg.set_stream(packet_definition, count=25, inter=0.5, iface=port, adjust_size=True)
            stream_list.append(stream_id)

        time_stamp = time.time()
        tg.start_streams(stream_list)
        print("Time to start stream %2.6fs." % (time.time() - time_stamp))
        tg.stop_streams(stream_list)

    def test_multistreams_on_single_iface(self, tg):
        """Multiple streams and one iface.

        """
        stream_list = []
        for packet_definition in PACKET_DEFS:
            stream_id = tg.set_stream(packet_definition, count=25, inter=0.5, iface=tg.ports[0], adjust_size=True)
            stream_list.append(stream_id)

        time_stamp = time.time()
        tg.start_streams(stream_list)
        print("Time to start stream %2.6fs." % (time.time() - time_stamp))
        tg.stop_streams(stream_list)

    def test_multistreams_and_one(self, tg):
        """Multiple streams and one on same iface.

        """
        stream_list = []
        for packet_definition in PACKET_DEFS[:2]:
            stream_id = tg.set_stream(packet_definition, count=3, inter=2, iface=tg.ports[0], adjust_size=True)
            stream_list.append(stream_id)

        tg.start_streams(stream_list)
        tg.stop_streams(stream_list)

        stream_id = tg.set_stream(PACKET_DEFS[2], count=2, inter=1, iface=tg.ports[0], adjust_size=True)
        tg.send_stream(stream_id)

    def test_exact_packets_delivery(self, tg):
        """Verify that send stream send exact packets count.

        """
        iface = tg.ports[0]
        packet_count = 1000
        src_mac = PACKET_DEFINITION[0]["Ethernet"]["src"]
        stream_id = tg.set_stream(PACKET_DEFINITION, count=packet_count, iface=iface,
                                  adjust_size=True, required_size=200, inter=0.005)
        tg.start_sniff([iface], sniffing_time=10, filter_layer="IP", src_filter=src_mac)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

    def test_start_stop_parallel_and_independent_set_quantity_streams(self, tg):
        """Verify parallel and independent set quantity of streams.

        """
        iface = tg.ports[0]
        packet_count = 11
        stream_id_1 = tg.set_stream(PACKET_DEFS[0], count=packet_count - 1, iface=iface)
        stream_id_2 = tg.set_stream(PACKET_DEFS[1], count=packet_count - 10, iface=iface)
        tg.start_sniff([iface], sniffing_time=3, filter_layer="IP", dst_filter=BROADCAT_MAC)
        tg.send_stream(stream_id_1)
        tg.send_stream(stream_id_2)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

    def test_start_stop_parallel_and_independent_continuous_streams(self, tg):
        """Verify parallel and independent streams starts and stops.

        """
        iface = tg.ports[0]
        # Packet count per stream equals 1 by default
        expected_count = 2
        stream_id_1 = tg.set_stream(PACKET_DEFS[0], iface=iface)
        stream_id_2 = tg.set_stream(PACKET_DEFS[1], iface=iface)
        tg.start_sniff([iface], sniffing_time=3, filter_layer="IP", dst_filter=BROADCAT_MAC)
        tg.start_streams([stream_id_1])
        tg.start_streams([stream_id_2])
        tg.stop_streams([stream_id_1])
        tg.stop_streams([stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == expected_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), expected_count)

    def test_streams_corruption_1(self, tg):
        """Verify that set_stream does not corrupt already started streams.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id_1 = tg.set_stream(PACKET_DEFS[0], count=packet_count, inter=0.1, iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="IP", dst_filter=BROADCAT_MAC)
        tg.start_streams([stream_id_1])
        tg.set_stream(PACKET_DEFS[1], count=1, iface=iface)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        for packet in packets:
            assert tg.get_packet_field(packet, "Ethernet", "src") != PACKET_DEFS[1][0]['Ethernet']['src']

    def test_streams_corruption_2(self, tg):
        """Verify that set_stream does not corrupt already started streams.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id_1 = tg.set_stream(PACKET_DEFS[0], count=packet_count, inter=1, iface=iface)
        tg.start_sniff([iface], sniffing_time=10, dst_filter=BROADCAT_MAC)
        tg.start_streams([stream_id_1])
        stream_id_2 = tg.set_stream(PACKET_DEFS[1], count=1, iface=iface)
        tg.start_streams([stream_id_2])
        data = tg.stop_sniff([iface])
        tg.stop_streams([stream_id_1, stream_id_2])
        packets = data.get(iface, [])

        assert len(packets) >= packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

    def test_stop_all_streams(self, tg):
        """Verify that stop_streams stop all streams by default.

        """
        iface = tg.ports[0]
        stream_id_1 = tg.set_stream(PACKET_DEFS[0], count=10, inter=1, iface=iface)
        stream_id_2 = tg.set_stream(PACKET_DEFS[1], count=10, inter=1, iface=iface)
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        tg.start_sniff([iface], sniffing_time=5, dst_filter=BROADCAT_MAC)
        data = tg.stop_sniff([iface])

        assert data[iface] == []

    def test_arp_sniff_pattern(self, tg):
        """Verify ARP sniff pattern.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id_1 = tg.set_stream(PACKET_DEFINITION, count=1, iface=iface)
        stream_id_2 = tg.set_stream(ARP, count=packet_count, iface=iface)
        stream_id_3 = tg.set_stream(DOT1Q_ARP, count=1, iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="ARP")
        tg.start_streams([stream_id_1, stream_id_2, stream_id_3])
        tg.stop_streams([stream_id_1, stream_id_2, stream_id_3])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

    def test_sniffing_negative(self, tg):
        """Sniff for one packet, but sniff nothing.

        """
        iface = tg.ports[0]
        stream_id = tg.set_stream(DOT1Q_ARP, count=5, inter=0.02, iface=iface)
        tg.start_sniff([iface], sniffing_time=3, packets_count=1, filter_layer="ARP")
        tg.start_streams([stream_id])
        tg.stop_streams([stream_id])
        data = tg.stop_sniff([iface])

        assert data[iface] == []

    def test_qinq_packets_sniffer(self, tg):
        """Check QinQ packet send.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id_1 = tg.set_stream(QINQ, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=3)
        tg.start_streams([stream_id_1])
        tg.stop_streams([stream_id_1])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(QINQ, received)

    def test_check_statistics(self, tg):
        """Send 100 packets and check statistics.

        """
        iface = tg.ports[0]
        src_mac = PACKET_DEFINITION[0]["Ethernet"]["src"]
        stream_id_1 = tg.set_stream(PACKET_DEFINITION, count=100, iface=iface)
        tg.clear_statistics([iface])
        tg.start_sniff([iface], sniffing_time=5, filter_layer="IP", src_filter=src_mac)
        tg.send_stream(stream_id_1)
        tg.stop_sniff([iface])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics == 100
        assert end_sent_statistics == 100

    def test_incremented_streams(self, tg):
        """Send incremented streams.

        """
        iface = tg.ports[0]

        packet1 = ({"Ethernet": {'src': "00:00:00:00:00:04", 'dst': "00:00:00:00:00:02"}}, {"IP": {}})
        packet2 = ({"Ethernet": {'src': "00:00:00:00:00:05", 'dst': "00:00:00:00:00:02"}}, {"IP": {}})
        packet3 = ({"Ethernet": {'src': "00:00:00:00:00:06", 'dst': "00:00:00:00:00:02"}},)
        packet4 = ({"Ethernet": {'src': "00:00:00:00:00:07", 'dst': "00:00:00:00:00:02"}}, {"IP": {}})
        packet5 = ({"Ethernet": {'src': "00:00:00:00:00:08", 'dst': "00:00:00:00:00:02"}}, {"IP": {}})
        packet6 = ({"Ethernet": {'src': "00:00:00:00:00:09", 'dst': "00:00:00:00:00:02"}}, {"IP": {}})
        packet7 = ({"Ethernet": {'src': "00:00:00:00:00:0a", 'dst': "00:00:00:00:00:02"}}, {"IP": {}})
        packet8 = ({"Ethernet": {'src': "00:00:00:00:00:0b", 'dst': "00:00:00:00:00:02"}}, {"IP": {}})
        packet9 = ({"Ethernet": {'src': "00:00:00:00:00:0c", 'dst': "00:00:00:00:00:02"}}, {"IP": {}})

        stream1 = tg.set_stream(packet1, count=20, sa_increment=(2, 20), iface=iface)
        stream2 = tg.set_stream(packet2, count=15, da_increment=(3, 15), iface=iface)
        stream3 = tg.set_stream(packet3, count=300, sa_increment=(2, 20), da_increment=(3, 15), iface=iface)
        stream4 = tg.set_stream(packet4, count=1, sa_increment=(2, 20), continuous=True, iface=iface)
        stream5 = tg.set_stream(packet5, count=1, da_increment=(2, 20), continuous=True, iface=iface)
        stream6 = tg.set_stream(packet6, count=20, sa_increment=(-2, 20), iface=iface)
        stream7 = tg.set_stream(packet7, count=15, da_increment=(-3, 15), iface=iface)
        stream8 = tg.set_stream(packet8, count=1, sa_increment=(-2, 20), continuous=True, iface=iface)
        stream9 = tg.set_stream(packet9, count=1, da_increment=(-3, 15), continuous=True, iface=iface)

        tg.clear_statistics([iface])

        tg.start_sniff([iface], sniffing_time=5, dst_filter="00:00:00:00:00:02")
        tg.start_streams([stream1])
        tg.stop_sniff([iface])
        tg.stop_streams([stream1])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics == 20
        assert end_sent_statistics == 20

        tg.clear_statistics([iface])

        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:00:00:00:05")
        tg.start_streams([stream2])
        tg.stop_sniff([iface])
        tg.stop_streams([stream2])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics == 15
        assert end_sent_statistics == 15

        tg.clear_statistics([iface])

        tg.start_sniff([iface], sniffing_time=5, filter_layer="notIP")
        tg.start_streams([stream3])
        tg.stop_sniff([iface])
        tg.stop_streams([stream3])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics >= 300
        assert end_sent_statistics == 300

        tg.clear_statistics([iface])

        tg.start_sniff([iface], sniffing_time=5)
        tg.start_streams([stream4])

        middle_receive_statistics = tg.get_received_frames_count(iface)
        middle_sent_statistics = tg.get_sent_frames_count(iface)

        assert middle_receive_statistics > 0
        assert middle_sent_statistics > 0

        tg.stop_sniff([iface])
        tg.stop_streams([stream4])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics > middle_receive_statistics
        assert end_sent_statistics > middle_sent_statistics

        tg.clear_statistics([iface])

        tg.start_sniff([iface], sniffing_time=5)
        tg.start_streams([stream5])

        middle_receive_statistics = tg.get_received_frames_count(iface)
        middle_sent_statistics = tg.get_sent_frames_count(iface)

        assert middle_receive_statistics > 0
        assert middle_sent_statistics > 0

        tg.stop_sniff([iface])
        tg.stop_streams([stream5])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics > middle_receive_statistics
        assert end_sent_statistics > middle_sent_statistics

        tg.clear_statistics([iface])

        tg.start_sniff([iface], sniffing_time=5, dst_filter="00:00:00:00:00:02")
        tg.start_streams([stream6])
        tg.stop_sniff([iface])
        tg.stop_streams([stream6])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics == 20
        assert end_sent_statistics == 20

        tg.clear_statistics([iface])

        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:00:00:00:0a")
        tg.start_streams([stream7])
        tg.stop_sniff([iface])
        tg.stop_streams([stream7])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics == 15
        assert end_sent_statistics == 15

        tg.clear_statistics([iface])

        tg.start_sniff([iface], sniffing_time=5)
        tg.start_streams([stream8])

        middle_receive_statistics = tg.get_received_frames_count(iface)
        middle_sent_statistics = tg.get_sent_frames_count(iface)

        assert middle_receive_statistics > 0
        assert middle_sent_statistics > 0

        tg.stop_sniff([iface])
        tg.stop_streams([stream8])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics > middle_receive_statistics
        assert end_sent_statistics > middle_sent_statistics

        tg.clear_statistics([iface])

        tg.start_sniff([iface], sniffing_time=5)
        tg.start_streams([stream9])

        time.sleep(1)

        middle_receive_statistics = tg.get_received_frames_count(iface)
        middle_sent_statistics = tg.get_sent_frames_count(iface)

        assert middle_receive_statistics > 0
        assert middle_sent_statistics > 0

        tg.stop_sniff([iface])
        tg.stop_streams([stream9])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics > middle_receive_statistics
        assert end_sent_statistics > middle_sent_statistics

    def test_packet_fragmentation(self, tg):
        """Check packet fragmentation.

        """
        ix_iface = tg.ports[0]
        packet_count = 2
        stream_id = tg.set_stream(ETH_IP_ICMP, count=1, iface=ix_iface, required_size=200, fragsize=110)
        tg.start_sniff([ix_iface], sniffing_time=5, filter_layer="ICMP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([ix_iface])
        packets = data.get(ix_iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

    def test_sa_incrementation_1(self, tg):
        """Check SA incrementation. Count == Increment count.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(ETH_IP_ICMP, count=packet_count, sa_increment=(1, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="ICMP", dst_filter=DST_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different src macs
        src_mac_set = set([tg.get_packet_field(packet, "Ethernet", "src") for packet in packets])
        assert len(src_mac_set) == packet_count

    def test_sa_incrementation_2(self, tg):
        """Check SA incrementation.  Count > Increment count.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_ICMP, count=packet_count, sa_increment=(1, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, packets_count=10, filter_layer="ICMP", dst_filter=DST_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different src macs
        src_mac_set = set([tg.get_packet_field(packet, "Ethernet", "src") for packet in packets])
        assert len(src_mac_set) == packet_count // 2

    def test_da_incrementation_1(self, tg):
        """Check DA incrementation. Count == Increment count.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(ETH_IP_ICMP, count=packet_count, da_increment=(1, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="ICMP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different dst macs
        dst_mac_set = set([tg.get_packet_field(packet, "Ethernet", "dst") for packet in packets])
        assert len(dst_mac_set) == packet_count

    def test_da_incrementation_2(self, tg):
        """Check DA incrementation.  Count > Increment count.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_ICMP, count=packet_count, da_increment=(1, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="ICMP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different dst macs
        dst_mac_set = set([tg.get_packet_field(packet, "Ethernet", "dst") for packet in packets])
        assert len(dst_mac_set) == packet_count // 2

    def test_sa_incrementation_and_packet_fragmentation(self, tg):
        """Check SA incrementation + packet fragmentation. Count == Increment count.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(ETH_IP_ICMP, iface=iface,
                                  count=packet_count, sa_increment=(1, 5),
                                  required_size=200, fragsize=110)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="ICMP", dst_filter=DST_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that sniffed count == (count of packets) * (number of fragments per packet)
        assert len(packets) == packet_count * 2, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count * 2)
        # Verify that all packets with different src macs
        src_mac_set = set([tg.get_packet_field(packet, "Ethernet", "src") for packet in packets])
        assert len(src_mac_set) == 5

    def test_packet_random_size_1(self, tg):
        """Check packet random size setting. Count=1.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id = tg.set_stream(ETH_IP_ICMP, iface=iface,
                                  count=packet_count, required_size=("Random", 100, 1500))
        tg.start_sniff([iface], sniffing_time=3, filter_layer="ICMP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that length of packet is random value between 100 and 1500 bytes
        packet_length = len(packets[0])
        assert 100 <= packet_length <= 1500

    def test_packet_random_size_2(self, tg):
        """Check packet random size setting. Count=5.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(ETH_IP_ICMP, iface=iface,
                                  count=packet_count, required_size=("Random", 1000, 1500))
        tg.start_sniff([iface], sniffing_time=5, filter_layer="ICMP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

        size_set = set([len(packet) for packet in packets])
        # Verify that length of packet is random value between 1000 and 1500 bytes
        assert all([1000 <= size <= 1500 for size in size_set])

    def test_packet_size_incrementing_1(self, tg):
        """Check packet size incrementing. Count=1, increment count=5.

        """
        iface = tg.ports[0]
        packet_count = 1
        start_size = 70
        stream_id = tg.set_stream(ETH_IP_ICMP, iface=iface, count=packet_count,
                                  required_size=("Increment", 2, start_size, 78))
        tg.start_sniff([iface], sniffing_time=3, filter_layer="ICMP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        assert len(packets[0]) == start_size

    def test_packet_size_incrementing_2(self, tg):
        """Check packet size incrementing. Count=5, increment count=5.

        """
        iface = tg.ports[0]
        packet_count = 5
        strat_size = 70
        step = 2
        end_size = 78
        expected_size_set = set(range(strat_size, end_size + 1, step))
        stream_id = tg.set_stream(ETH_IP_ICMP, iface=iface, count=packet_count,
                                  required_size=("Increment", step, strat_size, end_size))
        tg.start_sniff([iface], sniffing_time=5, filter_layer="ICMP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different size
        size_set = set([len(packet) for packet in packets])
        assert len(size_set) == packet_count
        # Verify that length of packet is from (70,72,74,76,78)
        assert size_set == expected_size_set

    def test_packet_size_decrementing(self, tg):
        """Check packet size decrementing. Count=9, decrement count=9.

        """
        iface = tg.ports[0]
        packet_count = 5
        start_size = 70
        step = -1
        end_size = 78
        # Ixia starts count from max frame size when step is negative
        expected_size_set = sorted(range(end_size, start_size - 1, step))[packet_count - 1:]
        stream_id = tg.set_stream(ETH_IP_ICMP, iface=iface, count=packet_count,
                                  required_size=("Increment", step, start_size, end_size))
        tg.start_sniff([iface], sniffing_time=5, filter_layer="ICMP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different size
        size_set = set([len(packet) for packet in packets])
        assert len(size_set) == packet_count
        # Verify that length of packet is from (70,71,72,73,74)
        assert sorted(size_set) == expected_size_set

    def test_src_ip_incrementation_dot1q_disabled_1(self, tg):
        """Check source_ip incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(ETH_IP_ICMP, count=packet_count, sip_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="ICMP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different src ip
        src_ip_set = set([tg.get_packet_field(packet, "IP", "src") for packet in packets])
        assert len(src_ip_set) == packet_count

    def test_src_ip_incrementation_dot1q_disabled_2(self, tg):
        """Check source_ip incrementation. Count = 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_ICMP, count=packet_count, sip_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="ICMP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different src ip
        src_ip_set = set([tg.get_packet_field(packet, "IP", "src") for packet in packets])
        assert len(src_ip_set) == packet_count // 2

    def test_src_ip_incrementation_dot1q_enabled_1(self, tg):
        """Check source_ip incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP_ICMP, count=packet_count, sip_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.ICMP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different src ip
        src_ip_set = set([tg.get_packet_field(packet, "IP", "src") for packet in packets])
        assert len(src_ip_set) == packet_count

    def test_src_ip_incrementation_dot1q_enabled_2(self, tg):
        """Check source_ip incrementation. Count = 2*Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP_ICMP, count=packet_count, sip_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.ICMP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different src ip
        src_ip_set = set([tg.get_packet_field(packet, "IP", "src") for packet in packets])
        assert len(src_ip_set) == packet_count

    def test_dst_ip_incrementation_dot1q_disabled_1(self, tg):
        """Check destination_ip incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(ETH_IP_ICMP, count=packet_count, dip_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="ICMP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different dst ip
        dst_ip_set = set([tg.get_packet_field(packet, "IP", "dst") for packet in packets])
        assert len(dst_ip_set) == packet_count

    def test_dst_ip_incrementation_dot1q_disabled_2(self, tg):
        """Check destination_ip incrementation. Count = 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_ICMP, count=packet_count, dip_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="ICMP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different dst ip
        dst_ip_set = set([tg.get_packet_field(packet, "IP", "dst") for packet in packets])
        assert len(dst_ip_set) == packet_count // 2

    def test_dst_ip_incrementation_dot1q_enabled_1(self, tg):
        """Check destination_ip incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP_ICMP, count=packet_count, dip_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.ICMP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different dst ip
        dst_ip_set = set([tg.get_packet_field(packet, "IP", "dst") for packet in packets])
        assert len(dst_ip_set) == packet_count

    def test_dst_ip_incrementation_dot1q_enabled_2(self, tg):
        """Check destination_ip incrementation. Count = 2*Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(DOT1Q_IP_ICMP, count=packet_count, dip_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.ICMP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different dst ip
        dst_ip_set = set([tg.get_packet_field(packet, "IP", "dst") for packet in packets])
        assert len(dst_ip_set) == packet_count // 2

    def test_clear_and_check_statistics(self, tg):
        """Send 100 packets, clear and check statistics.

        """
        iface = tg.ports[0]
        packet_count = 100
        src_mac = PACKET_DEFINITION[0]["Ethernet"]["src"]

        tg.clear_statistics([iface])
        stream_id_1 = tg.set_stream(PACKET_DEFINITION, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=7, filter_layer="IP", src_filter=src_mac)
        tg.start_streams([stream_id_1])
        tg.stop_sniff([iface])
        tg.stop_streams([stream_id_1])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics == packet_count
        assert end_sent_statistics == packet_count

        tg.clear_statistics([iface])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics == 0
        assert end_sent_statistics == 0

    def test_arp_incrementation_dot1q_disabled_1(self, tg):
        """Check arp incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(ARP, count=packet_count, arp_sa_increment=(3, 5), arp_sip_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="ARP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different src ip, src mac and hwsrc
        src_ip_set = set([tg.get_packet_field(packet, "ARP", "spa") for packet in packets])
        src_mac_set = set([tg.get_packet_field(packet, "Ethernet", "src") for packet in packets])
        hwsrc_set = set([tg.get_packet_field(packet, "ARP", "sha") for packet in packets])
        assert len(src_ip_set) == packet_count
        assert len(src_mac_set) == packet_count
        assert len(hwsrc_set) == packet_count

    def test_arp_incrementation_dot1q_enabled(self, tg):
        """Check arp incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_ARP, count=packet_count, arp_sa_increment=(3, 5),
                                  arp_sip_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.ARP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different src ip, src mac and hwsrc
        src_ip_set = set([tg.get_packet_field(packet, "ARP", "spa") for packet in packets])
        src_mac_set = set([tg.get_packet_field(packet, "Ethernet", "src") for packet in packets])
        hwsrc_set = set([tg.get_packet_field(packet, "ARP", "sha") for packet in packets])
        assert len(src_ip_set) == packet_count
        assert len(src_mac_set) == packet_count
        assert len(hwsrc_set) == packet_count

    def test_arp_incrementation_dot1q_disabled_2(self, tg):
        """Check arp incrementation. Count == 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ARP, count=packet_count, arp_sa_increment=(3, 5),
                                  arp_sip_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="ARP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different src ip, src mac and hwsrc
        src_ip_set = set([tg.get_packet_field(packet, "ARP", "spa") for packet in packets])
        src_mac_set = set([tg.get_packet_field(packet, "Ethernet", "src") for packet in packets])
        hwsrc_set = set([tg.get_packet_field(packet, "ARP", "sha") for packet in packets])
        assert len(src_ip_set) == packet_count // 2
        assert len(src_mac_set) == packet_count // 2
        assert len(hwsrc_set) == packet_count // 2

    def test_vlan_incrementation_increment_count_1(self, tg):
        """Check vlan incrementation. Count == Increment count.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP_TCP, count=packet_count, vlan_increment=(3, 5), iface=iface)

        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.IP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different src ip, src mac and hwsrc
        vlan_set = set([tg.get_packet_field(packet, "S-Dot1Q", "vid") for packet in packets])
        assert len(vlan_set) == packet_count

    def test_vlan_incrementation_increment_count_2(self, tg):
        """Check vlan incrementation. Count == 2*Increment count.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(DOT1Q_IP_TCP, count=packet_count, vlan_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.IP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different src ip, src mac and hwsrc
        vlan_set = set([tg.get_packet_field(packet, "S-Dot1Q", "vid") for packet in packets])
        assert len(vlan_set) == packet_count // 2

    def test_da_incrementation_continuous_traffic(self, tg):
        """Check DA incrementation.  Continuous traffic.

        """
        iface = tg.ports[0]
        start_mac_val = 1
        end_mac_val = 5
        min_packet_count = len(range(start_mac_val, end_mac_val + 1))
        stream_id = tg.set_stream(ETH_IP_ICMP, continuous=True,
                                  da_increment=(start_mac_val, end_mac_val), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="ICMP", src_filter=SRC_MAC)
        tg.start_streams([stream_id])
        tg.stop_streams([stream_id])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) >= min_packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), min_packet_count)
        # Verify that all packets with 5 different dst macs
        dst_mac_set = set([tg.get_packet_field(packet, "Ethernet", "dst") for packet in packets])
        assert len(dst_mac_set) == min_packet_count

    def test_sniffed_packets_timestamp(self, tg):
        """Check sniffed packets timestamp.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, inter=0.5, iface=iface)
        tg.start_sniff([iface], sniffing_time=10, packets_count=10, filter_layer="IP", src_filter=SRC_MAC)
        tg.start_streams([stream_id])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with 10 different timestamps
        time_set = set([packet.time for packet in packets])
        assert len(time_set) == packet_count

    def test_srcmac_filter(self, tg):
        """Check srcMac filter.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, sa_increment=(1, 2), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="IP", src_filter=SRC_MAC)
        tg.start_streams([stream_id])
        tg.stop_streams([stream_id])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count // 2, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with specified srcMac are sniffed
        src_set = set([tg.get_packet_field(packet, "Ethernet", "src") for packet in packets])
        assert len(src_set) == 1

    def test_dstmac_filter(self, tg):
        """Check dstMac filter.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, da_increment=(1, 2), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="IP", dst_filter=DST_MAC)
        tg.start_streams([stream_id])
        tg.stop_streams([stream_id])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count // 2, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with specified dstMac are sniffed
        dst_set = set([tg.get_packet_field(packet, "Ethernet", "dst") for packet in packets])
        assert len(dst_set) == 1

    def test_srcmac_and_dstmac_filter(self, tg):
        """Check srcMac and dstMac filter.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, sa_increment=(1, 2), da_increment=(1, 2), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="IP", src_filter=SRC_MAC, dst_filter=DST_MAC)
        tg.start_streams([stream_id])
        tg.stop_streams([stream_id])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count // 2, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with specified dstMac and srcMac are sniffed
        dst_set = set([tg.get_packet_field(packet, "Ethernet", "dst") for packet in packets])
        src_set = set([tg.get_packet_field(packet, "Ethernet", "src") for packet in packets])
        assert len(dst_set) == 1
        assert len(src_set) == 1

    def test_srcmac_and_dstmac_wrong_layer_filter(self, tg):
        """Check srcMac and dstMac filter with wrong filter_layer.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, sa_increment=(1, 2), da_increment=(1, 2), iface=iface)
        tg.start_sniff([iface], sniffing_time=7, packets_count=packet_count, filter_layer="ARP",
                       src_filter=SRC_MAC, dst_filter=DST_MAC)
        tg.start_streams([stream_id])
        tg.stop_streams([stream_id])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert packets == [], \
            "Captured packets count {0} does not match expected {1}".format(len(packets), 0)

    @pytest.mark.skip("Pypacker does not support LLDP")
    def test_lldp_incrementation_increment_count_1(self, tg):
        """Check lldp incrementation. Count == Increment count.

        """
        iface = tg.ports[0]

        stream_id = tg.set_stream(LLDP, count=5, sa_increment=(1, 5), lldp_sa_increment=(1, 5), iface=iface)

        tg.start_sniff([iface], sniffing_time=5, dst_filter="01:80:c2:00:00:0e")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])

        assert iface in list(data.keys())

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that LLDP mac are different
        mac_set = set()
        lldp_set = set()
        for packet in data[iface]:
            mac_set.add(tg.get_packet_field(packet, "Ethernet", "src"))
            lldp_set.add(tg.get_packet_field(packet, "LLDPChassisId", "macaddr"))

        assert len(mac_set) == 5
        assert len(lldp_set) == 5

    @pytest.mark.skip("Pypacker does not support LLDP")
    def test_lldp_incrementation_increment_count_2(self, tg):
        """Check lldp incrementation. Count == 2*Increment count.

        """
        iface = tg.ports[0]

        stream_id = tg.set_stream(LLDP, count=10, sa_increment=(1, 5), lldp_sa_increment=(1, 5), iface=iface)

        tg.start_sniff([iface], sniffing_time=5, dst_filter="01:80:c2:00:00:0e")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])

        assert iface in list(data.keys())

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that LLDP mac are different
        mac_set = set()
        lldp_set = set()
        for packet in data[iface]:
            mac_set.add(tg.get_packet_field(packet, "Ethernet", "src"))
            lldp_set.add(tg.get_packet_field(packet, "LLDPChassisId", "macaddr"))

        assert len(mac_set) == 5
        assert len(lldp_set) == 5

    @pytest.mark.skip("Pypacker does not support LLDP")
    def test_lldp_incrementation_continuous_traffic_1(self, tg):
        """Check lldp incrementation. Continuous traffic.

        """
        iface = tg.ports[0]

        stream_id = tg.set_stream(LLDP, continuous=True, sa_increment=(1, 5), lldp_sa_increment=(1, 5), iface=iface)

        tg.start_sniff([iface], sniffing_time=5, packets_count=20, filter_layer="LLDP", dst_filter="01:80:c2:00:00:0e")
        tg.start_streams([stream_id])
        time.sleep(5)
        tg.stop_streams([stream_id])
        data = tg.stop_sniff([iface])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) >= 20

        # Verify that LLDP mac are different
        mac_set = set()
        lldp_set = set()
        for packet in data[iface]:
            mac_set.add(tg.get_packet_field(packet, "Ethernet", "src"))
            lldp_set.add(tg.get_packet_field(packet, "LLDPChassisId", "macaddr"))

        assert len(mac_set) == 5
        assert len(lldp_set) == 5

    @pytest.mark.skip("Pypacker does not support LLDP")
    def test_lldp_incrementation_continuous_traffic_2(self, tg):
        """Check lldp incrementation. Continuous traffic.

        """
        iface = tg.ports[0]

        stream_id = tg.set_stream(LLDP, continuous=True, sa_increment=(1, 0), lldp_sa_increment=(1, 0), iface=iface)

        tg.start_sniff([iface], sniffing_time=5, packets_count=20, dst_filter="01:80:c2:00:00:0e")
        tg.start_streams([stream_id])
        time.sleep(5)
        tg.stop_streams([stream_id])
        data = tg.stop_sniff([iface])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) >= 20

        # Verify that LLDP mac are different
        mac_set = set()
        lldp_set = set()
        for packet in data[iface]:
            mac_set.add(tg.get_packet_field(packet, "Ethernet", "src"))
            lldp_set.add(tg.get_packet_field(packet, "LLDPChassisId", "macaddr"))

        assert len(mac_set) >= 20
        assert len(lldp_set) >= 20

    def test_src_udp_incrementation_dot1q_disabled_1(self, tg):
        """Check source_udp incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, sudp_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="UDP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different src udp
        src_udp_set = set([tg.get_packet_field(packet, "UDP", "sport") for packet in packets])
        assert len(src_udp_set) == packet_count

    def test_src_tcp_incrementation_dot1q_disabled_1(self, tg):
        """Check source_tcp incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(ETH_IP_TCP, count=packet_count, stcp_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="TCP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different src tcp
        src_tcp_set = set([tg.get_packet_field(packet, "TCP", "sport") for packet in packets])
        assert len(src_tcp_set) == packet_count

    def test_src_udp_incrementation_dot1q_disabled_2(self, tg):
        """Check source_udp incrementation. Count = 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, sudp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface], sniffing_time=5, filter_layer="UDP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different src udp
        src_udp_set = set([tg.get_packet_field(packet, "UDP", "sport") for packet in packets])
        assert len(src_udp_set) == packet_count // 2

    def test_src_tcp_incrementation_dot1q_disabled_2(self, tg):
        """Check source_tcp incrementation. Count = 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_TCP, count=packet_count, stcp_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="TCP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different src udp
        src_tcp_set = set([tg.get_packet_field(packet, "TCP", "sport") for packet in packets])
        assert len(src_tcp_set) == packet_count // 2

    def test_src_udp_incrementation_dot1q_enabled(self, tg):
        """Check source_udp incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, sudp_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.IP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different src udp
        src_udp_set = set([tg.get_packet_field(packet, "UDP", "sport") for packet in packets])
        assert len(src_udp_set) == packet_count

    def test_src_tcp_incrementation_dot1q_enabled(self, tg):
        """Check source_tcp incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP_TCP, count=packet_count, stcp_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.IP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different src tcp
        src_tcp_set = set([tg.get_packet_field(packet, "TCP", "sport") for packet in packets])
        assert len(src_tcp_set) == packet_count

    def test_dst_udp_incrementation_dot1q_disabled_1(self, tg):
        """Check destination_udp incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, dudp_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="UDP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different dst udp
        dst_udp_set = set([tg.get_packet_field(packet, "UDP", "dport") for packet in packets])
        assert len(dst_udp_set) == packet_count

    def test_dst_udp_incrementation_dot1q_disabled_2(self, tg):
        """Check destination_udp incrementation. Count = 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, dudp_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="UDP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different dst udp
        dst_udp_set = set([tg.get_packet_field(packet, "UDP", "dport") for packet in packets])
        assert len(dst_udp_set) == packet_count // 2

    def test_dst_udp_incrementation_dot1q_enabled(self, tg):
        """Check destination_udp incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, dudp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.IP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different dst udp
        dst_udp_set = set([tg.get_packet_field(packet, "UDP", "dport") for packet in packets])
        assert len(dst_udp_set) == packet_count

    def test_src_udp_and_dst_udp_incrementation_dot1q_disabled_1(self, tg):
        """Check source_udp and destination_udp incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, sudp_increment=(3, 5), dudp_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="UDP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different dst and src udp
        dst_udp_set = set([tg.get_packet_field(packet, "UDP", "dport") for packet in packets])
        src_udp_set = set([tg.get_packet_field(packet, "UDP", "sport") for packet in packets])
        assert len(dst_udp_set) == packet_count
        assert len(src_udp_set) == packet_count

    def test_src_tcp_and_dst_tcp_incrementation_dot1q_disabled_1(self, tg):
        """Check source_tcp and destination_tcp incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(ETH_IP_TCP, count=packet_count, stcp_increment=(3, 5),
                                  dtcp_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="TCP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different dst and src tcp
        dst_tcp_set = set([tg.get_packet_field(packet, "TCP", "dport") for packet in packets])
        src_tcp_set = set([tg.get_packet_field(packet, "TCP", "sport") for packet in packets])
        assert len(dst_tcp_set) == packet_count
        assert len(src_tcp_set) == packet_count

    def test_src_udp_and_dst_udp_incrementation_dot1q_disabled_2(self, tg):
        """Check source_udp and destination_udp incrementation. Count = 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, sudp_increment=(3, 5), dudp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface], sniffing_time=5, filter_layer="UDP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different dst and src udp
        dst_udp_set = set([tg.get_packet_field(packet, "UDP", "dport") for packet in packets])
        src_udp_set = set([tg.get_packet_field(packet, "UDP", "sport") for packet in packets])
        assert len(dst_udp_set) == packet_count // 2
        assert len(src_udp_set) == packet_count // 2

    def test_src_tcp_and_dst_tcp_incrementation_dot1q_disabled_2(self, tg):
        """Check source_tcp and destination_tcp incrementation. Count = 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_TCP, count=packet_count, stcp_increment=(3, 5), dtcp_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="TCP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different dst and src tcp
        dst_tcp_set = set([tg.get_packet_field(packet, "TCP", "dport") for packet in packets])
        src_tcp_set = set([tg.get_packet_field(packet, "TCP", "sport") for packet in packets])
        assert len(dst_tcp_set) == packet_count // 2
        assert len(src_tcp_set) == packet_count // 2

    def test_src_udp_and_dst_udp_incrementation_dot1q_enabled(self, tg):
        """Check source_udp and destination_udp incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, sudp_increment=(3, 5), dudp_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.IP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different dst and src udp
        dst_udp_set = set([tg.get_packet_field(packet, "UDP", "dport") for packet in packets])
        src_udp_set = set([tg.get_packet_field(packet, "UDP", "sport") for packet in packets])
        assert len(dst_udp_set) == packet_count
        assert len(src_udp_set) == packet_count

    def test_src_tcp_and_dst_tcp_incrementation_dot1q_enabled(self, tg):
        """Check source_tcp and destination_tcp incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP_TCP, count=packet_count, stcp_increment=(3, 5), dtcp_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.IP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different dst and src tcp
        dst_tcp_set = set([tg.get_packet_field(packet, "TCP", "dport") for packet in packets])
        src_tcp_set = set([tg.get_packet_field(packet, "TCP", "sport") for packet in packets])
        assert len(dst_tcp_set) == packet_count
        assert len(src_tcp_set) == packet_count

    def test_ip_protocol_incrementation_dot1q_disabled(self, tg):
        """Check ip protocol incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, protocol_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="IP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different ip proto
        proto_ip_set = set([tg.get_packet_field(packet, "IP", "p") for packet in packets])
        assert len(proto_ip_set) == packet_count

    def test_ip_protocol_incrementation_dot1q_disabled_2(self, tg):
        """Check ip protocol incrementation. Count = 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, protocol_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="IP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different ip proto
        proto_ip_set = set([tg.get_packet_field(packet, "IP", "p") for packet in packets])
        assert len(proto_ip_set) == packet_count // 2

    def test_ip_protocol_incrementation_dot1q_enabled(self, tg):
        """Check destination_udp incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, protocol_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.IP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different ip proto
        proto_ip_set = set([tg.get_packet_field(packet, "IP", "p") for packet in packets])
        assert len(proto_ip_set) == packet_count

    def test_ip_protocol_and_sip_increment_dot1q_disabled(self, tg):
        """Check ip protocol and sip_increment incrementation. Count = 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, sip_increment=(3, 5), protocol_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="IP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different ip proto and src ip.
        proto_ip_set = set([tg.get_packet_field(packet, "IP", "p") for packet in packets])
        src_ip_set = set([tg.get_packet_field(packet, "IP", "src") for packet in packets])
        assert len(proto_ip_set) == packet_count // 2
        assert len(src_ip_set) == packet_count // 2

    def test_ip_protocol_and_sip_increment_dot1q_enabled(self, tg):
        """Check ip protocol and sip_increment incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, sip_increment=(3, 5), protocol_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.IP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different ip proto and src ip.
        proto_ip_set = set([tg.get_packet_field(packet, "IP", "p") for packet in packets])
        src_ip_set = set([tg.get_packet_field(packet, "IP", "src") for packet in packets])
        assert len(proto_ip_set) == packet_count
        assert len(src_ip_set) == packet_count

    def test_ether_incrementation_dot1q_disabled_1(self, tg):
        """Check ether type incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, eth_type_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different ether type
        eth_type_set = set([tg.get_packet_field(packet, "Ethernet", "type") for packet in packets])
        assert len(eth_type_set) == packet_count

    def test_ether_incrementation_dot1q_disabled_2(self, tg):
        """Check ip protocol incrementation. Count = 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, eth_type_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different ether type
        eth_type_set = set([tg.get_packet_field(packet, "Ethernet", "type") for packet in packets])
        assert len(eth_type_set) == packet_count // 2

    def test_dscp_incrementation_dot1q_disabled_1(self, tg):
        """Check dscp incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, dscp_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="IP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different ip dscp
        dscp_set = set([tg.get_packet_field(packet, "IP", "tos") for packet in packets])
        assert len(dscp_set) == packet_count

    def test_dscp_incrementation_dot1q_disabled_2(self, tg):
        """Check dscp incrementation. Count = 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, dscp_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="IP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different ip dscp
        dscp_set = set([tg.get_packet_field(packet, "IP", "tos") for packet in packets])
        assert len(dscp_set) == packet_count // 2

    def test_ip_dscp_incrementation_dot1q_enabled(self, tg):
        """Check ip dscp incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, dscp_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.IP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different ip dscp
        dscp_set = set([tg.get_packet_field(packet, "IP", "tos") for packet in packets])
        assert len(dscp_set) == packet_count

    def test_ip_dscp_and_sip_increment_dot1q_disabled_1(self, tg):
        """Check ip dscp and sip_increment incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, sip_increment=(3, 5), dscp_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="IP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different ip dscp and src
        dscp_set = set([tg.get_packet_field(packet, "IP", "tos") for packet in packets])
        src_ip_set = set([tg.get_packet_field(packet, "IP", "src") for packet in packets])
        assert len(dscp_set) == packet_count
        assert len(src_ip_set) == packet_count

    def test_ip_dscp_and_sip_increment_dot1q_disabled_2(self, tg):
        """Check ip dscp and sip_increment incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, sip_increment=(3, 15), dip_increment=(3, 10),
                                  dscp_increment=(3, 5), protocol_increment=(3, 30), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="IP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only packets with different ip dscp, src, dst and proto
        dscp_set = set([tg.get_packet_field(packet, "IP", "tos") for packet in packets])
        src_ip_set = set([tg.get_packet_field(packet, "IP", "src") for packet in packets])
        dst_ip_set = set([tg.get_packet_field(packet, "IP", "dst") for packet in packets])
        proto_ip_set = set([tg.get_packet_field(packet, "IP", "p") for packet in packets])
        assert len(dscp_set) == packet_count
        assert len(src_ip_set) == packet_count
        assert len(dst_ip_set) == packet_count
        assert len(proto_ip_set) == packet_count

    def test_ip_dip_and_sip_increment_udf_dependant(self, tg):
        """Check ip dip and sip_increment incrementation. Dip increment dependant from sip increment.

        """
        iface = tg.ports[0]
        packet_count = 18
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, sip_increment=(3, 3), dip_increment=(3, 3),
                                  dscp_increment=(3, 3), iface=iface, udf_dependancies={'sip_increment': 'dip_increment'})
        tg.start_sniff([iface], sniffing_time=5, filter_layer="IP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only 9 different packets received
        dscp_set = set([tg.get_packet_field(packet, "IP", "tos") for packet in packets])
        src_ip_set = set([tg.get_packet_field(packet, "IP", "src") for packet in packets])
        dst_ip_set = set([tg.get_packet_field(packet, "IP", "dst") for packet in packets])
        packet_set = set([packet.bin() for packet in packets])
        assert len(dscp_set) == 3
        assert len(src_ip_set) == 3
        assert len(dst_ip_set) == 3
        assert len(packet_set) == 9

    def test_ip_dscp_dip_sip_increment_udf_dependant(self, tg):
        """Check ip dscp, dip and sip_increment incrementation. Dependant increments.

        """
        iface = tg.ports[0]
        packet_count = 54
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, sip_increment=(3, 3),
                                  dip_increment=(3, 3), dscp_increment=(3, 3), iface=iface,
                                  udf_dependancies={'dip_increment': 'sip_increment', 'dscp_increment': 'dip_increment'})
        tg.start_sniff([iface], sniffing_time=5, filter_layer="IP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only 27 different packets received
        dscp_set = set([tg.get_packet_field(packet, "IP", "tos") for packet in packets])
        src_ip_set = set([tg.get_packet_field(packet, "IP", "src") for packet in packets])
        dst_ip_set = set([tg.get_packet_field(packet, "IP", "dst") for packet in packets])
        packet_set = set([packet.bin() for packet in packets])
        assert len(dscp_set) == 3
        assert len(src_ip_set) == 3
        assert len(dst_ip_set) == 3
        assert len(packet_set) == 27

    def test_ip_dscp_dip_sip_increment_udf_one_dependant(self, tg):
        """Check ip dscp, dip and sip_increment incrementation. Dependant increments form sip.

        """
        iface = tg.ports[0]
        packet_count = 54
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, sip_increment=(3, 3),
                                  dip_increment=(3, 3), dscp_increment=(3, 3), iface=iface,
                                  udf_dependancies={'dip_increment': 'sip_increment', 'dscp_increment': 'sip_increment'})
        tg.start_sniff([iface], sniffing_time=5, filter_layer="IP", src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that only 9 different packets received
        dscp_set = set([tg.get_packet_field(packet, "IP", "tos") for packet in packets])
        src_ip_set = set([tg.get_packet_field(packet, "IP", "src") for packet in packets])
        dst_ip_set = set([tg.get_packet_field(packet, "IP", "dst") for packet in packets])
        packet_set = set([packet.bin() for packet in packets])
        assert len(dscp_set) == 3
        assert len(src_ip_set) == 3
        assert len(dst_ip_set) == 3
        assert len(packet_set) == 9

    def test_src_ipv6_incrementation_dot1q_disabled_1(self, tg):
        """Check SRC IPv6 incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(IP6, count=packet_count, sipv6_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 src address
        sipv6_set = set([tg.get_packet_field(packet, "IP6", "src") for packet in packets])
        assert len(sipv6_set) == packet_count

    def test_src_ipv6_incrementation_dot1q_disabled_2(self, tg):
        """Check SRC IPv6 incrementation. Count = 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(IP6, count=packet_count, sipv6_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 src address
        sipv6_set = set([tg.get_packet_field(packet, "IP6", "src") for packet in packets])
        assert len(sipv6_set) == packet_count // 2

    def test_src_ipv6_incrementation_dot1q_enabled_1(self, tg):
        """Check SRC IPv6 incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP6, count=packet_count, sipv6_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.IPv6", src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 src address
        sipv6_set = set([tg.get_packet_field(packet, "IP6", "src") for packet in packets])
        assert len(sipv6_set) == packet_count

    def test_src_ipv6_incrementation_dot1q_enabled_2(self, tg):
        """Check SRC IPv6 incrementation. Count > Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(DOT1Q_IP6, count=packet_count, sipv6_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.IPv6", src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 src address
        sipv6_set = set([tg.get_packet_field(packet, "IP6", "src") for packet in packets])
        assert len(sipv6_set) == packet_count // 2

    def test_src_and_dst_ipv6_incrementation_dot1q_disabled(self, tg):
        """Check SRC and DST IPv6 incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(IP6, count=packet_count, sipv6_increment=(3, 5),
                                  dipv6_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 src and dst address
        sipv6_set = set([tg.get_packet_field(packet, "IP6", "src") for packet in packets])
        dipv6_set = set([tg.get_packet_field(packet, "IP6", "dst") for packet in packets])
        assert len(sipv6_set) == packet_count
        assert len(dipv6_set) == packet_count

    def test_src_and_dst_ipv6_incrementation_dot1q_enabled(self, tg):
        """Check SRC and DST IPv6 incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP6, count=packet_count, sipv6_increment=(3, 5), dipv6_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.IPv6", src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 src and dst address
        sipv6_set = set([tg.get_packet_field(packet, "IP6", "src") for packet in packets])
        dipv6_set = set([tg.get_packet_field(packet, "IP6", "dst") for packet in packets])
        assert len(sipv6_set) == packet_count
        assert len(dipv6_set) == packet_count

    def test_dst_ipv6_incrementation_dot1q_disabled_1(self, tg):
        """Check DST IPv6 incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(IP6, count=packet_count, dipv6_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 dst address
        dipv6_set = set([tg.get_packet_field(packet, "IP6", "dst") for packet in packets])
        assert len(dipv6_set) == packet_count

    def test_dst_ipv6_incrementation_dot1q_disabled_2(self, tg):
        """Check DST IPv6 incrementation. Count = 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(IP6, count=packet_count, dipv6_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 dst address
        dipv6_set = set([tg.get_packet_field(packet, "IP6", "dst") for packet in packets])
        assert len(dipv6_set) == packet_count // 2

    def test_dst_ipv6_incrementation_dot1q_enabled_1(self, tg):
        """Check DST IPv6 incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP6, count=packet_count, dipv6_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.IPv6", src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 dst address
        dipv6_set = set([tg.get_packet_field(packet, "IP6", "dst") for packet in packets])
        assert len(dipv6_set) == packet_count

    def test_dst_ipv6_incrementation_dot1q_enabled_2(self, tg):
        """Check DST IPv6 incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(DOT1Q_IP6, count=packet_count, dipv6_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.IPv6", src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 dst address
        dipv6_set = set([tg.get_packet_field(packet, "IP6", "dst") for packet in packets])
        assert len(dipv6_set) == packet_count // 2

    def test_flow_label_ipv6_incrementation_dot1q_disabled_1(self, tg):
        """Check Flow Label IPv6 incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(IP6, count=packet_count, fl_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 flow
        fl_set = set([tg.get_packet_field(packet, "IP6", "flow") for packet in packets])
        assert len(fl_set) == packet_count

    def test_flow_label_ipv6_incrementation_dot1q_disabled_2(self, tg):
        """Check Flow Label incrementation. Count = 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(IP6, count=packet_count, fl_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 flow
        fl_set = set([tg.get_packet_field(packet, "IP6", "flow") for packet in packets])
        assert len(fl_set) == packet_count // 2

    def test_flow_label_ipv6_incrementation_dot1q_enabled(self, tg):
        """Check Flow Label IPv6 incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP6, count=packet_count, fl_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 flow
        fl_set = set([tg.get_packet_field(packet, "IP6", "flow") for packet in packets])
        assert len(fl_set) == packet_count

    def test_flow_label_src_ipv6_incrementation(self, tg):
        """Check Flow Label with SRC IPv6 incrementation. Count = 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(IP6, count=packet_count, fl_increment=(3, 5), sipv6_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 flow and src address
        fl_set = set([tg.get_packet_field(packet, "IP6", "flow") for packet in packets])
        sipv6_set = set([tg.get_packet_field(packet, "IP6", "src") for packet in packets])
        assert len(fl_set) == packet_count // 2
        assert len(sipv6_set) == packet_count // 2

    def test_flow_label_dst_ipv6_incrementation(self, tg):
        """Check Flow Label and DST IPv6 incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP6, count=packet_count, fl_increment=(3, 5), dipv6_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 flow and dst address
        fl_set = set([tg.get_packet_field(packet, "IP6", "flow") for packet in packets])
        dipv6_set = set([tg.get_packet_field(packet, "IP6", "dst") for packet in packets])
        assert len(fl_set) == packet_count
        assert len(dipv6_set) == packet_count

    def test_next_header_ipv6_incrementation_dot1q_disabled(self, tg):
        """Check next header incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(IP6, count=packet_count, nh_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 next header
        nxt_set = set([tg.get_packet_field(packet, "IP6", "nxt") for packet in packets])
        assert len(nxt_set) == packet_count

    def test_next_header_ipv6_incrementation_dot1q_disabled_2(self, tg):
        """Check next header incrementation. Count = 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(IP6, count=packet_count, nh_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 next header
        nxt_set = set([tg.get_packet_field(packet, "IP6", "nxt") for packet in packets])
        assert len(nxt_set) == packet_count // 2

    def test_next_header_ipv6_incrementation_dot1q_enabled(self, tg):
        """Check next header IPv6 incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP6, count=packet_count, nh_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 next header
        nxt_set = set([tg.get_packet_field(packet, "IP6", "nxt") for packet in packets])
        assert len(nxt_set) == packet_count

    def test_traffic_class_ipv6_incrementation_dot1q_disabled(self, tg):
        """Check traffic class incrementation. Count == Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(IP6, count=packet_count, tc_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 traffic class
        tc_set = set([tg.get_packet_field(packet, "IP6", "fc") for packet in packets])
        assert len(tc_set) == packet_count

    def test_traffic_class_ipv6_incrementation_dot1q_disabled_2(self, tg):
        """Check traffic class incrementation. Count = 2*Increment count. Dot1Q disabled.

        """
        iface = tg.ports[0]
        packet_count = 10
        stream_id = tg.set_stream(IP6, count=packet_count, tc_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 traffic class
        tc_set = set([tg.get_packet_field(packet, "IP6", "fc") for packet in packets])
        assert len(tc_set) == packet_count // 2

    def test_traffic_class_ipv6_incrementation_dot1q_enabled(self, tg):
        """Check traffic class IPv6 incrementation. Count == Increment count. Dot1Q enabled.

        """
        iface = tg.ports[0]
        packet_count = 5
        stream_id = tg.set_stream(DOT1Q_IP6, count=packet_count, tc_increment=(3, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=5, src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        # Verify that all packets with different IPv6 traffic class
        tc_set = set([tg.get_packet_field(packet, "IP6", "fc") for packet in packets])
        assert len(tc_set) == packet_count

    def test_qos_vlan_stat(self, tg):
        """Check Ixia QoS vlan stat reading.

        """
        if tg.type != "ixiahl":
            pytest.skip("Get Qos Frames count increment isn't supported by Pypacker TG")
        iface = tg.ports[0]
        packet_count = 52
        dst_mac = "00:00:00:00:00:aa"
        src_mac = "00:00:00:00:00:bb"

        pack_p0 = ({"Ethernet": {"dst": dst_mac, "src": src_mac}},
                   {"Dot1Q": {"vid": 10, "prio": 0}},
                   {"IP": {"p": 17}}, {"UDP": {}}, )
        pack_p1 = ({"Ethernet": {"dst": dst_mac, "src": src_mac}},
                   {"Dot1Q": {"vid": 10, "prio": 1}},
                   {"IP": {"p": 17}}, {"UDP": {}}, )
        pack_p2 = ({"Ethernet": {"dst": dst_mac, "src": src_mac}},
                   {"Dot1Q": {"vid": 10, "prio": 2}},
                   {"IP": {"p": 17}}, {"UDP": {}}, )
        pack_p3 = ({"Ethernet": {"dst": dst_mac, "src": src_mac}},
                   {"Dot1Q": {"vid": 10, "prio": 3}},
                   {"IP": {"p": 17}}, {"UDP": {}}, )
        pack_p4 = ({"Ethernet": {"dst": dst_mac, "src": src_mac}},
                   {"Dot1Q": {"vid": 10, "prio": 4}},
                   {"IP": {"p": 17}}, {"UDP": {}}, )
        pack_p5 = ({"Ethernet": {"dst": dst_mac, "src": src_mac}},
                   {"Dot1Q": {"vid": 10, "prio": 5}},
                   {"IP": {"p": 17}}, {"UDP": {}}, )
        pack_p6 = ({"Ethernet": {"dst": dst_mac, "src": src_mac}},
                   {"Dot1Q": {"vid": 10, "prio": 6}},
                   {"IP": {"p": 17}}, {"UDP": {}}, )
        pack_p7 = ({"Ethernet": {"dst": dst_mac, "src": src_mac}},
                   {"Dot1Q": {"vid": 10, "prio": 7}},
                   {"IP": {"p": 17}}, {"UDP": {}}, )

        stream_ids = []
        stream_ids.append(tg.set_stream(pack_p0, count=8, iface=iface))
        stream_ids.append(tg.set_stream(pack_p1, count=7, iface=iface))
        stream_ids.append(tg.set_stream(pack_p2, count=6, iface=iface))
        stream_ids.append(tg.set_stream(pack_p3, count=5, iface=iface))
        stream_ids.append(tg.set_stream(pack_p4, count=5, iface=iface))
        stream_ids.append(tg.set_stream(pack_p5, count=6, iface=iface))
        stream_ids.append(tg.set_stream(pack_p6, count=7, iface=iface))
        stream_ids.append(tg.set_stream(pack_p7, count=8, iface=iface))

        tg.set_qos_stat_type(iface, "VLAN")
        tg.clear_statistics([iface])

        tg.start_sniff([iface], sniffing_time=5)
        tg.start_streams(stream_ids)
        data = tg.stop_sniff([iface])
        tg.stop_streams(stream_ids)
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        assert tg.get_received_frames_count(iface) == packet_count

        assert tg.get_qos_frames_count(iface, 0) == 8
        assert tg.get_qos_frames_count(iface, 1) == 7
        assert tg.get_qos_frames_count(iface, 2) == 6
        assert tg.get_qos_frames_count(iface, 3) == 5
        assert tg.get_qos_frames_count(iface, 4) == 5
        assert tg.get_qos_frames_count(iface, 5) == 6
        assert tg.get_qos_frames_count(iface, 6) == 7
        assert tg.get_qos_frames_count(iface, 7) == 8

    def test_qos_iptos_stat(self, tg):
        """Check Ixia QoS IP TOS stat reading.

        """
        if tg.type != "ixiahl":
            pytest.skip("Get Qos Frames count increment isn't supported by Pypacker TG")
        iface = tg.ports[0]

        dst_mac = "00:00:00:00:00:55"
        src_mac = "00:00:00:00:00:77"

        pack_list = []
        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x00}}, {"TCP": {}}))
        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x0f}}, {"TCP": {}}))
        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x1f}}, {"TCP": {}}))

        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x20}}, {"TCP": {}}))
        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x30}}, {"TCP": {}}))
        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x3f}}, {"TCP": {}}))

        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x40}}, {"TCP": {}}))
        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x5a}}, {"TCP": {}}))
        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x5f}}, {"TCP": {}}))

        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x60}}, {"TCP": {}}))
        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x71}}, {"TCP": {}}))
        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x7f}}, {"TCP": {}}))

        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x80}}, {"TCP": {}}))
        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x8f}}, {"TCP": {}}))
        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x9f}}, {"TCP": {}}))

        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xa0}}, {"TCP": {}}))
        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xb3}}, {"TCP": {}}))
        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xbf}}, {"TCP": {}}))

        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xc0}}, {"TCP": {}}))
        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xc5}}, {"TCP": {}}))
        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xdf}}, {"TCP": {}}))

        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xe0}}, {"TCP": {}}))
        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xe1}}, {"TCP": {}}))
        pack_list.append(({"Ethernet": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xff}}, {"TCP": {}}))

        packet_count = len(pack_list)
        stream_ids = []
        for pack in pack_list:
            stream_ids.append(tg.set_stream(pack, count=1, iface=iface))

        tg.set_qos_stat_type(iface, "IP")
        tg.clear_statistics([iface])

        tg.start_sniff([iface], sniffing_time=5)
        tg.start_streams(stream_ids)
        data = tg.stop_sniff([iface])
        tg.stop_streams(stream_ids)
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        assert tg.get_received_frames_count(iface) == packet_count

        for prio in range(8):
            assert tg.get_qos_frames_count(iface, prio) == 3

    def test_get_rate_stat(self, tg):
        """Check transmit rate reading.

        """
        if tg.type != "ixiahl":
            pytest.skip("Get port txrate increment isn't supported by Pypacker TG.")
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(ETH_IP_TCP, continuous=True, inter=0.1, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_TCP, continuous=True, inter=0.05, iface=iface)

        tg.start_streams([stream_id_1])
        time.sleep(1)
        assert 10 * 0.9 <= tg.get_port_txrate(iface) <= 10 * 1.1
        assert 10 * 0.9 <= tg.get_port_rxrate(iface) <= 10 * 1.1
        tg.stop_streams([stream_id_1])

        tg.start_streams([stream_id_2])
        time.sleep(1)
        assert 20 * 0.95 <= tg.get_port_txrate(iface) <= 20 * 1.05
        assert 20 * 0.95 <= tg.get_port_rxrate(iface) <= 20 * 1.05
        tg.stop_streams([stream_id_2])

        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        assert 30 * 0.96 <= tg.get_port_txrate(iface) <= 30 * 1.04
        assert 30 * 0.96 <= tg.get_port_rxrate(iface) <= 30 * 1.04
        tg.stop_streams([stream_id_1, stream_id_2])

    def test_check_increment_ip_src(self, tg):
        """Check all fields in incremented packet. IP.src increment.

        """
        iface = tg.ports[0]
        packet_count = 5
        src_mac = DOT1Q_IP_UDP[0]["Ethernet"]["src"]
        stream_id = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, sip_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=2, src_filter=src_mac)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(DOT1Q_IP_UDP, received)

    def test_check_increment_ip_dst(self, tg):
        """Check all fields in incremented packet. IP.dst increment.

        """
        iface = tg.ports[0]
        packet_count = 1
        src_mac = DOT1Q_IP_UDP[0]["Ethernet"]["src"]
        stream_id = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, dip_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=2, src_filter=src_mac)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(DOT1Q_IP_UDP, received)

    def test_check_increment_ip_dscp(self, tg):
        """Check all fields in incremented packet. IP.tos increment.

        """
        iface = tg.ports[0]
        packet_count = 1
        src_mac = DOT1Q_IP_UDP[0]["Ethernet"]["src"]
        stream_id = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, dscp_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=2, src_filter=src_mac)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(DOT1Q_IP_UDP, received)

    def test_check_increment_ip_proto(self, tg):
        """Check all fields in incremented packet. IP.proto increment.

        """
        iface = tg.ports[0]
        packet_count = 1
        src_mac = DOT1Q_IP_UDP[0]["Ethernet"]["src"]
        stream_id = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, protocol_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=2, src_filter=src_mac)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(DOT1Q_IP_UDP, received)

    def test_check_increment_arp_hwsrc(self, tg):
        """Check all fields in incremented packet. APR.hwsrc increment.

        """
        iface = tg.ports[0]
        packet_count = 3
        src_mac = DOT1Q_ARP[0]["Ethernet"]["src"]
        stream_id = tg.set_stream(DOT1Q_ARP, count=3, arp_sa_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=3, src_filter=src_mac)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == 1, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(DOT1Q_ARP, received)

    def test_check_increment_arp_psrc(self, tg):
        """Check all fields in incremented packet. APR.psrc increment.

        """
        iface = tg.ports[0]
        packet_count = 1
        src_mac = DOT1Q_ARP[0]["Ethernet"]["src"]
        stream_id = tg.set_stream(DOT1Q_ARP, count=1, arp_sip_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=3, src_filter=src_mac)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(DOT1Q_ARP, received)

    def test_check_increment_igmp_ip(self, tg):
        """Check all fields in incremented packet. IGMP.ip increment.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id = tg.set_stream(ETH_IP_IGMP, count=packet_count, igmp_ip_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=2, src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(ETH_IP_IGMP, received)

        packet = copy.deepcopy(ETH_IP_IGMP)
        packet[3]["IGMP"]["type"] = 18
        stream_id = tg.set_stream(packet, count=packet_count, igmp_ip_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=2, src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(packet, received)

        packet = copy.deepcopy(ETH_IP_IGMP)
        packet[3]["IGMP"]["type"] = 23
        stream_id = tg.set_stream(packet, count=packet_count, igmp_ip_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=2, src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(packet, received)

        packet = copy.deepcopy(ETH_IP_IGMP)
        packet[3]["IGMP"]["type"] = 34
        packet[3]["IGMP"]["maxresp"] = 0
        stream_id = tg.set_stream(packet, count=packet_count, igmp_ip_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=2, src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(packet, received)

        packet_count = 4
        packet = copy.deepcopy(ETH_IP_IGMP)
        packet[3]["IGMP"]["type"] = 22
        stream_id = tg.set_stream(packet, count=packet_count, igmp_ip_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=2, src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(packet, received)

    def test_check_increment_ip_icmp(self, tg):
        """Check all fields in incremented packet. IP.src increment.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id = tg.set_stream(ETH_IP_ICMP, count=packet_count, sip_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=3, src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(ETH_IP_ICMP, received)

    def test_check_increment_udp_sport(self, tg):
        """Check all fields in incremented packet. UDP.sport increment.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, sudp_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=2, src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(ETH_IP_UDP, received)

    def test_check_increment_udp_dport(self, tg):
        """Check all fields in incremented packet. UDP.dport increment.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id = tg.set_stream(ETH_IP_UDP, count=packet_count, dudp_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=2, src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(ETH_IP_UDP, received)

    def test_check_increment_dot1q_vlan_single(self, tg):
        """Check all fields in incremented packet. Dot1Q.vlan increment.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, vlan_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=2, src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(DOT1Q_IP_UDP, received)

    def test_check_increment_dot1q_vlan_double(self, tg):
        """Check all fields in incremented packet. Dot1Q.vlan increment.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id = tg.set_stream(QINQ, count=packet_count, vlan_increment=(2, 5), iface=iface)
        tg.start_sniff([iface], sniffing_time=2, src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(QINQ, received)

    def test_stop_sniffing(self, tg):
        """Start continuous stream and stop sniffing.

        """
        iface = tg.ports[0]
        stream_id_1 = tg.set_stream(PACKET_DEFINITION, continuous=True, iface=iface)

        tg.start_sniff([iface])
        tg.start_streams([stream_id_1])
        tg.stop_streams([stream_id_1])
        tg.stop_sniff([iface])
        start_receive_statistics = tg.get_received_frames_count(iface)
        end_receive_statistics = tg.get_received_frames_count(iface)

        assert start_receive_statistics == end_receive_statistics

    def test_packet_with_ipoption(self, tg):
        """Test building packet with IPOption.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id = tg.set_stream(ETH_IP_IGMP, count=packet_count, iface=iface, adjust_size=False)
        tg.start_sniff([iface], sniffing_time=2)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(ETH_IP_IGMP, received)

    def test_dot1q_arp_filter(self, tg):
        """Check Dot1Q.ARP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id_1 = tg.set_stream(DOT1Q_ARP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ARP, count=packet_count, iface=iface)

        tg.start_sniff([iface], sniffing_time=2, filter_layer="Dot1Q.ARP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified Dot1Q.ARP filter layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(DOT1Q_ARP, received)

    def test_dot1q_arp_custom_filter(self, tg):
        """Check Dot1Q.ARP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        filter_dot1q_arp = (12, "81 00 00 00 08 06", "00 00 FF FF 00 00")
        stream_id_1 = tg.set_stream(DOT1Q_ARP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ARP, count=packet_count, iface=iface)

        tg.start_sniff([iface], sniffing_time=5, filter_layer="Dot1Q.ARP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified Dot1Q.ARP filter layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

        p1 = packets[0]
        tg.start_sniff([iface], sniffing_time=5, filter_layer=filter_dot1q_arp)
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])
        # Verify that only packets with specified Dot1Q.ARP filter layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

        p2 = packets[0]
        assert p1.bin() == p2.bin()

    def test_not_arp_filter(self, tg):
        """Check notARP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id_1 = tg.set_stream(DOT1Q_IP_ICMP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ARP, count=packet_count, iface=iface)
        stream_id_3 = tg.set_stream(ETH_IP_UDP, count=packet_count, iface=iface)
        stream_id_4 = tg.set_stream(DOT1Q_ARP, count=packet_count, iface=iface)

        tg.start_sniff([iface], sniffing_time=4, filter_layer="notARP",
                       src_filter=SRC_MAC)
        tg.start_streams([stream_id_1, stream_id_2, stream_id_3, stream_id_4])
        tg.stop_streams([stream_id_1, stream_id_2, stream_id_3, stream_id_4])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified ARP filter layer are sniffed
        assert len(packets) == packet_count * 3, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

    def test_dot1q_filter(self, tg):
        """Check Dot1Q filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id_1 = tg.set_stream(DOT1Q_ARP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ARP, count=packet_count, iface=iface)

        tg.start_sniff([iface], sniffing_time=4, filter_layer="Dot1Q.ARP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified Dot1Q filter layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        assert tg.get_packet_field(packets[0], "Ethernet", "vlan")

    def test_dot1q_custom_filter(self, tg):
        """Check Dot1Q filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        filter_dot1q_arp = (12, "81 00 00 00 08 06", "00 00 FF FF 00 00")
        stream_id_1 = tg.set_stream(DOT1Q_ARP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ARP, count=packet_count, iface=iface)

        tg.start_sniff([iface], sniffing_time=2, filter_layer="Dot1Q.ARP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified Dot1Q filter layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

        p1 = packets[0]
        tg.start_sniff([iface], sniffing_time=2, filter_layer=filter_dot1q_arp)
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified Dot1Q filter layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

        p2 = packets[0]
        assert p1.bin() == p2.bin()

    def test_ip_filter(self, tg):
        """Check IP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id_1 = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_UDP, count=packet_count, iface=iface)

        tg.start_sniff([iface], sniffing_time=2, filter_layer="IP", dst_filter=DST_MAC)
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified IP filter layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(ETH_IP_UDP, received)

    def test_ip_custom_filter(self, tg):
        """Check IP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        filter_ip = (12, "08 00", "00 00")
        stream_id_1 = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_UDP, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=2, filter_layer="IP", dst_filter=DST_MAC)
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified IP filter layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

        p1 = packets[0]
        tg.start_sniff([iface], sniffing_time=2, filter_layer=filter_ip, dst_filter=DST_MAC)
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified IP filter layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        p2 = packets[0]
        assert p1.bin() == p2.bin()

    def test_dot1q_ip_filter(self, tg):
        """Check Dot1Q.IP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id_1 = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_UDP, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=2, filter_layer="Dot1Q.IP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified Dot1Q.IP filter layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(DOT1Q_IP_UDP, received)

    def test_dot1q_ip_custom_filter(self, tg):
        """Check Dot1Q.IP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        filter_dot1q_ip = (12, "81 00 00 00 08 00", "00 00 FF FF 00 00")
        stream_id_1 = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_UDP, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=2, filter_layer="Dot1Q.IP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified Dot1Q.IP filter layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

        p1 = packets[0]
        tg.start_sniff([iface], sniffing_time=2, filter_layer=filter_dot1q_ip)
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified Dot1Q.IP filter layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        p2 = packets[0]
        assert p1.bin() == p2.bin()

    @pytest.mark.skip("STP is not integrated yet")
    def test_stp_filter(self, tg):
        """Check STP filter.

        """
        iface = tg.ports[0]
        stream_id_1 = tg.set_stream(STP, count=1, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_UDP, count=1, iface=iface)

        tg.start_sniff([iface], sniffing_time=2, filter_layer="STP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])

        # Verify that only packets with specified STP layer are sniffed
        assert len(data[iface]) == 1

        assert tg.get_packet_layer(data[iface][0], "STP") is not None

    @pytest.mark.skip("STP is not integrated yet")
    def test_stp_custom_filter(self, tg):
        """Check STP filter.

        """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(STP, count=1, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_UDP, count=1, iface=iface)

        tg.start_sniff([iface], sniffing_time=2, filter_layer="STP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])

        # Verify that only packets with specified STP layer are sniffed
        assert len(data[iface]) == 1

        p1 = data[iface][0]

        tg.start_sniff([iface], sniffing_time=2, filter_layer=(14, "42 42 03 00 00", "00 00 00 00 00"))
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])

        # Verify that only packets with specified STP layer are sniffed
        assert len(data[iface]) == 1

        p2 = data[iface][0]

        assert p1.bin() == p2.bin()

    @pytest.mark.skip("STP is not integrated yet")
    def test_not_stp_filter(self, tg):
        """Check notSTP filter.

        """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(STP, count=1, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_UDP, count=1, iface=iface)

        tg.start_sniff([iface], sniffing_time=2, filter_layer="notSTP",
                       src_filter=SRC_MAC)
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])

        # Verify that only packets with specified not STP layer are sniffed
        assert len(data[iface]) == 1

        assert tg.get_packet_layer(data[iface][0], "STP") is None

    def test_tcp_filter(self, tg):
        """Check TCP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id_1 = tg.set_stream(ETH_IP_UDP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_TCP, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=2, filter_layer="TCP", dst_filter=DST_MAC)
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified TCP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(ETH_IP_TCP, received)

    def test_tcp_custom_filter(self, tg):
        """Check TCP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        filter_tcp = (12, "08 00 00 00 00 00 00 00 00 00 00 06", "00 00 FF FF FF FF FF FF FF FF FF 00")
        stream_id_1 = tg.set_stream(ETH_IP_UDP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_TCP, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=2, filter_layer="TCP", dst_filter=DST_MAC)
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified TCP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

        p1 = packets[0]
        tg.start_sniff([iface], sniffing_time=2, filter_layer=filter_tcp, dst_filter=DST_MAC)
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified TCP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        p2 = packets[0]
        assert p1.bin() == p2.bin()

    def test_dot1q_tcp_filter(self, tg):
        """Check Dot1Q.TCP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id_1 = tg.set_stream(DOT1Q_IP_TCP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_TCP, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=2, filter_layer="Dot1Q.TCP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified Dot1Q.TCP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(DOT1Q_IP_TCP, received)

    def test_dot1q_tcp_custom_filter(self, tg):
        """Check Dot1Q.TCP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        filter_dot1q_tcp = (12, "81 00 00 00 08 00 00 00 00 00 00 00 00 00 00 06",
                            "00 00 FF FF 00 00 FF FF FF FF FF FF FF FF FF 00")
        stream_id_1 = tg.set_stream(DOT1Q_IP_TCP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_TCP, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=2, filter_layer="Dot1Q.TCP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified Dot1Q.TCP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

        p1 = packets[0]
        tg.start_sniff([iface], sniffing_time=2, filter_layer=filter_dot1q_tcp)
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified Dot1Q.TCP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        p2 = packets[0]
        assert p1.bin() == p2.bin()

    def test_udp_filter(self, tg):
        """Check UDP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id_1 = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_UDP, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=2, filter_layer="UDP", src_filter=SRC_MAC)
        tg.start_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified UDP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(ETH_IP_UDP, received)

    def test_udp_custom_filter(self, tg):
        """Check UDP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        filter_udp = (12, "08 00 00 00 00 00 00 00 00 00 00 11",
                      "00 00 FF FF FF FF FF FF FF FF FF 00")
        stream_id_1 = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_UDP, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=2, filter_layer="UDP", src_filter=SRC_MAC)
        tg.start_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified UDP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

        p1 = packets[0]
        tg.start_sniff([iface], sniffing_time=2, filter_layer=filter_udp, src_filter=SRC_MAC)
        tg.start_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified UDP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        p2 = packets[0]
        assert p1.bin() == p2.bin()

    def test_dot1q_udp_filter(self, tg):
        """Check Dot1Q.UDP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id_1 = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_UDP, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=2, filter_layer="Dot1Q.UDP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified Dot1Q.UDP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(DOT1Q_IP_UDP, received)

    def test_dot1q_udp_custom_filter(self, tg):
        """Check Dot1Q.UDP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        filter_dot1q_udp = (12, "81 00 00 00 08 00 00 00 00 00 00 00 00 00 00 11",
                            "00 00 FF FF 00 00 FF FF FF FF FF FF FF FF FF 00")
        stream_id_1 = tg.set_stream(DOT1Q_IP_UDP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_UDP, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=2, filter_layer="Dot1Q.UDP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified Dot1Q.UDP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

        p1 = packets[0]
        tg.start_sniff([iface], sniffing_time=2, filter_layer=filter_dot1q_udp)
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified Dot1Q.UDP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        p2 = packets[0]
        assert p1.bin() == p2.bin()

    def test_icmp_filter(self, tg):
        """Check ICMP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id_1 = tg.set_stream(DOT1Q_IP_ICMP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_ICMP, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=2, filter_layer="ICMP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified ICMP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(ETH_IP_ICMP, received)

    def test_icmp_custom_filter(self, tg):
        """Check ICMP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        filter_icmp = (12, "08 00 00 00 00 00 00 00 00 00 00 01",
                       "00 00 FF FF FF FF FF FF FF FF FF 00")
        stream_id_1 = tg.set_stream(DOT1Q_IP_ICMP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_ICMP, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=2, filter_layer="ICMP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified ICMP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

        p1 = packets[0]
        tg.start_sniff([iface], sniffing_time=2, filter_layer=filter_icmp)
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified ICMP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        p2 = packets[0]
        assert p1.bin() == p2.bin()

    def test_dot1q_icmp_filter(self, tg):
        """Check Dot1Q.ICMP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id_1 = tg.set_stream(DOT1Q_IP_ICMP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_ICMP, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=2, filter_layer="Dot1Q.ICMP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified Dot1Q.ICMP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(DOT1Q_IP_ICMP, received)

    def test_dot1q_icmp_custom_filter(self, tg):
        """Check Dot1Q.ICMP filter.

        """
        iface = tg.ports[0]
        packet_count = 1
        filter_dot1q_icmp = (12, "81 00 00 00 08 00 00 00 00 00 00 00 00 00 00 01",
                             "00 00 FF FF 00 00 FF FF FF FF FF FF FF FF FF 00")
        stream_id_1 = tg.set_stream(DOT1Q_IP_ICMP, count=packet_count, iface=iface)
        stream_id_2 = tg.set_stream(ETH_IP_ICMP, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=2, filter_layer="Dot1Q.ICMP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified Dot1Q.ICMP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)

        p1 = packets[0]
        tg.start_sniff([iface], sniffing_time=2, filter_layer=filter_dot1q_icmp)
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        # Verify that only packets with specified Dot1Q.ICMP layer are sniffed
        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        p2 = packets[0]
        assert p1.bin() == p2.bin()

    @pytest.mark.skip("BGP is not integrated yet")
    def test_build_bgp_packet_simple(self, tg):
        """Check building BGP packet.

        """
        iface = tg.ports[0]

        src_mac = '00:00:00:00:00:cc'
        dst_mac = '00:00:00:00:00:99'
        bgp_open = ({"Ether": {"src": src_mac, "dst": dst_mac, "type": 0x8100}},
                    {"Dot1Q": {"vid": 7}},
                    {"IP": {"dst": "10.0.0.1", "src": "10.0.0.2", "tos": 6}},
                    {"TCP": {"sport": 179, "dport": 47330, "seq": 305, "ack": 887850408, "flags": 0x18}},
                    {"BGPHeader": {"type": 2}},
                    {"BGPUpdate": {"withdrawn_len": 0, "withdrawn": [], "nlri": [(24, '20.1.1.0')],
                                   "total_path": [{"BGPPathAttribute": {"type": 1, "origin": 1}},
                                                  {"BGPPathAttribute": {"type": 2, "aspath": []}}]}}, )
        stream_id = tg.set_stream(bgp_open, count=1, iface=iface)
        tg.start_sniff([iface], sniffing_time=4, filter_layer="Dot1Q.TCP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])

        assert iface in data and data[iface]
        # filter our packets from data
        data[iface] = [x for x in data[iface] if x.get_lfield("Ether", "dst") == dst_mac and x.get_lfield("Ether", "src") == src_mac]
        assert len(data[iface]) == 1

        assert data[iface][0].get_lfield("BGPHeader", "type") is not None
        assert tg.packet_dictionary(data[iface][0])
        assert data[iface][0].get_lcount("BGPPathAttribute") == 2

    @pytest.mark.skip("BGP is not integrated yet")
    def test_build_bgp_packet_as_path(self, tg):
        """Check building BGP packet with multiple as_path.

        """
        iface = tg.ports[0]

        src_mac = '00:00:00:00:00:aa'
        dst_mac = '00:00:00:00:00:bb'
        bgp_update = ({'Ether': {'src': src_mac, 'dst': dst_mac, 'type': 2048}},
                      {'IP': {'frag': 0, 'src': '192.168.0.15', 'proto': 6, 'tos': 0, 'dst': '192.168.0.33',
                              'ttl': 64, 'id': 18669, 'version': 4, 'flags': 2, 'ihl': 5, 'chksum': 28554}},
                      {'TCP': {'reserved': 0, 'seq': 3593706898, 'ack': 2051072118, 'dataofs': 5,
                               'dport': 179, 'window': 32120, 'flags': 24, 'chksum': 21876,
                               'urgptr': 0, 'sport': 2124, 'options': []}},
                      {'BGPHeader': {'type': 4, 'len': 19}},
                      {'BGPHeader': {'type': 2, 'len': 98}},
                      {'BGPUpdate': {'nlri': (16, "172.16.0.0"), 'tp_len': 72, 'withdrawn_len': 0,
                                     'total_path': [
                          {'BGPPathAttribute': {'origin': 2, 'attr_len': 1, 'flags': 64, 'type': 1}},
                          {'BGPPathAttribute': {'flags': 64, 'type': 2, 'attr_len': 10, 'aspath': [
                              {'BGPASPath': {'ases': [500, 500], 'type': 1, 'len': 2}},
                              {'BGPASPath': {'ases': [65211], 'type': 2, 'len': 1}}]}},
                          {'BGPPathAttribute': {'attr_len': 4, 'nexthop': '192.168.0.15', 'flags': 64, 'type': 3}},
                          {'BGPPathAttribute': {'attr_len': 4, 'localpref': 100, 'flags': 64, 'type': 5}},
                          {'BGPPathAttribute': {'attr_len': 0, 'value': '', 'flags': 64, 'type': 6}},
                          {'BGPPathAttribute': {'attr_len': 6, 'aggas': 65210, 'aggorigin': '192.168.0.10',
                                                'flags': 192, 'type': 7}},
                          {'BGPPathAttribute': {'attr_len': 12, 'flags': 192, 'type': 8,
                                                'communities': [4273930241, 51773444, 22282490]}},
                          {'BGPPathAttribute': {'attr_len': 4, 'oi': '192.168.0.15',
                                                'flags': 128, 'type': 9}},
                          {'BGPPathAttribute': {'type': 10, 'flags': 128, 'value': '\xc0\xa8\x00\xfa',
                                                'attr_len': 4}}], }},
                      {'BGPHeader': {'type': 2, 'len': 99}},
                      {'BGPUpdate': {'withdrawn': [], 'nlri': (22, '192.168.4.0'), 'tp_len': 72,
                                     'withdrawn_len': 0, 'total_path': [
                          {'BGPPathAttribute': {'origin': 0, 'attr_len': 1, 'flags': 64, 'type': 1}},
                          {'BGPPathAttribute': {'flags': 64, 'type': 2, 'attr_len': 10, 'aspath': [
                              {'BGPASPath': {'ases': [500, 500], 'type': 1, 'len': 2}},
                              {'BGPASPath': {'ases': [65211], 'type': 2, 'len': 1}}]}},
                          {'BGPPathAttribute': {'attr_len': 4, 'nexthop': '192.168.0.15',
                                                'flags': 64, 'type': 3}},
                          {'BGPPathAttribute': {'attr_len': 4, 'localpref': 100, 'flags': 64, 'type': 5}},
                          {'BGPPathAttribute': {'attr_len': 0, 'value': '', 'flags': 64, 'type': 6}},
                          {'BGPPathAttribute': {'attr_len': 6, 'flags': 192, 'type': 7,
                                                'aggas': 65210, 'aggorigin': "192.168.0.10"}},
                          {'BGPPathAttribute': {'attr_len': 12, 'flags': 192, 'type': 8,
                                                'communities': [4273930241, 51773444, 22282490]}},
                          {'BGPPathAttribute': {'attr_len': 4, 'oi': '192.168.0.15',
                                                'flags': 128, 'type': 9}},
                          {'BGPPathAttribute': {'type': 10, 'flags': 128, 'value': '\xc0\xa8\x00\xfa',
                                                'attr_len': 4}}]}})

        stream_id = tg.set_stream(bgp_update, count=1, iface=iface)

        tg.start_sniff([iface], sniffing_time=4, filter_layer="TCP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])

        assert iface in data and data[iface]
        # filter our packets from data
        data[iface] = [x for x in data[iface] if x.get_lfield("Ether", "dst") == dst_mac and x.get_lfield("Ether", "src") == src_mac]
        assert len(data[iface]) == 1

        assert data[iface][0].get_lfield("BGPHeader", "type") is not None
        assert data[iface][0].get_lfield("BGPUpdate", "total_path") is not None
        assert data[iface][0].get_lfield("BGPPathAttribute", "type") is not None

    @pytest.mark.skip("BGP is not integrated yet")
    def test_build_bgp_notification_packet(self, tg):
        """Check building BGPNotification packet.

        """
        iface = tg.ports[0]

        src_mac = '00:00:00:00:00:cc'
        dst_mac = '00:00:00:00:00:99'
        bgp_open = ({"Ether": {"src": src_mac, "dst": dst_mac, "type": 0x8100}},
                    {"Dot1Q": {"vid": 7}},
                    {"IP": {"dst": "10.0.0.1", "src": "10.0.0.2", "tos": 6}},
                    {"TCP": {"sport": 179, "dport": 47330, "seq": 305, "ack": 887850408, "flags": 0x18}},
                    {"BGPHeader": {"type": 3}},
                    {"BGPNotification": {"ErrorCode": 6, "ErrorSubCode": 1, "Data": '\x00\x01\x01\x00\x00\x00\x02'}},
                    )
        stream_id = tg.set_stream(bgp_open, count=1, iface=iface)
        tg.start_sniff([iface], sniffing_time=4, filter_layer="Dot1Q.TCP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])

        assert iface in data and data[iface]
        # filter our packets from data
        data[iface] = [x for x in data[iface] if x.get_lfield("Ether", "dst") == dst_mac and x.get_lfield("Ether", "src") == src_mac]
        assert len(data[iface]) == 1

        assert data[iface][0].get_lfield("BGPHeader", "type") is not None
        assert tg.packet_dictionary(data[iface][0])
        assert data[iface][0].get_lcount("BGPNotification") == 1

    @pytest.mark.skip("STP is not integrated yet")
    def test_xstp_build_capture(self, tg):
        """Check stp/rstp/mstp build and detection.

        """
        iface = tg.ports[0]

        pack_rstp_2 = ({"Dot3": {"src": "00:00:00:11:11:11", "dst": DST_MAC}},
                       {"LLC": {"dsap": 66, "ssap": 66, "ctrl": 3}},
                       {"STP": {"proto": 0, "version": 2, "v1len": 0}})
        pack_mstp_2 = MSTP + MSTI_BPDU

        stream_id_1 = tg.set_stream(STP, count=2, inter=0.1, iface=iface, adjust_size=False)
        stream_id_2 = tg.set_stream(RSTP, count=2, inter=0.1, iface=iface, adjust_size=False)
        stream_id_3 = tg.set_stream(pack_rstp_2, count=2, inter=0.1, iface=iface, adjust_size=False)
        stream_id_4 = tg.set_stream(RSTP, count=2, inter=0.1, iface=iface, adjust_size=False)
        stream_id_5 = tg.set_stream(pack_mstp_2, count=2, inter=0.1, iface=iface, adjust_size=False)

        tg.start_sniff([iface], sniffing_time=20, filter_layer="STP", src_filter="00:00:00:11:11:11")
        tg.start_streams([stream_id_1, stream_id_2, stream_id_3, stream_id_4, stream_id_5])

        data = tg.stop_sniff([iface])
        tg.stop_streams([stream_id_1, stream_id_2, stream_id_3, stream_id_4, stream_id_5])

        assert iface in data and data[iface]
        assert len(data[iface]) == 10

        # Verify that we captured 2 ConfBPDUs
        assert len([x for x in data[iface] if x.get_lfield("STP", "version") == 0]) == 2
        # Verify that we captured 4 RST BPDUs and all of them have v1len field
        assert len([x for x in data[iface] if x.get_lfield("STP", "version") == 2 and x.get_lfield("STP", "v1len") == 0]) == 4
        # Verify that we captured 4 MST BPDUs
        assert len([x for x in data[iface] if x.get_lfield("STP", "version") == 3]) == 4
        # Verify that 2 MST BPDUs have MSTI Configuration messages
        assert len([x for x in data[iface] if x.get_lfield("STP", "version") == 3 and x.get_lfield("STP", "v3len") > 64 and x.get_lfield("MstiConfigMsg", "rootmac")]) == 2

    def test_double_tagged_packet_1(self, tg):
        """Verify that pypacker can recognize QinQ packets type 0x9100.

        """
        iface = tg.ports[0]
        packet_count = 1
        src_mac = QINQ[0]["Ethernet"]["src"]
        stream_id = tg.set_stream(QINQ, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=2, src_filter=src_mac)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        packet = packets[0]
        # Verify ether type
        assert tg.get_packet_field(packet, "Ethernet", "type") == ETHER_TYPE_IP
        assert tg.get_packet_field(packet, "S-Dot1Q", "type") == ETHER_TYPE_TUNNELING
        assert tg.get_packet_field(packet, "C-Dot1Q", "type") == ETHER_TYPE_8021Q
        # Verify that we have 2 Dot1Q layers with different prio.
        assert tg.get_packet_field(packet, "S-Dot1Q", "prio") == DOT1Q_PRIO_1
        assert tg.get_packet_field(packet, "C-Dot1Q", "prio") == DOT1Q_PRIO_2

    def test_double_tagged_packet_2(self, tg):
        """Verify that pypacker can recognize QinQ packets type 0x88A8.

        """
        iface = tg.ports[0]
        packet_count = 1
        packet = copy.deepcopy(QINQ)
        packet[1]["Dot1Q"]["type"] = ETHER_TYPE_PBRIDGE
        src_mac = packet[0]["Ethernet"]["src"]
        stream_id = tg.set_stream(packet, count=packet_count, iface=iface)
        tg.start_sniff([iface], sniffing_time=2, src_filter=src_mac)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(packet, received)

    def test_default_ether_type(self, tg):
        """Verify that default Ether type for tagged packets is equal to 0x8100.

        """
        iface = tg.ports[0]
        packet_count = 1
        # Define packet without setting type for Ether layer.
        pack = copy.deepcopy(DOT1Q_IP_TCP)
        pack[1]["Dot1Q"]["prio"] = DOT1Q_PRIO_2
        stream_id = tg.set_stream(pack, count=packet_count, iface=iface, adjust_size=False)
        tg.start_sniff([iface], sniffing_time=2, src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        packet = packets[0]
        assert tg.get_packet_field(packet, "Ethernet", "src") == SRC_MAC
        assert tg.get_packet_field(packet, "Ethernet", "dst") == DST_MAC
        assert tg.get_packet_field(packet, "Ethernet", "type") == ETHER_TYPE_IP
        assert tg.check_packet_field(packet, "S-Dot1Q", "vid", VLAN_1)
        assert tg.check_packet_field(packet, "S-Dot1Q", "type", ETHER_TYPE_8021Q)
        assert tg.check_packet_field(packet, "S-Dot1Q", "cfi", DOT1Q_DEFAULT_CFI)
        assert tg.check_packet_field(packet, "S-Dot1Q", "prio", DOT1Q_PRIO_2)

    def test_pause_frames_0001(self, tg):
        """Verify that MAC Control Pause frames with opcode 0x0001 are builded and sniffed correctly.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id = tg.set_stream(PAUSE, count=packet_count, iface=iface, adjust_size=False)
        tg.start_sniff([iface], sniffing_time=2, src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        packet = packets[0]
        assert tg.get_packet_field(packet, "Ethernet", "type") == ETHER_TYPE_EFC
        assert tg.get_packet_field(packet, "FlowControl", "opcode") == PAUSE_CODE
        assert tg.get_packet_field(packet, "Pause", "ptime") == PAUSE_TIME

    def test_pause_frames_0101(self, tg):
        """Verify that MAC Control Pause frames with opcode 0x0101 are builded and sniffed correctly.

        """
        iface = tg.ports[0]
        packet_count = 1
        stream_id = tg.set_stream(PFC, count=packet_count, iface=iface, adjust_size=False)
        tg.start_sniff([iface], sniffing_time=2, src_filter=SRC_MAC)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        packet = packets[0]
        assert tg.get_packet_field(packet, "Ethernet", "type") == ETHER_TYPE_EFC
        assert tg.get_packet_field(packet, "FlowControl", "opcode") == PFC_CODE
        assert tg.get_packet_field(packet, "PFC", "ms") == PFC_MS
        assert tg.get_packet_field(packet, "PFC", "ls_list") == PFC_LS
        assert tg.get_packet_field(packet, "PFC", "time_list") == PFC_TIME

    def test_pause_frames_ffff(self, tg):
        """Verify that MAC Control Pause frames with unknown are builded and sniffed correctly.

        """
        iface = tg.ports[0]
        packet_count = 1
        opcode = 0xffff
        pack = copy.deepcopy(PAUSE)
        pack[1]["FlowControl"]["opcode"] = opcode
        stream_id = tg.set_stream(pack, count=packet_count, iface=iface, adjust_size=False)
        tg.start_sniff([iface], sniffing_time=2)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        received = tg.packet_dictionary(packets[0])
        # Verify received packet is equal to sent packet
        self.verify_packets_data(pack, received)

    @pytest.mark.skip("Pypacker does not support LLDP")
    def test_lldp_build_capture(self, tg):
        """Verify that LLDP packets are builded and sniffed correctly.

        """
        iface = tg.ports[0]

        dst_mac = "01:80:c2:00:00:0e"
        src_mac = "00:00:00:00:00:aa"
        pack = ({'Ether': {'src': src_mac, 'dst': dst_mac, 'type': 35020}},
                {'LLDP': {'tlvlist': [{'LLDPChassisId': {'subtype': 4, 'length': 7, 'macaddr': '00:11:11:11:11:11',
                                                         'type': 1, 'value': None}},
                                      {'LLDPPortId': {'subtype': 3, 'length': 7, 'macaddr': '00:01:7c:d7:de:c9',
                                                      'type': 2, 'value': None}},
                                      {'LLDPTTL': {'seconds': 20, 'length': 2, 'type': 3}},
                                      {'LLDPSystemName': {'length': 8, 'type': 5, 'value': 'windws01'}},
                                      {'LLDPSystemDescription': {'length': 71, 'type': 6,
                                                                 'value': 'Linux 2.6.32-38-generic #83-Ubuntu SMP Wed Jan 4 11:13:04 UTC 2012 i686'}},
                                      {'LLDPSystemCapabilities': {'enabled': 0, 'length': 4, 'type': 7,
                                                                  'capabilities': 28}},
                                      {'LLDPManagementAddress': {'ip6addr': None, 'macaddr': None, 'addrval': None,
                                                                 'ifsubtype': 2, 'ifnumber': 2, 'oid': '1.3.6.1.4.1.731.3.2.30.1.1.7',
                                                                 'ipaddr': '172.20.20.202', 'addrlen': 5,
                                                                 'length': 25, 'oidlen': 13, 'type': 8,
                                                                 'addrsubtype': 1}},
                                      {'LLDPPortDescription': {'length': 4, 'type': 4, 'value': 'imp0'}},
                                      {'LLDPOrgSpecGeneric': {'subtype': 3, 'length': 9, 'type': 127, 'oui': 4623,
                                                              'value': '\x01\x00\x00\x00\x00'}},
                                      {'LLDPOrgSpecGeneric': {'subtype': 1, 'length': 9, 'type': 127, 'oui': 4623,
                                                              'value': '\x00\x00\x00\x00\x0b'}},
                                      {'LLDPOrgSpecGeneric': {'subtype': 4, 'length': 6, 'type': 127, 'oui': 4623,
                                                              'value': '\x05\xdc'}},
                                      {'LLDPOrgSpecGeneric': {'subtype': 1, 'length': 7, 'type': 127, 'oui': 4795,
                                                              'value': '\x00\x00\x00'}},
                                      {'LLDPOrgSpecGeneric': {'subtype': 5, 'length': 18, 'type': 127, 'oui': 4795,
                                                              'value': 'System Version'}},
                                      {'LLDPOrgSpecGeneric': {'subtype': 6, 'length': 11, 'type': 127, 'oui': 4795,
                                                              'value': '0406   '}},
                                      {'LLDPOrgSpecGeneric': {'subtype': 7, 'length': 21, 'type': 127, 'oui': 4795,
                                                              'value': '2.6.32-38-generic'}},
                                      {'LLDPOrgSpecGeneric': {'subtype': 8, 'length': 24, 'type': 127, 'oui': 4795,
                                                              'value': 'System Serial Number'}},
                                      {'LLDPOrgSpecGeneric': {'subtype': 9, 'length': 23, 'type': 127, 'oui': 4795,
                                                              'value': 'System manufacturer'}},
                                      {'LLDPOrgSpecGeneric': {'subtype': 10, 'length': 23, 'type': 127, 'oui': 4795,
                                                              'value': 'System Product Name'}},
                                      {'LLDPOrgSpecGeneric': {'subtype': 11, 'length': 20, 'type': 127, 'oui': 4795,
                                                              'value': 'Asset-1234567890'}},
                                      {'LLDPDUEnd': {'length': 0, 'type': 0}}]}})
        stream_id = tg.set_stream(pack, count=1, iface=iface, adjust_size=False)

        tg.start_sniff([iface], sniffing_time=2)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])

        assert iface in data, "No packets were sniffed."
        # filter our packets from data
        data[iface] = [x for x in data[iface] if x.get_lfield("Ether", "dst") == dst_mac and x.get_lfield("Ether", "src") == src_mac]
        assert len(data[iface]) == 1, "Expected to sniff 1 packet but sniffed %s" % (len(data[iface]), )

        assert data[iface][0].haslayer("Ether")
        assert data[iface][0].haslayer("LLDP")
        assert data[iface][0].haslayer("LLDPChassisId")
        assert data[iface][0].haslayer("LLDPPortId")
        assert data[iface][0].haslayer("LLDPTTL")
        assert data[iface][0].haslayer("LLDPSystemName")
        assert data[iface][0].haslayer("LLDPSystemDescription")
        assert data[iface][0].haslayer("LLDPSystemCapabilities")
        assert data[iface][0].haslayer("LLDPManagementAddress")
        assert data[iface][0].haslayer("LLDPPortDescription")
        assert data[iface][0].haslayer("LLDPOrgSpecGeneric")
        assert data[iface][0].haslayer("LLDPDUEnd")

    @pytest.mark.skip("Pypacker does not support LLDP")
    def test_lldp_dcbx(self, tg):
        """Verify that DCBX packets are built and captured correctly.

        """
        iface = tg.ports[0]

        dst_mac = "01:80:c2:00:00:0e"
        src_mac = "00:00:00:00:00:ee"
        pack_dcbx = ({"Ether": {"dst": dst_mac, "src": src_mac, "type": 0x88cc}},
                     {"LLDP": {"tlvlist": [{"LLDPChassisId": {"type": 1, "length": 7, "subtype": "MAC address", "macaddr": "00:00:01:02:03:04"}},
                                           {"LLDPPortId": {"type": 2, "length": 4, "subtype": "Interface alias", "value": 'ge0'}},
                                           {"LLDPTTL": {"type": 3, "length": 2, "seconds": 40}},
                                           {"LLDPPortDescription": {"type": 4, "length": 0, "value": ""}},
                                           {"LLDPSystemName": {"type": 5, "length": 10, "value": '<sys-name>'}},
                                           {"LLDPSystemDescription": {"type": 6, "length": 10, "value": '<sys-desc>'}},
                                           {"LLDPSystemCapabilities": {"type": 7, "length": 4, "capabilities": "bridge", "enabled": "bridge"}},
                                           {"DCBXConfiguration": {"type": 127, "length": 25, "oui": 0x80c2,
                                                                  "subtype": "ETS Configuration", "willing": 0, "cbs": 0,
                                                                  "reserved": 0, "maxtcs": 3, "priority": [0, 1, 2, 3, 3, 3, 3, 3],
                                                                  "tcbandwith": [50, 50, 0, 0, 0, 0, 0, 0],
                                                                  "tsaassigment": [2, 2, 2, 2, 2, 2, 2, 2]}},
                                           {"DCBXRecommendation": {"type": 127, "length": 25, "oui": 0x80c2,
                                                                   "subtype": "ETS Recommendation", "reserved": 0,
                                                                   "priority": [0, 1, 2, 3, 3, 3, 3, 3],
                                                                   "tcbandwith": [50, 50, 0, 0, 0, 0, 0, 0],
                                                                   "tsaassigment": [2, 2, 2, 2, 2, 2, 2, 2]}},
                                           {"DCBXPriorityBasedFlowControlConfiguration": {"type": 127, "length": 6, "oui": 0x80c2,
                                                                                          "subtype": "Priority-based Flow Control Configuration",
                                                                                          "willing": 0, "mbc": 0, "reserved": 0, "pfccap": 0,
                                                                                          "pfcenable": [0, 0, 0, 0, 0, 0, 0, 0]}},
                                           {"DCBXApplicationPriority": {"type": 127, "length": 5, "oui": 0x80c2,
                                                                        "subtype": "Application Priority", "reserved": 0,
                                                                        "apppriotable": []}},
                                           {"LLDPDUEnd": {"type": 0, "length": 0}}]}})
        stream_id = tg.set_stream(pack_dcbx, count=1, iface=iface, adjust_size=False)

        tg.start_sniff([iface], sniffing_time=2)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])

        assert iface in data, "No packets were sniffed."
        # filter our packets from data
        data[iface] = [x for x in data[iface] if x.get_lfield("Ether", "dst") == dst_mac and x.get_lfield("Ether", "src") == src_mac]
        assert len(data[iface]) == 1, "Expected to sniff 1 packet but sniffed %s" % (len(data[iface]), )

        assert data[iface][0].haslayer("Ether")
        assert data[iface][0].haslayer("LLDP")
        assert data[iface][0].haslayer("LLDPChassisId")
        assert data[iface][0].haslayer("LLDPPortId")
        assert data[iface][0].haslayer("LLDPTTL")
        assert data[iface][0].haslayer("LLDPSystemName")
        assert data[iface][0].haslayer("LLDPSystemDescription")
        assert data[iface][0].haslayer("LLDPSystemCapabilities")
        assert data[iface][0].haslayer("DCBXConfiguration")
        assert data[iface][0].haslayer("DCBXRecommendation")
        assert data[iface][0].haslayer("DCBXPriorityBasedFlowControlConfiguration")
        assert data[iface][0].haslayer("DCBXApplicationPriority")
        assert data[iface][0].haslayer("LLDPDUEnd")

    @pytest.mark.skip("Pypacker does not support LLDP")
    def test_lldp_dcbx_app_prio_table(self, tg):
        """Verify that DCBX packets with Application Priority Tables are built and captured correctly.

        """
        iface = tg.ports[0]

        dst_mac = "01:80:c2:00:00:0e"
        src_mac = "00:00:00:00:00:44"
        pack_dcbx = ({'Ether': {'src': src_mac, 'dst': dst_mac, 'type': 35020}},
                     {'LLDP': {'tlvlist': [{'LLDPChassisId': {'subtype': 4, 'length': 7, 'macaddr': '00:01:04:05:06:22', 'type': 1}},
                                           {'LLDPPortId': {'subtype': 1, 'length': 4, 'type': 2, 'value': 'ge0'}},
                                           {'LLDPTTL': {'seconds': 40, 'length': 2, 'type': 3}},
                                           {'LLDPPortDescription': {'length': 0, 'type': 4, 'value': ''}},
                                           {'LLDPSystemName': {'length': 10, 'type': 5, 'value': '<sys-name>'}},
                                           {'LLDPSystemDescription': {'length': 10, 'type': 6, 'value': '<sys-desc>'}},
                                           {'LLDPSystemCapabilities': {'enabled': 4, 'length': 4, 'type': 7,
                                                                       'capabilities': 4}},
                                           {'DCBXApplicationPriority': {'oui': 0x80c2, 'reserved': 128,
                                                                        'apppriotable': [{'DCBXApplicationPriorityTable': {'priority': 0, 'protocolid': 884,
                                                                                                                           'sel': 2, 'reserved': 0}},
                                                                                         {'DCBXApplicationPriorityTable': {'priority': 0, 'protocolid': 53,
                                                                                                                           'sel': 3, 'reserved': 0}}]}},
                                           {'LLDPDUEnd': {'length': 0, 'type': 0}}]}})

        stream_id = tg.set_stream(pack_dcbx, count=1, iface=iface, adjust_size=False)

        tg.start_sniff([iface], sniffing_time=2)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])

        assert iface in data, "No packets were sniffed."
        # filter our packets from data
        data[iface] = [x for x in data[iface] if x.get_lfield("Ether", "dst") == dst_mac and x.get_lfield("Ether", "src") == src_mac]
        assert len(data[iface]) == 1, "Expected to sniff 1 packet but sniffed %s" % (len(data[iface]), )

        assert data[iface][0].haslayer("Ether")
        assert data[iface][0].haslayer("LLDP")
        assert data[iface][0].haslayer("LLDPChassisId")
        assert data[iface][0].haslayer("LLDPPortId")
        assert data[iface][0].haslayer("LLDPTTL")
        assert data[iface][0].haslayer("DCBXApplicationPriority")
        assert data[iface][0].haslayer("DCBXApplicationPriorityTable")
        assert tg.check_packet_field(data[iface][0], "DCBXApplicationPriorityTable", "protocolid", 884)
        assert tg.check_packet_field(data[iface][0], "DCBXApplicationPriorityTable", "protocolid", 53)
        assert data[iface][0].haslayer("LLDPDUEnd")

    @pytest.mark.skip("Pypacker does not support LLDP")
    def test_lldp_sys_capabilities(self, tg):
        """Verify that LLDP packets with full System capabilities list are built and captured correctly.

        """
        iface = tg.ports[0]

        dst_mac = "01:80:c2:00:00:0e"
        src_mac = "00:00:00:00:00:77"

        pack = ({"Ether": {"dst": dst_mac, "src": src_mac, "type": 0x88cc}},
                {"LLDP": {"tlvlist": [{"LLDPChassisId": {"type": 1, "length": 7, "subtype": "MAC address",
                                                         "macaddr": "00:01:02:03:04:11"}},
                                      {"LLDPPortId": {"type": 2, "length": 4, "subtype": "Interface alias", "value": 'ge0'}},
                                      {"LLDPTTL": {"type": 3, "length": 2, "seconds": 20}},
                                      {"LLDPPortDescription": {"type": 4, "length": 0, "value": ""}},
                                      {"LLDPSystemName": {"type": 5, "length": 10, "value": '<sys-name>'}},
                                      {"LLDPSystemDescription": {"type": 6, "length": 10, "value": '<sys-desc>'}},
                                      {"LLDPSystemCapabilities": {"type": 7, "length": 4,
                                                                  "capabilities": "other+repeater+bridge+router+telephone",
                                                                  "enabled": "other+repeater+bridge+router"}},
                                      {"LLDPDUEnd": {"type": 0, "length": 0}}]}})
        stream_id = tg.set_stream(pack, count=1, iface=iface, adjust_size=False)

        tg.start_sniff([iface], sniffing_time=2)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])

        assert iface in data, "No packets were sniffed."
        # filter our packets from data
        data[iface] = [x for x in data[iface] if x.get_lfield("Ether", "dst") == dst_mac and x.get_lfield("Ether", "src") == src_mac]
        assert len(data[iface]) == 1, "Expected to sniff 1 packet but sniffed %s" % (len(data[iface]), )

        assert data[iface][0].haslayer("Ether")
        assert data[iface][0].haslayer("LLDP")
        assert data[iface][0].haslayer("LLDPSystemCapabilities")
        assert data[iface][0].get_lfield("LLDPSystemCapabilities", "capabilities") == 55
        assert data[iface][0].get_lfield("LLDPSystemCapabilities", "enabled") == 23
        assert data[iface][0].haslayer("LLDPDUEnd")

    @pytest.mark.skip("Pypacker does not support LLDP")
    def test_lldp_with_padding(self, tg):
        """Verify that LLDP packets with with padding are built and captured correctly.

        """
        iface = tg.ports[0]

        dst_mac = "01:80:c2:00:00:0e"
        src_mac = "00:00:00:00:00:22"

        pack = ({"Ether": {"dst": dst_mac, "src": src_mac, "type": 0x88cc}},
                {"LLDP": {'tlvlist': [{'LLDPChassisId': {'subtype': 4, 'macaddr': '00:02:10:00:03:02'}},
                                      {'LLDPPortId': {'subtype': 2, 'value': 'xe1'}},
                                      {'LLDPTTL': {'seconds': 0}},
                                      {'LLDPDUEnd': {}}]}},
                {"Raw": {'load': "\x00" * 10}},
                {"Padding": {'load': "\x00" * 10}},)
        stream_id = tg.set_stream(pack, count=1, iface=iface, adjust_size=False)

        tg.start_sniff([iface], sniffing_time=2)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])

        assert iface in data, "No packets were sniffed."
        # filter our packets from data
        data[iface] = [x for x in data[iface] if x.get_lfield("Ether", "dst") == dst_mac and x.get_lfield("Ether", "src") == src_mac]
        assert len(data[iface]) == 1, "Expected to sniff 1 packet but sniffed %s" % (len(data[iface]), )

        assert data[iface][0].haslayer("Ether")
        assert data[iface][0].haslayer("LLDP")
        assert data[iface][0].haslayer("LLDPChassisId")
        assert data[iface][0].haslayer("LLDPPortId")
        assert data[iface][0].haslayer("LLDPTTL")
        assert data[iface][0].haslayer("LLDPDUEnd")

    @pytest.mark.skip("Pypacker does not support LACP")
    def test_lacp_layers(self, tg):
        """Verify that LACP packets are built and captured correctly.

        """
        iface = tg.ports[0]

        dst_mac = "01:80:c2:00:00:02"
        src_mac = "00:00:00:00:11:22"

        pack = ({"Ethernet": {"dst": dst_mac, "src": src_mac, "type": 0x8809}},
                {"LACP": {'subtype': 1, 'version': 1}},
                {"LACPActorInfoTlv": {'type': 1, 'length': 20, 'sysprio': 32768, 'sys': "00:11:00:ff:00:aa",
                                      'key': 0, 'portprio': 32768, "port": 2,
                                      'expired': 1, 'defaulted': 0, 'distribute': 1, 'collect': 0,
                                      'synch': 1, 'aggregate': 0, 'timeout': 1, 'activity': 1,
                                      'reserved': "\x00" * 3}},
                {"LACPPartnerInfoTlv": {'type': 2, 'length': 20, 'sysprio': 32768, 'sys': "00:ee:00:ff:00:aa",
                                        'key': 0, 'portprio': 32768, "port": 1,
                                        'expired': 1, 'defaulted': 0, 'distribute': 1, 'collect': 0,
                                        'synch': 1, 'aggregate': 1, 'timeout': 0, 'activity': 1,
                                        'reserved': "\x00" * 3}},
                {"LACPCollectorInfoTlv": {'type': 3, 'length': 16, 'maxdelay': 10, "reserved": "\x00" * 12}},
                {"LACPTerminatorTlv": {'type': 0, 'length': 0}},
                {"LACPReserved": {'reserved': "\x00" * 50}}, )
        stream_id = tg.set_stream(pack, count=1, iface=iface, adjust_size=False)

        tg.start_sniff([iface], sniffing_time=2, dst_filter=dst_mac, src_filter=src_mac)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])

        assert iface in data, "No packets were sniffed."
        assert len(data[iface]) == 1, "Expected to sniff 1 packet but sniffed %s" % (len(data[iface]), )

        assert data[iface][0].haslayer("Ether")
        assert data[iface][0].haslayer("LACP")
        assert data[iface][0].haslayer("LACPActorInfoTlv")
        assert data[iface][0].haslayer("LACPPartnerInfoTlv")
        assert data[iface][0].haslayer("LACPCollectorInfoTlv")
        assert data[iface][0].haslayer("LACPTerminatorTlv")
        assert data[iface][0].haslayer("LACPReserved")

    def test_pproc_packet_fragmentation_1(self, tg):
        """Check packet fragmentation.

        """
        fragments = tg.packet_fragment(ETH_IP_ICMP, required_size=200, fragsize=110)
        assert len(fragments) == 2

    def test_pproc_packet_fragmentation_2(self, tg):
        """Check packet fragmentation. fragsize is None.

        """
        fragments = tg.packet_fragment(ETH_IP_ICMP, required_size=200)
        assert len(fragments) == 1

    def test_pproc_packet_dictionary(self, tg):
        """Check packet dictionary. Fragsize is None.

        """
        fragments = tg.packet_fragment(DOT1Q_IP_UDP, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == DOT1Q_IP_UDP

        fragments = tg.packet_fragment(DOT1Q_IP_TCP, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == DOT1Q_IP_TCP

        fragments = tg.packet_fragment(DOT1Q_IP_ICMP, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == DOT1Q_IP_ICMP

        fragments = tg.packet_fragment(DOT1Q_ARP, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == DOT1Q_ARP

        fragments = tg.packet_fragment(ETH_IP_ICMP, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == ETH_IP_ICMP

        fragments = tg.packet_fragment(ETH_IP_UDP, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == ETH_IP_UDP

        fragments = tg.packet_fragment(ETH_IP_TCP, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == ETH_IP_TCP

        fragments = tg.packet_fragment(ARP, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == ARP

        fragments = tg.packet_fragment(DOT1Q, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == DOT1Q

        fragments = tg.packet_fragment(QINQ, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == QINQ

        fragments = tg.packet_fragment(STP, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == STP

    @pytest.mark.skip("DHCP is not integrated yet")
    def test_dhcp_ip_incrementation(self, tg):
        """Check dhcp ip incrementation. Count == Increment count.

        """
        iface = tg.ports[0]

        dhcp_request = ({"Ether": {"dst": BROADCAT_MAC, "src": '00:00:10:00:01:02'}},
                        {"IP": {"src": "0.0.0.0", "dst": "255.255.255.255", "ttl": 128}},
                        {"UDP": {"sport": 68, "dport": 67}},
                        {"BOOTP": {"chaddr": '00:00:10:00:01:02', "op": 1, "hops": 0, "siaddr": '10.0.3.3'}},
                        {"DHCP": {"options": [("message-type", "request"), "end"]}})

        stream_id = tg.set_stream(dhcp_request, count=5, dhcp_si_increment=(2, 5), required_size=346, iface=iface)

        tg.start_sniff([iface], sniffing_time=5, filter_layer="IP", src_filter="00:00:10:00:01:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface])

        assert iface in list(data.keys())

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different src ip
        src_ip_set = set()
        for packet in data[iface]:
            src_ip_set.add(tg.get_packet_field(packet, "BOOTP", "siaddr"))
        assert len(src_ip_set) == 5

    @pytest.mark.parametrize("padding_size", [26, 1476])
    def test_send_sniff_max_min_packets(self, tg, padding_size):
        """Verify sending and sniffing of packets with minimal and maximal size.

        """
        # 26(padding) + 20(ip header) + 14(ether header) + 4(crc) = 64
        # 1476(padding) + 20(ip header) + 14(ether header) + 4(crc) = 1514
        iface = tg.ports[0]
        packet_count = 1
        padding = b""
        eth_len, ip_len, crc = 14, 20, 4
        packet_size = padding_size + ip_len + eth_len + crc
        for _ in range(padding_size):
            padding += chr(random.randint(0, 16)).encode()

        # send packet, sniff pkt stream
        pkt = ({"Ethernet": {"src": SRC_MAC, "dst": DST_MAC, "padding": padding}},
               {"IP": {"src": IP_SRC, "dst": IP_DST, "p": IP_PROTO_IP}})
        tg.start_sniff([iface], sniffing_time=3,
                       filter_layer="IP", src_filter=SRC_MAC, dst_filter=DST_MAC)
        tg.send_stream(tg.set_stream(pkt, count=packet_count, iface=iface, required_size=packet_size))
        data = tg.stop_sniff([iface])
        packets = data.get(iface, [])

        assert len(packets) == packet_count, \
            "Captured packets count {0} does not match expected {1}".format(len(packets), packet_count)
        packet = packets[0]
        # Expected size ==  Actual size
        assert packet_size == len(packet), \
            "Expected size: {0}\nActual size: {1}".format(packet_size, len(packet))
        # Get padding and compare to original
        received_padding = tg.get_packet_field(packet, "Ethernet", "padding")
        assert padding_size + crc == len(received_padding)

    def test_incrementation_negative_1(self, tg):
        """Verify that method set_stream returns Error message when layer is not defined in packet(1).

        """
        if tg.type == 'ixiahl':
            pytest.skip("This behavior isn't supported by IXIA TG")
        iface = tg.ports[0]
        packet = ({"Ethernet": {"src": SRC_MAC, "dst": DST_MAC, "type": ETHER_TYPE_IP}},
                  {"TCP": {}})
        exception_message = []
        kwargs = [{"sipv6_increment": (3, 5)},
                  {"dipv6_increment": (3, 5)},
                  {"sudp_increment": (3, 5)},
                  {"dudp_increment": (3, 5)},
                  {"fl_increment": (3, 5)},
                  {"vlan_increment": (3, 5)},
                  {"igmp_ip_increment": (1, 5)},
                  {"arp_sip_increment": (2, 5)},
                  {"dscp_increment": (1, 5)},
                  {"protocol_increment": (2, 5)}]

        for kwarg in kwargs:
            with pytest.raises(PypackerException) as excepinfo:
                tg.set_stream(packet, count=5, iface=iface, **kwarg)
            exception_message.append(excepinfo.value.parameter)

        # verify expected result
        result = ["Layer UDP is not defined", "Layer IP6 is not defined",
                  "VLAN tag is not defined", "Layer IGMP is not defined",
                  "Layer ARP is not defined", "Layer IP is not defined"]
        assert len(exception_message) == len(kwargs)
        assert set(exception_message) == set(result)

    def test_incrementation_negative_2(self, tg):
        """Verify that method set_stream returns Error message when when layer is not defined in packet(2).

        """
        if tg.type == 'ixiahl':
            pytest.skip("This behavior isn't supported by IXIA TG")
        iface = tg.ports[0]
        packet = ({"IP": {"src": IP_SRC, "dst": IP_DST}}, {"TCP": {}})
        exception_message = []
        kwargs = [{"sa_increment": (3, 5)},
                  {"da_increment": (3, 5)},
                  {"arp_sa_increment": (3, 5)},
                  {"eth_type_increment": (3, 5)}]

        for kwarg in kwargs:
            with pytest.raises(PypackerException) as excepinfo:
                tg.set_stream(packet, count=5, iface=iface, **kwarg)
            exception_message.append(excepinfo.value.parameter)

        # verify expected result
        result = ["Layer Ethernet is not defined", "Layer Ethernet is not defined",
                  "Layer Ethernet is not defined", "Layer Ethernet is not defined"]
        assert len(exception_message) == len(kwargs)
        assert set(exception_message) == set(result)

    def test_send_stream_several_times(self, tg):
        """Send stream several times and check statistics.

        """
        iface = tg.ports[0]
        packet_count = 10000
        stream_id_1 = tg.set_stream(PACKET_DEFINITION, count=packet_count, rate=0.01, iface=iface)
        tg.clear_statistics([iface])

        tg.send_stream(stream_id_1)
        end_sent_statistics = tg.get_sent_frames_count(iface)
        assert end_sent_statistics == packet_count

        # Send stream again and verify all packets were sent
        tg.send_stream(stream_id_1)
        end_sent_statistics = tg.get_sent_frames_count(iface)
        assert end_sent_statistics == 2 * packet_count

    def test_send_several_streams(self, tg):
        """Send several streams.

        """
        iface = tg.ports[0]
        packets_count = 20
        src_mac = PACKET_DEFINITION[0]["Ethernet"]["src"]

        tg.clear_statistics([iface])
        stream_1 = tg.set_stream(PACKET_DEFINITION, count=packets_count // 2, inter=0.1, iface=iface)
        stream_2 = tg.set_stream(PACKET_DEFINITION, count=packets_count // 2, inter=0.1, iface=iface)
        tg.start_sniff([iface], sniffing_time=4, src_filter=src_mac)
        tg.send_stream(stream_1)
        tg.send_stream(stream_2)
        data = tg.stop_sniff([iface])

        assert iface in data
        assert len(data[iface]) == packets_count
        sent_statistics = tg.get_sent_frames_count(iface)
        assert sent_statistics == packets_count
