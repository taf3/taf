"""
@copyright Copyright (c) 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file test_trextg.py

@summary TRex traffic generator's unittests.

@note To run TRex unittests:
        1. Install TRex client package
        2. Configure and start TRex server
        3. Specify IP address and ports in the following variables: TREX_HLT_CONFIG, TREX_CONFIG
"""

import time

import pytest

try:
    skip_flag = False
    from testlib import dev_trextg
except ImportError:
    skip_flag = True


TREX_CONFIG = {"name": "TRex", "entry_type": "tg", "instance_type": "trex", "id": "id_number",
               "ipaddr": "X.X.X.X", "ssh_user": "", "ssh_pass": "",
               "ports": [0, 1]}

TREX_HLT_CONFIG = {"name": "TRex", "entry_type": "tg", "instance_type": "trex", "id": "id_number",
                   "trex_hltapi": True, "ipaddr": "X.X.X.X", "ssh_user": "", "ssh_pass": "",
                   "ports": [0, 1]}


@pytest.fixture
def trex(request):
    tg = dev_trextg.Trex(TREX_CONFIG, request.config.option)
    tg.create()
    tg.cleanup()
    request.addfinalizer(tg.destroy)
    return tg


@pytest.fixture
def trex_hlt(request):
    tg = dev_trextg.Trex(TREX_HLT_CONFIG, request.config.option)
    tg.create()
    tg.cleanup()
    request.addfinalizer(tg.destroy)
    return tg


@pytest.mark.skipif(skip_flag, reason="Need to install TRex client package")
class TestTrexTg(object):

    packet_definition = ({"Ether": {"dst": "ff:ff:ff:ff:ff:ff", "src": "00:00:00:00:00:02"}}, {"IP": {"src": '10.1.1.1', "dst": '20.1.1.1'}}, {"UDP": {"sport": 10, "dport": 50}},)

    packet_definition_tcp = ({"Ether": {"dst": "ff:ff:ff:ff:ff:ff", "src": "00:00:00:00:00:02"}}, {"IP": {"src": '10.1.1.1', "dst": '20.1.1.1'}}, {"TCP": {"sport": 10, "dport": 50}},)

    def test_single_stream_trex(self, trex):
        """
        @brief  Send single stream using send_stream method
        """
        # Define interface and packet
        iface = trex.ports[0]
        packet_count = 1
        # Set traffic stream
        stream_id = trex.set_stream(self.packet_definition, count=packet_count, iface=iface, adjust_size=True)
        # Send traffic
        trex.send_stream(stream_id)
        time.sleep(1)
        # Stop stream
        trex.stop_streams([stream_id])
        # get and verify interface statistic
        data = trex.get_statistics(iface)
        assert data['opackets'] == packet_count

    def test_send_2_streams_trex(self, trex):
        """
        @brief  Send 2 streams using send_stream method on different interfaces
        """
        # Define interface and packet
        iface1 = trex.ports[0]
        iface2 = trex.ports[1]
        packet_count1 = 1
        packet_count2 = 10
        # Set traffic streams
        stream_id1 = trex.set_stream(self.packet_definition, count=packet_count1, iface=iface1, required_size=1024)
        stream_id2 = trex.set_stream(self.packet_definition, count=packet_count2, iface=iface2, required_size=64)
        # Send traffic streams
        trex.send_stream(stream_id1)
        trex.send_stream(stream_id2)
        time.sleep(1)
        # Stop streams
        trex.stop_streams([stream_id1, stream_id2])
        # get and verify interfaces statistics
        data = trex.get_statistics(iface1)
        data2 = trex.get_statistics(iface2)
        assert data['opackets'] == packet_count1
        assert data2['opackets'] == packet_count2

    def test_send_2_streams_on_same_interface_trex(self, trex):
        """
        @brief  Send 2 streams using send_stream method on same interface
        """
        # Define interface and packet
        iface = trex.ports[0]
        packet_count1 = 1
        packet_count2 = 10
        # Set traffic streams
        stream_id1 = trex.set_stream(self.packet_definition, count=packet_count1, iface=iface, required_size=1024)
        stream_id2 = trex.set_stream(self.packet_definition, count=packet_count2, iface=iface, required_size=64)
        # Send traffic streams
        trex.send_stream(stream_id1)
        time.sleep(1)
        # Stop first stream and send next stream
        trex.stop_streams([stream_id1])
        trex.send_stream(stream_id2)
        time.sleep(1)
        # Stop second stream
        trex.stop_streams([stream_id2])
        # get and verify interface statistics
        data = trex.get_statistics(iface)
        assert data['opackets'] == packet_count1 + packet_count2

    def test_start_2_streams_trex(self, trex):
        """
        @brief  Send 2 streams using start_streams method on different interfaces
        """
        # Define interfaces and packets
        iface1 = trex.ports[0]
        iface2 = trex.ports[1]
        packet_count = 1
        # Set traffic streams
        stream_id1 = trex.set_stream(self.packet_definition, count=packet_count, iface=iface1, required_size=1024)
        stream_id2 = trex.set_stream(self.packet_definition, count=packet_count, iface=iface2, required_size=64)
        # Send streams
        trex.start_streams([stream_id1, stream_id2])
        time.sleep(1)
        # Stop streams
        trex.stop_streams([stream_id1])
        # get and verify interfaces statistic
        data = trex.get_statistics(iface1)
        data2 = trex.get_statistics(iface2)
        assert data['opackets'] == packet_count
        assert data2['opackets'] == packet_count

    def test_start_2_streams_on_same_interface_trex(self, trex):
        """
        @brief  Send 2 streams using start_streams method on same interface
        """
        # Define interface and packets
        iface = trex.ports[0]
        packet_count1 = 1
        packet_count2 = 10
        # Set traffic streams
        stream_id1 = trex.set_stream(self.packet_definition, count=packet_count1, rate=50, iface=iface)
        stream_id2 = trex.set_stream(self.packet_definition, count=packet_count2, rate=50, iface=iface)
        # Send streams
        trex.start_streams([stream_id1, stream_id2])
        time.sleep(1)
        # Stop streams
        trex.stop_streams([stream_id1, stream_id2])
        # get and verify interfaces statistic
        data = trex.get_statistics(iface)
        assert data['opackets'] == packet_count1 + packet_count2

    def test_start_2_continuous_streams_trex(self, trex):
        """
        @brief  Send 2 continuous streams using start_streams method on different interfaces
        """
        # Define interfaces and packets size
        iface1 = trex.ports[0]
        iface2 = trex.ports[1]
        size1 = 1024
        size2 = 64
        # Set continuous traffic streams
        stream_id1 = trex.set_stream(self.packet_definition, continuous=True, iface=iface1, required_size=size1)
        stream_id2 = trex.set_stream(self.packet_definition, continuous=True, iface=iface2, required_size=size2)
        # Send streams
        trex.start_streams([stream_id1, stream_id2])
        time.sleep(2)
        # Stop streams
        trex.stop_streams([stream_id1, stream_id2])
        # get and verify interfaces statistics
        data = trex.get_statistics(iface1)
        data2 = trex.get_statistics(iface2)
        assert data['opackets'] != 0
        assert data2['opackets'] != 0
        assert data['obytes'] == data['opackets'] * size1
        assert data2['obytes'] == data2['opackets'] * size2

    def test_start_2_continuous_on_same_interface_streams_trex(self, trex):
        """
        @brief  Send 2 continuous streams using start_streams method on same interface
        """
        # Define interfaces and packet size
        iface = trex.ports[0]
        size = 1024
        # Set continuous traffic streams
        stream_id1 = trex.set_stream(self.packet_definition, continuous=True, rate=50, iface=iface, required_size=size)
        stream_id2 = trex.set_stream(self.packet_definition, continuous=True, rate=50, iface=iface, required_size=size)
        # Send streams
        trex.start_streams([stream_id1, stream_id2])
        time.sleep(2)
        # Stop streams
        trex.stop_streams([stream_id1, stream_id2])
        # get and verify interfaces statistics
        data = trex.get_statistics(iface)
        assert data['opackets'] != 0
        assert data['obytes'] == data['opackets'] * size

    def test_single_stream_with_packet_interval_trex(self, trex):
        """
        @brief  Send single stream with packets interval
        """
        # Define interface, packet and interval
        iface = trex.ports[1]
        packet_count = 9
        interval = 2
        sleep = 6
        # Set traffic stream
        stream_id = trex.set_stream(self.packet_definition, count=packet_count, inter=interval, iface=iface, adjust_size=True)
        # Send stream
        trex.start_streams([stream_id, ])
        time.sleep(sleep)
        # Stop streams
        trex.stop_streams([stream_id, ])
        # get and verify interface statistics
        data = trex.get_statistics(iface)
        assert sleep / interval - 1 <= data['opackets'] <= sleep / interval + 1

    def test_clear_statistics(self, trex):
        """
        @brief  Clear interface statistics
        """
        # Define interface and packets
        iface = trex.ports[0]
        packet_count = 10
        # get default interface statistics
        default_stat = trex.get_sent_frames_count(iface)
        # Set and send traffic stream
        stream_id = trex.set_stream(self.packet_definition, count=packet_count, iface=iface)
        trex.send_stream(stream_id)
        time.sleep(1)
        # Stop stream
        trex.stop_streams([stream_id, ])
        # get and verify interface statistics
        assert trex.get_sent_frames_count(iface) == packet_count
        # Clear statistics and verify that statistic was cleared
        trex.clear_statistics([iface])
        stat = trex.get_sent_frames_count(iface)
        assert default_stat == stat
        assert trex.get_sent_frames_count(iface) == 0

    def test_increment_required_size_1(self, trex):
        """
        @brief  Set stream with 'required_size' increment and send it
        @note  Two TRex interfaces should be connected to each other
        """
        # Define interface and packet
        iface1 = trex.ports[0]
        iface2 = trex.ports[1]
        packet_count = 2
        min_size = 84
        max_size = min_size * 2
        # Set traffic stream
        stream_id = trex.set_stream(self.packet_definition, count=packet_count, iface=iface1,
                                    required_size=('Increment', min_size, min_size, max_size))
        # Send traffic
        trex.send_stream(stream_id)
        time.sleep(1)
        # Stop stream
        trex.stop_streams([stream_id])
        # get and verify interface statistic
        data1 = trex.get_statistics(iface1)
        data2 = trex.get_statistics(iface2)
        assert data1['opackets'] == packet_count
        assert data2['ipackets'] == packet_count
        assert data2['ibytes'] == min_size + max_size

    def test_random_required_size(self, trex):
        """
        @brief  Set stream with random 'required_size' and send it
        @note  Two TRex interfaces should be connected to each other
        """
        # Define interface and packet
        iface1 = trex.ports[0]
        iface2 = trex.ports[1]
        packet_count = 2
        min_size = 84
        max_size = min_size * 2
        # Set traffic stream
        stream_id = trex.set_stream(self.packet_definition, count=packet_count, iface=iface1,
                                    required_size=('Random', min_size, max_size))
        # Send traffic
        trex.send_stream(stream_id)
        time.sleep(1)
        # Stop stream
        trex.stop_streams([stream_id])
        # get and verify interface statistic
        data1 = trex.get_statistics(iface1)
        data2 = trex.get_statistics(iface2)
        assert data1['opackets'] == packet_count
        assert data2['ipackets'] == packet_count
        assert data2['ibytes'] > max_size

    def test_increment_required_size_in_loop(self, trex):
        """
        @brief  Set stream with increment 'required_size' and verify that size is wrapped back to min value
        @note  Two TRex interfaces should be connected to each other
        """
        # Define interface and packet
        iface1 = trex.ports[0]
        iface2 = trex.ports[1]
        packets_count = 3
        min_size = 64
        max_size = min_size + 1
        # Set traffic stream
        stream_id = trex.set_stream(self.packet_definition, count=packets_count, iface=iface1,
                                    required_size=('Increment', 1, min_size, max_size))
        # Send traffic
        trex.send_stream(stream_id)
        time.sleep(1)
        # Stop stream
        trex.stop_streams([stream_id])
        # get and verify interface statistic
        data1 = trex.get_statistics(iface1)
        data2 = trex.get_statistics(iface2)
        assert data2['ipackets'] == packets_count
        assert data2['obytes'] == data1['ibytes']
        assert data2['ibytes'] == min_size * 2 + max_size

    def test_increment_src_ip(self, trex):
        """
        @brief  Set stream with source ip increment and send it
        @note  Two TRex interfaces should be connected to each other
        """
        # Define interface and packet
        iface1 = trex.ports[0]
        iface2 = trex.ports[1]
        packets_count = 3
        # Set traffic stream
        stream_id = trex.set_stream(self.packet_definition, count=packets_count, iface=iface1,
                                    sip_increment=(1, packets_count))
        # Send traffic
        trex.send_stream(stream_id)
        time.sleep(1)
        # Stop stream
        trex.stop_streams([stream_id])
        # get and verify interface statistic
        data1 = trex.get_statistics(iface1)
        data2 = trex.get_statistics(iface2)
        assert data1['opackets'] == data2['ipackets']
        assert data2['ipackets'] == packets_count

    def test_increment_dst_ip(self, trex):
        """
        @brief  Set stream with destination ip increment and send it
        @note  Two TRex interfaces should be connected to each other"""
        # Define interface and packet
        iface1 = trex.ports[0]
        iface2 = trex.ports[1]
        packets_count = 3
        # Set traffic stream
        stream_id = trex.set_stream(self.packet_definition, count=packets_count, iface=iface1,
                                    dip_increment=(1, packets_count))
        # Send traffic
        trex.send_stream(stream_id)
        time.sleep(1)
        # Stop stream
        trex.stop_streams([stream_id])
        # get and verify interface statistic
        data1 = trex.get_statistics(iface1)
        data2 = trex.get_statistics(iface2)
        assert data1['opackets'] == data2['ipackets']
        assert data2['ipackets'] == packets_count

    def test_increment_tcp_src_port(self, trex):
        """
        @brief  Set stream with TCP source port increment and send it
        @note  Two TRex interfaces should be connected to each other"""
        # Define interface and packet
        iface1 = trex.ports[0]
        iface2 = trex.ports[1]
        packets_count = 3
        # Set traffic stream
        stream_id = trex.set_stream(self.packet_definition_tcp, count=packets_count, iface=iface1,
                                    stcp_increment=(1, packets_count))
        # Send traffic
        trex.send_stream(stream_id)
        time.sleep(1)
        # Stop stream
        trex.stop_streams([stream_id])
        # get and verify interface statistic
        data1 = trex.get_statistics(iface1)
        data2 = trex.get_statistics(iface2)
        assert data1['opackets'] == data2['ipackets']
        assert data2['ipackets'] == packets_count

    def test_increment_tcp_dst_port(self, trex):
        """
        @brief  Set stream with TCP destination port increment and send it
        @note  Two TRex interfaces should be connected to each other
        """
        # Define interface and packet
        iface1 = trex.ports[0]
        iface2 = trex.ports[1]
        packets_count = 3
        # Set traffic stream
        stream_id = trex.set_stream(self.packet_definition_tcp, count=packets_count, iface=iface1,
                                    dtcp_increment=(1, packets_count))
        # Send traffic
        trex.send_stream(stream_id)
        time.sleep(1)
        # Stop stream
        trex.stop_streams([stream_id])
        # get and verify interface statistic
        data1 = trex.get_statistics(iface1)
        data2 = trex.get_statistics(iface2)
        assert data1['opackets'] == data2['ipackets']
        assert data2['ipackets'] == packets_count

    def test_increment_udp_src_port(self, trex):
        """
        @brief  Set stream with UDP source port increment and send it
        @note  Two TRex interfaces should be connected to each other
        """
        # Define interface and packet
        iface1 = trex.ports[0]
        iface2 = trex.ports[1]
        packets_count = 3
        # Set traffic stream
        stream_id = trex.set_stream(self.packet_definition, count=packets_count, iface=iface1,
                                    sudp_increment=(1, packets_count))
        # Send traffic
        trex.send_stream(stream_id)
        time.sleep(1)
        # Stop stream
        trex.stop_streams([stream_id])
        # get and verify interface statistic
        data1 = trex.get_statistics(iface1)
        data2 = trex.get_statistics(iface2)
        assert data1['opackets'] == data2['ipackets']
        assert data2['ipackets'] == packets_count

    def test_increment_udp_dst_port(self, trex):
        """
        @brief  Set stream with UDP destination port increment and send it
        @note  Two TRex interfaces should be connected to each other
        """
        # Define interface and packet
        iface1 = trex.ports[0]
        iface2 = trex.ports[1]
        packets_count = 3
        # Set traffic stream
        stream_id = trex.set_stream(self.packet_definition, count=packets_count, iface=iface1,
                                    dudp_increment=(1, packets_count))
        # Send traffic
        trex.send_stream(stream_id)
        time.sleep(1)
        # Stop stream
        trex.stop_streams([stream_id])
        # get and verify interface statistic
        data1 = trex.get_statistics(iface1)
        data2 = trex.get_statistics(iface2)
        assert data1['opackets'] == data2['ipackets']
        assert data2['ipackets'] == packets_count

    def test_all_supported_increments_simultaneously(self, trex):
        """
        @brief  Set stream with all supported increments simultaneously and send it
        @note  Two TRex interfaces should be connected to each other
        """
        # Define interface and packet
        iface1 = trex.ports[0]
        iface2 = trex.ports[1]
        packet_count = 2
        min_size = 84
        max_size = min_size * 2
        # Set traffic stream
        stream_id = trex.set_stream(self.packet_definition_tcp, count=packet_count, iface=iface1,
                                    sip_increment=(1, packet_count), dip_increment=(1, packet_count),
                                    stcp_increment=(1, packet_count), dtcp_increment=(1, packet_count),
                                    required_size=('Increment', min_size, min_size, max_size))
        # Send traffic
        trex.send_stream(stream_id)
        time.sleep(1)
        # Stop stream
        trex.stop_streams([stream_id])
        # get and verify interface statistic
        data1 = trex.get_statistics(iface1)
        data2 = trex.get_statistics(iface2)
        assert data1['opackets'] == data2['ipackets']
        assert data2['ipackets'] == packet_count
        assert data2['ibytes'] == min_size + max_size


@pytest.mark.skipif(skip_flag, reason="Need to install TRex client package")
class TestTrexHLTTg(object):

    def test_simple_udp(self, trex_hlt):
        """
        @brief  Send bidirectional UDP stream
        """
        iface1 = trex_hlt.ports[0]
        iface2 = trex_hlt.ports[1]
        sleep = 1
        rate = 100
        # Creating traffic
        trex_hlt.traffic_config(
                                mode='create',
                                bidirectional=True,
                                port_handle=iface1,
                                port_handle2=iface2,
                                frame_size=64,
                                mac_src="00:50:56:b9:de:75",
                                mac_dst="00:50:56:b9:34:f3",
                                mac_src2="00:50:56:b9:34:f3",
                                mac_dst2="00:50:56:b9:de:75",
                                l3_protocol='ipv4',
                                ip_src_addr='10.0.0.1',
                                ip_dst_addr='8.0.0.1',
                                l4_protocol='udp',
                                udp_dst_port=12,
                                udp_src_port=1025,
                                stream_id=1,
                                rate_pps=rate)
        trex_hlt.clear_statistics(trex_hlt.ports)
        # Starting traffic
        trex_hlt.traffic_control(action='run', port_handle=trex_hlt.ports)
        time.sleep(sleep)
        # Stopping traffic
        trex_hlt.traffic_control(action='stop', port_handle=trex_hlt.ports)
        # Get statistics
        data = trex_hlt.traffic_stats(mode='aggregate', port_handle=trex_hlt.ports)
        assert data[iface1]['aggregate']['tx']['pkt_count'] >= sleep * rate
        assert data[iface2]['aggregate']['tx']['pkt_count'] >= sleep * rate
