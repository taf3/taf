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

@file test_tg.py

@summary Traffic generator's unittests.
"""
import random
import time

import pytest

from testlib import dev_ixia
from testlib.custom_exceptions import PypackerException


IXIA_CONFIG = {"name": "IXIA", "entry_type": "tg", "instance_type": "ixiahl", "id": 1, "ip_host": "X.X.X.X",
               "ports": [[1, 6, 13]]}


class FakeOpts(object):
    def __init__(self):
        self.setup = "setup.json"
        self.env = ""
        self.get_only = False
        self.lhost_ui = 'linux_bash'


@pytest.fixture
def tg(request):
    tg = dev_ixia.Ixia(IXIA_CONFIG, request.config.option)
    tg.create()
    # traffic_generator.cleanup()
    iface = tg.ports[0]
    chassis, card, port = iface
    tg.tcl("ixClearPortStats %(chassis)s %(card)s %(port)s; \
                           port get %(chassis)s %(card)s %(port)s; \
                           port config -rxTxMode gigLoopback; \
                           port config -loopback portLoopback; \
                           port set %(chassis)s %(card)s %(port)s; \
                           port write %(chassis)s %(card)s %(port)s" %
           {'chassis': chassis, 'card': card, 'port': port})
    request.addfinalizer(tg.destroy)
    return tg


@pytest.mark.unittests
class TestIxia(object):

    packet_definition = ({"Ethernet": {"dst": "ff:ff:ff:ff:ff:ff", "src": "00:00:00:00:00:02"}}, {"IP": {"p": 17}}, {"UDP": {}},)
    packet_defs = [({"Ethernet": {"dst": "ff:ff:ff:ff:ff:ff", "src": "00:00:00:00:00:02"}}, {"IP": {"p": 17}}, {"UDP": {}},),
                   ({"Ethernet": {"dst": "ff:ff:ff:ff:ff:ff", "src": "00:00:00:00:00:03"}}, {"IP": {"p": 1}}, {"ICMP": {}},),
                   ({"Ethernet": {"dst": "ff:ff:ff:ff:ff:ff", "src": "00:00:00:00:00:04"}}, {"IP": {}}, {"TCP": {}},)]

    pack_dot1q_ip_udp = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                         {"Dot1Q": {"vlan": 5}},
                         {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "p": 17}},
                         {"UDP": {"dport": 23, "sport": 23}},
                         )

    pack_dot1q_ip_tcp = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                         {"Dot1Q": {"vlan": 5}},
                         {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1"}},
                         {"TCP": {}},
                         )

    pack_dot1q_ip_icmp = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                          {"Dot1Q": {"vlan": 5}},
                          {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "p": 1}},
                          {"ICMP": {}}, {"ICMP.Echo": {}},
                          )

    pack_dot1q_arp = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                      {"Dot1Q": {"vlan": 5}},
                      {"ARP": {"sha": "00:00:20:00:10:02", "spa": "1.1.1.1", "tha": "00:00:00:00:00:00", "tpa": "1.1.1.2"}},
                      )

    pack_ip_icmp = ({"Ethernet": {"src": "00:00:20:00:10:01", "dst": "00:00:00:33:33:33", "type": 0x0800}},
                    {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "p": 1}},
                    {"ICMP": {"type": 6}}, {"ICMP.Echo": {"seq": 0}},
                    )

    pack_ip_udp = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x0800}},
                   {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "p": 17}},
                   {"UDP": {}},
                   )

    pack_ip_tcp = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x0800}},
                   {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1"}},
                   {"TCP": {}},
                   )

    pack_arp = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x0806}},
                {"ARP": {"sha": "00:00:20:00:10:02", "spa": "1.1.1.1", "tha": "00:00:00:00:00:00", "tpa": "1.1.1.2"}},
                )

    pack_dot1q = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
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

    pack_ipv6 = ({"Ether": {"src": '00:00:0a:00:02:08', "dst": "00:01:12:12:34:12"}}, {"IPv6": {"src": '2000::1:2', "dst": '2000::2:2'}})

    pack_dot1q_ipv6 = ({"Ether": {"dst": "00:00:00:01:02:03", "src": "00:00:00:03:02:01", 'type': 0x8100}},
                       {"Dot1Q": {"vlan": 2, "prio": 1}},
                       {"IPv6": {"src": "2001:db8:1:2:60:8ff:fe52:f9d8", "dst": "2001:db8:1:2:60:8ff:fe52:f9d9"}}, {"TCP": {}})

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

    def test_stream(self, tg):
        """ Verify that send stream send exact packets count. """
        iface = tg.ports[0]
        packet_count = 100

        stream_id = tg.set_stream(self.packet_definition, count=packet_count,
                                  iface=iface, adjust_size=True, required_size=1450)

        tg.start_sniff([iface, ], sniffing_time=5, src_filter="00:00:00:00:00:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data
        packet_count = packet_count

        assert len(data[iface]) == packet_count

    def test_single_packet(self, tg):
        """ Single packet """
        time_stamp = time.time()
        stream_id = tg.set_stream(self.packet_definition, count=1, iface=tg.ports[0], adjust_size=True)
        print("Stream set time %2.6fs." % (time.time() - time_stamp))

        time_stamp = time.time()
        tg.send_stream(stream_id)
        print("Packet send time %2.6fs." % (time.time() - time_stamp))

    def test_single_stream(self, tg):
        """ Single stream """
        stream_id = tg.set_stream(self.packet_definition, count=9, inter=2, iface=tg.ports[0], adjust_size=True)
        time_stamp = time.time()
        tg.start_streams([stream_id, ])
        print("Time to start stream %2.6fs." % (time.time() - time_stamp))
        time.sleep(6)
        tg.stop_streams([stream_id, ])

    def test_multistreams_and_multifaces(self, tg):
        """ Multiple streams and multiple ifaces """
        stream_list = []
        for packet_definition, port in zip(self.packet_defs, tg.ports):
            stream_id = tg.set_stream(packet_definition, count=25, inter=0.5, iface=port, adjust_size=True)
            stream_list.append(stream_id)

        time_stamp = time.time()
        tg.start_streams(stream_list)
        print("Time to start stream %2.6fs." % (time.time() - time_stamp))
        time.sleep(6)
        tg.stop_streams(stream_list)

    def test_multistreams_on_single_iface(self, tg):
        """ Multiple streams and one iface """
        stream_list = []
        for packet_definition in self.packet_defs:
            stream_id = tg.set_stream(packet_definition, count=25, inter=0.5, iface=tg.ports[0], adjust_size=True)
            stream_list.append(stream_id)

        time_stamp = time.time()
        tg.start_streams(stream_list)
        print("Time to start stream %2.6fs." % (time.time() - time_stamp))
        time.sleep(6)
        tg.stop_streams(stream_list)

    def test_multistreams_and_one(self, tg):
        """ Multiple streams and one on same iface """
        stream_list = []
        for packet_definition in self.packet_defs[:2]:
            stream_id = tg.set_stream(packet_definition, count=3, inter=2, iface=tg.ports[0], adjust_size=True)
            stream_list.append(stream_id)

        tg.start_streams(stream_list)
        time.sleep(6)
        tg.stop_streams(stream_list)

        stream_id = tg.set_stream(self.packet_defs[2], count=2, inter=1, iface=tg.ports[0], adjust_size=True)
        tg.send_stream(stream_id)

    def test_exact_packets_delivery(self, tg):
        """ Verify that send stream send exact packets count. """
        iface = tg.ports[0]
        packet_count = 1000

        stream_id = tg.set_stream(self.packet_definition, count=packet_count, iface=iface, adjust_size=True, required_size=200, inter=0.005)

        tg.start_sniff([iface, ], sniffing_time=25, filter_layer="IP", src_filter="00:00:00:00:00:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data
        assert len(data[iface]) == packet_count

    def test_start_stop_parallel_and_independent_set_quantity_streams(self, tg):
        """ Verify parallel and independent set quantity of streams. """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.packet_defs[0], count=10, iface=iface)
        stream_id_2 = tg.set_stream(self.packet_defs[1], count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="IP", dst_filter="ff:ff:ff:ff:ff:ff")

        tg.send_stream(stream_id_1)
        tg.send_stream(stream_id_2)

        data = tg.stop_sniff([iface, ])

        assert iface in data
        assert len(data[iface]) == 11

    def test_start_stop_parallel_and_independent_continuous_streams(self, tg):
        """ Verify parallel and independent streams starts and stops.
            No packet count set in set_stream function ISSUE in function need to be fixed ISSUE in function need to be fixed"""
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.packet_defs[0], iface=iface)
        stream_id_2 = tg.set_stream(self.packet_defs[1], iface=iface)

        tg.start_sniff([iface, ], sniffing_time=15, filter_layer="IP", dst_filter="ff:ff:ff:ff:ff:ff")
        tg.start_streams([stream_id_1, ])
        tg.start_streams([stream_id_2, ])
        tg.stop_streams([stream_id_1, ])
        tg.stop_streams([stream_id_2, ])

        data = tg.stop_sniff([iface, ])

        # Count number of packets from stream 2
        count = 0
        for packet in data[iface]:
            if tg.get_packet_field(packet, "Ethernet", "src") == self.packet_defs[1][0]['Ethernet']['src']:
                count += 1

        assert 1 <= count <= 2

    def test_streams_corruption_1(self, tg):
        """ Verify that set_stream does not corrupt already started streams. """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.packet_defs[0], count=10, inter=0.1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=15, filter_layer="IP", dst_filter="ff:ff:ff:ff:ff:ff")

        tg.start_streams([stream_id_1, ])
        tg.set_stream(self.packet_defs[1], count=1, iface=iface)
        time.sleep(4)
        tg.stop_streams([stream_id_1, ])

        data = tg.stop_sniff([iface, ])

        assert iface in data
        assert len(data[iface]) >= 10

        # Count number of packets from stream 2
        count = 0
        for packet in data[iface]:
            if tg.get_packet_field(packet, "Ethernet", "src") == self.packet_defs[1][0]['Ethernet']['src']:
                count += 1
        assert count == 0

    def test_streams_corruption_2(self, tg):
        """ Verify that set_stream does not corrupt already started streams. """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.packet_defs[0], count=10, inter=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=15, dst_filter="ff:ff:ff:ff:ff:ff")
        tg.start_streams([stream_id_1, ])
        stream_id_2 = tg.set_stream(self.packet_defs[1], count=1, iface=iface)
        tg.start_streams([stream_id_2, ])
        time.sleep(1)
        data = tg.stop_sniff([iface, ])

        tg.stop_streams([stream_id_1, stream_id_2, ])

        assert iface in list(data.keys())
        assert len(data[iface]) >= 10

        # Count number of packets from stream 2
        count = 0
        for packet in data[iface]:
            if tg.get_packet_field(packet, "Ethernet", "src") == self.packet_defs[1][0]['Ethernet']['src']:
                count += 1
        assert 1 <= count <= 2

    def test_stop_all_streams(self, tg):
        """ Verify that stop_streams stop all streams by default. """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.packet_defs[0], count=10, inter=1, iface=iface)
        stream_id_2 = tg.set_stream(self.packet_defs[1], count=10, inter=1, iface=iface)

        tg.start_streams([stream_id_1, stream_id_2, ])
        time.sleep(3)
        tg.stop_streams([stream_id_1, stream_id_2, ])

        tg.start_sniff([iface, ], sniffing_time=5, dst_filter="ff:ff:ff:ff:ff:ff")
        data = tg.stop_sniff([iface, ])

        assert not len(data[iface])

    def test_arp_sniff_pattern(self, tg):
        """ Verify ARP sniff pattern """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.packet_definition, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_arp, count=1, iface=iface)
        stream_id_3 = tg.set_stream(self.pack_dot1q_arp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="ARP")
        tg.start_streams([stream_id_1, stream_id_2, stream_id_3, ])
        tg.stop_streams([stream_id_1, stream_id_2, stream_id_3, ])
        data = tg.stop_sniff([iface, ])

        assert iface in data
        assert len(data[iface]) == 1

    def test_sniffing_negative(self, tg):
        """ Sniff for one packet, but sniff nothing """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_arp, count=5, inter=0.02, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, packets_count=1, filter_layer="ARP")
        tg.start_streams([stream_id, ])
        tg.stop_streams([stream_id, ])
        data = tg.stop_sniff([iface, ])

        assert len(data[iface]) == 0

    @pytest.mark.skip("Pypacker does not support QinQ")
    def test_qinq_packets_sniffer(self, tg):
        """ Check QinQ packet send """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_qinq, count=300, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_dot1q_arp, count=70, inter=0.01, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10)
        tg.start_streams([stream_id_1, stream_id_2, ])
        tg.stop_streams([stream_id_1, stream_id_2, ])
        data = tg.stop_sniff([iface, ])

        assert iface in data

    def test_check_statistics(self, tg):
        """ Send 100 packets and check statistics"""
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.packet_definition, count=100, iface=iface)

        tg.clear_statistics([iface, ])

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="IP", src_filter="00:00:00:00:00:02")
        tg.send_stream(stream_id_1)
        tg.stop_sniff([iface, ])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics == 100
        assert end_sent_statistics == 100

    def test_incremented_streams(self, tg):
        """ Send incremented streams """
        iface = tg.ports[0]

        packet1 = ({"Ethernet": {'src': "00:00:00:00:00:04", 'dst': "00:00:00:00:00:02"}}, {"IP": {}})
        packet2 = ({"Ethernet": {'src': "00:00:00:00:00:05", 'dst': "00:00:00:00:00:02"}}, {"IP": {}})
        packet3 = ({"Ethernet": {'src': "00:00:00:00:00:06", 'dst': "00:00:00:00:00:02"}}, {"IP": {}})
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

        tg.clear_statistics([iface, ])

        tg.start_sniff([iface, ], sniffing_time=10, dst_filter="00:00:00:00:00:02")
        tg.start_streams([stream1, ])
        tg.stop_sniff([iface, ])
        tg.stop_streams([stream1, ])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics == 20
        assert end_sent_statistics == 20

        tg.clear_statistics([iface, ])

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:00:00:00:05")
        tg.start_streams([stream2, ])
        tg.stop_sniff([iface, ])
        tg.stop_streams([stream2, ])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics == 15
        assert end_sent_statistics == 15

        tg.clear_statistics([iface, ])

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="notIP")
        tg.start_streams([stream3, ])
        tg.stop_sniff([iface, ])
        tg.stop_streams([stream3, ])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics >= 300
        assert end_sent_statistics == 300

        tg.clear_statistics([iface, ])

        tg.start_sniff([iface, ], sniffing_time=5)
        tg.start_streams([stream4, ])

        time.sleep(1)

        middle_receive_statistics = tg.get_received_frames_count(iface)
        middle_sent_statistics = tg.get_sent_frames_count(iface)

        assert middle_receive_statistics > 0
        assert middle_sent_statistics > 0

        time.sleep(1)

        tg.stop_sniff([iface, ])
        tg.stop_streams([stream4, ])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics > middle_receive_statistics
        assert end_sent_statistics > middle_sent_statistics

        tg.clear_statistics([iface, ])

        tg.start_sniff([iface, ], sniffing_time=5)
        tg.start_streams([stream5, ])

        time.sleep(1)

        middle_receive_statistics = tg.get_received_frames_count(iface)
        middle_sent_statistics = tg.get_sent_frames_count(iface)

        assert middle_receive_statistics > 0
        assert middle_sent_statistics > 0

        time.sleep(1)

        tg.stop_sniff([iface, ])
        tg.stop_streams([stream5, ])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics > middle_receive_statistics
        assert end_sent_statistics > middle_sent_statistics

        tg.clear_statistics([iface, ])

        tg.start_sniff([iface, ], sniffing_time=10, dst_filter="00:00:00:00:00:02")
        tg.start_streams([stream6, ])
        tg.stop_sniff([iface, ])
        tg.stop_streams([stream6, ])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics == 20
        assert end_sent_statistics == 20

        tg.clear_statistics([iface, ])

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:00:00:00:0a")
        tg.start_streams([stream7, ])
        tg.stop_sniff([iface, ])
        tg.stop_streams([stream7, ])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics == 15
        assert end_sent_statistics == 15

        tg.clear_statistics([iface, ])

        tg.start_sniff([iface, ], sniffing_time=5)
        tg.start_streams([stream8, ])

        time.sleep(1)

        middle_receive_statistics = tg.get_received_frames_count(iface)
        middle_sent_statistics = tg.get_sent_frames_count(iface)

        assert middle_receive_statistics > 0
        assert middle_sent_statistics > 0

        time.sleep(1)

        tg.stop_sniff([iface, ])
        tg.stop_streams([stream8, ])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics > middle_receive_statistics
        assert end_sent_statistics > middle_sent_statistics

        tg.clear_statistics([iface, ])

        tg.start_sniff([iface, ], sniffing_time=5)
        tg.start_streams([stream9, ])

        time.sleep(1)

        middle_receive_statistics = tg.get_received_frames_count(iface)
        middle_sent_statistics = tg.get_sent_frames_count(iface)

        assert middle_receive_statistics > 0
        assert middle_sent_statistics > 0

        time.sleep(1)

        tg.stop_sniff([iface, ])
        tg.stop_streams([stream9, ])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics > middle_receive_statistics
        assert end_sent_statistics > middle_sent_statistics

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_packet_fragmentation(self, tg):
        """ Check packet fragmentation """
        ix_iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_icmp, count=1, iface=ix_iface, required_size=200, fragsize=110)

        tg.start_sniff([ix_iface, ], sniffing_time=10, filter_layer="ICMP", src_filter="00:00:20:00:10:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([ix_iface, ])

        assert ix_iface in data

        assert len(data[ix_iface]) == 2

    def test_sa_incrementation_1(self, tg):
        """ Check SA incrementation. Count == Increment count """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_icmp, count=5, sa_increment=(1, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="ICMP", dst_filter="00:00:00:33:33:33")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that all packets with different src macs
        src_mac_set = set()
        for packet in data[iface]:
            src_mac_set.add(tg.get_packet_field(packet, "Ethernet", "src"))
        assert len(src_mac_set) == 5

    def test_sa_incrementation_2(self, tg):
        """ Check SA incrementation.  Count > Increment count """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_icmp, count=10, sa_increment=(1, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, packets_count=10, filter_layer="ICMP", dst_filter="00:00:00:33:33:33")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that all packets with different src macs
        src_mac_set = set()
        for packet in data[iface]:
            src_mac_set.add(tg.get_packet_field(packet, "Ethernet", "src"))
        assert len(src_mac_set) == 5

    def test_da_incrementation_1(self, tg):
        """ Check DA incrementation. Count == Increment count """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_icmp, count=5, da_increment=(1, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="ICMP", src_filter="00:00:20:00:10:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that all packets with different dst macs
        dst_mac_set = set()
        for packet in data[iface]:
            dst_mac_set.add(tg.get_packet_field(packet, "Ethernet", "dst"))
        assert len(dst_mac_set) == 5

    def test_da_incrementation_2(self, tg):
        """ Check DA incrementation.  Count > Increment count """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_icmp, count=10, da_increment=(1, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, filter_layer="ICMP", src_filter="00:00:20:00:10:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that all packets with different dst macs
        dst_mac_set = set()
        for packet in data[iface]:
            dst_mac_set.add(tg.get_packet_field(packet, "Ethernet", "dst"))
        assert len(dst_mac_set) == 5

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_sa_incrementation_and_packet_fragmentation(self, tg):
        """ Check SA incrementation + packet fragmentation. Count == Increment count """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_icmp, iface=iface,
                                  count=5, sa_increment=(1, 5),
                                  required_size=200, fragsize=110)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="ICMP", dst_filter="00:00:00:33:33:33")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == (count of packets) * (number of fragments per packet)
        assert len(data[iface]) == 10

        # Verify that all packets with different src macs
        src_mac_set = set()
        for packet in data[iface]:
            src_mac_set.add(tg.get_packet_field(packet, "Ethernet", "src"))
        assert len(src_mac_set) == 5

    def test_packet_random_size_1(self, tg):
        """ Check packet random size setting. Count=1 """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_icmp, iface=iface,
                                  count=1, required_size=('Random', 48, 2000))

        tg.start_sniff([iface, ], sniffing_time=5, filter_layer="ICMP", src_filter="00:00:20:00:10:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == 1
        assert len(data[iface]) == 1

        # Verify that length of packet is random value between 48 and 2000 bytes
        packet_length = len(data[iface][0])
        assert packet_length <= 2000
        assert packet_length >= 48

    def test_packet_random_size_2(self, tg):
        """ Check packet random size setting. Count=5 """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_icmp, iface=iface,
                                  count=5, required_size=('Random', 1530, 14000))

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="ICMP", src_filter="00:00:20:00:10:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == 5
        assert len(data[iface]) == 5

        # Verify that all packets with different size
        size_set = set()
        for packet in data[iface]:
            size_set.add(len(packet))
        assert 1 <= len(size_set) <= 5

        # Verify that length of packet is random value between 64 and 14000 bytes
        for _size in size_set:
            assert _size <= 14000
            assert _size >= 1530

    def test_packet_size_incrementing_1(self, tg):
        """ Check packet size incrementing. Count=1, increment count=5 """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_icmp, iface=iface, count=1, required_size=('Increment', 2, 70, 78))

        tg.start_sniff([iface, ], sniffing_time=3, filter_layer="ICMP", src_filter="00:00:20:00:10:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in list(data.keys())

        # Verify that sniffed count == 1
        assert len(data[iface]) == 1

        # Verify that all packets with different size
        size_set = set()
        for packet in data[iface]:
            size_set.add(len(packet))
        assert len(size_set) == 1

        # Verify that length of packet is from (70,72,74,76,78)
        for _size in size_set:
            assert _size in (70, 72, 74, 76, 78)

    def test_packet_size_incrementing_2(self, tg):
        """ Check packet size incrementing. Count=5, increment count=5 """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_icmp, iface=iface, count=5, required_size=('Increment', 2, 70, 78))

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="ICMP", src_filter="00:00:20:00:10:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in list(data.keys())

        # Verify that sniffed count == 5
        assert len(data[iface]) == 5

        # Verify that all packets with different size
        size_set = set()
        for packet in data[iface]:
            size_set.add(len(packet))
        assert len(size_set) == 5

        # Verify that length of packet is from (70,72,74,76,78)
        for _size in size_set:
            assert _size in (70, 72, 74, 76, 78)

    def test_packet_size_decrementing(self, tg):
        """ Check packet size decrementing. Count=9, decrement count=9 """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_icmp, iface=iface, count=9, required_size=('Increment', -1, 70, 78))

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="ICMP", src_filter="00:00:20:00:10:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in list(data.keys())

        # Verify that sniffed count == 9
        assert len(data[iface]) == 9

        # Verify that all packets with different size
        size_set = set()
        for packet in data[iface]:
            size_set.add(len(packet))
        assert len(size_set) == 9

        # Verify that length of packet is from (70,72,74,76,78)
        for _size in size_set:
            assert _size in (70, 71, 72, 73, 74, 75, 76, 77, 78)

    def test_src_ip_incrementation_dot1q_disabled_1(self, tg):
        """ Check source_ip incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_icmp, count=5, sip_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="ICMP", src_filter="00:00:20:00:10:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different src ip
        src_ip_set = set()
        for packet in data[iface]:
            src_ip_set.add(tg.get_packet_field(packet, "IP", "src"))
        assert len(src_ip_set) == 5

    def test_src_ip_incrementation_dot1q_disabled_2(self, tg):
        """ Check source_ip incrementation. Count = 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_icmp, count=10, sip_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="ICMP", src_filter="00:00:20:00:10:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different src ip
        src_ip_set = set()
        for packet in data[iface]:
            src_ip_set.add(tg.get_packet_field(packet, "IP", "src"))
        assert len(src_ip_set) == 5

    def test_src_ip_incrementation_dot1q_enabled_1(self, tg):
        """ Check source_ip incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ip_icmp, count=5, sip_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.ICMP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different src ip
        src_ip_set = set()
        for packet in data[iface]:
            src_ip_set.add(tg.get_packet_field(packet, "IP", "src"))
        assert len(src_ip_set) == 5

    def test_src_ip_incrementation_dot1q_enabled_2(self, tg):
        """ Check source_ip incrementation. Count = 2*Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ip_icmp, count=10, sip_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.ICMP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different src ip
        src_ip_set = set()
        for packet in data[iface]:
            src_ip_set.add(tg.get_packet_field(packet, "IP", "src"))
        assert len(src_ip_set) == 5

    def test_dst_ip_incrementation_dot1q_disabled_1(self, tg):
        """ Check destination_ip incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_icmp, count=5, dip_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="ICMP", src_filter="00:00:20:00:10:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different dst ip
        dst_ip_set = set()
        for packet in data[iface]:
            dst_ip_set.add(tg.get_packet_field(packet, "IP", "dst"))
        assert len(dst_ip_set) == 5

    def test_dst_ip_incrementation_dot1q_disabled_2(self, tg):
        """ Check destination_ip incrementation. Count = 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_icmp, count=10, dip_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="ICMP", src_filter="00:00:20:00:10:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different dst ip
        dst_ip_set = set()
        for packet in data[iface]:
            dst_ip_set.add(tg.get_packet_field(packet, "IP", "dst"))
        assert len(dst_ip_set) == 5

    def test_dst_ip_incrementation_dot1q_enabled_1(self, tg):
        """ Check destination_ip incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ip_icmp, count=5, dip_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.ICMP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different dst ip
        dst_ip_set = set()
        for packet in data[iface]:
            dst_ip_set.add(tg.get_packet_field(packet, "IP", "dst"))
        assert len(dst_ip_set) == 5

    def test_dst_ip_incrementation_dot1q_enabled_2(self, tg):
        """ Check destination_ip incrementation. Count = 2*Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ip_icmp, count=10, dip_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.ICMP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different dst ip
        dst_ip_set = set()
        for packet in data[iface]:
            dst_ip_set.add(tg.get_packet_field(packet, "IP", "dst"))
        assert len(dst_ip_set) == 5

    def test_clear_and_check_statistics(self, tg):
        """ Send 100 packets, clear and check statistics """
        iface = tg.ports[0]

        tg.clear_statistics([iface, ])

        stream_id_1 = tg.set_stream(self.packet_definition, count=100, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="IP", src_filter="00:00:00:00:00:02")
        tg.start_streams([stream_id_1, ])
        tg.stop_sniff([iface, ])
        tg.stop_streams([stream_id_1, ])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics == 100
        assert end_sent_statistics == 100

        tg.clear_statistics([iface, ])

        end_receive_statistics = tg.get_received_frames_count(iface)
        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_receive_statistics == 0
        assert end_sent_statistics == 0

    def test_arp_incrementation_dot1q_disabled_1(self, tg):
        """ Check arp incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_arp, count=5, arp_sa_increment=(3, 5), arp_sip_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="ARP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different src ip, src mac and hwsrc.
        src_ip_set = set()
        src_mac_set = set()
        hwsrc_set = set()
        for packet in data[iface]:
            src_ip_set.add(tg.get_packet_field(packet, "ARP", "spa"))
            src_mac_set.add(tg.get_packet_field(packet, "Ethernet", "src"))
            hwsrc_set.add(tg.get_packet_field(packet, "ARP", "sha"))
        assert len(src_ip_set) == 5
        assert len(src_mac_set) == 5
        assert len(hwsrc_set) == 5

    def test_arp_incrementation_dot1q_enabled(self, tg):
        """ Check arp incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_arp, count=5, arp_sa_increment=(3, 5), arp_sip_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.ARP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different src ip, src mac and hwsrc.
        src_ip_set = set()
        src_mac_set = set()
        hwsrc_set = set()
        for packet in data[iface]:
            src_ip_set.add(tg.get_packet_field(packet, "ARP", "spa"))
            src_mac_set.add(tg.get_packet_field(packet, "Ethernet", "src"))
            hwsrc_set.add(tg.get_packet_field(packet, "ARP", "sha"))
        assert len(src_ip_set) == 5
        assert len(src_mac_set) == 5
        assert len(hwsrc_set) == 5

    def test_arp_incrementation_dot1q_disabled_2(self, tg):
        """ Check arp incrementation. Count == 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_arp, count=10, arp_sa_increment=(3, 5), arp_sip_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="ARP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different src ip, src mac and hwsrc.
        src_ip_set = set()
        src_mac_set = set()
        hwsrc_set = set()
        for packet in data[iface]:
            src_ip_set.add(tg.get_packet_field(packet, "ARP", "spa"))
            src_mac_set.add(tg.get_packet_field(packet, "Ethernet", "src"))
            hwsrc_set.add(tg.get_packet_field(packet, "ARP", "sha"))
        assert len(src_ip_set) == 5
        assert len(src_mac_set) == 5
        assert len(hwsrc_set) == 5

    def test_vlan_incrementation_increment_count_1(self, tg):
        """ Check vlan incrementation. Count == Increment count. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ip_tcp, count=5, vlan_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.IP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different vlan.
        vlan_set = set()
        for packet in data[iface]:
            vlan_set.add(tg.get_packet_field(packet, "Ethernet", "vlan"))
        assert len(vlan_set) == 5

    def test_vlan_incrementation_increment_count_2(self, tg):
        """ Check vlan incrementation. Count == 2*Increment count. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ip_tcp, count=10, vlan_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.IP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different vlan.
        vlan_set = set()
        for packet in data[iface]:
            vlan_set.add(tg.get_packet_field(packet, "Ethernet", "vlan"))
        assert len(vlan_set) == 5

    def test_da_incrementation_continuous_traffic(self, tg):
        """ Check DA incrementation.  Continuous traffic """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_icmp, continuous=True, da_increment=(1, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, filter_layer="ICMP", src_filter="00:00:20:00:10:01")
        tg.start_streams([stream_id, ])
        time.sleep(5)
        tg.stop_streams([stream_id, ])
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that all packets with 5 different dst macs
        dst_mac_set = set()
        for packet in data[iface]:
            dst_mac_set.add(tg.get_packet_field(packet, "Ethernet", "dst"))
        assert len(dst_mac_set) == 5

    def test_sniffed_packets_timestamp(self, tg):
        """ Check sniffed packets timestamp. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=10, inter=0.5, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, packets_count=10, filter_layer="IP", src_filter="00:00:20:00:10:02")
        tg.start_streams([stream_id, ])
        time.sleep(5)
        tg.stop_streams([stream_id, ])
        data = tg.stop_sniff([iface, ])

        # Verify that all packets with 10 different timestamps
        time_set = set()
        for packet in data[iface]:
            time_set.add(packet.time)
        assert len(time_set) == 10

    def test_srcmac_filter(self, tg):
        """ Check srcMac filter. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=10, sa_increment=(1, 2), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="IP", src_filter="00:00:20:00:10:02")
        tg.start_streams([stream_id, ])
        time.sleep(5)
        tg.stop_streams([stream_id, ])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified srcMac are sniffed
        assert len(data[iface]) == 5
        src_set = set()
        for packet in data[iface]:
            src_set.add(tg.get_packet_field(packet, "Ethernet", "src"))
        assert len(src_set) == 1

    def test_dstmac_filter(self, tg):
        """ Check dstMac filter. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=10, da_increment=(1, 2), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="IP", dst_filter="00:00:00:33:33:33")
        tg.start_streams([stream_id, ])
        time.sleep(5)
        tg.stop_streams([stream_id, ])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified srcMac are sniffed
        assert len(data[iface]) == 5
        dst_set = set()
        for packet in data[iface]:
            dst_set.add(tg.get_packet_field(packet, "Ethernet", "dst"))
        assert len(dst_set) == 1

    def test_srcmac_and_dstmac_filter(self, tg):
        """ Check srcMac and dstMac filter. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=10, sa_increment=(1, 2), da_increment=(1, 2), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="IP", src_filter="00:00:20:00:10:02", dst_filter="00:00:00:33:33:33")
        tg.start_streams([stream_id, ])
        time.sleep(5)
        tg.stop_streams([stream_id, ])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified srcMac are sniffed
        assert len(data[iface]) == 5
        src_set = set()
        dst_set = set()
        for packet in data[iface]:
            dst_set.add(tg.get_packet_field(packet, "Ethernet", "dst"))
            src_set.add(tg.get_packet_field(packet, "Ethernet", "src"))
        assert len(src_set) == 1
        assert len(dst_set) == 1

    def test_srcmac_and_dstmac_wrong_layer_filter(self, tg):
        """ Check srcMac and dstMac filter with wrong filter_layer. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=10, sa_increment=(1, 2), da_increment=(1, 2), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, packets_count=10, filter_layer="ARP", src_filter="00:00:20:00:10:02", dst_filter="00:00:00:33:33:33")
        tg.start_streams([stream_id, ])
        time.sleep(5)
        tg.stop_streams([stream_id, ])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified srcMac are sniffed
        if iface in list(data.keys()):
            assert len(data[iface]) == 0
        else:
            assert data == {}

    @pytest.mark.skip("Pypacker does not support LLDP")
    def test_lldp_incrementation_increment_count_1(self, tg):
        """ Check lldp incrementation. Count == Increment count """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_lldp, count=5, sa_increment=(1, 5), lldp_sa_increment=(1, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, dst_filter="01:80:c2:00:00:0e")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

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
        """ Check lldp incrementation. Count == 2*Increment count """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_lldp, count=10, sa_increment=(1, 5), lldp_sa_increment=(1, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, dst_filter="01:80:c2:00:00:0e")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

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
        """ Check lldp incrementation. Continuous traffic """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_lldp, continuous=True, sa_increment=(1, 5), lldp_sa_increment=(1, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, packets_count=20, filter_layer="LLDP", dst_filter="01:80:c2:00:00:0e")
        tg.start_streams([stream_id, ])
        time.sleep(5)
        tg.stop_streams([stream_id, ])
        data = tg.stop_sniff([iface, ])

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
        """ Check lldp incrementation. Continuous traffic """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_lldp, continuous=True, sa_increment=(1, 0), lldp_sa_increment=(1, 0), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, packets_count=20, dst_filter="01:80:c2:00:00:0e")
        tg.start_streams([stream_id, ])
        time.sleep(5)
        tg.stop_streams([stream_id, ])
        data = tg.stop_sniff([iface, ])

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
        """ Check source_udp incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=5, sudp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="UDP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different src udp
        src_udp_set = set()
        for packet in data[iface]:
            src_udp_set.add(tg.get_packet_field(packet, "UDP", "sport"))
        assert len(src_udp_set) == 5

    def test_src_tcp_incrementation_dot1q_disabled_1(self, tg):
        """ Check source_tcp incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_tcp, count=5, stcp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="TCP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different src tcp
        src_tcp_set = set()
        for packet in data[iface]:
            src_tcp_set.add(tg.get_packet_field(packet, "TCP", "sport"))
        assert len(src_tcp_set) == 5

    def test_src_udp_incrementation_dot1q_disabled_2(self, tg):
        """ Check source_udp incrementation. Count = 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=10, sudp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="UDP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different src udp.
        src_udp_set = set()
        for packet in data[iface]:
            src_udp_set.add(tg.get_packet_field(packet, "UDP", "sport"))
        assert len(src_udp_set) == 5

    def test_src_tcp_incrementation_dot1q_disabled_2(self, tg):
        """ Check source_tcp incrementation. Count = 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_tcp, count=10, stcp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="TCP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different src tcp.
        src_tcp_set = set()
        for packet in data[iface]:
            src_tcp_set.add(tg.get_packet_field(packet, "TCP", "sport"))
        assert len(src_tcp_set) == 5

    def test_src_udp_incrementation_dot1q_enabled(self, tg):
        """ Check source_udp incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ip_udp, count=5, sudp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.IP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different src udp.
        src_udp_set = set()
        for packet in data[iface]:
            src_udp_set.add(tg.get_packet_field(packet, "UDP", "sport"))
        assert len(src_udp_set) == 5

    def test_src_tcp_incrementation_dot1q_enabled(self, tg):
        """ Check source_tcp incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ip_tcp, count=5, stcp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.IP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different src udp.
        src_tcp_set = set()
        for packet in data[iface]:
            src_tcp_set.add(tg.get_packet_field(packet, "TCP", "sport"))
        assert len(src_tcp_set) == 5

    def test_dst_udp_incrementation_dot1q_disabled_1(self, tg):
        """ Check destination_udp incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=5, dudp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="UDP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different dst udp
        dst_udp_set = set()
        for packet in data[iface]:
            dst_udp_set.add(tg.get_packet_field(packet, "UDP", "dport"))
        assert len(dst_udp_set) == 5

    def test_dst_udp_incrementation_dot1q_disabled_2(self, tg):
        """ Check destination_udp incrementation. Count = 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=10, dudp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="UDP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different dst udp.
        dst_udp_set = set()
        for packet in data[iface]:
            dst_udp_set.add(tg.get_packet_field(packet, "UDP", "dport"))
        assert len(dst_udp_set) == 5

    def test_dst_udp_incrementation_dot1q_enabled(self, tg):
        """ Check destination_udp incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ip_udp, count=5, dudp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.IP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different dst udp.
        dst_udp_set = set()
        for packet in data[iface]:
            dst_udp_set.add(tg.get_packet_field(packet, "UDP", "dport"))
        assert len(dst_udp_set) == 5

    def test_src_udp_and_dst_udp_incrementation_dot1q_disabled_1(self, tg):
        """ Check source_udp and destination_udp incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=5, sudp_increment=(3, 5), dudp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="UDP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different src and dst udp
        src_udp_set = set()
        dst_udp_set = set()
        for packet in data[iface]:
            src_udp_set.add(tg.get_packet_field(packet, "UDP", "sport"))
            dst_udp_set.add(tg.get_packet_field(packet, "UDP", "dport"))
        assert len(src_udp_set) == 5
        assert len(dst_udp_set) == 5

    def test_src_tcp_and_dst_tcp_incrementation_dot1q_disabled_1(self, tg):
        """ Check source_tcp and destination_tcp incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_tcp, count=5, stcp_increment=(3, 5), dtcp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="TCP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different src and dst udp
        src_tcp_set = set()
        dst_tcp_set = set()
        for packet in data[iface]:
            src_tcp_set.add(tg.get_packet_field(packet, "TCP", "sport"))
            dst_tcp_set.add(tg.get_packet_field(packet, "TCP", "dport"))
        assert len(src_tcp_set) == 5
        assert len(dst_tcp_set) == 5

    def test_src_udp_and_dst_udp_incrementation_dot1q_disabled_2(self, tg):
        """ Check source_udp and destination_udp incrementation. Count = 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=10, sudp_increment=(3, 5), dudp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="UDP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different src and dst udp.
        src_udp_set = set()
        dst_udp_set = set()
        for packet in data[iface]:
            src_udp_set.add(tg.get_packet_field(packet, "UDP", "sport"))
            dst_udp_set.add(tg.get_packet_field(packet, "UDP", "dport"))
        assert len(src_udp_set) == 5
        assert len(dst_udp_set) == 5

    def test_src_tcp_and_dst_tcp_incrementation_dot1q_disabled_2(self, tg):
        """ Check source_tcp and destination_tcp incrementation. Count = 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_tcp, count=10, stcp_increment=(3, 5), dtcp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="TCP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different src and dst udp.
        src_tcp_set = set()
        dst_tcp_set = set()
        for packet in data[iface]:
            src_tcp_set.add(tg.get_packet_field(packet, "TCP", "sport"))
            dst_tcp_set.add(tg.get_packet_field(packet, "TCP", "dport"))
        assert len(src_tcp_set) == 5
        assert len(dst_tcp_set) == 5

    def test_src_udp_and_dst_udp_incrementation_dot1q_enabled(self, tg):
        """ Check source_udp and destination_udp incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ip_udp, count=5, sudp_increment=(3, 5), dudp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.IP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different src and dst udp.
        src_udp_set = set()
        dst_udp_set = set()
        for packet in data[iface]:
            src_udp_set.add(tg.get_packet_field(packet, "UDP", "sport"))
            dst_udp_set.add(tg.get_packet_field(packet, "UDP", "dport"))
        assert len(src_udp_set) == 5
        assert len(dst_udp_set) == 5

    def test_src_tcp_and_dst_tcp_incrementation_dot1q_enabled(self, tg):
        """ Check source_tcp and destination_tcp incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ip_tcp, count=5, stcp_increment=(3, 5), dtcp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.IP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different src and dst udp.
        src_tcp_set = set()
        dst_tcp_set = set()
        for packet in data[iface]:
            src_tcp_set.add(tg.get_packet_field(packet, "TCP", "sport"))
            dst_tcp_set.add(tg.get_packet_field(packet, "TCP", "dport"))
        assert len(src_tcp_set) == 5
        assert len(dst_tcp_set) == 5

    @pytest.mark.skip("IP protocol increment is not integrated yet")
    def test_ip_protocol_incrementation_dot1q_disabled(self, tg):
        """ Check ip protocol incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=5, protocol_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="IP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different ip proto
        proto_ip_set = set()
        for packet in data[iface]:
            proto_ip_set.add(tg.get_packet_field(packet, "IP", "proto"))
        assert len(proto_ip_set) == 5

    @pytest.mark.skip("IP protocol increment is not integrated yet")
    def test_ip_protocol_incrementation_dot1q_disabled_2(self, tg):
        """ Check ip protocol incrementation. Count = 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=10, protocol_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="IP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different ip proto.
        proto_ip_set = set()
        for packet in data[iface]:
            proto_ip_set.add(tg.get_packet_field(packet, "IP", "proto"))
        assert len(proto_ip_set) == 5

    @pytest.mark.skip("IP protocol increment is not integrated yet")
    def test_ip_protocol_incrementation_dot1q_enabled(self, tg):
        """ Check destination_udp incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ip_udp, count=5, protocol_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.IP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different ip proto.
        proto_ip_set = set()
        for packet in data[iface]:
            proto_ip_set.add(tg.get_packet_field(packet, "IP", "proto"))
        assert len(proto_ip_set) == 5

    @pytest.mark.skip("IP protocol increment is not integrated yet")
    def test_ip_protocol_and_sip_increment_dot1q_disabled(self, tg):
        """ Check ip protocol and sip_increment incrementation. Count = 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=10, sip_increment=(3, 5), protocol_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="IP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different ip proto and src ip.
        proto_ip_set = set()
        src_ip_set = set()
        for packet in data[iface]:
            proto_ip_set.add(tg.get_packet_field(packet, "IP", "proto"))
            src_ip_set.add(tg.get_packet_field(packet, "IP", "src"))
        assert len(proto_ip_set) == 5
        assert len(src_ip_set) == 5

    @pytest.mark.skip("IP protocol increment is not integrated yet")
    def test_ip_protocol_and_sip_increment_dot1q_enabled(self, tg):
        """ Check ip protocol and sip_increment incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ip_udp, count=5, sip_increment=(3, 5), protocol_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.IP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different ip proto.
        proto_ip_set = set()
        src_ip_set = set()
        for packet in data[iface]:
            proto_ip_set.add(tg.get_packet_field(packet, "IP", "proto"))
            src_ip_set.add(tg.get_packet_field(packet, "IP", "src"))
        assert len(proto_ip_set) == 5
        assert len(src_ip_set) == 5

    def test_ether_incrementation_dot1q_disabled_1(self, tg):
        """ Check ether type incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=5, eth_type_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different ip proto
        eth_type_set = set()
        for packet in data[iface]:
            eth_type_set.add(tg.get_packet_field(packet, "Ethernet", "type"))
        assert len(eth_type_set) == 5

    def test_ether_incrementation_dot1q_disabled_2(self, tg):
        """ Check ip protocol incrementation. Count = 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=10, eth_type_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different ip proto.
        eth_type_set = set()
        for packet in data[iface]:
            eth_type_set.add(tg.get_packet_field(packet, "Ethernet", "type"))
        assert len(eth_type_set) == 5

    @pytest.mark.skip("IP DSCP increment is not integrated yet")
    def test_dscp_incrementation_dot1q_disabled_1(self, tg):
        """ Check dscp incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=5, dscp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="IP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different ip dscp
        dscp_set = set()
        for packet in data[iface]:
            dscp_set.add(tg.get_packet_field(packet, "IP", "tos"))
        assert len(dscp_set) == 5

    @pytest.mark.skip("IP DSCP increment is not integrated yet")
    def test_dscp_incrementation_dot1q_disabled_2(self, tg):
        """ Check dscp incrementation. Count = 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=10, dscp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="IP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different ip dscp.
        dscp_set = set()
        for packet in data[iface]:
            dscp_set.add(tg.get_packet_field(packet, "IP", "tos"))
        assert len(dscp_set) == 5

    @pytest.mark.skip("IP DSCP increment is not integrated yet")
    def test_ip_dscp_incrementation_dot1q_enabled(self, tg):
        """ Check ip dscp incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ip_udp, count=5, dscp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.IP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different ip proto.
        dscp_set = set()
        for packet in data[iface]:
            dscp_set.add(tg.get_packet_field(packet, "IP", "tos"))
        assert len(dscp_set) == 5

    @pytest.mark.skip("IP DSCP increment is not integrated yet")
    def test_ip_dscp_and_sip_increment_dot1q_disabled_1(self, tg):
        """ Check ip dscp and sip_increment incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=5, sip_increment=(3, 5), dscp_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="IP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different ip proto.
        dscp_ip_set = set()
        src_ip_set = set()
        for packet in data[iface]:
            dscp_ip_set.add(tg.get_packet_field(packet, "IP", "tos"))
            src_ip_set.add(tg.get_packet_field(packet, "IP", "src"))
        assert len(dscp_ip_set) == 5
        assert len(src_ip_set) == 5

    @pytest.mark.skip("IP DSCP increment is not integrated yet")
    def test_ip_dscp_and_sip_increment_dot1q_disabled_2(self, tg):
        """ Check ip dscp and sip_increment incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=5, sip_increment=(3, 15), dip_increment=(3, 10), dscp_increment=(3, 5),
                                  protocol_increment=(3, 30), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="IP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different ip proto.
        dscp_ip_set = set()
        src_ip_set = set()
        dst_ip_set = set()
        proto_ip_set = set()
        for packet in data[iface]:
            dscp_ip_set.add(tg.get_packet_field(packet, "IP", "tos"))
            src_ip_set.add(tg.get_packet_field(packet, "IP", "src"))
            dst_ip_set.add(tg.get_packet_field(packet, "IP", "dst"))
            proto_ip_set.add(tg.get_packet_field(packet, "IP", "proto"))
        assert len(dscp_ip_set) == 5
        assert len(src_ip_set) == 5
        assert len(dst_ip_set) == 5
        assert len(proto_ip_set) == 5

    @pytest.mark.skip("IP DSCP increment is not integrated yet")
    def test_ip_dip_and_sip_increment_udf_dependant(self, tg):
        """ Check ip dip and sip_increment incrementation. Dip increment dependant from sip increment. """

        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=18, sip_increment=(3, 3), dip_increment=(3, 3), dscp_increment=(3, 3), iface=iface,
                                  udf_dependancies={'sip_increment': 'dip_increment'})

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="IP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 18

        # Verify that only 9 different packets received
        _packets = []
        dscp_ip_set = set()
        src_ip_set = set()
        dst_ip_set = set()
        for packet in data[iface]:
            if packet not in _packets:
                _packets.append(packet)
            dscp_ip_set.add(tg.get_packet_field(packet, "IP", "tos"))
            src_ip_set.add(tg.get_packet_field(packet, "IP", "src"))
            dst_ip_set.add(tg.get_packet_field(packet, "IP", "dst"))
        assert len(dscp_ip_set) == 3
        assert len(src_ip_set) == 3
        assert len(dst_ip_set) == 3
        assert len(_packets) == 9

    @pytest.mark.skip("IP DSCP increment is not integrated yet")
    def test_ip_dscp_dip_sip_increment_udf_dependant(self, tg):
        """ Check ip dscp, dip and sip_increment incrementation. Dependant increments. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=54, sip_increment=(3, 3), dip_increment=(3, 3), dscp_increment=(3, 3), iface=iface,
                                  udf_dependancies={'dip_increment': 'sip_increment', 'dscp_increment': 'dip_increment'})

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="IP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 54

        # Verify that only 27 different packets received
        _packets = []
        dscp_ip_set = set()
        src_ip_set = set()
        dst_ip_set = set()
        for packet in data[iface]:
            if packet not in _packets:
                _packets.append(packet)
            dscp_ip_set.add(tg.get_packet_field(packet, "IP", "tos"))
            src_ip_set.add(tg.get_packet_field(packet, "IP", "src"))
            dst_ip_set.add(tg.get_packet_field(packet, "IP", "dst"))
        assert len(dscp_ip_set) == 3
        assert len(src_ip_set) == 3
        assert len(dst_ip_set) == 3
        assert len(_packets) == 27

    @pytest.mark.skip("IP DSCP increment is not integrated yet")
    def test_ip_dscp_dip_sip_increment_udf_one_dependant(self, tg):
        """ Check ip dscp, dip and sip_increment incrementation. Dependant increments form sip. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ip_udp, count=54, sip_increment=(3, 3), dip_increment=(3, 3), dscp_increment=(3, 3), iface=iface,
                                  udf_dependancies={'dip_increment': 'sip_increment', 'dscp_increment': 'sip_increment'})

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="IP", src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 54

        # Verify that only 9 different packets received
        _packets = []
        dscp_ip_set = set()
        src_ip_set = set()
        dst_ip_set = set()
        for packet in data[iface]:
            if packet not in _packets:
                _packets.append(packet)
            dscp_ip_set.add(tg.get_packet_field(packet, "IP", "tos"))
            src_ip_set.add(tg.get_packet_field(packet, "IP", "src"))
            dst_ip_set.add(tg.get_packet_field(packet, "IP", "dst"))
        assert len(dscp_ip_set) == 3
        assert len(src_ip_set) == 3
        assert len(dst_ip_set) == 3
        assert len(_packets) == 9

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_src_ipv6_incrementation_dot1q_disabled_1(self, tg):
        """ Check SRC IPv6 incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ipv6, count=5, sipv6_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different IPv6 SRC address
        sipv6_set = set()
        for packet in data[iface]:
            sipv6_set.add(tg.get_packet_field(packet, "IPv6", "src"))
        assert len(sipv6_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_src_ipv6_incrementation_dot1q_disabled_2(self, tg):
        """ Check SRC IPv6 incrementation. Count = 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ipv6, count=10, sipv6_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different IPv6 SRC address
        sipv6_set = set()
        for packet in data[iface]:
            sipv6_set.add(tg.get_packet_field(packet, "IPv6", "src"))
        assert len(sipv6_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_src_ipv6_incrementation_dot1q_enabled_1(self, tg):
        """ Check SRC IPv6 incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ipv6, count=5, sipv6_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.IPv6", src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different IPv6 SRC address
        sipv6_set = set()
        for packet in data[iface]:
            sipv6_set.add(tg.get_packet_field(packet, "IPv6", "src"))
        assert len(sipv6_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_src_ipv6_incrementation_dot1q_enabled_2(self, tg):
        """ Check SRC IPv6 incrementation. Count > Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ipv6, count=10, sipv6_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.IPv6", src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different IPv6 SRC address
        sipv6_set = set()
        for packet in data[iface]:
            sipv6_set.add(tg.get_packet_field(packet, "IPv6", "src"))
        assert len(sipv6_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_src_and_dst_ipv6_incrementation_dot1q_disabled(self, tg):
        """ Check SRC and DST IPv6 incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ipv6, count=5, sipv6_increment=(3, 5), dipv6_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different IPv6 SRC and DST address
        sipv6_set = set()
        dipv6_set = set()
        for packet in data[iface]:
            sipv6_set.add(tg.get_packet_field(packet, "IPv6", "src"))
            dipv6_set.add(tg.get_packet_field(packet, "IPv6", "dst"))
        assert len(sipv6_set) == 5
        assert len(dipv6_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_src_and_dst_ipv6_incrementation_dot1q_enabled(self, tg):
        """ Check SRC and DST IPv6 incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ipv6, count=5, sipv6_increment=(3, 5), dipv6_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.IPv6", src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different IPv6 SRC and DST address
        sipv6_set = set()
        dipv6_set = set()
        for packet in data[iface]:
            sipv6_set.add(tg.get_packet_field(packet, "IPv6", "src"))
            dipv6_set.add(tg.get_packet_field(packet, "IPv6", "dst"))
        assert len(sipv6_set) == 5
        assert len(dipv6_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_dst_ipv6_incrementation_dot1q_disabled_1(self, tg):
        """ Check DST IPv6 incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ipv6, count=5, dipv6_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different IPv6 DST address
        dipv6_set = set()
        for packet in data[iface]:
            dipv6_set.add(tg.get_packet_field(packet, "IPv6", "dst"))
        assert len(dipv6_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_dst_ipv6_incrementation_dot1q_disabled_2(self, tg):
        """ Check DST IPv6 incrementation. Count = 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ipv6, count=10, dipv6_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different IPv6 DST address
        dipv6_set = set()
        for packet in data[iface]:
            dipv6_set.add(tg.get_packet_field(packet, "IPv6", "dst"))
        assert len(dipv6_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_dst_ipv6_incrementation_dot1q_enabled_1(self, tg):
        """ Check DST IPv6 incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ipv6, count=5, dipv6_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.IPv6", src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different IPv6 DST address
        dipv6_set = set()
        for packet in data[iface]:
            dipv6_set.add(tg.get_packet_field(packet, "IPv6", "dst"))
        assert len(dipv6_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_dst_ipv6_incrementation_dot1q_enabled_2(self, tg):
        """ Check DST IPv6 incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ipv6, count=10, dipv6_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="Dot1Q.IPv6", src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different IPv6 DST address
        dipv6_set = set()
        for packet in data[iface]:
            dipv6_set.add(tg.get_packet_field(packet, "IPv6", "dst"))
        assert len(dipv6_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_flow_label_ipv6_incrementation_dot1q_disabled_1(self, tg):
        """ Check Flow Label IPv6 incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ipv6, count=5, fl_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different IPv6 Flow Label
        fl_set = set()
        for packet in data[iface]:
            fl_set.add(tg.get_packet_field(packet, "IPv6", "fl"))
        assert len(fl_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_flow_label_ipv6_incrementation_dot1q_disabled_2(self, tg):
        """ Check Flow Label incrementation. Count = 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ipv6, count=10, fl_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different IPv6 Flow Label
        fl_set = set()
        for packet in data[iface]:
            fl_set.add(tg.get_packet_field(packet, "IPv6", "fl"))
        assert len(fl_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_flow_label_ipv6_incrementation_dot1q_enabled(self, tg):
        """ Check Flow Label IPv6 incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ipv6, count=5, fl_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different IPv6 Flow Label
        fl_set = set()
        for packet in data[iface]:
            fl_set.add(tg.get_packet_field(packet, "IPv6", "fl"))
        assert len(fl_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_flow_label_src_ipv6_incrementation(self, tg):
        """ Check Flow Label with SRC IPv6 incrementation. Count = 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ipv6, count=10, fl_increment=(3, 5), sipv6_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different IPv6 Flow Label
        fl_set = set()
        sipv6_set = set()
        for packet in data[iface]:
            fl_set.add(tg.get_packet_field(packet, "IPv6", "fl"))
            sipv6_set.add(tg.get_packet_field(packet, "IPv6", "src"))
        assert len(fl_set) == 5
        assert len(sipv6_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_flow_label_dst_ipv6_incrementation(self, tg):
        """ Check Flow Label and DST IPv6 incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ipv6, count=5, fl_increment=(3, 5), dipv6_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different IPv6 Flow Label
        fl_set = set()
        dipv6_set = set()
        for packet in data[iface]:
            fl_set.add(tg.get_packet_field(packet, "IPv6", "fl"))
            dipv6_set.add(tg.get_packet_field(packet, "IPv6", "dst"))
        assert len(fl_set) == 5
        assert len(dipv6_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_next_header_ipv6_incrementation_dot1q_disabled(self, tg):
        """ Check next header incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ipv6, count=5, nh_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different next header
        nh_set = set()
        for packet in data[iface]:
            nh_set.add(tg.get_packet_field(packet, "IPv6", "nh"))
        assert len(nh_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_next_header_ipv6_incrementation_dot1q_disabled_2(self, tg):
        """ Check next header incrementation. Count = 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ipv6, count=10, nh_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different next header
        nh_set = set()
        for packet in data[iface]:
            nh_set.add(tg.get_packet_field(packet, "IPv6", "nh"))
        assert len(nh_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_next_header_ipv6_incrementation_dot1q_enabled(self, tg):
        """ Check next header IPv6 incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ipv6, count=5, nh_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different IPv6 next header
        nh_set = set()
        for packet in data[iface]:
            nh_set.add(tg.get_packet_field(packet, "IPv6", "nh"))
        assert len(nh_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_traffic_class_ipv6_incrementation_dot1q_disabled(self, tg):
        """ Check traffic class incrementation. Count == Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ipv6, count=5, tc_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different traffic class
        tc_set = set()
        for packet in data[iface]:
            tc_set.add(tg.get_packet_field(packet, "IPv6", "tc"))
        assert len(tc_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_traffic_class_ipv6_incrementation_dot1q_disabled_2(self, tg):
        """ Check traffic class incrementation. Count = 2*Increment count. Dot1Q disabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_ipv6, count=10, tc_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:0a:00:02:08")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 10

        # Verify that all packets with different traffic class
        tc_set = set()
        for packet in data[iface]:
            tc_set.add(tg.get_packet_field(packet, "IPv6", "tc"))
        assert len(tc_set) == 5

    @pytest.mark.skip("IPv6 increment is not integrated yet")
    def test_traffic_class_ipv6_incrementation_dot1q_enabled(self, tg):
        """ Check traffic class IPv6 incrementation. Count == Increment count. Dot1Q enabled. """
        iface = tg.ports[0]

        stream_id = tg.set_stream(self.pack_dot1q_ipv6, count=5, tc_increment=(3, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, src_filter="00:00:00:03:02:01")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different IPv6 traffic class
        tc_set = set()
        for packet in data[iface]:
            tc_set.add(tg.get_packet_field(packet, "IPv6", "tc"))
        assert len(tc_set) == 5

    @pytest.mark.skip("Pypacker does not support QOS")
    def test_qos_vlan_stat(self, tg):
        """ Check Ixia QoS vlan stat reading. """
        iface = tg.ports[0]

        dst_mac = "00:00:00:00:00:aa"
        src_mac = "00:00:00:00:00:bb"

        pack_p0 = ({"Ether": {"dst": dst_mac, "src": src_mac}},
                   {"Dot1Q": {"vlan": 10, "prio": 0, "type": 0x8100}},
                   {"IP": {}}, {"UDP": {}}, )
        pack_p1 = ({"Ether": {"dst": dst_mac, "src": src_mac}},
                   {"Dot1Q": {"vlan": 10, "prio": 1, "type": 0x8100}},
                   {"IP": {}}, {"UDP": {}}, )
        pack_p2 = ({"Ether": {"dst": dst_mac, "src": src_mac}},
                   {"Dot1Q": {"vlan": 10, "prio": 2, "type": 0x8100}},
                   {"IP": {}}, {"UDP": {}}, )
        pack_p3 = ({"Ether": {"dst": dst_mac, "src": src_mac}},
                   {"Dot1Q": {"vlan": 10, "prio": 3, "type": 0x8100}},
                   {"IP": {}}, {"UDP": {}}, )
        pack_p4 = ({"Ether": {"dst": dst_mac, "src": src_mac}},
                   {"Dot1Q": {"vlan": 10, "prio": 4, "type": 0x8100}},
                   {"IP": {}}, {"UDP": {}}, )
        pack_p5 = ({"Ether": {"dst": dst_mac, "src": src_mac}},
                   {"Dot1Q": {"vlan": 10, "prio": 5, "type": 0x8100}},
                   {"IP": {}}, {"UDP": {}}, )
        pack_p6 = ({"Ether": {"dst": dst_mac, "src": src_mac}},
                   {"Dot1Q": {"vlan": 10, "prio": 6, "type": 0x8100}},
                   {"IP": {}}, {"UDP": {}}, )
        pack_p7 = ({"Ether": {"dst": dst_mac, "src": src_mac}},
                   {"Dot1Q": {"vlan": 10, "prio": 7, "type": 0x8100}},
                   {"IP": {}}, {"UDP": {}}, )

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
        tg.clear_statistics([iface, ])

        tg.start_sniff([iface, ], sniffing_time=5)
        tg.start_streams(stream_ids)
        data = tg.stop_sniff([iface, ])
        tg.stop_streams(stream_ids)

        assert iface in data
        # Verify that sniffed count == count
        assert len(data[iface]) == 52
        assert tg.get_received_frames_count(iface) == 52

        assert tg.get_qos_frames_count(iface, 0) == 8
        assert tg.get_qos_frames_count(iface, 1) == 7
        assert tg.get_qos_frames_count(iface, 2) == 6
        assert tg.get_qos_frames_count(iface, 3) == 5
        assert tg.get_qos_frames_count(iface, 4) == 5
        assert tg.get_qos_frames_count(iface, 5) == 6
        assert tg.get_qos_frames_count(iface, 6) == 7
        assert tg.get_qos_frames_count(iface, 7) == 8

    @pytest.mark.skip("Pypacker does not support QOS")
    def test_qos_iptos_stat(self, tg):
        """Check Ixia QoS IP TOS stat reading."""
        iface = tg.ports[0]

        dst_mac = "00:00:00:00:00:55"
        src_mac = "00:00:00:00:00:77"

        pack_list = []
        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x00}}, {"TCP": {}}))
        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x0f}}, {"TCP": {}}))
        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x1f}}, {"TCP": {}}))

        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x20}}, {"TCP": {}}))
        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x30}}, {"TCP": {}}))
        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x3f}}, {"TCP": {}}))

        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x40}}, {"TCP": {}}))
        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x5a}}, {"TCP": {}}))
        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x5f}}, {"TCP": {}}))

        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x60}}, {"TCP": {}}))
        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x71}}, {"TCP": {}}))
        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x7f}}, {"TCP": {}}))

        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x80}}, {"TCP": {}}))
        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x8f}}, {"TCP": {}}))
        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0x9f}}, {"TCP": {}}))

        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xa0}}, {"TCP": {}}))
        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xb3}}, {"TCP": {}}))
        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xbf}}, {"TCP": {}}))

        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xc0}}, {"TCP": {}}))
        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xc5}}, {"TCP": {}}))
        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xdf}}, {"TCP": {}}))

        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xe0}}, {"TCP": {}}))
        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xe1}}, {"TCP": {}}))
        pack_list.append(({"Ether": {"dst": dst_mac, "src": src_mac}}, {"IP": {"tos": 0xff}}, {"TCP": {}}))

        stream_ids = []
        for pack in pack_list:
            stream_ids.append(tg.set_stream(pack, count=1, iface=iface))

        tg.set_qos_stat_type(iface, "IP")
        tg.clear_statistics([iface, ])

        tg.start_sniff([iface, ], sniffing_time=5)
        tg.start_streams(stream_ids)
        data = tg.stop_sniff([iface, ])
        tg.stop_streams(stream_ids)

        assert iface in data
        # Verify that sniffed count == count
        assert len(data[iface]) == 24
        assert tg.get_received_frames_count(iface) == 24

        for prio in range(8):
            assert tg.get_qos_frames_count(iface, 0) == 3

    def test_get_rate_stat(self, tg):
        """ Check transmit rate reading """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_ip_tcp, continuous=True, inter=0.1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_tcp, continuous=True, inter=0.05, iface=iface)

        tg.start_streams([stream_id_1, ])
        time.sleep(1)
        assert 10 * 0.9 <= tg.get_port_txrate(iface) <= 10 * 1.1
        assert 10 * 0.9 <= tg.get_port_rxrate(iface) <= 10 * 1.1
        tg.stop_streams([stream_id_1, ])

        tg.start_streams([stream_id_2, ])
        time.sleep(1)
        assert 20 * 0.95 <= tg.get_port_txrate(iface) <= 20 * 1.05
        assert 20 * 0.95 <= tg.get_port_rxrate(iface) <= 20 * 1.05
        tg.stop_streams([stream_id_2, ])

        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        assert 30 * 0.96 <= tg.get_port_txrate(iface) <= 30 * 1.04
        assert 30 * 0.96 <= tg.get_port_rxrate(iface) <= 30 * 1.04
        tg.stop_streams([stream_id_1, stream_id_2])

    @pytest.mark.skip("IP OPTS is not integrated yet")
    def test_check_increment_ip_src(self, tg):
        """  Check all fields in incremented packet. IP.src increment """
        iface = tg.ports[0]

        packet = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                  {"Dot1Q": {"vlan": 5}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "tos": 255, "id": 2, "flags": 1, "frag": 0,
                   "options": [{"IPOption_Router_Alert": {"length": 4}}, ]}},
                  {"UDP": {"dport": 23, "sport": 23}},
                  )
        stream_id = tg.set_stream(packet, count=5, sip_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])
        assert iface in data

        received = tg.packet_dictionary(data[iface][0])

        # Verify received packet is equal to sent packet
        assert self._check_packets_data(packet, received)

    @pytest.mark.skip("IP OPTS is not integrated yet")
    def test_check_increment_ip_dst(self, tg):
        """  Check all fields in incremented packet. IP.dst increment """
        iface = tg.ports[0]

        packet = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                  {"Dot1Q": {"vlan": 5}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "tos": 255, "id": 2, "flags": 1, "frag": 0,
                   "options": [{"IPOption_Router_Alert": {"length": 4}}, ]}},
                  {"UDP": {"dport": 23, "sport": 23}},
                  )
        stream_id = tg.set_stream(packet, count=1, dip_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        received = tg.packet_dictionary(data[iface][0])

        # Verify received packet is equal to sent packet
        assert self._check_packets_data(packet, received)

    @pytest.mark.skip("IP DSCP is not integrated yet")
    def test_check_increment_ip_dscp(self, tg):
        """  Check all fields in incremented packet. IP.tos increment"""
        iface = tg.ports[0]

        packet = ({"Ether": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                  {"Dot1Q": {"vlan": 5}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "tos": 255, "id": 2, "flags": 1, "frag": 0,
                   "options": [{"IPOption_Router_Alert": {"length": 4}}, ]}},
                  {"UDP": {"dport": 23, "sport": 23}},
                  )
        stream_id = tg.set_stream(packet, count=1, dscp_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        received = tg.packet_dictionary(data[iface][0])

        # Verify received packet is equal to sent packet
        assert self._check_packets_data(packet, received)

    @pytest.mark.skip("IP proto increment  is not integrated yet")
    def test_check_increment_ip_proto(self, tg):
        """  Check all fields in incremented packet. IP.proto increment """
        iface = tg.ports[0]

        packet = ({"Ether": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                  {"Dot1Q": {"vlan": 5}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "tos": 255, "id": 2, "flags": 1, "frag": 0,
                   "options": [{"IPOption_Router_Alert": {"length": 4}}, ]}},
                  {"UDP": {"dport": 23, "sport": 23}},
                  )
        stream_id = tg.set_stream(packet, count=1, protocol_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        received = tg.packet_dictionary(data[iface][0])

        # Verify received packet is equal to sent packet
        assert self._check_packets_data(packet, received)

    @pytest.mark.skip("packet_dictionary is not integrated yet")
    def test_check_increment_arp_hwsrc(self, tg):
        """  Check all fields in incremented packet. APR.hwsrc increment """
        iface = tg.ports[0]

        packet = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                  {"Dot1Q": {"vlan": 5}},
                  {"ARP": {"op": 1, "sha": "00:00:20:00:10:02", "spa": "1.1.1.1", "tha": "00:00:00:00:00:00", "tpa": "1.1.1.2"}},
                  )
        stream_id = tg.set_stream(packet, count=1, arp_sa_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        received = tg.packet_dictionary(data[iface][0])

        # Verify received packet is equal to sent packet
        assert self._check_packets_data(packet, received)

    @pytest.mark.skip("packet_dictionary is not integrated yet")
    def test_check_increment_arp_psrc(self, tg):
        """  Check all fields in incremented packet. APR.psrc increment """
        iface = tg.ports[0]

        packet = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                  {"Dot1Q": {"vlan": 5}},
                  {"ARP": {"op": 2, "sha": "00:00:20:00:10:02", "spa": "1.1.1.1", "tha": "00:00:00:00:00:00", "tpa": "1.1.1.2"}},
                  )
        stream_id = tg.set_stream(packet, count=1, arp_sip_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        received = tg.packet_dictionary(data[iface][0])

        # Verify received packet is equal to sent packet
        assert self._check_packets_data(packet, received)

    @pytest.mark.skip("IGMP increment  is not integrated yet")
    def test_check_increment_igmp_ip(self, tg):
        """  Check all fields in incremented packet. IGMP.ip increment """
        iface = tg.ports[0]

        packet = ({"Ether": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                  {"Dot1Q": {"vlan": 5}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "tos": 255, "id": 2, "flags": 1, "frag": 0,
                   "options": [{"IPOption_Router_Alert": {"length": 4}}, ]}},
                  {"IGMP": {"type": 17, "mrtime": 23, "gaddr": '10.0.2.5'}},
                  )
        stream_id = tg.set_stream(packet, count=1, igmp_ip_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        received = tg.packet_dictionary(data[iface][0])

        # Verify received packet is equal to sent packet
        assert self._check_packets_data(packet, received)

        packet = ({"Ether": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                  {"Dot1Q": {"vlan": 5}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "tos": 255, "id": 2, "flags": 1, "frag": 0,
                   "options": [{"IPOption_Router_Alert": {"length": 4}}, ]}},
                  {"IGMP": {"type": 18, "mrtime": 23, "gaddr": '10.0.2.5'}},
                  )
        stream_id = tg.set_stream(packet, count=1, igmp_ip_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        received = tg.packet_dictionary(data[iface][0])

        # Verify received packet is equal to sent packet
        assert self._check_packets_data(packet, received)

        packet = ({"Ether": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                  {"Dot1Q": {"vlan": 5}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "tos": 255, "id": 2, "flags": 1, "frag": 0,
                   "options": [{"IPOption_Router_Alert": {"length": 4}}, ]}},
                  {"IGMP": {"type": 23, "mrtime": 23, "gaddr": '10.0.2.5'}},
                  )
        stream_id = tg.set_stream(packet, count=1, igmp_ip_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        received = tg.packet_dictionary(data[iface][0])

        # Verify received packet is equal to sent packet
        assert self._check_packets_data(packet, received)

        packet = ({"Ether": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                  {"Dot1Q": {"vlan": 5}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "tos": 255, "id": 2, "flags": 1, "frag": 0,
                   "options": [{"IPOption_Router_Alert": {"length": 4}}, ]}},
                  {"IGMP": {"type": 34, "mrtime": 23, "gaddr": '10.0.2.5'}},
                  )
        stream_id = tg.set_stream(packet, count=1, igmp_ip_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        received = tg.packet_dictionary(data[iface][0])

        # Verify received packet is equal to sent packet
        assert self._check_packets_data(packet, received)

        packet = ({"Ether": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                  {"Dot1Q": {"vlan": 5}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "tos": 255, "id": 2, "flags": 1, "frag": 0,
                   "options": [{"IPOption_Router_Alert": {"length": 4}}, ]}},
                  {"IGMP": {"type": 22, "mrtime": 23, "gaddr": '10.0.2.5'}},
                  )
        stream_id = tg.set_stream(packet, count=1, igmp_ip_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        received = tg.packet_dictionary(data[iface][0])

        # Verify received packet is equal to sent packet
        assert self._check_packets_data(packet, received)

    @pytest.mark.skip("IP OPTS is not integrated yet")
    def test_check_increment_ip_icmp(self, tg):
        """  Check all fields in incremented packet. IP.src increment """
        iface = tg.ports[0]

        packet = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                  {"Dot1Q": {"vlan": 5}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "tos": 255, "id": 2, "flags": 1, "frag": 0,
                   "options": [{"IPOption_Router_Alert": {"length": 4}}, ]}},
                  {"ICMP": {"type": 11, "code": 23, "id": 3, "seq": 20}},
                  )
        stream_id = tg.set_stream(packet, count=1, sip_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        received = tg.packet_dictionary(data[iface][0])

        # Verify received packet is equal to sent packet
        assert self._check_packets_data(packet, received)

    @pytest.mark.skip("IP OPTS is not integrated yet")
    def test_check_increment_udp_sport(self, tg):
        """  Check all fields in incremented packet. UDP.sport increment """
        iface = tg.ports[0]

        packet = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                  {"Dot1Q": {"vlan": 5}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "tos": 255, "id": 2, "flags": 1, "frag": 0,
                   "options": [{"IPOption_Router_Alert": {"length": 4}}, ]}},
                  {"UDP": {"sport": 20, "dport": 80}},
                  )
        stream_id = tg.set_stream(packet, count=1, sudp_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        received = tg.packet_dictionary(data[iface][0])

        # Verify received packet is equal to sent packet
        assert self._check_packets_data(packet, received)

    @pytest.mark.skip("IP OPTS is not integrated yet")
    def test_check_increment_udp_dport(self, tg):
        """  Check all fields in incremented packet. UDP.dport increment """
        iface = tg.ports[0]

        packet = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                  {"Dot1Q": {"vlan": 5}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "tos": 255, "id": 2, "flags": 1, "frag": 0,
                   "options": [{"IPOption_Router_Alert": {"length": 4}}, ]}},
                  {"UDP": {"sport": 20, "dport": 80}},
                  )
        stream_id = tg.set_stream(packet, count=1, dudp_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        received = tg.packet_dictionary(data[iface][0])

        # Verify received packet is equal to sent packet
        assert self._check_packets_data(packet, received)

    @pytest.mark.skip("IP opts is not integrated yet")
    def test_check_increment_dot1q_vlan_single(self, tg):
        """  Check all fields in incremented packet. Dot1Q.vlan increment """
        iface = tg.ports[0]

        packet = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                  {"Dot1Q": {"vlan": 5, "prio": 2}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "tos": 255, "id": 2, "flags": 1, "frag": 0,
                   "options": [{"IPOption_Router_Alert": {"length": 4}}, ]}},
                  {"UDP": {"sport": 20, "dport": 80}},
                  )
        stream_id = tg.set_stream(packet, count=1, vlan_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        received = tg.packet_dictionary(data[iface][0])

        # Verify received packet is equal to sent packet
        assert self._check_packets_data(packet, received)

    @pytest.mark.skip("IP opts is not integrated yet")
    def test_check_increment_dot1q_vlan_double(self, tg):
        """  Check all fields in incremented packet. Dot1Q.vlan increment"""
        iface = tg.ports[0]

        packet = ({"Ethernet": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x8100}},
                  {"Dot1Q": {"vlan": 5, "prio": 2}}, {"Dot1Q": {"vlan": 6, "prio": 3}},
                  {"IP": {"src": "20.0.10.2", "dst": "10.10.10.1", "tos": 255, "id": 2, "flags": 1, "frag": 0,
                   "options": [{"IPOption_Router_Alert": {"length": 4}}, ]}},
                  {"UDP": {"sport": 20, "dport": 80}},
                  )
        stream_id = tg.set_stream(packet, count=1, vlan_increment=(2, 5), iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, src_filter="00:00:20:00:10:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data

        received = tg.packet_dictionary(data[iface][0])

        # Verify received packet is equal to sent packet
        assert self._check_packets_data(packet, received)

    def test_stop_sniffing(self, tg):
        """ Start continuous stream and stop sniffing """
        iface = tg.ports[0]
        stream_id_1 = tg.set_stream(self.packet_definition, continuous=True, iface=iface)

        tg.start_sniff([iface, ])
        tg.start_streams([stream_id_1, ])
        time.sleep(3)
        tg.stop_streams([stream_id_1, ])
        tg.stop_sniff([iface, ])
        start_receive_statistics = tg.get_received_frames_count(iface)
        time.sleep(5)
        end_receive_statistics = tg.get_received_frames_count(iface)

        assert start_receive_statistics == end_receive_statistics

    @pytest.mark.skip("IP opts is not integrated yet")
    def test_packet_with_ipoption(self, tg):
        """
        @brief  Test building packet with IPOption.
        """
        iface = tg.ports[0]
        dst_mac = "01:00:5E:00:01:05"
        src_mac = "00:00:05:04:03:02"
        igmp_query = ({"Ethernet": {"dst": dst_mac, "src": src_mac, "type": 0x0800}},
                      {"IP": {"src": "10.0.1.101", "dst": "224.0.1.5", "p": 2, "ttl": 1,
                              "opts": [{"IP_OPT_RTRALT": {"len": 4}}, ], "tos": 0xc0, "len": 36}},
                      {"IGMP": {"type": 17, "maxresp": 100}},)

        stream_id = tg.set_stream(igmp_query, count=1, iface=iface, adjust_size=False)

        tg.start_sniff([iface, ], sniffing_time=3)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data, "No packets were sniffed."
        # filter our packets from data
        # TODO: update with [x for x in data[iface] if tg.get_packet_field(x,"Ethernet", "dst") == dst_mac]
        # data[iface] = [x for x in data[iface] if x.get_packet_field("Ether", "dst") == dst_mac and x.get_packet_field("Ether", "src") == src_mac]
        assert len(data[iface]) == 1, "Expected to sniff 1 packet but sniffed %s" % (len(data[iface]), )

        assert data[iface][0].haslayer("IPOption_Router_Alert") and data[iface][0].get_lfield("IPOption_Router_Alert", "length") == 4

    def test_dot1q_arp_filter(self, tg):
        """ Check Dot1Q.ARP filter """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_arp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_arp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=7, filter_layer="Dot1Q.ARP")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q.ARP filter layer are sniffed
        assert len(data[iface]) == 1

        assert tg.get_packet_layer(data[iface][0], "ARP") is not None and tg.get_packet_field(data[iface][0], "Ethernet", "vlan") is not None

    def test_dot1q_arp_custom_filter(self, tg):
        """ Check Dot1Q.ARP filter """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_arp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_arp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=7, filter_layer="Dot1Q.ARP")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q.ARP filter layer are sniffed
        assert len(data[iface]) == 1

        p1 = data[iface][0]

        tg.start_sniff([iface, ], sniffing_time=7, filter_layer=(12, "81 00 00 00 08 06", "00 00 FF FF 00 00"))
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q.ARP filter layer are sniffed
        assert len(data[iface]) == 1

        p2 = data[iface][0]

        assert p1.bin() == p2.bin()

    def test_not_arp_filter(self, tg):
        """ Check notARP filter """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_ip_icmp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_arp, count=1, iface=iface)
        stream_id_3 = tg.set_stream(self.pack_ip_udp, count=1, iface=iface)
        stream_id_4 = tg.set_stream(self.pack_dot1q_arp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=4, filter_layer="notARP",
                       src_filter="00:00:20:00:10:02")
        tg.start_streams([stream_id_1, stream_id_2, stream_id_3, stream_id_4, ])
        time.sleep(2)
        tg.stop_streams([stream_id_1, stream_id_2, stream_id_3, stream_id_4, ])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified ARP filter layer are sniffed
        if iface in data:
            assert len(data[iface]) == 3

    def test_dot1q_filter(self, tg):
        """ Check Dot1Q filter """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_arp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_arp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=4, filter_layer="Dot1Q.ARP")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q filter layer are sniffed
        assert len(data[iface]) == 1

        assert tg.get_packet_field(data[iface][0], "Ethernet", "vlan") is not None

    def test_dot1q_custom_filter(self, tg):
        """ Check Dot1Q filter """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_arp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_arp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=4, filter_layer="Dot1Q.ARP")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q filter layer are sniffed
        assert len(data[iface]) == 1

        p1 = data[iface][0]

        tg.start_sniff([iface, ], sniffing_time=4, filter_layer=(12, "81 00 00 00 08 06", "00 00 FF FF 00 00"))
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q filter layer are sniffed
        assert len(data[iface]) == 1

        p2 = data[iface][0]

        assert p1.bin() == p2.bin()

    def test_ip_filter(self, tg):
        """ Check IP filter """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_ip_udp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_udp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=3, filter_layer="IP", dst_filter="00:00:00:33:33:33")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified IP filter layer are sniffed
        assert len(data[iface]) == 1

        assert tg.get_packet_layer(data[iface][0], "IP") is not None and tg.get_packet_field(data[iface][0], "Ethernet", "vlan") is None

    def test_ip_custom_filter(self, tg):
        """ Check IP filter """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_ip_udp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_udp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=3, filter_layer="IP", dst_filter="00:00:00:33:33:33")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified IP filter layer are sniffed
        assert len(data[iface]) == 1

        p1 = data[iface][0]

        tg.start_sniff([iface, ], sniffing_time=3, filter_layer=(12, "08 00", "00 00"), dst_filter="00:00:00:33:33:33")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified IP filter layer are sniffed
        assert len(data[iface]) == 1

        p2 = data[iface][0]

        assert p1.bin() == p2.bin()

    def test_dot1q_ip_filter(self, tg):
        """ Check Dot1Q.IP filter """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_ip_udp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_udp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=4, filter_layer="Dot1Q.IP")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q.IP filter layer are sniffed
        assert len(data[iface]) == 1

        assert tg.get_packet_layer(data[iface][0], "IP") is not None and tg.get_packet_field(data[iface][0], "Ethernet", "vlan") is not None

    def test_dot1q_ip_custom_filter(self, tg):
        """ Check Dot1Q.IP filter """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_ip_udp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_udp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=4, filter_layer="Dot1Q.IP")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q.IP filter layer are sniffed
        assert len(data[iface]) == 1

        p1 = data[iface][0]

        tg.start_sniff([iface, ], sniffing_time=4, filter_layer=(12, "81 00 00 00 08 00", "00 00 FF FF 00 00"))
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q.IP filter layer are sniffed
        assert len(data[iface]) == 1

        p2 = data[iface][0]

        assert p1.bin() == p2.bin()

    @pytest.mark.skip("STP is not integrated yet")
    def test_stp_filter(self, tg):
        """ Check STP filter """
        iface = tg.ports[0]
        stream_id_1 = tg.set_stream(self.pack_stp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_udp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=4, filter_layer="STP")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified STP layer are sniffed
        assert len(data[iface]) == 1

        assert tg.get_packet_layer(data[iface][0], "STP") is not None

    @pytest.mark.skip("STP is not integrated yet")
    def test_stp_custom_filter(self, tg):
        """ Check STP filter """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_stp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_udp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=4, filter_layer="STP")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified STP layer are sniffed
        assert len(data[iface]) == 1

        p1 = data[iface][0]

        tg.start_sniff([iface, ], sniffing_time=4, filter_layer=(14, "42 42 03 00 00", "00 00 00 00 00"))
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified STP layer are sniffed
        assert len(data[iface]) == 1

        p2 = data[iface][0]

        assert p1.bin() == p2.bin()

    @pytest.mark.skip("STP is not integrated yet")
    def test_not_stp_filter(self, tg):
        """ Check notSTP filter """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_stp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_udp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=3, filter_layer="notSTP",
                       src_filter="00:00:20:00:10:02")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(1)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified not STP layer are sniffed
        assert len(data[iface]) == 1

        assert tg.get_packet_layer(data[iface][0], "STP") is None

    def test_tcp_filter(self, tg):
        """ Check TCP filter"""
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_ip_udp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_tcp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="TCP", dst_filter="00:00:00:33:33:33")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified TCP layer are sniffed
        assert len(data[iface]) == 1

        assert tg.get_packet_layer(data[iface][0], "TCP") is not None and tg.get_packet_layer(data[iface][0], "UDP") is None

    def test_tcp_custom_filter(self, tg):
        """ Check TCP filter"""
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_ip_udp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_tcp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=10, filter_layer="TCP", dst_filter="00:00:00:33:33:33")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified TCP layer are sniffed
        assert len(data[iface]) == 1

        p1 = data[iface][0]

        tg.start_sniff([iface, ], sniffing_time=10,
                       filter_layer=(12, "08 00 00 00 00 00 00 00 00 00 00 06", "00 00 FF FF FF FF FF FF FF FF FF 00"), dst_filter="00:00:00:33:33:33")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified TCP layer are sniffed
        assert len(data[iface]) == 1

        p2 = data[iface][0]

        assert p1.bin() == p2.bin()

    def test_dot1q_tcp_filter(self, tg):
        """ Check Dot1Q.TCP filter"""
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_ip_tcp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_tcp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=4, filter_layer="Dot1Q.TCP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q.TCP layer are sniffed
        assert len(data[iface]) == 1

        assert tg.get_packet_layer(data[iface][0], "TCP") is not None and tg.get_packet_field(data[iface][0], "Ethernet", "vlan") is not None

    def test_dot1q_tcp_custom_filter(self, tg):
        """ Check Dot1Q.TCP filter"""
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_ip_tcp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_tcp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=4, filter_layer="Dot1Q.TCP")
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q.TCP layer are sniffed
        assert len(data[iface]) == 1

        p1 = data[iface][0]

        tg.start_sniff([iface, ], sniffing_time=4,
                       filter_layer=(12, "81 00 00 00 08 00 00 00 00 00 00 00 00 00 00 06", "00 00 FF FF 00 00 FF FF FF FF FF FF FF FF FF 00"))
        tg.start_streams([stream_id_1, stream_id_2])
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q.TCP layer are sniffed
        assert len(data[iface]) == 1

        p2 = data[iface][0]

        assert p1.bin() == p2.bin()

    def test_udp_filter(self, tg):
        """ Check UDP filter"""
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_ip_udp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_udp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=4, filter_layer="UDP", src_filter="00:00:20:00:10:02")
        tg.start_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified UDP layer are sniffed
        assert len(data[iface]) == 1

        assert tg.get_packet_layer(data[iface][0], "UDP") is not None and tg.get_packet_field(data[iface][0], "Ethernet", "vlan") is None

    def test_udp_custom_filter(self, tg):
        """ Check UDP filter"""
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_ip_udp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_udp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=4, filter_layer="UDP", src_filter="00:00:20:00:10:02")
        tg.start_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified UDP layer are sniffed
        assert len(data[iface]) == 1

        p1 = data[iface][0]

        tg.start_sniff([iface, ], sniffing_time=4,
                       filter_layer=(12, "08 00 00 00 00 00 00 00 00 00 00 11", "00 00 FF FF FF FF FF FF FF FF FF 00"), src_filter="00:00:20:00:10:02")
        tg.start_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified UDP layer are sniffed
        assert len(data[iface]) == 1

        p2 = data[iface][0]

        assert p1.bin() == p2.bin()

    def test_dot1q_udp_filter(self, tg):
        """ Check Dot1Q.UDP filter """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_ip_udp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_udp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=7, filter_layer="Dot1Q.UDP")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(5)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q.UDP layer are sniffed
        assert len(data[iface]) == 1
        assert tg.get_packet_layer(data[iface][0], "UDP") is not None and tg.get_packet_field(data[iface][0], "Ethernet", "vlan") is not None

    def test_dot1q_udp_custom_filter(self, tg):
        """ Check Dot1Q.UDP filter """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_ip_udp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_udp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=7, filter_layer="Dot1Q.UDP")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(5)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q.UDP layer are sniffed
        assert len(data[iface]) == 1

        p1 = data[iface][0]

        tg.start_sniff([iface, ], sniffing_time=7,
                       filter_layer=(12, "81 00 00 00 08 00 00 00 00 00 00 00 00 00 00 11", "00 00 FF FF 00 00 FF FF FF FF FF FF FF FF FF 00"))
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(5)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q.UDP layer are sniffed
        assert len(data[iface]) == 1

        p2 = data[iface][0]

        assert p1.bin() == p2.bin()

    def test_icmp_filter(self, tg):
        """ Check ICMP filter """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_ip_icmp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_icmp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=7, filter_layer="ICMP")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(5)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified ICMP layer are sniffed
        assert len(data[iface]) == 1

        assert tg.get_packet_layer(data[iface][0], "ICMP") is not None and tg.get_packet_field(data[iface][0], "Ethernet", "vlan") is None

    def test_icmp_custom_filter(self, tg):
        """ Check ICMP filter """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_ip_icmp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_icmp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=7, filter_layer="ICMP")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(5)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified ICMP layer are sniffed
        assert len(data[iface]) == 1

        p1 = data[iface][0]

        tg.start_sniff([iface, ], sniffing_time=7, filter_layer=(12, "08 00 00 00 00 00 00 00 00 00 00 01", "00 00 FF FF FF FF FF FF FF FF FF 00"))
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(5)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified ICMP layer are sniffed
        assert len(data[iface]) == 1

        p2 = data[iface][0]

        assert p1.bin() == p2.bin()

    def test_dot1q_icmp_filter(self, tg):
        """ Check Dot1Q.ICMP filter """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_ip_icmp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_icmp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=7, filter_layer="Dot1Q.ICMP")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(5)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q.ICMP layer are sniffed
        assert len(data[iface]) == 1

        assert tg.get_packet_layer(data[iface][0], "ICMP") is not None and tg.get_packet_field(data[iface][0], "Ethernet", "vlan") is not None

    def test_dot1q_icmp_custom_filter(self, tg):
        """ Check Dot1Q.ICMP filter """
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.pack_dot1q_ip_icmp, count=1, iface=iface)
        stream_id_2 = tg.set_stream(self.pack_ip_icmp, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=7, filter_layer="Dot1Q.ICMP")
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(5)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q.ICMP layer are sniffed
        assert len(data[iface]) == 1

        p1 = data[iface][0]

        tg.start_sniff([iface, ], sniffing_time=7,
                       filter_layer=(12, "81 00 00 00 08 00 00 00 00 00 00 00 00 00 00 01", "00 00 FF FF 00 00 FF FF FF FF FF FF FF FF FF 00"))
        tg.start_streams([stream_id_1, stream_id_2])
        time.sleep(5)
        tg.stop_streams([stream_id_1, stream_id_2])
        data = tg.stop_sniff([iface, ])

        # Verify that only packets with specified Dot1Q.ICMP layer are sniffed
        assert len(data[iface]) == 1

        p2 = data[iface][0]

        assert p1.bin() == p2.bin()

    @pytest.mark.skip("BGP is not integrated yet")
    def test_build_bgp_packet_simple(self, tg):
        """ Check building BGP packet. """
        iface = tg.ports[0]

        src_mac = '00:00:00:00:00:cc'
        dst_mac = '00:00:00:00:00:99'
        bgp_open = ({"Ether": {"src": src_mac, "dst": dst_mac, "type": 0x8100}},
                    {"Dot1Q": {"vlan": 7}},
                    {"IP": {"dst": "10.0.0.1", "src": "10.0.0.2", "tos": 6}},
                    {"TCP": {"sport": 179, "dport": 47330, "seq": 305, "ack": 887850408, "flags": 0x18}},
                    {"BGPHeader": {"type": 2}},
                    {"BGPUpdate": {"withdrawn_len": 0, "withdrawn": [], "nlri": [(24, '20.1.1.0')],
                                   "total_path": [{"BGPPathAttribute": {"type": 1, "origin": 1}},
                                                  {"BGPPathAttribute": {"type": 2, "aspath": []}}, ]}}, )
        stream_id = tg.set_stream(bgp_open, count=1, iface=iface)
        tg.start_sniff([iface, ], sniffing_time=4, filter_layer="Dot1Q.TCP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data and data[iface]
        # filter our packets from data
        data[iface] = [x for x in data[iface] if x.get_lfield("Ether", "dst") == dst_mac and x.get_lfield("Ether", "src") == src_mac]
        assert len(data[iface]) == 1

        assert data[iface][0].get_lfield("BGPHeader", "type") is not None
        assert tg.packet_dictionary(data[iface][0])
        assert data[iface][0].get_lcount("BGPPathAttribute") == 2

    @pytest.mark.skip("BGP is not integrated yet")
    def test_build_bgp_packet_as_path(self, tg):
        """ Check building BGP packet with multiple as_path. """
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

        tg.start_sniff([iface, ], sniffing_time=4, filter_layer="TCP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data and data[iface]
        # filter our packets from data
        data[iface] = [x for x in data[iface] if x.get_lfield("Ether", "dst") == dst_mac and x.get_lfield("Ether", "src") == src_mac]
        assert len(data[iface]) == 1

        assert data[iface][0].get_lfield("BGPHeader", "type") is not None
        assert data[iface][0].get_lfield("BGPUpdate", "total_path") is not None
        assert data[iface][0].get_lfield("BGPPathAttribute", "type") is not None

    @pytest.mark.skip("BGP is not integrated yet")
    def test_build_bgp_notification_packet(self, tg):
        """ Check building BGPNotification packet. """
        iface = tg.ports[0]

        src_mac = '00:00:00:00:00:cc'
        dst_mac = '00:00:00:00:00:99'
        bgp_open = ({"Ether": {"src": src_mac, "dst": dst_mac, "type": 0x8100}},
                    {"Dot1Q": {"vlan": 7}},
                    {"IP": {"dst": "10.0.0.1", "src": "10.0.0.2", "tos": 6}},
                    {"TCP": {"sport": 179, "dport": 47330, "seq": 305, "ack": 887850408, "flags": 0x18}},
                    {"BGPHeader": {"type": 3}},
                    {"BGPNotification": {"ErrorCode": 6, "ErrorSubCode": 1, "Data": '\x00\x01\x01\x00\x00\x00\x02'}},
                    )
        stream_id = tg.set_stream(bgp_open, count=1, iface=iface)
        tg.start_sniff([iface, ], sniffing_time=4, filter_layer="Dot1Q.TCP")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data and data[iface]
        # filter our packets from data
        data[iface] = [x for x in data[iface] if x.get_lfield("Ether", "dst") == dst_mac and x.get_lfield("Ether", "src") == src_mac]
        assert len(data[iface]) == 1

        assert data[iface][0].get_lfield("BGPHeader", "type") is not None
        assert tg.packet_dictionary(data[iface][0])
        assert data[iface][0].get_lcount("BGPNotification") == 1

    @pytest.mark.skip("Dot3 is not integrated yet")
    def test_xstp_build_capture(self, tg):
        """ Check stp/rstp/mstp build and detection."""
        iface = tg.ports[0]

        pack_rstp_2 = ({"Dot3": {"src": "00:00:00:11:11:11", "dst": "00:00:00:33:33:33"}},
                       {"LLC": {"dsap": 66, "ssap": 66, "ctrl": 3}},
                       {"STP": {"proto": 0, "version": 2, "v1len": 0}})
        pack_mstp_2 = self.pack_mstp + self.pack_msti

        stream_id_1 = tg.set_stream(self.pack_stp, count=2, inter=0.1, iface=iface, adjust_size=False)
        stream_id_2 = tg.set_stream(self.pack_rstp, count=2, inter=0.1, iface=iface, adjust_size=False)
        stream_id_3 = tg.set_stream(pack_rstp_2, count=2, inter=0.1, iface=iface, adjust_size=False)
        stream_id_4 = tg.set_stream(self.pack_mstp, count=2, inter=0.1, iface=iface, adjust_size=False)
        stream_id_5 = tg.set_stream(pack_mstp_2, count=2, inter=0.1, iface=iface, adjust_size=False)

        tg.start_sniff([iface, ], sniffing_time=20, filter_layer="STP", src_filter="00:00:00:11:11:11")
        tg.start_streams([stream_id_1, stream_id_2, stream_id_3, stream_id_4, stream_id_5])
        time.sleep(2)
        data = tg.stop_sniff([iface, ])
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

    @pytest.mark.skip("Pypacker does not support QinQ")
    def test_ether_packet(self, tg):
        """
        Verify that pypacker can recognize QinQ packets.
        """
        iface = tg.ports[0]

        dst_mac = "00:00:00:00:00:aa"
        src_mac = "00:00:00:00:00:bb"
        packet_def = ({"Ether": {"dst": dst_mac, "src": src_mac, "type": 0x9100}},
                      {"Dot1Q": {"prio": 1}},
                      {"Dot1Q": {"prio": 2}},
                      {"IP": {}}, {"TCP": {}})

        stream_id = tg.set_stream(packet_def, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=2, src_filter="00:00:00:00:00:bb")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data
        data[iface] = [x for x in data[iface] if x.get_lfield("Ether", "dst") == dst_mac and x.get_lfield("Ether", "src") == src_mac]
        assert len(data[iface]) == 1, "Expected to sniff 1 packet but sniffed %s" % (len(data[iface]), )

        # Verify ether type
        assert data[iface][0].get_lfield("Ether", "type") == 0x9100
        # Verify that we have 2 Dot1Q layers with different prio.
        assert tg.check_packet_field(data[iface][0], "Ethernet", "prio", 1)
        assert tg.check_packet_field(data[iface][0], "Ethernet", "prio", 2)

    @pytest.mark.skip("Pypacker does not support layer count")
    def test_layer_counter(self, tg):
        """
        Verify that layer counter works correctly
        """
        iface = tg.ports[0]

        dst_mac = "00:00:00:00:00:aa"
        src_mac = "00:00:00:00:00:bb"
        packet_def = ({"Ether": {"dst": dst_mac, "src": src_mac, "type": 0x9100}},
                      {"Dot1Q": {"prio": 1}},
                      {"Dot1Q": {"prio": 2}},
                      {"IP": {}}, {"TCP": {}})

        stream_id = tg.set_stream(packet_def, count=1, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=2, src_filter="00:00:00:00:00:bb")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data
        data[iface] = [x for x in data[iface] if x.get_lfield("Ether", "dst") == dst_mac and x.get_lfield("Ether", "src") == src_mac]
        assert len(data[iface]) == 1, "Expected to sniff 1 packet but sniffed %s" % (len(data[iface]), )

        assert data[iface][0].get_lcount("Dot1Q") == 2
        assert data[iface][0].get_lfield("Dot1Q", "prio") == 1
        assert data[iface][0].get_lfield("Dot1Q", "prio", 2) == 2

    @pytest.mark.skip("Pypacker does not support Dot1Q fields")
    def test_default_ether_type(self, tg):
        """
        Verify that default Ether type for tagged packets is equal to 0x8100.
        """
        iface = tg.ports[0]

        # Define packet without setting type for Ether layer.
        dst_mac = "00:00:00:00:00:11"
        src_mac = "00:00:00:00:00:22"
        pack = ({'Ether': {'dst': dst_mac, 'src': src_mac}},
                {'Dot1Q': {'type': 0x800, 'prio': 1}},
                {'IP': {}}, {'TCP': {}})

        stream_id = tg.set_stream(pack, count=1, iface=iface, adjust_size=False)

        tg.start_sniff([iface, ], sniffing_time=2)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data, "No packets were sniffed."
        # filter our packets from data
        data[iface] = [x for x in data[iface] if x.get_lfield("Ether", "dst") == dst_mac and x.get_lfield("Ether", "src") == src_mac]
        assert len(data[iface]) == 1, "Expected to sniff 1 packet but sniffed %s" % (len(data[iface]), )

        assert data[iface][0].get_lfield("Ether", "type") == 0x8100

    @pytest.mark.skip("Pypacker does not support Pause")
    def test_pause_frames_0001(self, tg):
        """
        Verify that MAC Control Pause frames with opcode 0x0001 are builded and sniffed correctly.
        """
        iface = tg.ports[0]

        # Define packet without setting type for Ether layer.
        dst_mac = "01:80:c2:00:00:01"
        src_mac = "00:00:00:00:00:aa"
        pack = ({'Ether': {'dst': dst_mac, 'src': src_mac}},
                {'Pause': {'opcode': 0x0001, 'ptime': 3}})

        stream_id = tg.set_stream(pack, count=1, iface=iface, adjust_size=False)

        tg.start_sniff([iface, ], sniffing_time=2)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data, "No packets were sniffed."
        # filter our packets from data
        data[iface] = [x for x in data[iface] if x.get_lfield("Ether", "dst") == dst_mac and x.get_lfield("Ether", "src") == src_mac]
        assert len(data[iface]) == 1, "Expected to sniff 1 packet but sniffed %s" % (len(data[iface]), )

        assert data[iface][0].get_lfield("Ether", "type") == 0x8808
        assert data[iface][0].get_lfield("Pause", "opcode") == 0x0001
        assert data[iface][0].get_lfield("Pause", "ptime") == 3

    @pytest.mark.skip("Pypacker does not support Pause")
    def test_pause_frames_0101(self, tg):
        """
        Verify that MAC Control Pause frames with opcode 0x0101 are builded and sniffed correctly.
        """
        iface = tg.ports[0]

        # Define packet without setting type for Ether layer.
        dst_mac = "01:80:c2:00:00:01"
        src_mac = "00:00:00:00:00:33"
        pack = ({'Ether': {'dst': dst_mac, 'src': src_mac}},
                {'Pause': {'opcode': 0x0101,
                           'ls': [0, 1, 0, 1, 1, 1, 0, 1],
                           'timelist': [0, 1, 0, 20, 3, 40, 3, 500]}})

        stream_id = tg.set_stream(pack, count=1, iface=iface, adjust_size=False)

        tg.start_sniff([iface, ], sniffing_time=2)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data, "No packets were sniffed."
        # filter our packets from data
        data[iface] = [x for x in data[iface] if x.get_lfield("Ether", "dst") == dst_mac and x.get_lfield("Ether", "src") == src_mac]
        assert len(data[iface]) == 1, "Expected to sniff 1 packet but sniffed %s" % (len(data[iface]), )

        assert data[iface][0].get_lfield("Ether", "type") == 0x8808
        assert data[iface][0].get_lfield("Pause", "opcode") == 0x0101
        assert data[iface][0].get_lfield("Pause", "ls") == [0, 1, 0, 1, 1, 1, 0, 1]
        assert data[iface][0].get_lfield("Pause", "timelist") == [0, 1, 0, 20, 3, 40, 3, 500]

    @pytest.mark.skip("Pypacker does not support Pause")
    def test_pause_frames_ffff(self, tg):
        """
        Verify that MAC Control Pause frames with unknown are builded and sniffed correctly.
        """
        iface = tg.ports[0]

        # Define packet without setting type for Ether layer.
        dst_mac = "01:80:c2:00:00:01"
        src_mac = "00:00:00:00:00:99"
        pack = ({'Ether': {'dst': dst_mac, 'src': src_mac}},
                {'Pause': {'opcode': 0xffff, 'ptime': 7}})

        stream_id = tg.set_stream(pack, count=1, iface=iface, adjust_size=False)

        tg.start_sniff([iface, ], sniffing_time=2)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data, "No packets were sniffed."
        # filter our packets from data
        data[iface] = [x for x in data[iface] if x.get_lfield("Ether", "dst") == dst_mac and x.get_lfield("Ether", "src") == src_mac]
        assert len(data[iface]) == 1, "Expected to sniff 1 packet but sniffed %s" % (len(data[iface]), )

        assert data[iface][0].get_lfield("Ether", "type") == 0x8808
        assert data[iface][0].get_lfield("Pause", "opcode") == 0xffff
        assert data[iface][0].get_lfield("Pause", "ptime") == 7

    @pytest.mark.skip("Pypacker does not support LLDP")
    def test_lldp_build_capture(self, tg):
        """
        @brief  Verify that LLDP packets are builded and sniffed correctly.
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

        tg.start_sniff([iface, ], sniffing_time=2)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

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
        """
        @brief  Verify that DCBX packets are built and captured correctly.
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

        tg.start_sniff([iface, ], sniffing_time=2)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

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
        """
        @brief  Verify that DCBX packets with Application Priority Tables are built and captured correctly.
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

        tg.start_sniff([iface, ], sniffing_time=2)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

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
        """
        @brief  Verify that LLDP packets with full System capabilities list are built and captured correctly.
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

        tg.start_sniff([iface, ], sniffing_time=2)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

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
        """
        @brief  Verify that LLDP packets with with padding are built and captured correctly.
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

        tg.start_sniff([iface, ], sniffing_time=2)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

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
        """
        @brief  Verify that LACP packets are built and captured correctly.
        """
        iface = tg.ports[0]

        dst_mac = "01:80:c2:00:00:02"
        src_mac = "00:00:00:00:11:22"

        pack = ({"Ether": {"dst": dst_mac, "src": src_mac, "type": 0x8809}},
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

        tg.start_sniff([iface, ], sniffing_time=2, dst_filter=dst_mac, src_filter=src_mac)
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in data, "No packets were sniffed."
        assert len(data[iface]) == 1, "Expected to sniff 1 packet but sniffed %s" % (len(data[iface]), )

        assert data[iface][0].haslayer("Ether")
        assert data[iface][0].haslayer("LACP")
        assert data[iface][0].haslayer("LACPActorInfoTlv")
        assert data[iface][0].haslayer("LACPPartnerInfoTlv")
        assert data[iface][0].haslayer("LACPCollectorInfoTlv")
        assert data[iface][0].haslayer("LACPTerminatorTlv")
        assert data[iface][0].haslayer("LACPReserved")

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_pproc_packet_fragmentation_1(self, tg):
        """ Check packet fragmentation """
        fragments = tg.packet_fragment(self.pack_ip_icmp, required_size=200, fragsize=110)
        assert len(fragments) == 2

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_pproc_packet_fragmentation_2(self, tg):
        """ Check packet fragmentation. fragsize is None"""
        fragments = tg.packet_fragment(self.pack_ip_icmp, required_size=200)
        assert len(fragments) == 1

    @pytest.mark.skip("Fragmentation is not integrated yet")
    def test_pproc_packet_dictionary(self, tg):
        """ Check packet dictionary. fragsize is None"""
        fragments = tg.packet_fragment(self.pack_dot1q_ip_udp, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == self.pack_dot1q_ip_udp

        fragments = tg.packet_fragment(self.pack_dot1q_ip_tcp, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == self.pack_dot1q_ip_tcp

        fragments = tg.packet_fragment(self.pack_dot1q_ip_icmp, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == self.pack_dot1q_ip_icmp

        fragments = tg.packet_fragment(self.pack_dot1q_arp, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == self.pack_dot1q_arp

        fragments = tg.packet_fragment(self.pack_ip_icmp, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == self.pack_ip_icmp

        fragments = tg.packet_fragment(self.pack_ip_udp, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == self.pack_ip_udp

        fragments = tg.packet_fragment(self.pack_ip_tcp, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == self.pack_ip_tcp

        fragments = tg.packet_fragment(self.pack_arp, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == self.pack_arp

        fragments = tg.packet_fragment(self.pack_dot1q, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == self.pack_dot1q

        fragments = tg.packet_fragment(self.pack_qinq, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == self.pack_qinq

        fragments = tg.packet_fragment(self.pack_stp, adjust_size=False, required_size=200)
        assert len(fragments) == 1
        pac = tg.packet_dictionary(fragments[0])
        assert pac == self.pack_stp

    @pytest.mark.skip("DHCP is not integrated yet")
    def test_dhcp_ip_incrementation(self, tg):
        """ Check dhcp ip incrementation. Count == Increment count."""
        iface = tg.ports[0]

        dhcp_request = ({"Ether": {"dst": "ff:ff:ff:ff:ff:ff", "src": '00:00:10:00:01:02'}},
                        {"IP": {"src": "0.0.0.0", "dst": "255.255.255.255", "ttl": 128}},
                        {"UDP": {"sport": 68, "dport": 67}},
                        {"BOOTP": {"chaddr": '00:00:10:00:01:02', "op": 1, "hops": 0, "siaddr": '10.0.3.3'}},
                        {"DHCP": {"options": [("message-type", "request"), "end"]}})

        stream_id = tg.set_stream(dhcp_request, count=5, dhcp_si_increment=(2, 5), required_size=346, iface=iface)

        tg.start_sniff([iface, ], sniffing_time=5, filter_layer="IP", src_filter="00:00:10:00:01:02")
        tg.send_stream(stream_id)
        data = tg.stop_sniff([iface, ])

        assert iface in list(data.keys())

        # Verify that sniffed count == count
        assert len(data[iface]) == 5

        # Verify that all packets with different src ip
        src_ip_set = set()
        for packet in data[iface]:
            src_ip_set.add(tg.get_packet_field(packet, "BOOTP", "siaddr"))
        assert len(src_ip_set) == 5

    @pytest.mark.skip("RAW is not integrated yet")
    @pytest.mark.parametrize("payload_size", [26, 1480])
    def test_send_sniff_max_min_packets(self, tg, payload_size):
        """ Verify sending and sniffing of packets with minimal and maximal size """
        # 26(payload) + 20(ip header) + 14(ether header) + 4(crc) = 64
        # 1480(payload) + 20(ip header) + 14(ether header) + 4(crc) = 1518
        iface = tg.ports[0]

        payload = b""
        for _ in range(payload_size):
            payload += chr(random.randint(0, 16)).encode()
        ether_src, ether_dst = "00:1e:67:0c:22:d4", "00:1e:67:0c:44:d5"

        # send packet, sniff pkt stream
        pkt = ({"Ethernet": {"src": ether_src, "dst": ether_dst, "type": 0x800}},
               {"IP": {"src": '4.3.2.1', "dst": '1.2.3.4', "len": len(payload) + 20}},
               {"Raw": {"load": payload}})
        tg.start_sniff([iface, ], sniffing_time=5,
                       filter_layer="IP", src_filter=ether_src, dst_filter=ether_dst)
        tg.send_stream(tg.set_stream(pkt, count=1, iface=iface))
        data = tg.stop_sniff([iface, ])

        assert len(data[iface]) == 1
        # Expected IP len == Actual IP len
        assert (payload_size + 20) == data[iface][0].get_lfield("IP", "len")
        # Expected size ==  Actual size
        if (payload_size + 34) != len(data[iface][0]):
            print("WARNING: Test packet was appended by padding.")
            print("Expected size: {0}\nActual size: {1}".format(payload_size + 34, len(data[iface][0])))
        # Get payload and compare to original
        buf = data[iface][0].get_lfield("Raw", "load")
        assert buf == payload

    @pytest.mark.skip("Does not supported yet")
    def test_incrementation_negative_1(self, tg):
        """ Verify that method set_stream returns Error message when layer is not defined in packet(1). """
        iface = tg.ports[0]

        packet = ({"Ether": {"src": "00:00:20:00:10:02", "dst": "00:00:00:33:33:33", "type": 0x0800}},
                  {"TCP": {}})

        exception_message = []
        arguments = [{"sipv6_increment": (3, 5)},
                     {"dipv6_increment": (3, 5)},
                     {"sudp_increment": (3, 5)},
                     {"dudp_increment": (3, 5)},
                     {"fl_increment": (3, 5)},
                     {"dhcp_si_increment": (3, 5)},
                     {"vlan_increment": (3, 5)},
                     {"igmp_ip_increment": (1, 5)},
                     {"arp_sip_increment": (2, 5)},
                     {"dscp_increment": (1, 5)},
                     {"protocol_increment": (2, 5)}]

        for argument in arguments:
            with pytest.raises(PypackerException) as excepinfo:
                tg.set_stream(packet, count=5, iface=iface, **argument)
            exception_message.append(excepinfo.value.parameter)

        # verify expected result
        result = ["Layer UDP is not defined.", "Layer IPv6 is not defined.", "Layer BOOTP is not defined.",
                  "Layer Dot1Q is not defined.", "Layer IGMP is not defined.", "Layer ARP is not defined.",
                  "Layer IP is not defined."]
        assert len(exception_message) == 11
        assert set(exception_message) == set(result)

    @pytest.mark.skip("Does not supported yet")
    def test_incrementation_negative_2(self, tg):
        """ Verify that method set_stream returns Error message when when layer is not defined in packet(2). """
        iface = tg.ports[0]

        packet = ({"IP": {"src": "20.0.10.2", "dst": "10.10.10.1"}}, {"TCP": {}})

        exception_message = []
        arguments = [{"sa_increment": (3, 5)},
                     {"da_increment": (3, 5)},
                     {"arp_sa_increment": (3, 5)},
                     {"eth_type_increment": (3, 5)}]

        for argument in arguments:
            with pytest.raises(PypackerException) as excepinfo:
                tg.set_stream(packet, count=5, iface=iface, **argument)
            exception_message.append(excepinfo.value.parameter)

        # verify expected result
        result = ["Incorrect packet or unsupported layers structure for sa/da incrementation.",
                  "Incorrect packet or unsupported layers structure for sa/da incrementation.",
                  "Incorrect packet or unsupported layers structure for sa/da incrementation.",
                  "Layer Ether is not defined."]
        assert len(exception_message) == 4
        assert set(exception_message) == set(result)

    def test_send_stream_several_times(self, tg):
        """ Send stream several times and check statistics"""
        iface = tg.ports[0]

        stream_id_1 = tg.set_stream(self.packet_definition, count=10000, rate=0.01, iface=iface)

        tg.clear_statistics([iface, ])

        tg.send_stream(stream_id_1)

        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_sent_statistics == 10000

        # Send stream again and verify all packets were sent
        tg.send_stream(stream_id_1)

        end_sent_statistics = tg.get_sent_frames_count(iface)

        assert end_sent_statistics == 20000

    def test_send_several_streams(self, tg):
        """ Send several streams"""
        iface = tg.ports[0]

        tg.clear_statistics([iface, ])

        stream_1 = tg.set_stream(self.packet_definition, count=20, inter=0.1, iface=iface)
        stream_2 = tg.set_stream(self.packet_definition, count=20, inter=0.1, iface=iface)

        tg.send_stream(stream_1)
        tg.send_stream(stream_2)
