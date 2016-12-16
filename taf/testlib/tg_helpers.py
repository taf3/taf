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

@file  tg_helpers.py

@summary  TGHelperMixin class for mixin for tg object.
"""
import re
import time
from copy import deepcopy

import pypacker
from netaddr import IPAddress, EUI, mac_unix_expanded, mac_cisco

from .custom_exceptions import TGException, UIException
from . import loggers


class TGHelperMixin(object):
    """
    @brief  Mixin class for switch.tg
    """

    # Create logger for the class
    class_logger = loggers.module_logger(name=__name__)

    def emulate_isis_neighbor_on_port(self, tg_port, mac_address=None, system_id=None, mtu=None,
                                      ipv4_address=None, ipv6_address=None, hostname=None,
                                      isis_emul_hosts=1, ipgap=1, wait_for_packets=10):
        """
        @brief  Emutation of IS-IS router on specified TG's port
        @param  tg_port: Name of TG port for emulation
        @type  tg_port: str
        @param  mac_address: Source MAC address for IS-IS PDUs
        @type  mac_address: str
        @param  system_id: System ID for IS-IS PDUs in format "xxxx.xxxx.xxxx"
        @type  system_id: str
        @param  ipv4_address: IPv4 address to announce as management IPv4 address
        @type  ipv4_address: str
        @param  ipv6_address: IPv6 address for announcement
        @type  ipv6_address: str
        @param  hostname: Hostname for announcement
        @type  hostname: str
        @param  isis_emul_hosts: number of ISIS Hosts to emulate
        @type  isis_emul_hosts: int
        @param  ipgap: rate of ISIS LSP ID's packets to emulate
        @type  ipgap: int
        @param  wait_for_packets: Time in seconds for sniffing packets
        @type  wait_for_packets: int
        @return  IS-IS neighbor parameters that are propagated in IS-IS packets
                 e.g. MAC address or area ID.
        @rtype  dict
        @note  The second IS-IS neighbor emulation on other port leads to link state changes
               and updates (LSPs) sent to already existing neighbors. LSPs require confirmations.
               The correct way seems to be running an interactive sniffer in separate thread
               and confirm every received LSP by an appropriate PSNP/CSNP. But current IXIA TAF
               implementation doesn't support threading, so for now, in terms of compatibility, this
               approach isn't implemented.
        """
        MAX_ISISLSP_NEIGHBOR_TLV = 22  # max number of neighbor entries in LSP packet

        self.class_logger.info("Start IS-IS neighbor emulation on TG port {}".format(tg_port))

        # Sniff IS-IS Hello packets
        self.start_sniff([tg_port], packets_count=1, filter_layer="IS-IS_IIH_P2P",
                         sniffing_time=wait_for_packets)

        # Get sniffed packets, find Hello packets
        sniffed = self.stop_sniff([tg_port])
        if not sniffed[tg_port]:
            raise TGException("No IS-IS Hellos were sniffed "
                              "during {} second.".format(wait_for_packets))

        self.class_logger.debug("Received IS-IS Hello packet from neighbor \"{}\" on \"{}\" "
                                "port".format(sniffed[tg_port][0].sourceid, tg_port))

        # Get values from received IS-IS Hello to create an appropriate IS-IS packets
        neighbor_id = sniffed[tg_port][0].sourceid + ".00"
        area_id = sniffed[tg_port][0].getlayer(pypacker.ISIS_AreaEntry).areaid

        # Prepare other required variables for IS-IS packets
        mac_address = mac_address if mac_address else str(pypacker.RandMAC())
        system_id = system_id if system_id else str(EUI(mac_address, dialect=mac_cisco))
        all_is_mac_address = "09:00:2b:00:00:05"
        ipv4_address = IPAddress(ipv4_address) if ipv4_address else IPAddress(str(pypacker.RandIP()))
        ipv6_address = ipv6_address if ipv6_address else str(EUI(mac_address).ipv6_link_local())
        hostname = hostname if hostname else "isis_host_on_{}".format(tg_port)

        # Count required amount of padding TLVs in accordance to current port's MTU
        tg_port_mtu = mtu if mtu else self.get_os_mtu(iface=tg_port)
        # Get host mtu take min of both values ...
        max_pad_tlv_len = 257
        isis_headers_len = 58
        max_sized_padding_count = (tg_port_mtu - isis_headers_len) // max_pad_tlv_len
        rest_padding = (tg_port_mtu - isis_headers_len) % max_pad_tlv_len - 2

        # Prepare basic TLVs for IS-IS Hello packet
        tlvs = [{"ISIS_AreaTlv": {"areas": {"ISIS_AreaEntry": {"areaid": area_id}}}},
                {"ISIS_ProtocolsSupportedTlv": {"nlpids": ["IPv6"]}},
                {"ISIS_Ipv6InterfaceAddressTlv": {"addresses": [ipv6_address]}}]

        # Prepare Padding TLVs
        tlvs.extend([{"ISIS_PaddingTlv":
                      {"len": 255, "padding": "\x00" * 255}}] * max_sized_padding_count)
        tlvs.append({"ISIS_PaddingTlv":  {"len": rest_padding, "padding": "\x00" * rest_padding}})

        # Prepare IS-IS Hello packet
        isis_hello = ({"Dot3": {"dst": all_is_mac_address, "src": mac_address,
                                'len': tg_port_mtu}},
                       {"LLC": {"dsap": 254, "ssap": 254, "ctrl": 3}},
                       {"ISIS_CommonHdr": {}},
                       {"ISIS_P2P_Hello": {"circuittype": "L1",
                                           "sourceid": system_id,
                                           "localcircuitid": 10,
                                           "tlvs": tlvs}})

        # Prepare base IS-IS LSP packet
        isis_lsp_host = (
            {"Dot3": {"dst": all_is_mac_address, "src": mac_address}},
            {"LLC": {"dsap": 254, "ssap": 254, "ctrl": 3}},
            {"ISIS_CommonHdr": {}},
            {"ISIS_L1_LSP": {"lspid": system_id + '.00-00',
                             "lifetime": 1200, "seqnum": 1,
                             "typeblock": "L1",
                             "tlvs": [
                                 {"ISIS_AreaTlv": {
                                     "areas": {
                                         "ISIS_AreaEntry": {"areaid": area_id}}}},
                                 {"ISIS_ProtocolsSupportedTlv": {"nlpids": ["IPv6"]}},
                                 {"ISIS_DynamicHostnameTlv": {"hostname": hostname.encode('hex')}},
                                 {"ISIS_IpInterfaceAddressTlv": {"len": 4,
                                                                 "addresses": [str(ipv4_address)]}},
                                 {"ISIS_GenericTlv": {"type": 134, "val": str(ipv4_address.packed)}},
                                 {"ISIS_ExtendedIsReachabilityTlv": {
                                     "neighbours": [{
                                         "ISIS_ExtendedIsNeighbourEntry": {
                                             "metric": 10, "neighbourid": neighbor_id}}]}}]}})

        self.class_logger.debug('Send IS-IS Hello messages from "{}" port '
                                'with system ID "{}"'.format(tg_port, system_id))

        # Set stream with hello packets to send them continuously every 5 seconds
        hello_stream = self.set_stream(isis_hello, inter=5, continuous=True,
                                       adjust_size=False, iface=tg_port)

        # Start sniff to get IS-IS LSP packets after IS-IS Hello is sent
        self.start_sniff([tg_port], filter_layer="IS-IS_LSP1", sniffing_time=wait_for_packets)

        # Send stream with IS-IS Hello Packets
        self.start_streams([hello_stream])

        # Get sniffed packets
        data = self.stop_sniff([tg_port])

        # If IS-IS packets are sniffed, get LSP entries from them for confirmation using CSNP
        lsp_dict = {}
        for lsp_packet in data[tg_port]:
            lsp_entry = {'ISIS_LspEntry': {'lspid': lsp_packet.lspid,
                                           'lifetime': lsp_packet.lifetime,
                                           'seqnum': lsp_packet.seqnum,
                                           'checksum': lsp_packet.checksum}}
            entry_in_dict = lsp_dict.setdefault(lsp_packet.lspid, lsp_entry)
            if lsp_entry['ISIS_LspEntry']['seqnum'] > entry_in_dict['ISIS_LspEntry']['seqnum']:
                lsp_dict[lsp_packet.lspid] = lsp_entry

        # Raise exception if no IS-IS LSPs were received
        if not lsp_dict:
            raise TGException("No LSP was received from "
                              "the device during {} seconds.".format(wait_for_packets))

        self.class_logger.debug("Clarify received IS-IS LSPs by IS-IS CSNP.")

        # Prepare IS-IS CSNP packet for LSPs confirmation and set stream
        isis_csnp = ({"Dot3": {"dst": all_is_mac_address, "src": mac_address}},
                     {"LLC": {"dsap": 254, "ssap": 254, "ctrl": 3}},
                     {"ISIS_CommonHdr": {}},
                     {"ISIS_L1_CSNP":
                      {"sourceid": system_id + "-00",
                       "tlvs": [{"ISIS_LspEntryTlv": {"entries": list(lsp_dict.values())}}]}})

        csnp_stream = self.set_stream(isis_csnp, count=1, adjust_size=False, iface=tg_port)

        # Send CSNP and LSP streams
        self.send_stream(csnp_stream)

        # Prepare ISIS LSP's from emulated hosts
        host_streams = []
        neigh_id_n = []
        for ix in range(1, isis_emul_hosts):
            if ix % MAX_ISISLSP_NEIGHBOR_TLV == 1:
                neigh_id_n = []
                isis_lsp_host1 = deepcopy(isis_lsp_host)
                isis_lsp_host1[3]["ISIS_L1_LSP"]["lspid"] = "{0}.00-{1:02}".format(
                    EUI(mac_address, dialect=mac_cisco), (ix-1)/MAX_ISISLSP_NEIGHBOR_TLV)
            neigh_id_n.append(
                {"ISIS_ExtendedIsNeighbourEntry": {
                    "metric": 11,
                    "neighbourid": str(EUI((EUI(mac_address).value + ix), dialect=mac_cisco)) + ".00"}})
            if ix % MAX_ISISLSP_NEIGHBOR_TLV == 0 or ix == isis_emul_hosts - 1:
                isis_lsp_host1[3]["ISIS_L1_LSP"]["tlvs"][5]["ISIS_ExtendedIsReachabilityTlv"]["neighbours"].extend(neigh_id_n)
                host_streams.append(
                    self.set_stream(isis_lsp_host1, count=1, adjust_size=False, iface=tg_port))

        isis_lsp_ep = deepcopy(isis_lsp_host)
        lsp_tlv = isis_lsp_ep[3]["ISIS_L1_LSP"]["tlvs"]
        lsp_tlv[2]["ISIS_DynamicHostnameTlv"]["hostname"] = ("isis_host_{}".format(1)).encode('hex')
        lsp_tlv[3]["ISIS_IpInterfaceAddressTlv"]["addresses"] = str(ipv4_address + 1)
        lsp_tlv[4]["ISIS_GenericTlv"]["val"] = (ipv4_address + 1).packed
        lsp_tlv[5]["ISIS_ExtendedIsReachabilityTlv"]["neighbours"][0]["ISIS_ExtendedIsNeighbourEntry"]["neighbourid"] = system_id + ".00"
        isis_lsp_ep_stream = self.set_stream(isis_lsp_ep, count=isis_emul_hosts - 1, inter=ipgap,
                                             adjust_size=False, iface=tg_port,
                                             isis_lspid_increment=(1, isis_emul_hosts - 1))
        for stream in host_streams:
            self.send_stream(stream)
        self.send_stream(isis_lsp_ep_stream)

        self.class_logger.info('IS-IS neighbor with system ID "{}" emulated '
                               'on port "{}"'.format(system_id, tg_port))

        return_values = {'area_id': area_id, 'mac_address': mac_address, 'system_id': system_id,
                         'ipv4_address': ipv4_address, 'ipv6_address': ipv6_address,
                         'hostname': hostname}
        return return_values

    def isis_packets_sending(self, env, tg_port, switch_id_port, mac_address=None, ipgap=1.0,
                             isis_nodes_cnt=5, mtu=1500):
        """
        @brief  Emutation of IS-IS DCRP node on specified TG's port
        @param  env: environment data
        @type  env:
        @param  tg_port: Name of TG port for emulation
        @type  tg_port: str
        @param  switch_id_port: Switch id and port id to set port UP
        @type  switch_id_port: tuple(str, str)
        @param  mac_address: Source MAC address for IS-IS PDUs
        @type  mac_address: str
        @param  ipgap: rate of ISIS LSP ID's packets to emulate
        @type  ipgap: int
        @param  isis_nodes_cnt: Number of ISIS DCRP nodes to emulate
        @type  isis_nodes_cnt: int
        @param  mtu: MTU of
        @type  mtu: int
        @return  IS-IS neighbor parameters that are propagated in IS-IS packets
                 e.g. MAC address or area ID.
        @rtype  dict
        @note  The second IS-IS neighbor emulation on other port leads to link state changes
               and updates (LSPs) sent to already existing neighbors. LSPs require confirmations.
               The correct way seems to be running an interactive sniffer in separate thread
               and confirm every received LSP by an appropriate PSNP/CSNP. But current IXIA TAF
               implementation doesn't support threading, so for now, in terms of compatibility, this
               approach isn't implemented.
        """
        cmd = "match -f 5555 -p 30001 get_rules table"
        sw_neigh = {}
        if mac_address is None:
            mac_address = "02:aa:aa:aa:10:00"
        try:
            switch_id = switch_id_port[0]
            sw_port_id = int(switch_id_port[1])
        except KeyError:
            raise UIException("Cannot get switch port id")
        sw_instance = [switch for switch in env.switch[1].node.values() if switch.id == switch_id]
        if not sw_instance:
            raise UIException("Not found switch id and port pair connection in configuration")
        # prepare ports to emulate ISIS neighbors
        env.tg[1].connect_port(tg_port)
        if sw_port_id not in env.switch[1].mesh_ports[switch_id]:
            raise UIException("Port {} is not configured as mesh for "
                              "switch {}".format(sw_port_id, sw_instance[0].name))
        sw_instance[0].ui.modify_ports(ports=[sw_port_id], adminMode='Up')
        sw_instance[0].ui.wait_for_port_value_to_change([sw_port_id], 'operationalStatus', "Up")

        # number ISIS nodes to emulate
        nodes_cnt = isis_nodes_cnt - len(list(env.switch[1].node.values()))

        self.emulate_isis_neighbor_on_port(tg_port, mac_address=mac_address, mtu=mtu,
                                           isis_emul_hosts=nodes_cnt, ipgap=ipgap)
        # wait till HW tables 4, 5, 6 are populated
        time.sleep(5)
        for switch in env.switch[1].node.values():
            for table in [4, 5, 6]:
                output = switch.ui.cli_send_command('{} {}'.format(cmd, table)).stdout
                sw_neigh[switch] = {table: len(re.findall(r'^table\s+:\s+{}'.format(table),
                                                          output, re.MULTILINE))}
        return sw_neigh

    def table_9_test_preparation(self, env, tg_port, sw_port, packet_num, ipgap, offset=0, arp_packet=None):
        """
        @brief Prepare ports, packets for table 9 related tests
        """
        # Configure ARP packet and stream
        if arp_packet:
            srcmac = arp_packet[0]['Ether']['src']
            arp_packet[0]['Ether']['src'] = str(EUI(EUI(srcmac).value + offset, dialect=mac_unix_expanded))
            srcip = arp_packet[1]['ARP']['psrc']
            arp_packet[1]['ARP']['psrc'] = str(IPAddress(srcip) + offset)
        else:
            raise UIException("ARP packet not supplied")

        # set admin status of host and switch to Up, wait till operational status is up
        sw_port_id = int(sw_port.split()[1])
        sw_instances = [switch for switch in env.switch[1].node.values() if switch.id != sw_port.split()[0]]
        sw_instance = [switch for switch in env.switch[1].node.values() if switch.id == sw_port.split()[0]]
        if not sw_instance:
            raise UIException("Not found switch id and port pair connection in configuration")
        env.tg[1].connect_port(tg_port)
        sw_instance[0].ui.modify_ports(ports=[sw_port_id], adminMode='Up')
        sw_instance[0].ui.wait_for_port_value_to_change([sw_port_id], 'operationalStatus', "Up")

        # Prepare and send stream
        arp_stream = env.tg[1].set_stream(arp_packet, count=packet_num, inter=ipgap, iface=tg_port,
                                          arp_sa_increment=(1, packet_num + offset),
                                          arp_sip_increment=(1, packet_num + offset))
        env.tg[1].start_streams([arp_stream])
        time.sleep(ipgap * packet_num)
        env.tg[1].stop_streams([arp_stream])
        return sw_instances

    def arp_packets_sending(self, env, tg_port, sw_port, packet_num, ipgap, arp_packet=None, offset=0, retry=False):
        cmd = "match -f 5555 -p 30001 get_rules table 9"
        sw_t9 = {}
        sw_instances = self.table_9_test_preparation(env, tg_port, sw_port, ipgap=ipgap,
                                                     packet_num=packet_num, arp_packet=arp_packet,
                                                     offset=offset)
        # wait for table 9 to be populated
        time.sleep(5)
        # check table 9 entries
        assert sw_instances, "No end point ports found connected to the host"
        for switch in sw_instances:
            output = switch.ui.cli_send_command(cmd).stdout
            sw_t9[switch] = len(re.findall(r'^table\s+:\s+9', output, re.MULTILINE))
        if not retry:
            return sw_t9

        failed = False
        for switch, count in sw_t9.items():
            if count != packet_num:
                failed = True
                break
        if not failed:
            return sw_t9
        # in case not all entries are learned fast, try add them again
        arp_packet = deepcopy(arp_packet)
        srcmac = arp_packet[0]['Ether']['src']
        srcip = arp_packet[1]['ARP']['psrc']
        count = 2
        while failed and count:
            count -= 1
            self.class_logger.info("Adding not learned MAC addresses to the table 9")
            sw_instances = [switch for switch in env.switch[1].node.values() if switch.id != sw_port.split()[0]]
            for switch in sw_instances:
                output = switch.ui.cli_send_command("match -f 5555 -p 30001 get_rules table 9").stdout
                learned = re.findall(r'ethernet.dst_mac\s=\s((?:[\w]{2}:){5}[\w]{2})', output, re.MULTILINE)
                to_add = [el for el in [str(EUI(EUI(srcmac).value + ix, dialect=mac_unix_expanded))
                                        for ix in range(packet_num)] if el not in learned]
                self.class_logger.info("{} entries are missing for switch {}".format(len(to_add), switch.name))
                for mac in to_add:
                    diff = EUI(mac).value - EUI(srcmac).value
                    arp_packet[0]['Ether']['src'] = str(EUI(EUI(srcmac).value + diff, dialect=mac_unix_expanded))
                    arp_packet[1]['ARP']['psrc'] = str(IPAddress(IPAddress(srcip).value + diff))
                    # Prepare and send stream
                    arp_stream = env.tg[1].set_stream(arp_packet, count=1, iface=tg_port)
                    env.tg[1].send_stream(arp_stream)

            self.class_logger.info("Verify table#9 entries")
            for switch in sw_instances:
                output = switch.ui.cli_send_command(cmd).stdout
                if packet_num == len(re.findall(r'^table\s+:\s+9', output, re.MULTILINE)):
                    failed = False
                else:
                    failed = True
                    time.sleep(3)
                    break

        for switch in sw_instances:
            output = switch.ui.cli_send_command(cmd).stdout
            sw_t9[switch] = len(re.findall(r'^table\s+:\s+9', output, re.MULTILINE))
        return sw_t9

    def check_traffic(self, env, packets, ports, tg_indexes, rate=10, bi_dir=True, time_run=30):
        """
        @brief  Send traffic: packet_1, packet_2 between port_1 and port_2, with tg indexes: ix_1, ix_2
        """
        packet_1, packet_2 = packets
        port_1, port_2 = ports
        ix_1, ix_2 = tg_indexes
        mac_1 = packet_1[0]['Ether']['src']
        mac_2 = packet_2[0]['Ether']['src']
        stream_1 = env.tg[ix_1].set_stream(packet_1, rate=rate, iface=port_1, continuous=True)
        env.tg[ix_1].clear_statistics([port_1, ])
        stream_2 = env.tg[ix_2].set_stream(packet_2, rate=rate, iface=port_2, continuous=True)
        env.tg[ix_2].clear_statistics([port_2, ])
        self.class_logger.info("Start sending traffic from both end points")
        env.tg[ix_2].start_sniff([port_2, ], src_filter=mac_1, dst_filter=mac_2)
        if bi_dir:
            env.tg[ix_1].start_sniff([port_1, ], src_filter=mac_2, dst_filter=mac_1)
        env.tg[ix_1].start_streams([stream_1, ])
        if bi_dir:
            env.tg[ix_2].start_streams([stream_2, ])
        time.sleep(time_run)
        env.tg[ix_1].stop_streams([stream_1, ])
        if bi_dir:
            env.tg[ix_2].stop_streams([stream_2, ])
        time.sleep(4)
        env.tg[ix_2].stop_sniff([port_2, ], drop_packets=True)
        if bi_dir:
            env.tg[ix_1].stop_sniff([port_1, ], drop_packets=True)
        time.sleep(4)
        self.class_logger.info("Stop sending traffic check statistic")
        sent_count_stream_1 = env.tg[ix_1].get_sent_frames_count(port_1, )
        get_count_stream_1 = env.tg[ix_2].get_filtered_frames_count(port_2, )
        self.class_logger.info("Received packets for stream#1: {}".format(get_count_stream_1))
        assert sent_count_stream_1 == get_count_stream_1, "Packets are lost for stream #1"
        if bi_dir:
            sent_count_stream_2 = env.tg[ix_2].get_sent_frames_count(port_2, )
            get_count_stream_2 = env.tg[ix_1].get_filtered_frames_count(port_1, )
            self.class_logger.info("Received packets for stream#2: {}".format(get_count_stream_2))
            assert sent_count_stream_2 == get_count_stream_2, "Packets are lost for stream #2"
