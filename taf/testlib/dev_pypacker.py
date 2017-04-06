# Copyright (c) 2017, Intel Corporation.
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

"""``dev_pypacker.py``

`Pypacker traffic generators specific functionality`

"""
import sys
import time
import socket
import ctypes
import codecs
import struct
import threading
import itertools
import traceback
from fcntl import ioctl
from io import StringIO
from functools import reduce
from subprocess import Popen
from subprocess import PIPE
from contextlib import suppress
from contextlib import closing
from collections import defaultdict

import pcapy
import pytest
from pypacker import psocket
from pypacker.layer12 import ethernet

from . import loggers
from .tg_template import GenericTG
from .custom_exceptions import PypackerException
from .packet_processor import PacketProcessor
from .tg_generators import (PypackerRandomPayloadGenerator, PypackerIncrementPayloadGenerator,
                            PypackerMacGenerator, PypackerIPGenerator, PypackerVlanGenerator,
                            PypackerProtocolGenerator, PypackerTCPOrUDPGenerator, PypackerIPv6Generator,
                            PypackerFlowLabelGenerator, PypackerTypeGenerator)


def verify_increment_conf(func):
    def wrapper(*args):
        if not args or len(args[0]) <= 1:
            err_msg = "Stream increment should be a tuple in format ('int', 'int') e.g. (1, 99)"
            raise TypeError(err_msg)
        return func(*args)
    return wrapper


class PypackerTG(PacketProcessor, GenericTG):
    """Traffic generator class based on Pypacker library.

    Notes:
        Configuration examples:

        Example 1::

            {
             "name": "Pypacker1"
             "entry_type": "tg",
             "instance_type": "pypacker",
             "id": "TG1",
             "ports": ["eth1", "eth2"],
            }

        Example 2::

            {
             "name": "Pypacker2"
             "entry_type": "tg",
             "instance_type": "pypacker",
             "id": "TG2",
             "port_list": [["eth100", 10000, "00:1e:67:0c:bb:d4"],
                           ["eth200", 10000, "00:1e:67:0c:bb:d5"]
                          ],
            }

        Where::
            \b entry_type and \b instance_type are mandatory values and cannot be changed for current device type.
            \n\b id - int or str uniq device ID (mandatory)
            \n\b name - User defined device name (optional)
            \n\b ports or \b port_list - short or long ports configuration
            \n\b You can safely add additional custom attributes. Only attributes described above will be analysed.

    """

    class_logger = loggers.ClassLogger()
    MAX_MTU = pow(2, 16)
    SIOCGIFMTU = 0x8921
    SIOCSIFMTU = 0x8922
    ETHER_HEADER = 14
    INCREMENT_ORDER = (
        ('sa_increment', 'Ethernet', 'src', 'PypackerMacGenerator', 'src_s'),
        ('da_increment', 'Ethernet', 'dst', 'PypackerMacGenerator', 'dst_s'),
        ('arp_sa_increment', 'Ethernet', 'src', 'PypackerMacGenerator', 'src_s'),
        ('arp_sa_increment', 'Ethernet', 'src', 'PypackerMacGenerator', 'arp.sha_s'),
        ('eth_type_increment', 'Ethernet', 'type', 'PypackerTypeGenerator', 'type'),
        ('vlan_increment', 'S-Dot1Q', 'vid', 'PypackerVlanGenerator', 'S-Dot1Q'),
        ('in_vlan_increment', 'C-Dot1Q', 'vid', 'PypackerVlanGenerator', 'C-Dot1Q'),
        ('arp_sip_increment', 'ARP', 'spa', 'PypackerIPGenerator', 'arp.spa_s'),
        ('sip_increment', 'IP', 'src', 'PypackerIPGenerator', 'ip.src_s'),
        ('dip_increment', 'IP', 'dst', 'PypackerIPGenerator', 'ip.dst_s'),
        ('sudp_increment', 'UDP', 'sport', 'PypackerTCPOrUDPGenerator', 'udp.sport'),
        ('dudp_increment', 'UDP', 'dport', 'PypackerTCPOrUDPGenerator', 'udp.dport'),
        ('stcp_increment', 'TCP', 'sport', 'PypackerTCPOrUDPGenerator', 'tcp.sport'),
        ('dtcp_increment', 'TCP', 'dport', 'PypackerTCPOrUDPGenerator', 'tcp.dport'),
        ('protocol_increment', 'IP', 'p', 'PypackerProtocolGenerator', 'ip.p'),
        ('dscp_increment', 'IP', 'tos', 'PypackerProtocolGenerator', 'ip.tos'),
        ('igmp_ip_increment', 'IGMP', 'group', 'PypackerIPGenerator', 'igmp.group_s'),
        ('sipv6_increment', 'IP6', 'src', 'PypackerIPv6Generator', 'ip6.src_s'),
        ('dipv6_increment', 'IP6', 'dst', 'PypackerIPv6Generator', 'ip6.dst_s'),
        ('fl_increment', 'IP6', 'flow', 'PypackerFlowLabelGenerator', 'ip6.flow'),
        ('tc_increment', 'IP6', 'fc', 'PypackerProtocolGenerator', 'ip6.fc'),
        ('nh_increment', 'IP6', 'nxt', 'PypackerProtocolGenerator', 'ip6.nxt'),
    )

    def __init__(self, config, opts):
        """Initialize PypackerTG class.

        Args:
            config(dict):  Configuration information.
            opts(OptionParser):  py.test config.option object which contains all py.test cli options.

         """
        super().__init__(config, opts)
        self.config = config
        self.id = config['id']
        self.type = config['instance_type']
        self.streams = {}
        self._send_threads = {}
        self._sniff_threads = []
        self._collector = Collector()
        self.receive_statistics = BaseStatistics()
        self.sent_statistics = BaseStatistics()
        self.ports, self.port_list = self._get_speed_ports(self.config)
        self.sniff_direction = self.config.get("sniff_direction", "egress")
        self.pcap = pcapy

    def _get_speed_ports(self, config):
        """Get ports with speed from config.

        Returns:
            tuple(list[tuple], list[tuple, int]):  Tuple with list of ports used in real config and list of port/speed values

        Notes:
            This function checks if port has speed in config file.

        """
        ports_list = config.get("port_list", [])
        ports = config.get("ports", [])
        related_conf = config.get("related_conf", {})

        if ports_list:
            ports = [x[0] for x in ports_list]
        elif related_conf:
            for rvalue in reversed(config['related_conf'].values()):
                if rvalue['instance_type'] in {'vlab', 'static'}:
                    ports, ports_list = self._get_speed_ports(rvalue)
                    break

        return ports, ports_list

    def _get_snaplen(self, mtu):
        """Return snaplen for sniffer.

        """
        # MTU + 14: where 14 is length os Ether header.
        snaplen = mtu + self.ETHER_HEADER
        if mtu == 0 or snaplen > self.MAX_MTU:
            return self.MAX_MTU
        else:
            return snaplen

    def _grab_data_from_thread(self, thr):
        """Return captured data from stopped sniffing thread.

        """
        data = []
        ifaces = [thr.sniff_port]
        thr.join()
        self._sniff_threads.remove(thr)
        for iface in ifaces:
            with suppress(KeyError):
                data.extend(self._collector.data.pop(iface))
        return data

    def create(self):
        """Perform all necessary procedures to initialize TG device and prepare it for interaction.

        Notes:
            Pypacker TG does not support this procedure

        """
        pass

    def destroy(self):
        """Perform all necessary procedures to uninitialize TG device.

        Notes:
            Pypacker TG does not support this procedure

        """
        pass

    def check(self):
        """Check if TG object is alive and ready for processing.

        Notes:
            Pypacker TG does not support this procedure

        """
        pass

    def sanitize(self):
        """Stop all threads to avoid pytest hanging.

        """
        self.stop_sniff(ifaces=None, force=True, drop_packets=True)

    @staticmethod
    def _gen_random_size(start_packet_size, end_packet_size, field_name):
        """Return random payload generator.

        """
        return field_name, PypackerRandomPayloadGenerator(start_packet_size,
                                                          end_packet_size,
                                                          None,
                                                          None)

    @staticmethod
    def _gen_incremented_size(start_packet_size, end_packet_size, size_increment_step, field_name):
        """Return incremented payload generator

        """
        return field_name, PypackerIncrementPayloadGenerator(start_packet_size,
                                                             end_packet_size,
                                                             size_increment_step,
                                                             None)

    @staticmethod
    @verify_increment_conf
    def _gen_list(increment_conf, start, gen_name, field_name):
        """Generate list.

        Raises:
            TypeError:  invalid arguments

        """
        type_generator = globals().get(gen_name)(start, None, increment_conf[0], increment_conf[1])
        return field_name, type_generator

    def set_stream(self, packet_def, count=1, inter=0, rate=None, sa_increment=None, da_increment=None, sip_increment=None, dip_increment=None, is_valid=False,
                   arp_sa_increment=None, arp_sip_increment=None, igmp_ip_increment=None, lldp_sa_increment=None, vlan_increment=None, continuous=False,
                   iface=None, adjust_size=True, required_size=64, fragsize=None, build_packet=True, sudp_increment=None, dudp_increment=None,
                   stcp_increment=None, dtcp_increment=None, eth_type_increment=None, dscp_increment=None, protocol_increment=None, sipv6_increment=None,
                   dipv6_increment=None, fl_increment=None, dhcp_si_increment=None, in_vlan_increment=None, cont_burst=False, force_errors=None,
                   udf_dependancies=None, tc_increment=None, nh_increment=None, isis_lspid_increment=None):
        """Set traffic stream with specified parameters on specified TG port.

        Args:
            packet_def(tuple(dict{dict})):  Packet definition. Tuple of dictionaries of dictionaries in format:
                                            ({layerX: {field1: value, field2: value}, {layerY: {field1:value, fieldN: value}})
            count(int):  How many packets to send in a stream.
            inter(int):  Interval between sending each packet.
            rate(int):  Interface rate in percents.
            continuous(bool):  Should stream be sent continuously or not. Continuous streams have to be started using start_streams method.
            iface(str, tuple):  Interface to use for packet sending (type depends on particular tg ports type).
            adjust_size(bool):  See description for _build_pypacker_packet function.
            required_size(int, tuple):  Integer or tuple of parameters needed to be set when packet size should be incremented.
                                        Tuple examples: ('Increment', <step>, <min>, <max>), ('Random', <min>, <max>)
            fragsize(int):  Max size of packet's single frame
            is_valid(bool):  Recalculate check sum and length for each packet layer
                             (by default pypacker do this automatically in case length and check sum aren't set).
                             This parameter has to be set True with all incrementation parameters.
            build_packet(bool):  Build packet from definition or use already built pypacker packet.
            sa_increment(tuple):  Source MAC increment parameters. Tuple (<step>, <count>). Use count=0 for continuous increment.
            da_increment(tuple):  Destination MAC increment parameters. Tuple (<step>, <count>). Use count=0 for continuous increment.
            sip_increment(tuple):  Source IPv4 increment parameters. Tuple (<step>, <count>). Use count=0 for continuous increment.
            dip_increment(tuple):  Destination IPv4 increment parameters. Tuple (<step>, <count>). Use count=0 for continuous increment.
            arp_sa_increment(tuple):  Source MAC increment parameters for ARP packet. Tuple (<step>, <count>). Has to be used in pair with arp_sip_increment.
            arp_sip_increment(tuple):  Source IP increment parameters for ARP packet. Tuple (<step>, <count>). Has to be used in pair with arp_sa_increment.
            igmp_ip_increment(tuple):  Destination IP increment parameters for IGMP packet. Tuple (<step>, <count>).
            lldp_sa_increment(tuple):  Source MAC increment parameters for LLDP packet. Tuple (<step>, <count>).
            vlan_increment(tuple):  VLAN increment parameters for tagged packet. Tuple (<step>, <count>).
            sudp_increment(tuple):  UDP source port increment parameters.
            dudp_increment(tuple):  UDP destination port increment parameters.
            eth_type_increment(tuple):  Ethernet frame type increment parameters.
            dscp_increment(tuple):  DSCP increment parameters.
            protocol_increment(tuple):  IP protocol incrementation..
            sipv6_increment(tuple):  Source IPv6 increment parameters.
            dipv6_increment(tuple):  Destination IPv6 increment parameters.
            fl_increment(tuple):  Flow label increment parameters.
            dhcp_si_increment(tuple):  DHCP IP increment parameters.
            in_vlan_increment(tuple):  Inner vlan ID increment parameters for double tagged frames. Tuple (<step>, <count>).
            tc_increment(tuple):  IPv6 Traffic Class increment parameters.
            nh_increment(tuple):  IPv6 Next Header increment parameters.

            cont_burst(bool):  Should stream be sent as continuous burst or not. Continuous streams have to be started using start_streams method.
            force_errors(str):  Emulate Errors for configured stream.
                                Enum ("bad" /*streamErrorBadCRC, "none" /*streamErrorNoCRC, "dribble" /*streamErrorDribble, "align" /*streamErrorAlignment).
            udf_dependancies(dict):  Set UDF dependencies in case one incerement is dependant from another.
                                     Dictionary {<dependant_increment> : <initial_increment>}
            stcp_increment(tuple):  source TCP address increment
            dtcp_increment(tuple):  destination TCP address increment

        Returns:
            int: stream id

        Notes:
            It's not expected to configure a lot of incrementation options. Different traffic generator could have different limitations for these options.

        Examples::

            stream_id_1 = tg.set_stream(pack_ip, count=100, iface=iface)
            stream_id_2 = tg.set_stream(pack_ip, continuous=True, inter=0.1, iface=iface)
            stream_id_3 = tg.set_stream(pack_ip_udp, count=5, protocol_increment=(3, 5), iface=iface)
            stream_id_4 = tg.set_stream(pack_ip_udp, count=18, sip_increment=(3, 3), dip_increment=(3, 3), iface=iface,
                                        udf_dependancies={'sip_increment': 'dip_increment'})

        Raises:
            TypeError:  incorrect type of increments

        """
        stream_id = (max(self.streams.keys()) + 1) if self.streams else 1
        kwargs = {}
        increments = []

        if rate is not None:
            self.class_logger.warning("Rate makes no effect for Pypacker TG")

        if force_errors is not None:
            self.class_logger.warning("Force errors makes no effect for Pypacker TG")

        if udf_dependancies is not None:
            self.class_logger.warning("UFD dependencies makes no effect for Pypacker TG")
            pytest.skip("UFD dependencies makes no effect for Pypacker TG")

        if not build_packet:
            packet = packet_def
        else:
            kwargs.update({
                'packet_definition': packet_def,
                'adjust_size': adjust_size,
            })
            if isinstance(required_size, int):
                kwargs['required_size'] = required_size
            packet = self._build_pypacker_packet(**kwargs)

        if fragsize is not None:
            pytest.skip("Packet fragmentation is not integrated yet")

        if isinstance(required_size, tuple):
            try:
                if required_size[0] == "Increment":
                    size_increment_step = required_size[1]
                    size_increment_min_val = required_size[2]
                    size_increment_max_val = required_size[3]
                    size_args = (size_increment_min_val, size_increment_max_val,
                                 size_increment_step, "padding")
                    if size_increment_step < 0:
                        size_args = (size_increment_max_val, size_increment_min_val,
                                     size_increment_step, "padding")
                    padding = self._gen_incremented_size(*size_args)
                    increments.append(padding)
                elif required_size[0] == "Random":
                    size_increment_min_val = required_size[1]
                    size_increment_max_val = required_size[2]
                    padding = self._gen_random_size(size_increment_min_val,
                                                    size_increment_max_val,
                                                    "padding")
                    increments.append(padding)
                else:
                    raise TypeError("required_size increment contains wrong values")
            except IndexError:
                err_msg = "required_size increment should be a tuple in format ('Increment', 10, 100, 1) | ('Random', 10, 100)"
                raise TypeError(err_msg)
            if size_increment_max_val < size_increment_min_val:
                raise TypeError("Max value in required_size increment is less than min value")

        # Set increments
        locals_map = locals()
        for local_name, field_type, field_name, gen_name, long_field_name in self.INCREMENT_ORDER:
            local_value = locals_map[local_name]
            if local_value is None:
                continue
            field_value = self.get_packet_field(packet, field_type, field_name)
            field_list = self._gen_list(local_value, field_value, gen_name, long_field_name)
            increments.append(field_list)

        args = {"iface": iface, "inter": inter, "is_valid": is_valid}
        if continuous:
            args["count"] = None
        else:
            args["count"] = count
        if increments:
            args["stream_increments"] = increments
        self.streams[stream_id] = {"packet": packet, "kwargs": args}

        self.class_logger.info("Stream ID:%s was set", stream_id)
        return stream_id

    def send_stream(self, stream_id=None):
        """Sends the stream created by 'set_stream' method.

        Args:
            stream_id(int):  ID of the stream to be send.

        Returns:
            float: timestamp.

        Raises:
            PypackerException:  error on stream sending

        """
        stop_lock = threading.Lock()
        self.class_logger.debug("Send stream id:%s", stream_id)
        try:
            if stream_id in self._send_threads:
                self._send_threads[stream_id]['active'] = True
            if isinstance(self.streams[stream_id]['packet'], list):
                for packet in self.streams[stream_id]['packet']:
                    self._sendp(packet, stop_lock=stop_lock, **self.streams[stream_id]['kwargs'])
            else:
                self._sendp(self.streams[stream_id]['packet'], stop_lock=stop_lock, **self.streams[stream_id]['kwargs'])
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback_message = traceback.format_exception(exc_type, exc_value, exc_traceback)
            message = "Error while sending stream:\n%s" % "".join(traceback_message)
            raise PypackerException(message)
        self.class_logger.debug("Stream ID:%s is sent", stream_id)

    def cleanup(self):
        """Stop any packets processing of the class and clear necessary attributes.

        """
        self.class_logger.info("Stop all flows")
        self.stop_streams()
        self.class_logger.info("Remove all streams")
        self.streams = {}
        self.class_logger.info("Stop all sniffers")
        self.stop_sniff()

    def start_sniff(self, ifaces, sniffing_time=None, packets_count=0, filter_layer=None, src_filter=None, dst_filter=None):
        """Starts sniffing on specified interfaces.

        Args:
            ifaces(list):  List of TG interfaces for capturing.
            sniffing_time(int):  Time in seconds for sniffing.
            packets_count(int):  Count of packets to sniff (no count limitation in case 0).
            filter_layer(str):  Name of predefined sniffing filter criteria.
            src_filter(str):  Sniff only packet with defined source MAC.
            dst_filter(str):  Sniff only packet with defined destination MAC.

        Returns:
            None

        Notes:
            This method introduces additional 1.5 seconds timeout after capture enabling.
            It's required by Ixia sniffer to wait until capturing is started.

        Examples::

            env.tg[1].start_sniff(['eth0', ], filter_layer='IP', src_filter='00:00:00:01:01:01', dst_filter='00:00:00:22:22:22')

        Raises:
            PypackerException:  sniffer on current iface already started

        """

        # Verify that there is no ports already used by another sniffer
        for thr in self._sniff_threads:
            for iface in ifaces:
                if iface == thr.sniff_port:
                    raise PypackerException("There is an another sniffer already started on port {}".format(iface))

        for sniff_port in ifaces:
            stop_lock = threading.Lock()
            thr = StoppableThread(target=self._sniffer, args=(sniff_port, packets_count, sniffing_time, filter_layer, src_filter, dst_filter, stop_lock))
            thr.daemon = True
            thr.sniff_port = sniff_port  # pylint: disable=attribute-defined-outside-init
            thr._thr_lock = stop_lock  # pylint: disable=attribute-defined-outside-init
            thr._stop_exception = KeyboardInterrupt  # pylint: disable=attribute-defined-outside-init, protected-access
            self._sniff_threads.append(thr)
            thr.start()

        # Wait for assurance that sniffing is started
        time.sleep(1.5)

    def stop_sniff(self, ifaces=None, force=False, drop_packets=False, sniff_packet_count=0):
        """Stops sniffing on specified interfaces and returns captured data.

        Args:
            ifaces(list):  List of interfaces where capturing has to be stopped.
            force(bool):  Stop capturing even if time or packet count criteria isn't achieved.
            drop_packets(bool):  Don't return sniffed data (used in case you need just read statistics).
            sniff_packet_count(int):  Default number of packets to return (used to avoid test hanging in case storm).

        Returns:
            dict: Dictionary where key = interface name, value = list of sniffed packets.

        """
        rdata = {}

        # Collect data and remove threads.
        # If ifaces list is defined, then stop sniffer only on this ifaces
        # Else - stop all sniffers
        if not ifaces:
            ifaces = [x.sniff_port for x in self._sniff_threads]

        sniff_threads = self._sniff_threads[:]
        if force:
            iter_thr = ((thr, iface, thr.terminate()) for thr, iface in ((thr, thr.sniff_port) for thr in sniff_threads) if iface in ifaces)
            rdata = {iface: self._grab_data_from_thread(thr) for thr, iface, _ in iter_thr}

        # Stop all threads without count and time
        sniff_threads = self._sniff_threads[:]
        for thr in sniff_threads:
            iface = thr.sniff_port
            if iface in ifaces and getattr(thr, '_args', ())[1:3] == (0, None):
                thr.terminate()
                rdata[iface] = self._grab_data_from_thread(thr)

        # Collect data where capturing has to be stopped
        sniff_threads = self._sniff_threads[:]
        for thr in sniff_threads:
            iface = thr.sniff_port
            if iface in ifaces:
                rdata[iface] = self._grab_data_from_thread(thr)
        return rdata

    def start_streams(self, stream_list):
        """Enable and start streams from the list simultaneously.

        Args:
            stream_list(list[int]):  List of stream IDs.

        Returns:
            None

        """
        for stream_id in stream_list:
            thr = StoppableThread(target=self.send_stream, args=(stream_id,))
            thr.daemon = True
            thr.stream_id = stream_id  # pylint: disable=attribute-defined-outside-init
            thr._thr_lock = threading.Lock()  # pylint: disable=attribute-defined-outside-init, protected-access
            thr._stop_exception = SystemExit  # pylint: disable=attribute-defined-outside-init, protected-access
            self._send_threads[stream_id] = {}
            self._send_threads[stream_id]['thread'] = thr
            self._send_threads[stream_id]['active'] = False
            thr.start()

        # Wait until all streams are activated.
        end_time = time.time() + len(stream_list)
        stop_flag = False
        while not stop_flag:
            if all(value['active'] for key, value in self._send_threads.items() if key in stream_list):
                stop_flag = True
            if time.time() > end_time:
                self.class_logger.warning("Exit start_streams method but all streams aren't started yet. (Infinity loop prevention.)")
                stop_flag = True
            time.sleep(0.1)

    def stop_streams(self, stream_list=None):
        """ Disable streams from the list.

        Args:
            stream_list(list[int]):  Stream IDs to stop. In case stream_list is not set all running streams will be stopped.

        Returns:
            None

        """
        # If stream_list not defined then stop all streams
        if not stream_list:
            stream_list = self.streams.keys()

        for thr_id in list(self._send_threads):
            if thr_id in stream_list:
                self._send_threads[thr_id]['thread'].terminate()
                self._send_threads[thr_id]['thread'].join()
                self._send_threads.pop(thr_id)

    def clear_streams(self):
        """Stop and clear all traffic streams.

        """
        self.stop_streams()
        self.streams = {}

    def _sendp(self, packet, iface=None, count=None, inter=0, stop_lock=None, is_valid=False, stream_increments=None):
        """Send packets.

        """
        p = PacketGenerator(packet, stream_increments)
        count_iter = itertools.count(0, 1)
        if count is not None:
            count_iter = itertools.takewhile(lambda x: x < count, count_iter)
        with closing(psocket.SocketHndl(iface_name=iface)) as s, suppress(KeyboardInterrupt):
            for _ in count_iter:
                with stop_lock:
                    s.send(next(p).bin())
                    self.sent_statistics.increase(iface)
                time.sleep(inter)

    def custom_packet_filter(self, pkt):
        """Filter received packet.

        """

        def hex_str_to_int(hex_str):
            return int('0x{}'.format(hex_str), 16)

        mask = reduce(lambda m, val: m.replace(*val), [(' ', ''), ('0', '1'), ('F', '0'), ('1', 'F')],
                      self.filter_mask)
        data = self.filter_data.replace(" ", "")
        pkt_hex = codecs.encode(pkt.bin(), "hex_codec").decode()[2 * self.filter_offset:2 * self.filter_offset + len(mask)]

        mask_hex = hex_str_to_int(mask)
        if mask_hex & hex_str_to_int(pkt_hex) == mask_hex & hex_str_to_int(data):
            return pkt
        return None

    def _sniffer(self, sniff_port, count, timeout, filter_layer, src_filter=None, dst_filter=None, stop_lock=None):
        """Thread safe sniffing method for PypackerTG class.

        Raises:
            PypackerException:  unknown filter layer

        """

        def put_to_collector(pkt_hdr, pkt_data):
            """Collect sniffed data.

            """
            pkt = packet_filter(ethernet.Ethernet(pkt_data))
            if pkt is not None:
                # Get packet timestamp
                pkt.time = float(".".join(map(str, pkt_hdr.getts())))
                self._collector.collect(sniff_port, pkt)
                self.receive_statistics.increase(sniff_port, 1)

        def packet_filter(pkt):
            """Filter packets.

            """
            if lambda_filter and not lambda_filter(pkt):
                return None
            else:
                return pkt

        def get_port_statistic():
            """Get sniffed data.

            """
            return self.receive_statistics.get_data(sniff_port)

        self.receive_statistics.clear(sniff_port)
        with StringIO() as log_message, StringIO() as capture_filter:
            self.class_logger.info("Sniffer on port %s", sniff_port)
            log_message.write("Started sniffing for")
            if timeout:
                log_message.write(" {0} seconds".format(timeout))
            if count:
                log_message.write(" {0} packets".format(count))

            lambda_filter = PacketProcessor.flt_patterns.get(filter_layer, {}).get('lfilter')
            if lambda_filter is None and filter_layer is not None:
                try:
                    self.filter_offset, self.filter_data, self.filter_mask = filter_layer  # pylint: disable=attribute-defined-outside-init
                    lambda_filter = self.custom_packet_filter
                except (TypeError, IndexError):
                    message = "Unknown filter_layer '{0}'. Supported layers: {1}".format(filter_layer,
                                                                                         list(PacketProcessor.flt_patterns.keys()))
                    raise PypackerException(message)
                log_message.write(", filter '{0}'".format(filter_layer))

            if src_filter and dst_filter:
                capture_filter.write("((ether src {0}) and (ether dst {1}))".format(src_filter, dst_filter))
                log_message.write(" - '{0}'".format(capture_filter.getvalue()))
            elif src_filter:
                capture_filter.write("(ether src {0})".format(src_filter))
                log_message.write(" - '{0}'".format(capture_filter.getvalue()))
            elif dst_filter:
                capture_filter.write("(ether dst {0})".format(dst_filter))
                log_message.write(" - '{0}'".format(capture_filter.getvalue()))

            log_message.write("...")

            self.class_logger.info(log_message.getvalue())
            # Use pcap library as sniffer
            # Opening the device for sniffing open_live(device, snaplen, promisc, to_ms)
            snaplen = self._get_snaplen(self.get_os_mtu(iface=sniff_port))
            pc = self.pcap.open_live(sniff_port, snaplen, 1, 10)  # pylint: disable=no-member
            # Set a filtering rule to the pcapObject setfilter(filter, optimize, netmask)
            pc.setfilter(capture_filter.getvalue())

        # check if pcap has setdirection attribute and set direction
        direction_map = {'both': 'PCAP_D_INOUT', 'egress': 'PCAP_D_OUT', 'ingress': 'PCAP_D_IN'}
        with suppress(KeyError, AttributeError):
            pc.setdirection(direction_map[self.sniff_direction])

        timeout_iter = iter(time.time, -1)
        if timeout is not None:
            start_time = time.time()
            timeout_iter = itertools.takewhile(lambda x: x < start_time + timeout, timeout_iter)

        port_data_iter = iter(get_port_statistic, object())
        if count != 0:
            port_data_iter = itertools.takewhile(lambda x: x < count, port_data_iter)

        with suppress(KeyboardInterrupt):
            for _ in zip(timeout_iter, port_data_iter):
                with stop_lock, suppress(self.pcap.PcapError):  # pylint: disable=no-member
                    pc.dispatch(100, put_to_collector)
                time.sleep(0.01)

        self.class_logger.info("Sniffing finished")

    def get_sent_frames_count(self, iface):
        """Read Pypacker statistics - framesSent.

        """
        return self.sent_statistics.get_data(iface)

    def clear_sent_statistics(self, sniff_port):
        """Clear Pypacker statistics - framesSent.

        """
        self.sent_statistics.clear(sniff_port)

    def clear_statistics(self, sniff_port_list):
        """Clearing statistics on TG ports.

        """
        for sniff_port in sniff_port_list:
            self.clear_sent_statistics(sniff_port)
            self.clear_received_statistics(sniff_port)

    def get_received_frames_count(self, sniff_port):
        """Read statistics - framesReceived.

        """
        return self.receive_statistics.get_data(sniff_port)

    def get_filtered_frames_count(self, sniff_port):
        """Read statistics - filtered frames received.

        """
        return self.receive_statistics.get_data(sniff_port)

    def get_uds_3_frames_count(self, sniff_port):
        """Read statistics - UDS3 - Capture Trigger (UDS3) - count of non-filtered received packets (valid and invalid).

        """
        return self.receive_statistics.get_data(sniff_port)

    def clear_received_statistics(self, sniff_port):
        """Clear statistics.

        """
        self.receive_statistics.clear(sniff_port)

    def get_port_txrate(self, iface):
        """Get ports Tx rate.

        """
        pytest.skip("Method is not supported by Pypacker TG")

    def get_port_rxrate(self, iface):
        """Get ports Rx rate.

        """
        pytest.skip("Method is not supported by Pypacker TG")

    def get_port_qos_rxrate(self, iface, qos):
        """Get ports Rx rate for specific qos.

        """
        pytest.skip("Method is not supported by Pypacker TG")

    def get_qos_frames_count(self, iface, prio):
        """Get QoS frames count.

        """
        pytest.skip("Method is not supported by Pypacker TG")

    def set_qos_stat_type(self, iface, ptype):
        """Set QoS stats type.

        """
        pytest.skip("Method is not supported by Pypacker TG")

    def set_flow_control(self, iface, mode):
        """Set Flow Control.

        """
        pytest.skip("Method is not supported by Pypacker TG")

    def _configure_port_state(self, iface, state):
        """Activate/Deactivate an interface.

        Args:
            iface(str): Interface name
            state(str): Interface state to be set ('up/down')

        Raises:
            PypackerException:  error on port configuration

        """
        self.class_logger.debug("Set %s port to %s state.", iface, state)
        process = Popen(['ip', 'link', 'dev', iface, state], stdout=PIPE, stderr=PIPE)
        process.wait()
        if process.returncode != 0:
            message = "Fail to set {0} port to {1} state.".format(iface, state)
            self.class_logger.error(message)
            self.class_logger.error("StdOut: %s", process.stdout.read())
            self.class_logger.error("StdErr: %s", process.stderr.read())
            raise PypackerException(message)

    def connect_port(self, iface):
        """Simulate port link connecting (set it to admin up etc).

        Args:
            iface(str):  Interface to connect.

        Raises:
            NotImplementedError:  not implemented

        Returns:
            None or raise and exception.

        """
        self._configure_port_state(iface, "up")

    def disconnect_port(self, iface):
        """Simulate port link disconnecting (set it to admin down etc).

        Args:
            iface(str):  Interface to disconnect.

        Raises:
            NotImplementedError:  not implemented

        Returns:
            None or raise and exception.

        """
        self._configure_port_state(iface, "down")

    def get_os_mtu(self, iface=None):
        """Get MTU value in host OS.

        Args:
            iface(str):  Interface for getting MTU in host OS

        Returns:
            int: Original MTU value

        Examples::

            env.tg[1].get_os_mtu(iface=ports[('tg1', 'sw1')][1])

        """
        try:
            soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            ifr = struct.pack('16sH', iface.encode("utf-8"), 0)
            mtu = struct.unpack('16sH', ioctl(soc, self.SIOCGIFMTU, ifr))[1]
        except Exception as err:
            raise PypackerException("ERROR: Getting MTU failed; {}".format(err))

        return mtu

    def set_os_mtu(self, iface=None, mtu=None):
        """Set MTU value in host OS.

        Args:
            iface(str):  Interface for changing MTU in host OS
            mtu(int):  New MTU value

        Returns:
            int:  Original MTU value

        Examples::

            env.tg[1].set_os_mtu(iface=ports[('tg1', 'sw1')][1], mtu=1650)

        """
        try:
            soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            ioctl(soc, self.SIOCSIFMTU, struct.pack('16sH', iface.encode("utf-8"), mtu) + b'\x00' * self.ETHER_HEADER)
        except Exception as err:
            raise PypackerException("ERROR: Setting MTU failed: {}".format(err))


class StoppableThread(threading.Thread):
    """Thread class with a terminate() method.

    """

    def raise_exc(self, excobj):
        """Raise exception processing.

        """
        if not self.isAlive():
            return
        tid = next((k for k, v in threading._active.items() if v is self), None) # pylint: disable=protected-access
        if tid is None:
            return
        with self._thr_lock:
            res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), ctypes.py_object(excobj))
        if res == 0:
            raise ValueError("nonexistent thread id")
        elif res > 1:
            # if it returns a number greater than one, you're in trouble,
            # and you should call it again with exc=NULL to revert the effect
            ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), 0)
            raise SystemError("PyThreadState_SetAsyncExc failed")

        # the thread was alive when we entered the loop, but was not found
        # in the dict, hence it must have been already terminated. should we raise
        # an exception here? silently ignore?

    def terminate(self):
        """Raise exception terminating.

        """
        # must raise the SystemExit type, instead of a SystemExit() instance
        # due to a bug in PyThreadState_SetAsyncExc
        self.raise_exc(self._stop_exception)


class Collector(object):
    """This class handles results collection from all sniffer threads.

    Notes:
        No direct calls supposed. Please see doc for Sniffer class.

    """

    def __init__(self):
        """Initialize Collector class.

        """
        self._lock = threading.RLock()
        self.data = defaultdict(list)

    def collect(self, sniff_port, captured_packet):
        """Add data to collector.

        """
        with self._lock:
            self.data[sniff_port].append(captured_packet)

    def get_data(self):
        """Get data from collector.

        """
        with self._lock:
            return self.data


class BaseStatistics(object):
    """This class handles results collection from all threads.

    Notes:
        No direct calls supposed.

    """

    def __init__(self):
        """Initialize BaseStatistics class.

        """
        self._lock = threading.Lock()
        self.data = defaultdict(int)

    def increase(self, iface, count=1):
        """Increase interface statistics.

        Args:
            iface(str):  Interface name
            count(int):  Increment value

        """
        with self._lock:
            self.data[iface] += count

    def get_data(self, iface):
        """Return data.

        Returns:
            int:  interface statistics

        """
        with self._lock:
            return self.data.get(iface, 0)

    def clear(self, iface):
        """Clear data.

        """
        with self._lock:
            self.data[iface] = 0


class PacketGenerator(object):
    """Packet generator used for creating field values based on generators.

    """

    def __init__(self, packet, stream_increments=None):
        """Initialize PacketGenerator class.

        Args:
            packet(pypacker.Packet):  Packet to analyze
            stream_increments(list(tuples(str, tg_generators.BaseGenerator))):  list of packet field name and appropriate Iteration class
                                                                                to generate field values

        """
        self.packet = packet
        self.stream_increments = stream_increments

    def __next__(self):
        """Return next item from container.

        """
        if not self.stream_increments:
            return self.packet
        else:
            fields, values = [], []
            for field, value in self.stream_increments:
                fields.append(field)
                values.append(value)
            for mapped_values in itertools.zip_longest(*values):
                for field, value in itertools.zip_longest(fields, mapped_values):
                    if not value:
                        continue
                    # Find layer and set value
                    elif '.' in field:
                        layer, layer_field = field.split('.')
                        # Set value for layer 3 and higher protocol
                        for layers in self.packet:
                            packet_layer = getattr(layers, layer, None)
                            if packet_layer:
                                setattr(packet_layer, layer_field, value)
                                break
                    # Set value for layer 2 protocol
                    elif field == "S-Dot1Q":
                        setattr(getattr(self.packet, "vlan", None)[0], "vid", value)
                    elif field == "C-Dot1Q":
                        setattr(getattr(self.packet, "vlan", None)[1], "vid", value)
                    elif field == "padding":
                        packet_str = self.packet.bin()
                        if len(packet_str) < value:
                            self.packet = ethernet.Ethernet(packet_str + (b"\x00" * (value - len(packet_str))))
                        else:
                            self.packet = ethernet.Ethernet(packet_str[:value])
                    else:
                        setattr(self.packet, field, value)
                return self.packet


ENTRY_TYPE = "tg"
INSTANCES = {"pypacker": PypackerTG}
NAME = "tg"
