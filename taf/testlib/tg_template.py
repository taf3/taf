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

"""``tg_template.py``

`Interface class for TG entries. This file contain description for public TG object API`

"""

from abc import ABCMeta, abstractmethod

from . import entry_template


class GenericTG(entry_template.GenericEntry, metaclass=ABCMeta):
    """Traffic Generator interface class.

    """

    # Constants in seconds
    DEFAULT_MAX_SNIFF_TIME = 3600

    @abstractmethod
    def check(self):
        """Check if TG object is alive and ready for processing.

        Returns:
            None or raise and exception.

        """
        pass

    @abstractmethod
    def create(self):
        """Perform all necessary procedures to initialize TG device and prepare it for interaction.

        Returns:
            None or raise and exception.

        Notes:
            Method has to check --get_only option.

            Set of steps to configure TG device is related to particular TG type.

        """
        pass

    @abstractmethod
    def destroy(self):
        """Perform all necessary procedures to uninitialize TG device.

        Returns:
            None or raise and exception.

        Notes:
            Method has to check --get_only and --leave_on options.
            Set of steps to unconfigure TG device is related to particular TG type.
            Method has to clear all connections and stop all captures and data streams.

        """
        pass

    @abstractmethod
    def cleanup(self, mode="complete"):
        """This method should do Ixia ports cleanup (remove streams etc).

        Args:
            mode(str): "fast" or "complete". If mode == "fast", method does not clear streams on the port, but stops them (str).

        Returns:
            None or raise and exception.

        """
        pass

    @abstractmethod
    def sanitize(self):
        """This method has to clear all stuff which can cause device inconsistent state after exit or unexpected exception.

        Notes:
            E.g. clear connections, stop threads. This method is called from pytest.softexit

        """
        pass

    @abstractmethod
    def clear_streams(self):
        """Stop and clear all traffic streams.

        """
        pass

    @abstractmethod
    def set_stream(self, packet_def=None, count=None, inter=0, rate=99,
                   continuous=False, iface=None, adjust_size=True, required_size=64,
                   fragsize=None, build_packet=True, is_valid=False,
                   sa_increment=None, da_increment=None, sip_increment=None, dip_increment=None,
                   arp_sa_increment=None, arp_sip_increment=None, igmp_ip_increment=None,
                   lldp_sa_increment=None, vlan_increment=None,
                   sudp_increment=None, dudp_increment=None,
                   eth_type_increment=None, dscp_increment=None, protocol_increment=None,
                   sipv6_increment=None, dipv6_increment=None, fl_increment=None,
                   dhcp_si_increment=None, in_vlan_increment=None,
                   tc_increment=None, nh_increment=None, isis_lspid_increment=None,
                   cont_burst=False, force_errors=None, udf_dependancies=None):
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

        """
        pass

    @abstractmethod
    def send_stream(self, stream_id):
        """Sends the stream created by 'set_stream' method.

        Args:
            stream_id(int):  ID of the stream to be send.

        Returns:
            float: timestamp.

        """
        pass

    @abstractmethod
    def start_streams(self, stream_list):
        """Enable and start streams from the list simultaneously.

        Args:
            stream_list(list[int]):  List of stream IDs.

        Returns:
            None

        """
        pass

    @abstractmethod
    def stop_streams(self, stream_list=None):
        """ Disable streams from the list.

        Args:
            stream_list(list[int]):  Stream IDs to stop. In case stream_list is not set all running streams will be stopped.

        Returns:
            None

        """
        pass

    @abstractmethod
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

        """
        pass

    @abstractmethod
    def stop_sniff(self, ifaces, force=False, drop_packets=False, sniff_packet_count=1000):
        """Stops sniffing on specified interfaces and returns captured data.

        Args:
            ifaces(list):  List of interfaces where capturing has to be stopped.
            force(bool):  Stop capturing even if time or packet count criteria isn't achieved.
            drop_packets(bool):  Don't return sniffed data (used in case you need just read statistics).
            sniff_packet_count(int):  Default number of packets to return (used to avoid test hanging in case storm).

        Returns:
            dict: Dictionary where key = interface name, value = list of sniffed packets.

        """
        pass

    @abstractmethod
    def clear_statistics(self, sniff_port_list):
        """Clear statistics - number of frames.

        Args:
            sniff_port_list(list):  List of interface names.

        Returns:
            None

        """
        pass

    @abstractmethod
    def get_received_frames_count(self, iface):
        """Read statistics - number of received valid frames.

        Args:
            iface(str):  Interface name.

        Returns:
            int: Number of received frames.

        """
        pass

    @abstractmethod
    def get_filtered_frames_count(self, iface):
        """Read statistics - number of received frames which fit filter criteria.

        Args:
            iface(str):  Interface name.

        Returns:
            int: Number of filtered frames.

        """
        pass

    @abstractmethod
    def get_uds_3_frames_count(self, iface):
        """Read statistics - number of non-filtered received frames (valid and invalid).

        Args:
            iface(str):  Interface name.

        Returns:
            int: Number of received frames

        """
        pass

    @abstractmethod
    def get_sent_frames_count(self, iface):
        """Read statistics - number of sent frames.

        Args:
            iface(str):  Interface name.

        Returns:
            int: Number of sent frames.

        """
        pass

    @abstractmethod
    def set_flow_control(self, iface, mode):
        """Enable/Disable flow control on the port.

        Args:
            iface(str):  Interface name.
            mode(bool):  True/False.

        Returns:
            None

        """
        pass

    @abstractmethod
    def set_qos_stat_type(self, iface, ptype):
        """Set the QoS counters to look for priority bits for given packets type.

        Args:
            iface(str):  Interface name.
            ptype(str):  Priority type: VLAN/IP.

        Returns:
            None

        """
        pass

    @abstractmethod
    def get_qos_frames_count(self, iface, prio):
        """Get captured QoS frames count.

        Args:
            iface(str):  Interface name.
            prio(int):  Priority.

        Returns:
            int: captured QoS frames count.

        """
        pass

    @abstractmethod
    def get_port_txrate(self, iface):
        """Return port transmission rate.

        Args:
            iface(str):  Interface name.

        Returns:
            int: Frames per second.

        """
        pass

    @abstractmethod
    def get_port_rxrate(self, iface):
        """Return port receiving rate.

        Args:
            iface(str):  Interface name.

        Returns:
            int: Frames per second.

        """
        pass

    @abstractmethod
    def get_port_qos_rxrate(self, iface, qos):
        """Return port receiving rate for specific qos.

        Args:
            iface(str):  Interface name.
            qos(int):  Qos value.

        Returns:
            int: Frames per second (int)

        """
        pass

    def disconnect_port(self, iface):
        """Simulate port link disconnecting (set it to admin down etc).

        Args:
            iface(str):  Interface to disconnect.

        Raises:
            NotImplementedError:  not implemented

        Returns:
            None or raise and exception.

        """
        raise NotImplementedError("Method is not implemented.")

    def connect_port(self, iface):
        """Simulate port link connecting (set it to admin up etc).

        Args:
            iface(str):  Interface to connect.

        Raises:
            NotImplementedError:  not implemented

        Returns:
            None or raise and exception.

        """
        raise NotImplementedError("Method is not implemented.")

    def iface_config(self, port, *args, **kwargs):
        """High-level interface config utility.

        Args:
            port(str):  Interface name

        Raises:
            NotImplementedError:  not implemented

        Note:
            This method has to support parameters supported by ::ixia::interface_config function for compatibility.
            You have to check already implemented parameters for other TG types.

        Examples::

            env.tg[1].iface_config(tgport1, autonegotiation=1, duplex="auto", speed="auto",
                                   intf_ip_addr="10.1.0.101", gateway="10.1.0.1", netmask="255.255.255.0",
                                   src_mac_addr="0000.0a01.0065")
            env.tg[1].iface_config(tgport2, autonegotiation=1, duplex="auto", speed="auto",
                                   intf_ip_addr="40.0.0.2", gateway="40.0.0.1", netmask="255.255.255.0",
                                   src_mac_addr="0000.2801.0065",
                                   connected_count=increment_count, gateway_step='0.0.0.0')

        """
        raise NotImplementedError("Method is not implemented.")

    @abstractmethod
    def get_os_mtu(self, iface=None):
        """Get MTU value in host OS.

        Args:
            iface(str):  Interface for getting MTU in host OS

        Returns:
            int: Original MTU value

        Examples::

            env.tg[1].get_os_mtu(iface=ports[('tg1', 'sw1')][1])

        """
        pass

    @abstractmethod
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
        pass
