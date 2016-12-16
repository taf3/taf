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

@file  tg_template.py

@summary  Interface class for TG entries. This file contain description for public TG object API.
"""

from abc import ABCMeta, abstractmethod

from . import entry_template


class GenericTG(entry_template.GenericEntry, metaclass=ABCMeta):
    """
    @description  Traffic Generator interface class.
    """

    # Constants in seconds
    DEFAULT_MAX_SNIFF_TIME = 3600

    @abstractmethod
    def check(self):
        """
        @brief  Check if TG object is alive and ready for processing
        @return:  None or raise and exception.
        """
        pass

    @abstractmethod
    def create(self):
        """
        @brief  Perform all necessary procedures to initialize TG device and prepare it for interaction.
        @return:  None or raise and exception.
        @note  Method has to check --get_only option.
               Set of steps to configure TG device is related to particular TG type.
        """
        pass

    @abstractmethod
    def destroy(self):
        """
        @brief  Perform all necessary procedures to uninitialize TG device.
        @return:  None or raise and exception.
        @note  Method has to check --get_only and --leave_on options.
               Set of steps to unconfigure TG device is related to particular TG type.
               Method has to clear all connections and stop all captures and data streams.
        """
        pass

    @abstractmethod
    def cleanup(self, mode="complete"):
        """
        @brief  This method should do Ixia ports cleanup (remove streams etc).
        @param mode: "fast" or "complete". If mode == "fast", method does not clear streams on the port, but stops them (str).
        @type  mode:  str
        @return:  None or raise and exception.
        """
        pass

    @abstractmethod
    def sanitize(self):
        """
        @brief  This method has to clear all stuff which can cause device inconsistent state after exit or unexpected exception.
        @note  E.g. clear connections, stop threads. This method is called from pytest.softexit
        """
        pass

    @abstractmethod
    def clear_streams(self):
        """
        @brief  Stop and clear all traffic streams.
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
        """
        @brief  Set traffic stream with specified parameters on specified TG port.

        @param packet_def:  Packet definition. Tuple of dictionaries of dictionaries in format:
                            ({layerX: {field1: value, field2: value}, {layerY: {field1:value, fieldN: value}})
        @type  packet_def:  tuple(dict{dict})
        @param count:  How many packets to send in a stream.
        @type  count:  int
        @param inter:  Interval between sending each packet.
        @type  inter:  int
        @param rate:  Interface rate in percents.
        @type  rate:  int
        @param continuous:  Should stream be sent continuously or not. Continuous streams have to be started using start_streams method.
        @type  continuous:  bool
        @param iface:  Interface to use for packet sending (type depends on particular tg ports type).
        @type  iface:  str, tuple
        @param adjust_size:  See description for _build_pypacker_packet function.
        @type  adjust_size:  bool
        @param required_size:  Integer or tuple of parameters needed to be set when packet size should be incremented (int or tuple).
                               Tuple examples: ('Increment', <step>, <min>, <max>), ('Random', <min>, <max>)
        @type  inter:  int, tuple
        @param fragsize:  Max size of packet's single frame
        @type  fragsize:  int
        @param is_valid:  Recalculate check sum and length for each packet layer
                          (by default pypacker do this automatically in case length and check sum aren't set).
                          This parameter has to be set True with all incrementation parameters.
        @type  is_valid:  bool
        @param build_packet:  Build packet from definition or use already built pypacker packet.
        @type  build_packet:  bool
        @param sa_increment:  Source MAC increment parameters. Tuple (<step>, <count>). Use count=0 for continuous increment.
        @type  sa_increment:  tuple
        @param da_increment:  Destination MAC increment parameters. Tuple (<step>, <count>). Use count=0 for continuous increment.
        @type  da_increment:  tuple
        @param sip_increment:  Source IPv4 increment parameters. Tuple (<step>, <count>). Use count=0 for continuous increment.
        @type  sip_increment:  tuple
        @param dip_increment:  Destination IPv4 increment parameters. Tuple (<step>, <count>). Use count=0 for continuous increment.
        @type  dip_increment:  tuple
        @param arp_sa_increment:  Source MAC increment parameters for ARP packet. Tuple (<step>, <count>). Has to be used in pair with arp_sip_increment.
        @type  arp_sa_increment:  tuple
        @param arp_sip_increment:  Source IP increment parameters for ARP packet. Tuple (<step>, <count>). Has to be used in pair with arp_sa_increment.
        @type  arp_sip_increment:  tuple
        @param igmp_ip_increment:  Destination IP increment parameters for IGMP packet. Tuple (<step>, <count>).
        @type  igmp_ip_increment:  tuple
        @param lldp_sa_increment:  Source MAC increment parameters for LLDP packet. Tuple (<step>, <count>).
        @type  lldp_sa_increment:  tuple
        @param vlan_increment:  VLAN increment parameters for tagged packet. Tuple (<step>, <count>).
        @type  vlan_increment:  tuple
        @param sudp_increment:  UDP source port increment parameters.
        @type  sudp_increment:  tuple
        @param dudp_increment:  UDP destination port increment parameters.
        @type  dudp_increment:  tuple
        @param eth_type_increment:  Ethernet frame type increment parameters.
        @type  eth_type_increment:  tuple
        @param dscp_increment:  DSCP increment parameters.
        @type  dscp_increment:  tuple
        @param protocol_increment:  IP protocol incrementation..
        @type  protocol_increment:  tuple
        @param sipv6_increment:  Source IPv6 increment parameters.
        @type  sipv6_increment:  tuple
        @param dipv6_increment:  Destination IPv6 increment parameters.
        @type  dipv6_increment:  tuple
        @param fl_increment:  Flow label increment parameters.
        @type  fl_increment:  tuple
        @param dhcp_si_increment:  DHCP IP increment parameters.
        @type  dhcp_si_increment:  tuple
        @param in_vlan_increment:  Inner vlan ID increment parameters for double tagged frames. Tuple (<step>, <count>).
        @type  in_vlan_increment:  tuple
        @param tc_increment:  IPv6 Traffic Class increment parameters.
        @type  tc_increment:  tuple
        @param nh_increment:  IPv6 Next Header increment parameters.
        @type  nh_increment:  tuple

        @param cont_burst:  Should stream be sent as continuous burst or not. Continuous streams have to be started using start_streams method.
        @type  cont_burst:  bool
        @param force_errors:  Emulate Errors for configured stream.
                              Enum ("bad" /*streamErrorBadCRC, "none" /*streamErrorNoCRC, "dribble" /*streamErrorDribble, "align" /*streamErrorAlignment)
        @type  force_errors:  str
        @param udf_dependancies:  Set UDF dependencies in case one incerement is dependant from another.
                                  Dictionary {<dependant_increment> : <initial_increment>}
        @type  udf_dependancies:  dict
        @rtype:  int
        @return:  stream id
        @note  It's not expected to configure a lot of incrementation options. Different traffic generator could have different limitations for these options.
        @par Example:
        @code{.py}
        stream_id_1 = tg.set_stream(pack_ip, count=100, iface=iface)
        stream_id_2 = tg.set_stream(pack_ip, continuous=True, inter=0.1, iface=iface)
        stream_id_3 = tg.set_stream(pack_ip_udp, count=5, protocol_increment=(3, 5), iface=iface)
        stream_id_4 = tg.set_stream(pack_ip_udp, count=18, sip_increment=(3, 3), dip_increment=(3, 3), iface=iface,
                                    udf_dependancies={'sip_increment': 'dip_increment'})
        @endcode
        """
        pass

    @abstractmethod
    def send_stream(self, stream_id):
        """
        @brief  Sends the stream created by 'set_stream' method.
        @param stream_id:  ID of the stream to be send
        @type  stream_id:  int
        @rtype:  float
        @return:  timestamp
        """
        pass

    @abstractmethod
    def start_streams(self, stream_list):
        """
        @brief  Enable and start streams from the list simultaneously.
        @param stream_list:  List of stream IDs.
        @type  stream_list:  list[int]
        @return:  None
        """
        pass

    @abstractmethod
    def stop_streams(self, stream_list=None):
        """
        @brief  Disable streams from the list.
        @param stream_list:  Stream IDs to stop. In case stream_list is not set all running streams will be stopped.
        @type  stream_list:  list[int]
        @return:  None
        """
        pass

    @abstractmethod
    def start_sniff(self, ifaces, sniffing_time=None, packets_count=0, filter_layer=None, src_filter=None, dst_filter=None):
        """
        @brief  Starts sniffing on specified interfaces.
        @param ifaces:  List of TG interfaces for capturing.
        @type  ifaces:  list
        @param sniffing_time:  Time in seconds for sniffing.
        @type  sniffing_time:  int
        @param packets_count:  Count of packets to sniff (no count limitation in case 0).
        @type  packets_count:  int
        @param filter_layer:  Name of predefined sniffing filter criteria.
        @type  filter_layer:  str
        @param src_filter:  Sniff only packet with defined source MAC.
        @type  src_filter:  str
        @param dst_filter:  Sniff only packet with defined destination MAC.
        @type  dst_filter:  str
        @return:  None

        @note  This method introduces additional 1.5 seconds timeout after capture enabling.
               It's required by Ixia sniffer to wait until capturing is started.

        @par Example:
        @code
        env.tg[1].start_sniff(['eth0', ], filter_layer='IP', src_filter='00:00:00:01:01:01', dst_filter='00:00:00:22:22:22')
        @endcode
        """
        pass

    @abstractmethod
    def stop_sniff(self, ifaces, force=False, drop_packets=False, sniff_packet_count=1000):
        """
        @brief  Stops sniffing on specified interfaces and returns captured data.
        @param ifaces:  List of interfaces where capturing has to be stopped.
        @type  ifaces:  list
        @param force:  Stop capturing even if time or packet count criteria isn't achieved.
        @type  force:  bool
        @param drop_packets:  Don't return sniffed data (used in case you need just read statistics).
        @type  drop_packets:  bool
        @param sniff_packet_count:  Default number of packets to return (used to avoid test hanging in case storm).
        @type  sniff_packet_count:  int
        @rtype:  dict
        @return:  Dictionary where key = interface name, value = list of sniffed packets.
        """
        pass

    @abstractmethod
    def clear_statistics(self, sniff_port_list):
        """
        @brief  Clear statistics - number of frames.
        @param sniff_port_list:  List of interface names.
        @type  sniff_port_list:  list
        @return:  None.
        """
        pass

    @abstractmethod
    def get_received_frames_count(self, iface):
        """
        @brief  Read statistics - number of received valid frames.
        @param iface:  Interface name.
        @type  iface:  str
        @rtype:  int
        @return:  Number of received frames.
        """
        pass

    @abstractmethod
    def get_filtered_frames_count(self, iface):
        """
        @brief  Read statistics - number of received frames which fit filter criteria.
        @param iface:  Interface name.
        @type  iface:  str
        @rtype:  int
        @return:  Number of filtered frames.
        """
        pass

    @abstractmethod
    def get_uds_3_frames_count(self, iface):
        """
        @brief  Read statistics - number of non-filtered received frames (valid and invalid)
        @param iface:  Interface name.
        @type  iface:  str
        @rtype:  int
        @return:  Number of received frames.
        """
        pass

    @abstractmethod
    def get_sent_frames_count(self, iface):
        """
        @brief  Read statistics - number of sent frames.
        @param iface:  Interface name.
        @type  iface:  str
        @rtype:  int
        @return:  Number of sent frames.
        """
        pass

    @abstractmethod
    def set_flow_control(self, iface, mode):
        """
        @brief  Enable/Disable flow control on the port.
        @param iface:  Interface name.
        @type  iface:  str
        @param mode:  True/False.
        @type  mode:  bool
        @return:  None
        """
        pass

    @abstractmethod
    def set_qos_stat_type(self, iface, ptype):
        """
        @brief  Set the QoS counters to look for priority bits for given packets type.
        @param iface:  Interface name.
        @type  iface:  str
        @param ptype:  Priority type: VLAN/IP.
        @type  ptype:  str
        @return:  None
        """
        pass

    @abstractmethod
    def get_qos_frames_count(self, iface, prio):
        """
        @brief  Get captured QoS frames count.
        @param iface:  Interface name.
        @type  iface:  str
        @param prio:  Priority.
        @type  prio:  int
        @rtype;  int
        @return:  captured QoS frames count
        """
        pass

    @abstractmethod
    def get_port_txrate(self, iface):
        """
        @brief  Return port transmission rate.
        @param iface:  Interface name.
        @type  iface:  str
        @rtype:  int
        @return:  Frames per second
        """
        pass

    @abstractmethod
    def get_port_rxrate(self, iface):
        """
        @brief  Return port receiving rate.
        @param iface:  Interface name.
        @type  iface:  str
        @rtype:  int
        @return  Frames per second (int)
        """
        pass

    @abstractmethod
    def get_port_qos_rxrate(self, iface, qos):
        """
        @brief  Return port receiving rate for specific qos.
        @param iface:  Interface name.
        @type  iface:  str
        @param qos:  Qos value.
        @type  qos:  int
        @rtype:  int
        @return  Frames per second (int)
        """
        pass

    def disconnect_port(self, iface):
        """
        @brief  Simulate port link disconnecting (set it to admin down etc).
        @param iface:  Interface to disconnect.
        @type  iface:  str
        @raise  NotImplementedError:  not implemented
        @return:  None or raise and exception.
        """
        raise NotImplementedError("Method is not implemented.")

    def connect_port(self, iface):
        """
        @brief  Simulate port link connecting (set it to admin up etc).
        @param iface:  Interface to connect.
        @type  iface:  str
        @raise  NotImplementedError:  not implemented
        @return:  None or raise and exception.
        """
        raise NotImplementedError("Method is not implemented.")

    def iface_config(self, port, *args, **kwargs):
        """
        @brief  High-level interface config utility.
        @param port:  Interface name
        @type  port:  str
        @raise  NotImplementedError:  not implemented
        @note  This method has to support parameters supported by ::ixia::interface_config function for compatibility.
               You have to check already implemented parameters for other TG types.
        @par  Example:
        @code
        env.tg[1].iface_config(tgport1, autonegotiation=1, duplex="auto", speed="auto",
                               intf_ip_addr="10.1.0.101", gateway="10.1.0.1", netmask="255.255.255.0",
                               src_mac_addr="0000.0a01.0065")
        env.tg[1].iface_config(tgport2, autonegotiation=1, duplex="auto", speed="auto",
                               intf_ip_addr="40.0.0.2", gateway="40.0.0.1", netmask="255.255.255.0",
                               src_mac_addr="0000.2801.0065",
                               connected_count=increment_count, gateway_step='0.0.0.0')
        @endcode
        """
        raise NotImplementedError("Method is not implemented.")

    @abstractmethod
    def get_os_mtu(self, iface=None):
        """
        @brief  Get MTU value in host OS
        @param iface:  Interface for getting MTU in host OS
        @type  iface:  str
        @rtype:  int
        @return:  Original MTU value
        @par  Example:
        @code
        env.tg[1].get_os_mtu(iface=ports[('tg1', 'sw1')][1])
        @endcode
        """
        pass

    @abstractmethod
    def set_os_mtu(self, iface=None, mtu=None):
        """
        @brief  Set MTU value in host OS
        @param iface:  Interface for changing MTU in host OS
        @type  iface:  str
        @param mtu:  New MTU value
        @type  mtu:  int
        @rtype:  int
        @return:  Original MTU value
        @par  Example:
        @code
        env.tg[1].set_os_mtu(iface=ports[('tg1', 'sw1')][1], mtu=1650)
        @endcode
        """
        pass
