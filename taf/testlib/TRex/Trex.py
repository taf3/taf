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

@file  Trex.py

@summary  TRex traffic generator based on TRex stateless Python API.
"""
import os

import pytest
import trex_stl_lib.api as TApi

from testlib.custom_exceptions import TrexException


class TrexMixin(object):
    """
    @description  TRex interaction base class
    """

    SYNC_PORT = 4501
    ASYNC_PORT = 4500

    class_logger = None

    SUPPORTED_INCREMENTS = ['sip_increment', 'dip_increment', 'sudp_increment', 'dudp_increment',
                            'stcp_increment', 'dtcp_increment', 'required_size']

    def __init__(self, config, opts):
        """
        @brief  Initializes connection to TRex
        @param config:  Configuration information
        @type  config:  dict
        @param opts:  py.test config.option object which contains all py.test cli options
        @type  opts:  OptionParser
        """
        super(TrexMixin, self).__init__(config, opts)
        self.stream_ids = {}
        self.connection_state = False
        self.user = self.config.get('ssh_user', '')
        self.sync_port = self.config.get('sync_port', self.SYNC_PORT)
        self.async_port = self.config.get('async_port', self.ASYNC_PORT)

        self.trex = TApi.STLClient(username=self.user, server=self.host, sync_port=self.sync_port, async_port=self.async_port)

    def connect(self):
        """
        @brief  Logs in to TRex server
        @raise  TrexException:  error on connecting to server
        @return:  None
        """
        try:
            self.trex.connect()
            self.connection_state = True
        except TApi.STLError as err:
            self.class_logger.debug("Error connecting to TRex server: %s", err)
            raise TrexException("Error on connecting to server")

        self.class_logger.info("TRex startup complete.")

    __connect = connect

    def _reset_ports(self):
        """
        @brief  Reset TG ports configuration
        @raise  TrexException:  error resetting ports
        @return:  None
        """
        try:
            self.trex.reset(ports=self.ports)
            self.trex.set_port_attr(self.ports, promiscuous=True)
        except TApi.STLError as err:
            self.class_logger.debug("Error resetting ports on TRex server: %s", err)
            raise TrexException("Error resetting ports")

    def disconnect(self, mode='fast'):
        """
        @brief  Logs out from TRex server
        @param mode:  Type of mode to execute
        @type  mode:  str
        @return:  None
        """
        self.trex.disconnect()

    __disconnect = disconnect

    def disconnect_port(self, iface):
        """
        @copydoc testlib::tg_template::GenericTG::disconnect_port()
        """
        pass

    def connect_port(self, iface):
        """
        @copydoc testlib::tg_template::GenericTG::connect_port()
        """
        pass

    def check(self):
        """
        @copydoc testlib::tg_template::GenericTG::check()
        """
        if not self.trex.is_connected():
            self.__connect()

    def create(self):
        """
        @copydoc testlib::tg_template::GenericTG::create()
        """
        self.__connect()

    def destroy(self):
        """
        @copydoc testlib::tg_template::GenericTG::destroy()
        """
        self.__disconnect()

    def cleanup(self, mode="complete"):
        """
        @copydoc testlib::tg_template::GenericTG::cleanup()
        """
        try:
            self.stop_streams()
        except TApi.STLError as err:
            self.class_logger.warning("Caught an exception while stopping streams. Type %s. Err: %s", type(err), err)
        if mode == "complete":
            self.clear_streams()

    def sanitize(self):
        """
        @copydoc testlib::tg_template::GenericTG::sanitize()
        """
        self.__disconnect()

    def clear_streams(self):
        """
        @copydoc testlib::tg_template::GenericTG::clear_streams()
        """
        self.stream_ids = {}
        self._reset_ports()

    def _check_supported_increments_and_values(self, **kwargs):
        """
        @brief  Check whether provided increments are supported or not
        @param  kwargs:  Increment parameters to be modified
        @type  kwargs:  dict
        @raise  TrexException: Unsupported increment is passed to method.
                TypeError:  Tuple must be passed to method.
        @rtype:  dict
        @return:  Dictionary of increments and values to be set
        """
        increments = {x: y for x, y in kwargs.items()
                      if y is not None and ('increment' in x or (x == 'required_size' and isinstance(y, tuple)))}

        if set(self.SUPPORTED_INCREMENTS + [x for x in increments]) != set(self.SUPPORTED_INCREMENTS):
            raise TrexException("Unsupported increment is passed to method.\n"
                                "Supported increments are: {}".format(self.SUPPORTED_INCREMENTS))

        if not all([isinstance(x, tuple) for x in increments.values() if 'increment' in x]):
            raise TypeError("Tuple must be passed to method.")

        if not all([isinstance(x[0], int) and isinstance(x[1], int) for x in increments.values()
                    if 'increment' in x]):
            raise TypeError("Tuple values must be integer.")

        if 'required_size' in increments:
            if increments['required_size'][0] == 'Increment':
                if not all([isinstance(increments['required_size'][1], int),
                            isinstance(increments['required_size'][2], int),
                            isinstance(increments['required_size'][3], int)]):
                    raise TypeError("Tuple values for required_size must be as follows: "
                                    "('Increment', <step>, <min>, <max>)")
            elif increments['required_size'][0] == 'Random':
                if not all([isinstance(increments['required_size'][1], int),
                            isinstance(increments['required_size'][2], int)]):
                    raise TypeError("Tuple values for required_size must be as follows: "
                                    "('Random', <min>, <max>)")
            else:
                raise TypeError("Incorrect required_size operation passed to method: "
                                "possible values are: 'Increment', 'Random'")
        return increments

    @staticmethod
    def _set_increments(packet, **kwargs):
        """
        @brief  Set increments for stream using Field Engine
        @param  kwargs:  Increment parameters to be modified
        @type  kwargs:  dict
        @rtype:  object(STLScVmRaw) | None
        @return:  Field Engine STLScVmRaw Class object
        """

        if not kwargs:
            return
        flow_vars = []
        if 'sip_increment' in kwargs:
            int_val_src_ip = TApi.convert_val(packet.getlayer('IP.src'))
            int_val_max_src_ip = int_val_src_ip + kwargs['sip_increment'][1]
            if kwargs['sip_increment'][0] >= 0:
                operation = 'inc'
            else:
                operation = 'dec'
            flow_vars.append(TApi.STLVmFlowVar("ip_src", min_value=int_val_src_ip,
                                               max_value=int_val_max_src_ip, size=4,
                                               step=abs(kwargs['sip_increment'][0]), op=operation))
            flow_vars.append(TApi.STLVmWrFlowVar(fv_name="ip_src", pkt_offset="IP.src"))

        if 'dip_increment' in kwargs:
            int_val_dst_ip = TApi.convert_val(packet.getlayer('IP.dst'))
            int_val_max_dst_ip = int_val_dst_ip + kwargs['dip_increment'][1]
            if kwargs['dip_increment'][0] >= 0:
                operation = 'inc'
            else:
                operation = 'dec'
            flow_vars.append(TApi.STLVmFlowVar("ip_dst", min_value=int_val_dst_ip,
                                               max_value=int_val_max_dst_ip, size=4,
                                               step=abs(kwargs['dip_increment'][0]), op=operation))
            flow_vars.append(TApi.STLVmWrFlowVar(fv_name="ip_dst", pkt_offset="IP.dst"))

        if 'sudp_increment' in kwargs:
            int_val_udp_p = packet.getlayer('UDP.sport')
            int_val_max_udp_p = int_val_udp_p + kwargs['sudp_increment'][1]
            if kwargs['sudp_increment'][0] >= 0:
                operation = 'inc'
            else:
                operation = 'dec'
            flow_vars.append(TApi.STLVmFlowVar("sudp", min_value=int_val_udp_p,
                                               max_value=int_val_max_udp_p, size=2,
                                               step=abs(kwargs['sudp_increment'][0]), op=operation))
            flow_vars.append(TApi.STLVmWrFlowVar(fv_name="sudp", pkt_offset="UDP.sport"))

        if 'dudp_increment' in kwargs:
            int_val_udp_p = packet.getlayer('UDP.dport')
            int_val_max_udp_p = int_val_udp_p + kwargs['dudp_increment'][1]
            if kwargs['dudp_increment'][0] >= 0:
                operation = 'inc'
            else:
                operation = 'dec'
            flow_vars.append(TApi.STLVmFlowVar("dudp", min_value=int_val_udp_p,
                                               max_value=int_val_max_udp_p, size=2,
                                               step=abs(kwargs['dudp_increment'][0]), op=operation))
            flow_vars.append(TApi.STLVmWrFlowVar(fv_name="dudp", pkt_offset="UDP.dport"))

        if 'stcp_increment' in kwargs:
            int_val_udp_p = packet.getlayer('TCP.sport')
            int_val_max_udp_p = int_val_udp_p + kwargs['stcp_increment'][1]
            if kwargs['stcp_increment'][0] >= 0:
                operation = 'inc'
            else:
                operation = 'dec'
            flow_vars.append(TApi.STLVmFlowVar("stcp", min_value=int_val_udp_p,
                                               max_value=int_val_max_udp_p, size=2,
                                               step=abs(kwargs['stcp_increment'][0]), op=operation))
            flow_vars.append(TApi.STLVmWrFlowVar(fv_name="stcp", pkt_offset="TCP.sport"))

        if 'dtcp_increment' in kwargs:
            int_val_udp_p = packet.getlayer('TCP.dport')
            int_val_max_udp_p = int_val_udp_p + kwargs['dtcp_increment'][1]
            if kwargs['dtcp_increment'][0] >= 0:
                operation = 'inc'
            else:
                operation = 'dec'
            flow_vars.append(TApi.STLVmFlowVar("dtcp", min_value=int_val_udp_p,
                                               max_value=int_val_max_udp_p, size=2,
                                               step=abs(kwargs['dtcp_increment'][0]), op=operation))
            flow_vars.append(TApi.STLVmWrFlowVar(fv_name="dtcp", pkt_offset="TCP.dport"))

        if 'required_size' in kwargs:
            if kwargs['required_size'][0] == 'Increment':
                flow_vars.append(TApi.STLVmFlowVar(name="req_size_inc", min_value=kwargs['required_size'][2] - 4,
                                                   max_value=kwargs['required_size'][3] - 4,
                                                   step=kwargs['required_size'][1],
                                                   size=2, op="inc"))
                flow_vars.append(TApi.STLVmTrimPktSize("req_size_inc"))
            elif kwargs['required_size'][0] == 'Random':
                flow_vars.append(TApi.STLVmFlowVar(name="req_size_rand", min_value=kwargs['required_size'][1] - 4,
                                                   max_value=kwargs['required_size'][2] - 4,
                                                   size=2, op="random"))
                flow_vars.append(TApi.STLVmTrimPktSize("req_size_rand"))

        vm = TApi.STLScVmRaw(flow_vars)
        return vm

    def set_stream(self, packet_def=None, count=1, inter=0, rate=99, sa_increment=None, da_increment=None, sip_increment=None, dip_increment=None,
                   is_valid=False, arp_sa_increment=None, arp_sip_increment=None, igmp_ip_increment=None, lldp_sa_increment=None, vlan_increment=None,
                   sudp_increment=None, dudp_increment=None, stcp_increment=None, dtcp_increment=None, continuous=False, iface=None, adjust_size=True,
                   required_size=64, fragsize=None, build_packet=True, eth_type_increment=None, dscp_increment=None, protocol_increment=None,
                   sipv6_increment=None, dipv6_increment=None, fl_increment=None, dhcp_si_increment=None, in_vlan_increment=None,
                   tc_increment=None, nh_increment=None, cont_burst=False, force_errors=None, udf_dependancies=None):
        """
        @copydoc testlib::tg_template::GenericTG::set_stream()
        @param stcp_increment:  source TCP address increment
        @type  stcp_increment:  tuple
        @param dtcp_increment:  destination TCP address increment
        @type  dtcp_increment:  tuple
        """
        stream_id = max(self.stream_ids) + 1 if self.stream_ids else 1
        self.class_logger.debug("Stream ID is: %s", stream_id)

        self.stream_ids[stream_id] = \
            {'iface': iface, 'count': count, 'inter': inter, 'rate': rate, 'continuous': continuous, 'sa_increment': sa_increment,
             'da_increment': da_increment, 'sip_increment': sip_increment, 'dip_increment': dip_increment, 'arp_sa_increment': arp_sa_increment,
             'arp_sip_increment': arp_sip_increment, 'igmp_ip_increment': igmp_ip_increment, 'vlan_increment': vlan_increment, 'ix_stream_id': [],
             'sudp_increment': sudp_increment, 'dudp_increment': dudp_increment, 'stcp_increment': stcp_increment, 'dtcp_increment': dtcp_increment,
             'eth_type_increment': eth_type_increment, 'sipv6_increment': sipv6_increment, 'dipv6_increment': dipv6_increment, 'fl_increment': fl_increment,
             'dhcp_si_increment': dhcp_si_increment, 'in_vlan_increment': in_vlan_increment, 'tc_increment': tc_increment, 'nh_increment': nh_increment,
             'cont_burst': cont_burst, 'force_errors': force_errors,
             'udf_dependancies': udf_dependancies}

        kwargs = locals()
        kwargs.pop("self")
        kwargs.pop("packet_def")
        kwargs.pop("fragsize")
        kwargs.pop("adjust_size")
        kwargs.pop("is_valid")
        kwargs.pop("build_packet")
        kwargs_copy = kwargs.copy()
        if build_packet:
            if isinstance(required_size, int):
                packet = self._build_trex_packet(packet_def, adjust_size=adjust_size, required_size=required_size - 4)
                kwargs_copy.pop("required_size")
            elif isinstance(required_size, tuple):
                self._check_supported_increments_and_values(required_size=required_size)
                packet = self._build_trex_packet(packet_def, adjust_size=adjust_size, required_size=required_size[-1] - 4)
            else:
                packet = self._build_trex_packet(packet_def, adjust_size=adjust_size)
        else:
            packet = packet_def

        # Check supported increments:
        increments = self._check_supported_increments_and_values(**kwargs_copy)
        vm = self._set_increments(packet, **increments)

        trex_packet = TApi.STLPktBuilder(pkt=packet, vm=vm)
        if continuous:
            _mode = TApi.STLTXCont(pps=1.0 / inter) if inter else TApi.STLTXCont(percentage=rate)
        else:
            _mode = TApi.STLTXSingleBurst(pps=1.0 / inter, total_pkts=count) \
                if inter else TApi.STLTXSingleBurst(percentage=rate, total_pkts=count)
        trex_strem = TApi.STLStream(packet=trex_packet,
                                    mode=_mode)
        self.stream_ids[stream_id]['trex_stream'] = trex_strem

        self.class_logger.debug("Stream set done.")
        self.class_logger.debug("stream_id[%s]: %s", stream_id, self.stream_ids[stream_id])
        self.class_logger.debug("stream_ids: %s", [_id for _id in self.stream_ids])

        return stream_id

    def send_stream(self, stream_id):
        """
        @copydoc testlib::tg_template::GenericTG::send_stream()
        """
        self.class_logger.debug("Sending stream %s...", stream_id)
        stream_port = self.stream_ids[stream_id]['iface']
        trex_traffic_profile = TApi.STLProfile([self.stream_ids[stream_id]['trex_stream']]).get_streams()
        self.trex.add_streams(trex_traffic_profile, ports=[stream_port])
        self.trex.start(ports=[stream_port])

    def start_streams(self, stream_list):
        """
        @copydoc testlib::tg_template::GenericTG::start_streams()
        """
        self.class_logger.debug("Starting streams %s...", stream_list)

        stream_ports = list(set([self.stream_ids[stream_id]['iface'] for stream_id in stream_list]))
        for port in stream_ports:
            trex_traffic_profile = [y['trex_stream'] for x, y in list(self.stream_ids.items()) if y['iface'] == port and x in stream_list]
            self.trex.add_streams(trex_traffic_profile, ports=[port])
        self.trex.start(ports=stream_ports)

    def start_streams_from_file(self, file_path, iface, wait=False):
        """
        @brief  Load and start stream(s) from profile file(yaml,pcap or py)
        @param file_path: path to file(yaml,pcap or py)
        @type  file_path:  str
        @param iface: interface name
        @type  iface:  int
        @param wait: wait until traffic is ended
        @type  wait:  bool
        @raise  TrexException:  error on opening profile file
        @return:  stream id list
        """
        # Try to load a profile
        try:
            profile = TApi.STLProfile.load(os.path.abspath(file_path))
        except TApi.STLError as err:
            self.class_logger.debug("Could not find profile file: %s", err)
            raise TrexException("Could not find profile file")
        # Update stream ids dict
        initial_id = max(self.stream_ids) + 1 if self.stream_ids else 1
        trex_streams = profile.get_streams()
        stream_id_list = [x for x in range(initial_id, len(trex_streams) + 1)]
        for stream_id, trex_stream in zip(stream_id_list, trex_streams):
            self.stream_ids[stream_id] = {"trex_stream":  trex_stream, "iface": iface}
        # Add and start streams
        self.trex.add_streams(trex_streams, ports=[iface])
        self.trex.start(ports=[iface])
        if wait:
            self.trex.wait_on_traffic(ports=[iface])
        return stream_id_list

    def stop_streams(self, stream_list=None):
        """
        @copydoc testlib::tg_template::GenericTG::stop_streams()
        """
        # If stream_list not defined then stop all streams
        if not stream_list:
            stream_list = [key for key in self.stream_ids]

        if stream_list:

            self.class_logger.debug("Stopping streams %s...", stream_list)

            stream_ports = [self.stream_ids[stream_id]['iface'] for stream_id in stream_list]
            self.trex.stop(ports=stream_ports)
            self.trex.remove_all_streams(ports=stream_ports)

    def stop_all_streams(self):
        """
        @brief  Stop streams for all owned ports
        @return:  None
        """
        self.trex.stop(ports=self.ports)
        self.trex.remove_all_streams(ports=self.ports)

    def get_statistics(self, iface=None):
        """
        @brief  Read statistics
        @param iface:  interface name
        @type  iface:  int
        @rtype:  dict
        @return:  interface statistics
        """
        if iface is not None:
            return self.trex.get_stats(iface)[iface]
        else:
            return self.trex.get_stats(self.ports)

    def clear_statistics(self, ifaces):
        """
        @brief  Clear statistics
        @param ifaces:  interfaces names
        @type  ifaces:  list
        @return:  None
        """
        self.trex.clear_stats(ports=ifaces)

    def get_received_frames_count(self, iface):
        """
        @copydoc testlib::tg_template::GenericTG::get_received_frames_count()
        """
        return self.trex.get_stats(iface)[iface]['ipackets']

    def get_sent_frames_count(self, iface):
        """
        @copydoc testlib::tg_template::GenericTG::get_sent_frames_count()
        """
        return self.trex.get_stats(iface)[iface]['opackets']

    def get_port_txrate(self, iface):
        """
        @copydoc testlib::tg_template::GenericTG::get_port_txrate()
        """
        return self.trex.get_stats(iface)[iface]['tx_pps']

    def get_port_rxrate(self, iface):
        """
        @copydoc testlib::tg_template::GenericTG::get_port_rxrate()
        """
        return self.trex.get_stats(iface)[iface]['rx_pps']

    def start_sniff(self, ifaces, sniffing_time=None, packets_count=0, filter_layer=None, src_filter=None, dst_filter=None):
        """
        @copydoc testlib::tg_template::GenericTG::start_sniff()
        """
        pytest.skip("Method is not supported by TRex TG")

    def stop_sniff(self, ifaces, force=False, drop_packets=False, sniff_packet_count=1000):
        """
        @copydoc testlib::tg_template::GenericTG::stop_sniff()
        """
        pytest.skip("Method is not supported by TRex TG")

    def get_filtered_frames_count(self, iface):
        """
        @copydoc testlib::tg_template::GenericTG::get_filtered_frames_count()
        """
        pytest.skip("Method is not supported by TRex TG")

    def get_uds_3_frames_count(self, iface):
        """
        @copydoc testlib::tg_template::GenericTG::get_uds_3_frames_count()
        """
        pytest.skip("Method is not supported by TRex TG")

    def set_flow_control(self, iface, mode):
        """
        @copydoc testlib::tg_template::GenericTG::set_flow_control()
        """
        pytest.skip("Method is not supported by TRex TG")

    def set_qos_stat_type(self, iface, ptype):
        """
        @copydoc testlib::tg_template::GenericTG::set_qos_stat_type()
        """
        pytest.skip("Method is not supported by TRex TG")

    def get_qos_frames_count(self, iface, prio):
        """
        @copydoc testlib::tg_template::GenericTG::get_qos_frames_count()
        """
        pytest.skip("Method is not supported by TRex TG")

    def get_port_qos_rxrate(self, iface, qos):
        """@copydoc testlib::tg_template::GenericTG::get_port_qos_rxrate()"""
        pytest.skip("Method is not supported by TRex TG")
