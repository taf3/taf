"""
@copyright Copyright (c) 2015 - 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  pytest_onsenv.py

@summary  Multiple traffic generator specific functionality.
"""
from collections import namedtuple

from . import loggers
from .tg_template import GenericTG
from .packet_processor import PacketProcessor


DEFAULT_SPEED = 10000


Port = namedtuple('Port', 'tg, port')


class MultipleTG(PacketProcessor, GenericTG):
    """
    @description  Class for general TG instance combined with multiple different TGs.
    """

    class_logger = loggers.ClassLogger()

    def __init__(self, traffic_generators, config, opts):
        """
        @brief  Initialize RemoteMultiHostTG class
        @param  traffic_generators:  Dictionary with TG instances in format {id:tg_instance}
        @type  traffic_generators:  dict
        @param  config:  Configuration information.
        @type  config:  dict
        @param  opts:  py.test config.option object which contains all py.test cli options.
        @type  opts:  OptionParser
        """
        super(MultipleTG, self).__init__(config, opts)

        # TG instances
        self.tgs = {x.id: x for x in traffic_generators.values()}

        # Get ports and port lists
        # For ports use namedtuple(tg.id, port.id)
        self.ports, self.port_list = self._get_speed_ports()

        self.streams = []

        # Indicates if TG object supports high level protocol emulation (can emulate dialogs).
        self.is_protocol_emulation_present = all(x.is_protocol_emulation_present
                                                 for x in self.tgs.values())

    def _get_speed_ports(self):
        """
        @brief  Get ports with speed from TG instances.
        @rtype:  tuple(list[tuple], list[tuple, int])
        @return:  Tuple with list of ports used in real config and list of port/speed values
        """
        ports = []
        ports_list = []
        if any(x.port_list for x in self.tgs.values()):
            for tg in self.tgs.values():
                if tg.port_list:
                    ports_list.extend([[Port(tg.id, _port[0]), _port[1]] for _port in tg.port_list])
                else:
                    ports_list.extend([[Port(tg.id, _port), DEFAULT_SPEED] for _port in tg.ports])
            ports = [_port[0] for _port in ports_list]
        else:
            ports = [Port(x.id, port) for x in self.tgs.values() for port in x.ports]

        return ports, ports_list

    def get_tg_port_map(self, ifaces):
        """
        @brief  Return ports related to specific TG
        @param ifaces: list of interfaces in format (tg_id, port_id)
        @type  ifaces:  list(tuple)
        @rtype:  dict
        @return:  dictionary in format {'host id': [port ids]}
        """
        iface_map = {}
        for iface in ifaces:
            iface_map.setdefault(iface.tg, []).append(iface.port)
        return iface_map

    def get_port_id(self, tg_id, port_id):
        """
        @brief  Return port's sequence number in list of ports
        @param  tg_id:  TG instance ID
        @type  tg_id:  int
        @param  port_id:  TG instance port's sequence number
        @type  port_id:  int
        @raises  ValueError:  in case expected port is not in list of ports
        @rtype:  int
        @return:  Port sequence number in list of ports starting from 1
        """
        port_name = self.tgs[tg_id].ports[port_id - 1]
        return self.ports.index(Port(tg_id, port_name)) + 1

    def start(self, wait_on=True):
        """
        @brief  Start TG instances.
        """
        for tg in self.tgs.values():
            tg.start()

        self.status = all(x.status for x in self.tgs.values())

    def stop(self):
        """
        @brief  Shutdown TG instances.
        """
        for tg in self.tgs.values():
            tg.stop()

    def create(self):
        """
        @brief  Start TG instances or get running ones..
        """
        for tg in self.tgs.values():
            tg.create()

    def destroy(self):
        """
        @brief  Stop or release TG instances.
        """
        for tg in self.tgs.values():
            tg.destroy()

    def cleanup(self, *args, **kwargs):
        """
        @brief  Cleanup TG instances.
        """
        self.streams = []
        for tg in self.tgs.values():
            tg.cleanup()

    def check(self):
        """
        @brief  Check TG instances.
        """
        for tg in self.tgs.values():
            tg.check()

    def sanitize(self):
        """
        @brief  Perform any necessary operations to leave environment in normal state.
        """
        self.streams = []
        for tg in self.tgs.values():
            tg.sanitize()

    def stop_sniff(self, *args, **kwargs):
        """
        @brief  Collect sniffed data from all TG instances.
        """
        iface_map = self.get_tg_port_map(*args)
        data_hosts = {}
        for tg, ifaces in iface_map.items():
            data_hosts[tg] = self.tgs[tg].stop_sniff(ifaces, **kwargs)

        data = {}
        for tg, ifaces in data_hosts.items():
            for iface in ifaces:
                data['{} {}'.format(tg, iface)] = data_hosts[tg][iface]
        return data

    def connect_port(self, iface):
        """
        @copydoc  testlib::tg_template::GenericTG::connect_port()
        """
        self.tgs[iface.tg].connect_port(iface.port)

    def disconnect_port(self, iface):
        """
        @copydoc  testlib::tg_template::GenericTG::disconnect_port()
        """
        self.tgs[iface.tg].disconnect_port(iface.port)

    def clear_streams(self):
        """
        @brief  Stop and remove all streams
        """
        self.streams = []
        for tg in self.tgs.values():
            tg.clear_streams()

    def set_stream(self, *args, **kwargs):
        """
        @copydoc  testlib::tg_template::GenericTG::set_stream()
        """
        tg, kwargs['iface'] = kwargs['iface']
        stream_id = self.tgs[tg].set_stream(*args, **kwargs)
        tg_stream_id = Port(tg, stream_id)
        self.streams.append(tg_stream_id)
        return tg_stream_id

    def send_stream(self, stream_id, **kwargs):
        """
        @copydoc  testlib::tg_template::GenericTG::send_stream()
        """
        tg, stream = stream_id
        self.tgs[tg].send_stream(stream, **kwargs)

    def start_streams(self, stream_list):
        """
        @copydoc  testlib::tg_template::GenericTG::start_streams()
        """
        stream_map = self.get_tg_port_map(stream_list)

        for tg, streams in stream_map.items():
            self.tgs[tg].start_streams(streams)

    def stop_streams(self, stream_list=None):
        """
        @copydoc  testlib::tg_template::GenericTG::stop_streams()
        """
        stream_map = self.get_tg_port_map(stream_list)

        for tg, streams in stream_map.items():
            self.tgs[tg].stop_streams(streams)

    def start_sniff(self, ifaces, **kwargs):
        """
        @copydoc  testlib::tg_template::GenericTG::start_sniff()
        """
        iface_map = self.get_tg_port_map(ifaces)

        for tg, ports in iface_map.items():
            self.tgs[tg].start_sniff(ports, **kwargs)

    def clear_statistics(self, sniff_port_list):
        """
        @brief  Clearing statistics on TG ports.
        """
        iface_map = self.get_tg_port_map(sniff_port_list)

        for tg, ports in iface_map.items():
            self.tgs[tg].clear_statistics(ports)

    def get_received_frames_count(self, iface):
        """
        @brief  Read statistics - framesReceived
        """
        return self.tgs[iface.tg].get_received_frames_count(iface.port)

    def get_filtered_frames_count(self, iface):
        """
        @brief  Read statistics - filtered frames received
        """
        return self.tgs[iface.tg].get_filtered_frames_count(iface.port)

    def get_uds_3_frames_count(self, iface):
        """
        @brief  Read statistics - UDS3 - Capture Trigger (UDS3) -
        count of non-filtered received packets (valid and invalid)
        """
        return self.tgs[iface.tg].get_uds_3_frames_count(iface.port)

    def clear_received_statistics(self, iface):
        """
        @brief  Clear statistics
        """
        return self.tgs[iface.tg].clear_received_statistics(iface.port)

    def get_sent_frames_count(self, iface):
        """
        @brief  Read statistics - framesSent
        """
        return self.tgs[iface.tg].get_sent_frames_count(iface.port)

    def get_port_txrate(self, iface):
        """
        @brief  Get port Tx rate
        """
        return self.tgs[iface.tg].get_port_txrate(iface.port)

    def get_port_rxrate(self, iface):
        """
        @brief  Get port Rx rate
        """
        return self.tgs[iface.tg].get_port_rxrate(iface.port)

    def get_port_qos_rxrate(self, iface, qos):
        """
        @brief  Get ports Rx rate for specific qos
        """
        return self.tgs[iface.tg].get_port_qos_rxrate(iface.port, qos)

    def get_qos_frames_count(self, iface, prio):
        """
        @brief  Get QoS packets count
        """
        return self.tgs[iface.tg].get_qos_frames_count(iface.port, prio)

    def set_qos_stat_type(self, iface, ptype):
        """
        @brief  Set QoS stats type
        """
        return self.tgs[iface.tg].set_qos_stat_type(iface.port, ptype)

    def set_flow_control(self, iface, mode):
        """
        @brief  Set Flow Control
        """
        return self.tgs[iface.tg].set_flow_control(iface.port, mode)

    def get_os_mtu(self, iface=None):
        """
        @copydoc  testlib::tg_template::GenericTG::get_os_mtu()
        """
        return self.tgs[iface.tg].get_os_mtu(iface.port)

    def set_os_mtu(self, iface=None, mtu=None):
        """
        @copydoc  testlib::tg_template::GenericTG::set_os_mtu()
        """
        return self.tgs[iface.tg].set_os_mtu(iface.port, mtu)
