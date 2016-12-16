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

@file  dev_iperftg.py

@summary  Remote Iperf traffic generators specific functionality.
"""
import copy
import time

import pytest

from . import loggers
from . import tg_template
from .dev_linux_host import GenericLinuxHost
from .dev_linux_host_vm import GenericLinuxVirtualHost
from .custom_exceptions import TGException

from testlib.linux.iperf import iperf_cmd


HOST_MAP = {
    "riperf": GenericLinuxHost,
    "riperf_vm": GenericLinuxVirtualHost,
}


class RemoteIperfTG(tg_template.GenericTG):
    """
    @description  Class for launching Iperf on remote server.

    @par  Configuration examples:

    @par  Remote Iperf Example:
    @code{.json}
    {
     "name": "RemoteIperf"
     "entry_type": "tg",
     "instance_type": "riperf",
     "id": "TG1",
     "ports": ["eth1", "eth2"],
     "ipaddr": "1.1.1.1",
     "ssh_user": "user",
     "ssh_pass": "PassworD",
     "host_type": "lhost",
     "results_folder": "/tmp/iperf_tg"
    }
    @endcode
    @par  Where:
    \b entry_type and \b instance_type are mandatory values and cannot be changed
    \n\b id - int or str uniq device ID (mandatory)
    \n\b name - User defined device name (optional)
    \n\b ports or \b port_list - short or long ports configuration (pick one exclusively)
    \n\b ipaddr - remote host IP address (mandatory)
    \n\b ssh_user - remote host login user (mandatory)
    \n\b ssh_pass - remote host login password (mandatory)
    \n\b results_folder - folder to store Iperf results

    @note  You can safely add additional custom attributes.
    """

    class_logger = loggers.ClassLogger()
    _lhost = None
    default_duration = 1000000
    namespace_prefix = 'ip netns exec {} '

    def __init__(self, config, opts, reuse_host=None):
        """
        @brief  Initialize RemoteIperfTG class
        @param  config:  Configuration information.
        @type  config:  dict
        @param  opts:  py.test config.option object which contains all py.test cli options.
        @type  opts:  OptionParser
        """
        super(RemoteIperfTG, self).__init__(config, opts)
        self.config = config
        self.opts = opts
        self.type = config['instance_type']
        self.id = config['id']
        self.name = config.get('name', "UndefinedName_{0}".format(self.id))
        self.ports = []
        self.port_list = []
        if "ports" in config:
            self.ports = config['ports']
        if "port_list" in config:
            self.port_list = config['port_list']
        if not self.ports and self.port_list:
            self.ports = [p[0] for p in self.port_list]

        self.init_lhost = reuse_host is None
        self._lhost = reuse_host

        # Indicates if TG object supports high level protocol emulation (can emulate dialogs).
        self.is_protocol_emulation_present = False

        # Store information about used ports
        self.used_ifaces = set()

        # Stream IDs
        self.streams = {}
        # Iperf server interfaces
        self.sniff_ports = {}
        # Store information about configured network namespaces
        self.namespaces = {}
        # Store information about configured iface IP addresses
        self.iface_ip = []

    def start(self, wait_on=True):
        """
        @brief  Start iperf TG.
        @param  wait_on:  Wait for device is loaded
        @type  wait_on:  bool
        """
        # Get host instance from related devices
        if self.init_lhost and self.related_obj:
            self._lhost = next(iter(dev for dev in self.related_obj.values()
                                    if hasattr(dev, 'ui')),
                               None)

        # Set remote host platform
        if self.init_lhost:
            self._lhost = HOST_MAP[self.type](self.config, self.opts)
            self._lhost.start()

        self.status = True

    def stop(self):
        """
        @brief  Shutdown Iperf TG device.
        """
        # Cleanup platform first.
        self.cleanup()

        if self.init_lhost:
            self._lhost.stop()

        self.status = False

    def create(self):
        """
        @brief  Start Iperf TG device or get running one.
        """
        return self.start()

    def destroy(self):
        """
        @brief  Stop or release Iperf TG device.
        """
        if not self.status:
            self.class_logger.info("Skip iperf tg id:{0}({1}) destroying because "
                                   "it's has already Off status.".format(self.id, self.name))
            return
        self.stop()

        self.sanitize()

    def cleanup(self, *args, **kwargs):
        """
        @brief  Cleanup host.
        """
        self.clear_streams()
        self.stop_sniff()
        self.used_ifaces.clear()
        self.streams.clear()
        self.sniff_ports.clear()
        self.delete_ipaddr()
        self.delete_namespaces()

        if self.init_lhost:
            self._lhost.cleanup()
            self._lhost.ui.iperf.cleanup()

    def check(self):
        """
        @brief  Check host.
        """
        self._lhost.check()

    def sanitize(self):
        """
        @brief  Perform any necessary operations to leave environment in normal state.
        """
        self.clear_streams()
        self.stop_sniff()
        if self.init_lhost:
            self._lhost.ui.disconnect()

    def clear_streams(self):
        """
        @brief  Stop and clear all traffic streams.
        """
        self.stop_streams()
        self.streams.clear()

    def set_stream(self, dst_ip=None, src_ip=None, l4_proto='tcp', l4_port=5001, l4_bandwidth=None,
                   duration=10, interval=10, units='m', iface=None, options=None, command=None):
        """
        @brief  Set traffic stream with specified parameters on specified TG port.
        @note  Method generates option for Iperf launching in client mode

        @param dst_ip:  Iperf server IP address('client' iperf client option).
        @type  dst_ip:  str
        @param src_ip:  Local TG interface IP address('bind' iperf general option).
        @type  src_ip:  str
        @param l4_proto:  Iperf L4 proto. tcp|udp('udp' iperf general option).
        @type  l4_proto:  str
        @param l4_port:  Iperf L4 port('port' iperf general option).
        @type  l4_port:  int
        @param l4_bandwidth:  Iperf UDP bandwidth('bandwidth' iperf general option).
        @type  l4_bandwidth:  str
        @param duration:  Traffic transmit duration('time' iperf client option).
        @type  duration:  int
        @param interval:  Iperf statistics interval('interval' iperf general option).
        @type  interval:  int
        @param units:  Iperf statistics reports foramat('format' iperf general option).
        @type  units:  str
        @param iface:  Interface to use for packet sending.
        @type  iface:  str, tuple

        @param options: intermediate iperf options list
        @type  options: list of str
        @param command: intermediate iperf command object
        @type  command: argparse.Namespace

        @rtype:  int
        @return:  stream id
        @par Example:
        @code{.py}
        stream_id_1 = tg.set_stream(dst_ip='1.1.1.1', iface=iface)
        stream_id_2 = tg.set_stream(dst_ip='1.1.1.1', l4_proto='udp', iface=iface)
        @endcode
        """
        stream_id = (max(self.streams.keys()) + 1) if self.streams else 1

        if l4_proto not in {'tcp', 'udp'}:
            raise TGException("l4_proto has incorrect value.")

        kwargs = {
            'client': dst_ip,
            'time': duration,
            'bandwidth': l4_bandwidth,

            'interval': interval,
            'format': units,
            'port': l4_port,
            'bind': src_ip,
            'udp': 'udp' in l4_proto
        }

        cmd = iperf_cmd.CmdIperf(**kwargs)
        # Let the options/command overwrite the method arguments in case of collision
        if options:
            _opts_cmd = iperf_cmd.CmdIperf(options)
            cmd.update(_opts_cmd)

        if command:
            cmd.update(command)

        if not cmd.get('client'):
            raise TGException("Server address (-c/--client) is not set for the iperf client.")

        self.streams[stream_id] = {
            'iface': iface,
            'iperf_cmd': cmd
        }

        # Add src_ip address to specific TG port
        if src_ip:
            self.iface_config(iface, intf_ip_addr=src_ip)

        self.class_logger.info("Stream ID:%s was set." % stream_id)
        return stream_id

    def send_stream(self, stream_id, get_result=False):
        """
        @brief  Start Iperf client with options from set_stream.

        @param stream_id:  ID of the stream to be send
        @type  stream_id:  int
        @param get_result:  flag that indicates whether to get iperf results or not
        @type  get_result:  bool
        @rtype:  list
        @return:  iperf client output
        """

        stream = self.streams.get(stream_id)
        if not stream:
            raise TGException("Stream with ID {} was not configured".format(stream_id))

        port = stream['iface']
        # Verify that there is no ports already used by another iperf instances
        if port and port in self.used_ifaces:
            raise TGException("There is an another iperf on port {}.".format(port))

        if port and port in self.namespaces:
            stream['prefix'] = self.namespace_prefix.format(self.namespaces[port])

        if port:
            self.used_ifaces.add(port)

        cmd = stream.get('iperf_cmd')
        prefix = stream.get('prefix')
        iid = self._lhost.ui.iperf.start(prefix=prefix, command=cmd)
        stream['instance_id'] = iid

        if get_result:
            cmd_time = cmd.get('time', 10)
            time.sleep(int(cmd_time))

            # make sure we stopped correctly
            return self.stop_stream(stream_id, ignore_inactive=True)

    def start_streams(self, stream_list, get_result=False):
        """
        @brief  Start streams from the list.
        @param stream_list:  List of stream IDs.
        @type  stream_list:  list[int]
        @param get_result: get results
        @type get_result: bool
        @return:  None
        """
        for stream_id in stream_list:
            self.send_stream(stream_id, get_result=get_result)

    def _stop_and_parse_instance(self, iid, **kwargs):
        """
        Stops an iperf instance and returns the parsed output.
        """
        inst = self._lhost.ui.iperf.instances.get(iid)
        if inst:
            self._lhost.ui.iperf.stop(iid, **kwargs)
            inst_res = self._lhost.ui.iperf.get_results(iid)
            if inst_res:
                cmd = inst.get('iperf_cmd')
                units = cmd.get('format', 'm')
                threads = cmd.get('parallel', 1)
                return self._lhost.ui.iperf.parse(inst_res, units=units, threads=threads)

    def stop_stream(self, stream_id, **kwargs):
        """
        @brief  Stop an iperf stream.
        @param stream_id:  Stream ID to stop.
        @type  stream_id:  int
        @rtype:  dict
        @return:  iperf output per stream
        @raises: UiCmdException: when check is True and service is already stopped or other error
        """
        stream = self.streams.pop(stream_id, None)
        if not stream:
            return

        iface = stream.get('iface')
        if iface:
            self.used_ifaces.remove(iface)

        # instance could have already been stopped in send_stream
        return self._stop_and_parse_instance(stream.get('instance_id'), **kwargs)

    def stop_streams(self, stream_list=None, **kwargs):
        """
        @brief  Stop all streams from the list.
        @param stream_list:  Stream IDs to stop.
        @type  stream_list:  list[int]
        @rtype:  dict
        @return:  iperf output per stream
        """
        if not stream_list:
            stream_list = list(self.streams.keys())

        results = {}
        for stream_id in stream_list:
            results[stream_id] = self.stop_stream(stream_id, **kwargs)

        return results

    def start_sniff(self, ifaces, src_ip=None, l4_proto='tcp', l4_port=5001, interval=10,
                    units='m', options=None, command=None):
        """
        @brief  Starts Iperf server on specified interfaces.
        @param ifaces:  List of TG interfaces for capturing.
        @type  ifaces:  list
        @param src_ip:  Local TG interface IP address('bind' iperf general option).
        @type  src_ip:  str
        @param l4_proto:  Iperf L4 proto. tcp|udp('udp' iperf general option).
        @type  l4_proto:  str
        @param l4_port:  Iperf L4 port('port' iperf general option).
        @type  l4_port:  int
        @param interval:  Iperf statistics interval('interval' iperf general option).
        @type  interval:  int
        @param units:  Iperf statistics reports foramat('format' iperf general option).
        @type  units:  str

        @param options: intermediate iperf options list
        @type  options: list of str
        @param command: intermediate iperf command object
        @type  command: argparse.Namespace

        @return:  None

        @par Example:
        @code
        env.tg[1].start_sniff(['eth0', ], src_ip='1.1.1.1')
        @endcode
        """
        if not ifaces:
            return

        if l4_proto not in {'tcp', 'udp'}:
            raise TGException("l4_proto has incorrect value.")

        kwargs = {
            'server': True,
            'interval': interval,
            'format': units,
            'port': l4_port,
            'bind': src_ip,
            'udp': 'udp' in l4_proto,

            'command': command,
            'options': options,
        }

        for iface in ifaces:
            # Verify that there is no ports already used by another iperf instances
            if iface in self.used_ifaces:
                raise TGException("There is an another iperf on port {}.".format(iface))

            _kwargs = copy.deepcopy(kwargs)

            if iface in self.namespaces:
                _kwargs['prefix'] = self.namespace_prefix.format(self.namespaces[iface])

            # Add src_ip address to specific TG port
            if _kwargs.get('bind'):
                self.iface_config(iface, intf_ip_addr=_kwargs['bind'])

            prefix = _kwargs.get('prefix')
            iid = self._lhost.ui.iperf.start(prefix=prefix, **_kwargs)
            self.sniff_ports[iface] = iid
            self.used_ifaces.add(iface)

            self.class_logger.info("Iperf server was started on iface {}." .format(iface))

    def stop_sniff(self, ifaces=None, **kwargs):
        """
        @param check:
        @type check:
        @brief  Stops sniffing on specified interfaces and returns captured data.
        @param ifaces:  List of interfaces where capturing has to be stopped.
        @type  ifaces:  list
        @rtype:  dict
        @return:  Dictionary where key = interface name, value = iperf statistics.
        """
        if not ifaces:
            # we destructively iterate over self.sniff_ports, so we have to copy keys
            ifaces = list(self.sniff_ports.keys())

        results = {}
        for iface in ifaces:
            results[iface] = self._stop_sniff(iface, **kwargs)
        return results

    def _stop_sniff(self, iface, **kwargs):
        iid = self.sniff_ports.pop(iface, None)
        assert iid
        self.used_ifaces.remove(iface)

        return self._stop_and_parse_instance(iid, **kwargs)

    def iface_config(self, iface, *args, **kwargs):
        """
        @param iface: interface name
        @type iface: str
        @brief  High-level interface config utility.
        @raise  NotImplementedError:  not implemented
        @note  This method has to support parameters supported by ::ixia::interface_config
               function for compatibility.
               You have to check already implemented parameters for other TG types.
        @par  Example:
        @code
        env.tg[1].iface_config(tgport1, intf_ip_addr="10.1.0.101", netns=True)
        @endcode
        """
        if not set(kwargs).issubset({'intf_ip_addr', 'netns', 'adminMode'}):
            raise NotImplementedError("Method is not implemented for current kwargs.")
        if kwargs.get('netns', False):
            # Create network namespaces for current iface
            self.create_namespaces(iface)
            del kwargs['netns']
        if 'intf_ip_addr' in kwargs:
            kwargs['ipAddr'] = "{}/24".format(kwargs['intf_ip_addr'])
        if iface in self.namespaces:
            self._lhost.ui.enter_namespace(self.namespaces[iface])
        self._lhost.ui.modify_ports([iface], **kwargs)
        if iface in self.namespaces:
            self._lhost.ui.exit_namespace()

    def create_namespaces(self, iface):
        """
        @brief  Create network namespace for specified interface
        @param iface:  interface name
        @type  iface:  str
        """
        if iface not in self.namespaces:
            name = "netns_{}".format(iface)
            self._lhost.ui.create_namespace(name)

            self._lhost.ui.modify_ports([iface], netns=name)
            self.namespaces[iface] = name

            self.iface_config(iface, adminMode='Up')

    def delete_namespaces(self, ifaces=None):
        """
        @brief  Delete network namespaces for specified interfaces
        @param ifaces:  interface names
        @type  ifaces:  list[str]
        """
        if not ifaces:
            ifaces = list(self.namespaces.keys())
        for iface in ifaces:
            self._lhost.ui.delete_namespace(self.namespaces[iface])
            del self.namespaces[iface]

    def delete_ipaddr(self, ifaces=None):
        """
        @brief  Delete configured IP addresses for specified interface
        @param ifaces:  interface names
        @type  ifaces:  list[str]
        """
        if not ifaces:
            ifaces = self.iface_ip
        for iface in ifaces:
            self._lhost.ui.modify_ports([iface], ipAddr=None)
        self.iface_ip = []

    def clear_statistics(self, sniff_port_list):
        """
        @brief  Clear statistics - number of frames.
        @param sniff_port_list:  List of interface names.
        @type  sniff_port_list:  list
        @return:  None.
        """
        pass

    def get_received_frames_count(self, iface):
        """
        @brief  Read statistics - number of received valid frames.
        @param iface:  Interface name.
        @type  iface:  str
        @rtype:  int
        @return:  Number of received frames.
        """
        pytest.skip("Method is not supported by Iperf TG")

    def get_filtered_frames_count(self, iface):
        """
        @brief  Read statistics - number of received frames which fit filter criteria.
        @param iface:  Interface name.
        @type  iface:  str
        @rtype:  int
        @return:  Number of filtered frames.
        """
        pytest.skip("Method is not supported by Iperf TG")

    def get_uds_3_frames_count(self, iface):
        """
        @brief  Read statistics - number of non-filtered received frames (valid and invalid)
        @param iface:  Interface name.
        @type  iface:  str
        @rtype:  int
        @return:  Number of received frames.
        """
        pytest.skip("Method is not supported by Iperf TG")

    def get_sent_frames_count(self, iface):
        """
        @brief  Read statistics - number of sent frames.
        @param iface:  Interface name.
        @type  iface:  str
        @rtype:  int
        @return:  Number of sent frames.
        """
        pytest.skip("Method is not supported by Iperf TG")

    def set_flow_control(self, iface, mode):
        """
        @brief  Enable/Disable flow control on the port.
        @param iface:  Interface name.
        @type  iface:  str
        @param mode:  True/False.
        @type  mode:  bool
        @return:  None
        """
        pytest.skip("Method is not supported by Iperf TG")

    def set_qos_stat_type(self, iface, ptype):
        """
        @brief  Set the QoS counters to look for priority bits for given packets type.
        @param iface:  Interface name.
        @type  iface:  str
        @param ptype:  Priority type: VLAN/IP.
        @type  ptype:  str
        @return:  None
        """
        pytest.skip("Method is not supported by Iperf TG")

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
        pytest.skip("Method is not supported by Iperf TG")

    def get_port_txrate(self, iface):
        """
        @brief  Return port transmission rate.
        @param iface:  Interface name.
        @type  iface:  str
        @rtype:  int
        @return:  Frames per second
        """
        pytest.skip("Method is not supported by Iperf TG")

    def get_port_rxrate(self, iface):
        """
        @brief  Return port receiving rate.
        @param iface:  Interface name.
        @type  iface:  str
        @rtype:  int
        @return  Frames per second (int)
        """
        pytest.skip("Method is not supported by Iperf TG")

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
        pytest.skip("Method is not supported by Iperf TG")

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
        pytest.skip("Method is not supported by Iperf TG")

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
        pytest.skip("Method is not supported by Iperf TG")

    def connect_port(self, iface):
        """
        @copydoc  testlib::tg_template::GenericTG::connect_port()
        """
        self.iface_config(iface, adminMode='Up')

    def disconnect_port(self, iface):
        """
        @copydoc  testlib::tg_template::GenericTG::disconnect_port()
        """
        self.iface_config(iface, adminMode='Down')


ENTRY_TYPE = "tg"
# used in HOST_MAP
INSTANCES = {"riperf": RemoteIperfTG,
             "riperf_vm": RemoteIperfTG}
NAME = "tg"
