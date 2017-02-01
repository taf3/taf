"""
@copyright Copyright (c) 2017, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  dev_pypacker.py

@summary  Pypacker traffic generators specific functionality.
"""
import sys
import time
import socket
import ctypes
import codecs
import struct
import threading
import traceback
from fcntl import ioctl
from subprocess import Popen, PIPE

import pcapy
import pytest
from pypacker import psocket
from pypacker.layer12 import ethernet

from . import tg_template
from . import loggers
from .custom_exceptions import PypackerException
from .packet_processor import PacketProcessor


class PypackerTG(PacketProcessor, tg_template.GenericTG):
    """
    @description  Traffic generator class based on Pypacker library.

    @note  Configuration examples:

    @par  Example 1:
    @code{.json}
    {
     "name": "Pypacker1"
     "entry_type": "tg",
     "instance_type": "pypacker",
     "id": "TG1",
     "ports": ["eth1", "eth2"],
    }
    @endcode

    @par  Example 2:
    @code{.json}
    {
     "name": "Pypacker2"
     "entry_type": "tg",
     "instance_type": "pypacker",
     "id": "TG2",
     "port_list": [["eth100", 10000, "00:1e:67:0c:bb:d4"],
                   ["eth200", 10000, "00:1e:67:0c:bb:d5"]
                  ],
    }
    @endcode

    @note  Where:
    \b entry_type and \b instance_type are mandatory values and cannot be changed for current device type.
    \n\b id - int or str uniq device ID (mandatory)
    \n\b name - User defined device name (optional)
    \n\b ports or \b port_list - short or long ports configuration
    \n\b ifaces - alias to ports (not recommended for use)
    \n\b You can safely add additional custom attributes. Only attributes described above will be analysed.
    """

    class_logger = loggers.ClassLogger()
    MAX_MTU = pow(2, 16)
    SIOCGIFMTU = 0x8921
    SIOCSIFMTU = 0x8922

    def __init__(self, config, opts):
        """
        @brief  Initialize PypackerTG class
        @param  config:  Configuration information.
        @type  config:  dict
        @param  opts:  py.test config.option object which contains all py.test cli options.
        @type  opts:  OptionParser
         """
        super(PypackerTG, self).__init__(config, opts)
        self.__config = config
        self.id = config['id']
        self.type = config['instance_type']
        self.streams = {}
        self._send_threads = {}
        self._sniff_threads = []
        self._collector = Collector()
        self.receive_statistics = BaseStatistics()
        self.sent_statistics = BaseStatistics()
        self.ports, self.port_list = self._get_speed_ports(self.__config)
        self.sniff_direction = "egress"
        if "sniff_direction" in config:
            self.sniff_direction = config["sniff_direction"]
        self.pcap = pcapy

    def _get_speed_ports(self, config):
        """
        @brief  Get ports with speed from config.
        @return:  Tuple with list of ports used in real config and list of port/speed values
        @rtype:  tuple(list[tuple], list[tuple, int])
        @note  This function checks if port has speed in config file.
        """
        ports = []
        ports_list = []
        if "port_list" in config:
            ports = [x[0] for x in config["port_list"]]
            ports_list = [[x[0], x[1]] for x in config["port_list"]]
        elif "ifaces" in config:
            ports = config['ifaces']
        elif 'ports' in config:
            ports = config["ports"]
        else:
            if "related_conf" in config:
                for rkey in list(config['related_conf'].keys()):
                    if config['related_conf'][rkey]['instance_type'] in ["vlab", "static"]:
                        ports, ports_list = self._get_speed_ports(config['related_conf'][rkey])

        return ports, ports_list

    def _get_snaplen(self, mtu):
        """
        @brief  Return snaplen for sniffer.
        """
        # MTU + 14: where 14 is length os Ether header.
        snaplen = mtu + 14
        if mtu == 0 or snaplen > self.MAX_MTU:
            return self.MAX_MTU
        else:
            return snaplen

    def _grab_data_from_thread(self, thr):
        """
        @brief  Return captured data from stopped sniffing thread.
        """
        data = []
        ifaces = [thr.sniff_port]
        thr.join()
        self._sniff_threads.remove(thr)
        for iface in ifaces:
            try:
                data.extend(self._collector.data.pop(iface))
            except KeyError:
                pass
        return data

    def create(self):
        """
        @brief  Perform all necessary procedures to initialize TG device and prepare it for interaction.
        @note  Pypacker TG does not support this procedure
        """
        pass

    def destroy(self):
        """
        @brief  Perform all necessary procedures to uninitialize TG device.
        @note  Pypacker TG does not support this procedure
        """
        pass

    def check(self):
        """
        @brief  Check if TG object is alive and ready for processing
        @note  Pypacker TG does not support this procedure
        """
        pass

    def sanitize(self):
        """
        @brief  Stop all threads to avoid pytest hanging.
        """
        self.stop_sniff(ifaces=None, force=True, drop_packets=True)

    def set_stream(self, packet_def, count=1, inter=0, rate=None, sa_increment=None, da_increment=None, sip_increment=None, dip_increment=None, is_valid=False,
                   arp_sa_increment=None, arp_sip_increment=None, igmp_ip_increment=None, lldp_sa_increment=None, vlan_increment=None, continuous=False,
                   iface=None, adjust_size=True, required_size=64, fragsize=None, build_packet=True, sudp_increment=None, dudp_increment=None,
                   stcp_increment=None, dtcp_increment=None, eth_type_increment=None, dscp_increment=None, protocol_increment=None, sipv6_increment=None,
                   dipv6_increment=None, fl_increment=None, dhcp_si_increment=None, in_vlan_increment=None, cont_burst=False, force_errors=None,
                   udf_dependancies=None, tc_increment=None, nh_increment=None, isis_lspid_increment=None):
        """
        @copydoc  testlib::tg_template::GenericTG::set_stream()
        @raise  TypeError:  incorrect type of increments
        """
        stream_id = (max(self.streams.keys()) + 1) if self.streams else 1
        kwargs = {}

        if rate is not None:
            self.class_logger.warning("Rate makes no effect for Pypacker TG.")

        if force_errors is not None:
            self.class_logger.warning("Force errors makes no effect for Pypacker TG.")

        if udf_dependancies is not None:
            self.class_logger.warning("UFD dependencies makes no effect for Pypacker TG.")
            pytest.skip("UFD dependencies makes no effect for Pypacker TG.")

        kwargs['packet_definition'] = packet_def

        packet_size = None
        size_increment_type = None
        if isinstance(required_size, int):
            packet_size = required_size
        elif isinstance(required_size, tuple):
            if required_size[0] == 'Increment':
                size_increment_type = 'increment'
                try:
                    size_increment_step = required_size[1]
                    size_increment_min_val = required_size[2] - 4
                    size_increment_max_val = required_size[3]
                except:
                    raise TypeError("'Increment' required_size must contain 3 integer values.")
                if size_increment_max_val < size_increment_min_val:
                    raise TypeError("'Increment' max_value is less than min_value.")
            elif required_size[0] == 'Random':
                size_increment_type = 'random'
                try:
                    size_increment_step = 0
                    size_increment_min_val = required_size[1] - 4
                    size_increment_max_val = required_size[2]
                except:
                    raise TypeError("'Increment' required_size must contain 3 integer values.")
                if size_increment_max_val < size_increment_min_val:
                    raise TypeError("'Increment' max_value is less than min_value.")
            else:
                raise TypeError("required_size contains wrong values.")
            packet_size = size_increment_max_val

        kwargs['adjust_size'] = adjust_size
        if required_size:
            kwargs['required_size'] = packet_size - 4
        if build_packet:
            packet = self._build_pypacker_packet(**kwargs)
        else:
            packet = packet_def

        args = {'iface': iface, 'inter': inter, 'is_valid': is_valid}
        if continuous:
            args['loop'] = 1
        elif cont_burst:
            args['loop'] = 1
            args['count'] = count
        else:
            args['count'] = count
        self.streams[stream_id] = {'packet': packet, 'kwargs': args}

        self.class_logger.info("Stream ID:%s was set." % stream_id)
        return stream_id

    def send_stream(self, stream_id=None):
        """
        @copydoc  testlib::tg_template::GenericTG::send_stream()
        @raise  PypackerException:  error on stream sending
        """
        stop_lock = threading.Lock()
        self.class_logger.debug("Send stream id:%s" % stream_id)
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
        self.class_logger.debug("Stream {0} is sent.".format(stream_id))

    def cleanup(self):
        """
        @brief  Stop any packets processing of the class and clear necessary attributes
        """
        self.class_logger.info("Stop all flows.")
        self.stop_streams()
        self.class_logger.info("Remove all streams.")
        self.streams = {}
        self.class_logger.info("Stop all sniffers.")
        self.stop_sniff()

    def start_sniff(self, ifaces, sniffing_time=None, packets_count=0, filter_layer=None, src_filter=None, dst_filter=None):
        """
        @copydoc  testlib::tg_template::GenericTG::start_sniff()
        @raise  PypackerException:  sniffer on current iface already started
        """

        # Verify that there is no ports already used by another sniffer
        for thr in self._sniff_threads:
            for iface in ifaces:
                if iface == thr.sniff_port:
                    raise PypackerException("There is an another sniffer already started on port %s." % iface)

        for sniff_port in ifaces:
            stop_lock = threading.Lock()
            thr = StoppableThread(target=self._sniffer, args=(sniff_port, packets_count, sniffing_time, filter_layer, src_filter, dst_filter, stop_lock))
            thr.daemon = True
            thr.sniff_port = sniff_port
            thr._thr_lock = stop_lock
            thr._stop_exception = KeyboardInterrupt
            self._sniff_threads.append(thr)
            thr.start()

        # Wait for assurance that sniffing is started
        time.sleep(1.5)

    def stop_sniff(self, ifaces=None, force=False, drop_packets=False, sniff_packet_count=0):
        """
        @copydoc  testlib::tg_template::GenericTG::stop_sniff()
        """
        rdata = {}

        # Collect data and remove threads.
        # If ifaces list is defined, then stop sniffer only on this ifaces
        # Else - stop all sniffers
        if not ifaces:
            ifaces = [x.sniff_port for x in self._sniff_threads]

        sniff_threads = self._sniff_threads[:]
        if force:
            for thr in sniff_threads:
                iface = thr.sniff_port
                if iface in ifaces:
                    thr.terminate()
                    rdata[iface] = self._grab_data_from_thread(thr)

        # Stop all threads without count and time
        sniff_threads = self._sniff_threads[:]
        for thr in sniff_threads:
            iface = thr.sniff_port
            if iface in ifaces:
                if hasattr(thr, "_args") and thr._args[1] == 0 and thr._args[2] is None:
                    thr.terminate()
                    rdata[iface] = self._grab_data_from_thread(thr)

        # Wait for other threads to stop
        sniff_threads = self._sniff_threads[:]
        for thr in sniff_threads:
            iface = thr.sniff_port
            if iface in ifaces:
                rdata[iface] = self._grab_data_from_thread(thr)
        return rdata

    def start_streams(self, stream_list):
        """
        @copydoc  testlib::tg_template::GenericTG::start_streams()
        """
        for stream_id in stream_list:
            thr = StoppableThread(target=self.send_stream, args=(stream_id,))
            thr.daemon = True
            thr.stream_id = stream_id
            thr._thr_lock = threading.Lock()
            thr._stop_exception = SystemExit
            self._send_threads[stream_id] = {}
            self._send_threads[stream_id]['thread'] = thr
            self._send_threads[stream_id]['active'] = False
            thr.start()

        # Wait until all streams are activated.
        end_time = time.time() + len(stream_list)
        stop_flag = False
        while not stop_flag:
            stream_status = list(set([_x[1]['active'] for _x in list(self._send_threads.items()) if _x[0] in stream_list]))
            if len(stream_status) == 1 and stream_status[0] is True:
                stop_flag = True
            if time.time() > end_time:
                self.class_logger.warning("Exit start_streams method but all streams aren't started yet. (Infinity loop prevention.)")
                stop_flag = True
            time.sleep(0.1)

    def stop_streams(self, stream_list=None):
        """
        @copydoc  testlib::tg_template::GenericTG::stop_streams()
        """
        # If stream_list not defined then stop all streams
        if not stream_list:
            stream_list = [key for key in list(self.streams.keys())]

        for thr_id in list(self._send_threads):
            if thr_id in stream_list:
                self._send_threads[thr_id]['thread'].terminate()
                self._send_threads[thr_id]['thread'].join()
                self._send_threads.pop(thr_id)

    def clear_streams(self):
        """
        @copydoc  testlib::tg_template::GenericTG::clear_streams()
        """
        self.stop_streams()
        self.streams = {}

    def _sendp(self, packet, iface=None, count=None, inter=0, loop=0, stop_lock=None, is_valid=False):
        """
        @brief  Send packets
        """
        s = psocket.SocketHndl(iface_name=iface)
        if count is not None:
            loop = -count
        elif not loop:
            loop = -1
        try:
            while loop:
                with stop_lock:
                    s.send(packet.bin())
                    self.sent_statistics.increase(iface)
                time.sleep(inter)
                if loop < 0:
                    loop += 1
        except KeyboardInterrupt:
            pass
        s.close()

    def custom_packet_filter(self, pkt):
        """
        @brief  Filter received packet
        """
        mask = self.filter_mask.replace(" ", "")
        mask = mask.replace("0", "1")
        mask = mask.replace("F", "0")
        mask = mask.replace("1", "F")
        data = self.filter_data.replace(" ", "")
        pkt_hex = codecs.encode(pkt.bin(), "hex_codec").decode()[2 * self.filter_offset:2 * self.filter_offset + len(mask)]

        if hex(int("0x" + mask, 16) & int("0x" + pkt_hex, 16)) == hex(int("0x" + mask, 16) & int("0x" + data, 16)):
            return pkt

    def _sniffer(self, sniff_port, count, timeout, filter_layer, src_filter=None, dst_filter=None, stop_lock=None):
        """
        @brief  Thread safe sniffing method for PypackerTG class
        @raise  PypackerException:  unknown filter layer
        """

        def put_to_collector(pkt_hdr, pkt_data):
            """
            @brief  Collect sniffed data
            """
            pkt = packet_filter(ethernet.Ethernet(pkt_data))
            if pkt is not None:
                self._collector.collect(sniff_port, pkt)
                self.receive_statistics.increase(sniff_port, 1)

        def packet_filter(pkt):
            """
            @brief  Filter packets
            """
            if not isinstance(lambda_filter, str) and not lambda_filter(pkt):
                return None
            else:
                return pkt

        lambda_filter = ""
        capture_filter = ""
        self.class_logger.info("Sniffer on port %s" % (sniff_port, ))
        log_message = "Started sniffing for"
        if timeout:
            log_message += " %s seconds" % (timeout, )
        if count:
            log_message += " %s packets" % (count, )
        if filter_layer:
            if filter_layer in PacketProcessor.flt_patterns:
                lambda_filter = PacketProcessor.flt_patterns[filter_layer]['lfilter']
            elif isinstance(filter_layer, tuple) and len(filter_layer) == 3:
                self.filter_offset = filter_layer[0]
                self.filter_data = filter_layer[1]
                self.filter_mask = filter_layer[2]
                lambda_filter = self.custom_packet_filter
            else:
                raise PypackerException("Unknown filter_layer=%s. Supported layers=%s" % (filter_layer, list(PacketProcessor.flt_patterns.keys())))
            log_message += ", filter '%s'" % (filter_layer, )

        if src_filter:
            if capture_filter != "":
                capture_filter = "(%s and (ether src %s))" % (capture_filter, src_filter)
            else:
                capture_filter = "(ether src %s)" % (src_filter, )

        if dst_filter:
            if capture_filter != "":
                capture_filter = "(%s and (ether dst %s))" % (capture_filter, dst_filter)
            else:
                capture_filter = "(ether dst %s)" % (dst_filter, )

        if capture_filter != "":
            log_message += " - '%s'" % (capture_filter, )

        log_message += "..."

        self.class_logger.info(log_message)
        # Use pcap library as sniffer
        # Opening the device for sniffing open_live(device, snaplen, promisc, to_ms)
        snaplen = self._get_snaplen(self.get_os_mtu(iface=sniff_port))
        pc = self.pcap.open_live(sniff_port, snaplen, 1, 10)  # pylint: disable=no-member
        # Set a filtering rule to the pcapObject setfilter(filter, optimize, netmask)
        pc.setfilter(capture_filter)
        # check if pcap has setdirection attribute and set direction
        if hasattr(pc, "setdirection"):
            # Change parameters
            if self.sniff_direction == "both":
                pc.setdirection("PCAP_D_INOUT")
            elif self.sniff_direction == "egress":
                pc.setdirection("PCAP_D_OUT")
            elif self.sniff_direction == "ingress":
                pc.setdirection("PCAP_D_IN")

        # calculate time out
        abs_timeout = time.time()
        if timeout:
            abs_timeout += timeout
        # start packets capture
        while not (timeout is not None and time.time() >= abs_timeout) and not (count != 0 and self.receive_statistics.get_data(sniff_port) >= count):
            try:
                # read the next packet from the interface
                with stop_lock:
                    try:
                        pc.dispatch(100, put_to_collector)
                    except self.pcap.PcapError:  # pylint: disable=no-member
                        pass
                # delay some time
                time.sleep(0.01)
            except KeyboardInterrupt:
                break
        # free pcap object
        del pc
        self.class_logger.info("Sniffing finished.")

    def get_sent_frames_count(self, iface):
        """
        @brief  Read Pypacker statistics - framesSent
        """
        return self.sent_statistics.get_data(iface)

    def clear_sent_statistics(self, sniff_port):
        """
        @brief  Clear Pypacker statistics - framesSent
        """
        self.sent_statistics.clear(sniff_port)

    def clear_statistics(self, sniff_port_list):
        """
        @brief  Clearing statistics on TG ports.
        """
        for sniff_port in sniff_port_list:
            self.clear_sent_statistics(sniff_port)
            self.clear_received_statistics(sniff_port)

    def get_received_frames_count(self, sniff_port):
        """
        @brief  Read statistics - framesReceived
        """
        return self.receive_statistics.get_data(sniff_port)

    def get_filtered_frames_count(self, sniff_port):
        """
        @brief  Read statistics - filtered frames received
        """
        return self.receive_statistics.get_data(sniff_port)

    def get_uds_3_frames_count(self, sniff_port):
        """
        @brief  Read statistics - UDS3 - Capture Trigger (UDS3) - count of non-filtered received packets (valid and invalid)
        """
        return self.receive_statistics.get_data(sniff_port)

    def clear_received_statistics(self, sniff_port):
        """
        @brief  Clear statistics
        """
        self.receive_statistics.clear(sniff_port)

    def get_port_txrate(self, iface):
        """
        @brief  Get ports Tx rate
        """
        pytest.skip("Method is not supported by Pypacker TG")

    def get_port_rxrate(self, iface):
        """
        @brief  Get ports Rx rate
        """
        pytest.skip("Method is not supported by Pypacker TG")

    def get_port_qos_rxrate(self, iface, qos):
        """
        @brief  Get ports Rx rate for specific qos
        """
        pytest.skip("Method is not supported by Pypacker TG")

    def get_qos_frames_count(self, iface, prio):
        """
        @brief  Get QoS frames count
        """
        pytest.skip("Method is not supported by Pypacker TG")

    def set_qos_stat_type(self, iface, ptype):
        """
        @brief  Set QoS stats type
        """
        pytest.skip("Method is not supported by Pypacker TG")

    def set_flow_control(self, iface, mode):
        """
        @brief  Set Flow Control
        """
        pytest.skip("Method is not supported by Pypacker TG")

    def connect_port(self, iface):
        """
        @copydoc  testlib::tg_template::GenericTG::connect_port()
        @raise  PypackerException:  error on port configuration
        """
        self.class_logger.debug("Set {0} port to Up state.".format(iface))
        process = Popen(["ifconfig", iface, "up"], stdout=PIPE, stderr=PIPE)
        process.wait()
        if process.returncode != 0:
            message = "Fail to set {0} port to Up state.".format(iface)
            self.class_logger.error(message)
            self.class_logger.error("StdOut: {0}".format(process.stdout.read()))
            self.class_logger.error("StdErr: {0}".format(process.stderr.read()))
            raise PypackerException(message)

    def disconnect_port(self, iface):
        """
        @copydoc  testlib::tg_template::GenericTG::disconnect_port()
        @raise  PypackerException:  error on port configuration
        """
        self.class_logger.debug("Set {0} port to Down state.".format(iface))
        process = Popen(["ifconfig", iface, "down"], stdout=PIPE, stderr=PIPE)
        process.wait()
        if process.returncode != 0:
            message = "Faile to set {0} port to Down state.".format(iface)
            self.class_logger.error(message)
            self.class_logger.error("StdOut: {0}".format(process.stdout.read()))
            self.class_logger.error("StdErr: {0}".format(process.stderr.read()))
            raise PypackerException(message)

    def get_os_mtu(self, iface=None):
        """
        @copydoc  testlib::tg_template::GenericTG::get_os_mtu()
        """
        try:
            soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            ifr = struct.pack('16sH', iface.encode("utf-8"), 0)
            mtu = struct.unpack('16sH', ioctl(soc, self.SIOCGIFMTU, ifr))[1]
        except Exception as err:
            raise PypackerException("ERROR: Getting MTU failed; %s" % err)

        return mtu

    def set_os_mtu(self, iface=None, mtu=None):
        """
        @copydoc  testlib::tg_template::GenericTG::set_os_mtu()
        """
        try:
            soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            ioctl(soc, self.SIOCSIFMTU, struct.pack('16sH', iface.encode("utf-8"), mtu) + b'\x00' * 14)
        except Exception as err:
            raise PypackerException("ERROR: Setting MTU failed: %s" % err)


class StoppableThread(threading.Thread):
    """
    @description  Thread class with a terminate() method.
    """

    def raise_exc(self, excobj):
        """
        @brief  Raise exception processing
        """
        if self.isAlive():
            for tid, tobj in list(threading._active.items()):
                if tobj is self:
                    with self._thr_lock:
                        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), ctypes.py_object(excobj))
                    if res == 0:
                        raise ValueError("nonexistent thread id")
                    elif res > 1:
                        # if it returns a number greater than one, you're in trouble,
                        # and you should call it again with exc=NULL to revert the effect
                        ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), 0)
                        raise SystemError("PyThreadState_SetAsyncExc failed")
                    return

        # the thread was alive when we entered the loop, but was not found
        # in the dict, hence it must have been already terminated. should we raise
        # an exception here? silently ignore?

    def terminate(self):
        """
        @brief  Raise exception terminating
        """
        # must raise the SystemExit type, instead of a SystemExit() instance
        # due to a bug in PyThreadState_SetAsyncExc
        self.raise_exc(self._stop_exception)


class Collector(object):
    """
    @description  This class handles results collection from all sniffer threads.
    @note  No direct calls supposed. Please see doc for Sniffer class.
    """

    def __init__(self):
        """
        @brief  Initialize Collector class
        """
        self._lock = threading.RLock()
        self.data = {}

    def collect(self, sniff_port, captured_packet):
        """
        @brief  Add data to collector.
        """
        with self._lock:
            try:
                self.data[sniff_port].append(captured_packet)
            except KeyError:
                self.data[sniff_port] = []
                self.data[sniff_port].append(captured_packet)

    def get_data(self):
        """
        @brief  Get data from collector.
        """
        with self._lock:
            return self.data


class BaseStatistics(object):
    """
    @description  This class handles results collection from all threads.
    @note  No direct calls supposed.
    """

    def __init__(self):
        """
        @brief  Initialize BaseStatistics class
        """
        self._lock = threading.Lock()
        self.data = {}

    def increase(self, iface, count=1):
        """
        @brief  Increase interface statistics
        @param  iface:  Interface name
        @type  iface:  str
        @param  count:  Increment value
        @type  count:  int
        """
        with self._lock:
            try:
                self.data[iface] += count
            except KeyError:
                self.data[iface] = count

    def get_data(self, iface):
        """
        @brief  Return data
        @rtype:  int
        @return:  interface statistics
        """
        with self._lock:
            try:
                return self.data[iface]
            except KeyError:
                return 0

    def clear(self, iface):
        """
        @brief  Clear data
        """
        with self._lock:
            self.data[iface] = 0


ENTRY_TYPE = "tg"
INSTANCES = {"pypacker": PypackerTG}
NAME = "tg"
