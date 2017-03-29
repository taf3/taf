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

"""``test_ixnet.py``

`Unittests for IxNetwork`

"""

import time
import platform
import os

import pytest
import pypacker

from testlib.Ixia.IxiaHLT import IxiaHLTMixin
from testlib.Ixia.IxiaHAL import IxiaHALMixin
from testlib.loggers import ClassLogger
from testlib.packet_processor import PacketProcessor
from testlib.custom_exceptions import IxiaException

IXNET_CONF = {"name": "IxNetwork-103", "entry_type": "tg", "instance_type": "ixiahl", "id": "1",
              "ip_host": "X.X.X.X", "tcl_server": "X.X.X.X:8200", "user": "IxNetwork/user",
              "kprio": 200, "sprio": 200, "cprio": 200, "tprio": 200,
              "ports": [[1, 2, 9]]}


class Tg(IxiaHLTMixin, PacketProcessor):
    """
    """
    class_logger = ClassLogger()

    # Constants in seconds
    DEFAULT_MAX_SNIFF_TIME = 3600

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sniff_ids = {}
        self.host = args[0]['ip_host']
        self.username = args[0]['user']

        self.ports, self.port_list = self._get_speed_ports(args[0])
        self.ifaces = "{"
        for iface in self.ports:
            self.ifaces = self.ifaces + self._convert_iface(iface) + " "
        self.ifaces = self.ifaces + "}"

    def _convert_iface(self, iface):
        return "{" + " ".join([str(x) for x in iface]) + "}"

    def _get_version(self):
        return self.tcl('version cget -productVersion')

    @staticmethod
    def _get_port_to_string(iface):
        """Simple helper which allows to get string representation for interface

        Args:
            iface(list): Which IXIA interface to use for packet sending (list in format [chassis_id, card_id, port_id])

        Returns:
            str: string in format "chassis_id/card_id/port_id"

        """
        return "/".join(map(str, iface))

    def _reset_ports(self):
        for iface in self.ports:
            chassis, card, port = iface
            self.class_logger.debug("Reseting config for port %s %s %s." % iface)
            assert self.tcl('port setFactoryDefaults %s %s %s' % (chassis, card, port)) == '0'
            self.tcl('port setDefault; port config -autonegotiate true; port config -duplex full; port config -numAddresses 1')
            self.tcl('port config -transmitMode portTxModeAdvancedScheduler')
            self.tcl('port set %s %s %s' % (chassis, card, port))
            self.tcl('port write %s %s %s' % (chassis, card, port))

    def _get_speed_ports(self, args):
        """Get ports with speed from config.

        Notes:
            This function check if port has speed in config file.

        Returns:
            List of ports used in real config

        """
        ports = []
        ports_list = []
        if 'ports' in args:
            ports = [tuple(x) for x in args["ports"]]
        if "port_list" in args:
            ports = [tuple(x[0]) for x in args["port_list"]]
            ports_list = [[tuple(x[0]), x[1]] for x in args["port_list"]]

        return ports, ports_list

    def connect_hal(self):
        """Logs in to IXIA and takes ports ownership.

        Returns:
            None

        """
        try:
            if platform.system() == 'Linux':
                self.tcl('ixConnectToTclServer %s' % (self.host, ))
                if self.username == "":
                    try:
                        os_username = os.environ['SUDO_USER']
                    except Exception:
                        os_username = os.environ['USER']
                    self.username = "%s__%s" % ("AutoTest", os_username.replace(".", "_"))
                self.class_logger.debug(self.username)
            assert self.tcl('set hostname %s' % (self.host, )) == self.host
            assert self.tcl('set userName %s' % (self.username, )) == self.username
            assert self.tcl('set portList %s' % (self.ifaces, )) == self.ifaces[1:-1]

            assert self.tcl('ixLogin %s' % (self.username, )) == '0'
            assert self.tcl('ixConnectToChassis %s' % (self.host, )) == '0'
            self.class_logger.info("IxTclHAL Version: %s." % (self.tcl('version cget -ixTclHALVersion'), ))
            self.class_logger.info("Product version: %s." % (self._get_version(), ))
            self.class_logger.info("Installed version: %s." % (self.tcl('version cget -installVersion'), ))
            self.connection_state = True
        except Exception as err:
            self.class_logger.debug("Error connecting to IXIA: %s" % (err, ))
            raise err

        errs = {}

        self.owned_ifaces = []

        for iface in self.ports:
            iface = self._convert_iface(iface)
            try:
                assert self.tcl('ixTakeOwnership {%s}' % iface) == '0'
                self.owned_ifaces.append(iface)
            except Exception as err:
                self.class_logger.debug("Error taking ownership on port %s" % (iface, ))
                errs[iface] = err

        if self.owned_ifaces:
            self.ownership_state = True
        if errs:
            raise RuntimeError("Error taking ownership: %s" % (errs, ))

        owned_ports = "{"
        owned_ports = owned_ports + " ".join(self.owned_ifaces) + " }"
        assert self.tcl('set ownedPortList %s' % (owned_ports, )) == owned_ports[1:-1]

        try:
            IxiaHALMixin.stop_all_streams(self)
        except Exception as err:
            self.class_logger.warning("Caught an exception while stopping streams on connection. Type %s. Err: %s" % (type(err), err))

        self._reset_ports()

        self.class_logger.info("Ixia startup complete.")

    def disconnect_hal(self, mode='fast'):
        """Logs out from IXIA and clears ports ownership.

        Returns:
            None

        """
        if self.ownership_state:
            for iface in self.owned_ifaces:
                assert self.tcl('ixClearOwnership {%s}' % (iface, )) == '0'
            self.ownership_state = False
        if self.connection_state:
            assert self.tcl('ixLogout') == '0'
            assert self.tcl('ixDisconnectFromChassis') == '0'
            if platform.system() == 'Linux':
                self.tcl('ixDisconnectTclServer %s' % (self.host, ))
            self.connection_state = False

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
        self.class_logger.debug("Starting capturing on ifaces: %s" % (ifaces, ))
        if filter_layer:
            if filter_layer not in self.flt_patterns:
                raise IxiaException("Invalid filter_layer = %s. Allowed values: %s" % (filter_layer, list(self.flt_patterns.keys())))

        self.class_logger.debug("Sniff params: %s seconds, %s packets, %s filter layer, %s srcMac, %s dstMac." %
                                (sniffing_time, packets_count if packets_count != 0 else None, filter_layer, src_filter, dst_filter))

        # Store sniff settings per port to dictionary
        for iface in ifaces:
            _iface = _get_port_to_string(iface)
            if _iface in self.sniff_ids:
                message = "Sniffer already started on iface %s %s %s." % iface
                self.class_logger.error(message)
                raise IxiaException(message)
            self.sniff_ids[_iface] = {}
            self.sniff_ids[_iface]['count'] = packets_count
            self.sniff_ids[_iface]['layer'] = filter_layer
            self.sniff_ids[_iface]['time'] = sniffing_time

        # Define empty filter by default
        filter_tcl = []
        filter_tcl.append("filter setDefault;")
        filter_tcl.append("capture setDefault;")
        filter_tcl.append("capture config -captureMode captureContinuousMode;")

        # Define realtime filter
        if filter_layer or src_filter or dst_filter:
            # and filtering_method == "realtime":
            self.class_logger.debug("Enabling filter for data capturing...")
            filter_tcl.append("filterPallette setDefault;")
            filter_tcl.append("capture config -continuousFilter captureContinuousFilter;")
            filter_tcl.append("filter config -captureFilterEnable true;")
        else:
            filter_tcl.append("filter config -captureFilterEnable false;")

        if filter_layer:
            # and filtering_method == "realtime":
            filter_tcl.append(self._set_filter_params(filter_layer))

        # Define srcMac filter
        if src_filter:
            if ':' in src_filter:
                src_filter = src_filter.replace(':', ' ')
            filter_tcl.append("filterPallette config -SA1 {%s};" % (src_filter, ))
            filter_tcl.append("filter config -captureFilterSA addr1;")

        # Define dstMac filter
        if dst_filter:
            if ':' in dst_filter:
                dst_filter = dst_filter.replace(':', ' ')
            filter_tcl.append("filterPallette config -DA1 {%s};" % (dst_filter, ))
            filter_tcl.append("filter config -captureFilterDA addr1;")

        # Send filter config to IXIA
        self.tcl(" ".join(filter_tcl))

        # Apply filter to ports
        ports_list = []
        tcl_cmd = []
        tcl_cmd.append("set retCode $::TCL_OK;")
        for iface in ifaces:
            chassis, card, port = iface
            tcl_cmd.append("if {[capture set %(chassis)s %(card)s %(port)s]} {errorMsg \"<<capture set>> return error.\"; set retCode $::TCL_ERROR};")
            if filter_layer or src_filter or dst_filter:
                tcl_cmd.append("if {[filterPallette set %(chassis)s %(card)s %(port)s]} \
                                {errorMsg \"<<filterPallette set>> command return error.\"; set retCode $::TCL_ERROR};")
            tcl_cmd.append("if {[filter set %(chassis)s %(card)s %(port)s]} {errorMsg \"<<filter set>> command return error.\"; set retCode $::TCL_ERROR};")
            tcl_cmd.append("return $retCode;")
            assert self.tcl(" ".join(tcl_cmd) % locals()) == "0"
            ports_list.append(iface)

        tcl_ports_list = str(ports_list).replace("(", "{").replace(")", "}").replace("[", "{").replace("]", "}").replace("'", "").replace(",", "")
        assert self.tcl("set rxPortIdList %s;\
                        set retCode $::TCL_OK;\
                        if {[ixWriteConfigToHardware rxPortIdList]} {errorMsg \"ixWriteConfigToHardware return error.\"; set retCode $::TCL_ERROR};\
                        if {[ixClearStats rxPortIdList]} {errorMsg \"ixClearStats return error.\"; set retCode $::TCL_ERROR};\
                        if {[ixStartCapture rxPortIdList]} {errorMsg \"ixStartCapture return error.\"; set retCode $::TCL_ERROR};\
                        if {[ixClearTimeStamp rxPortIdList]} {errorMsg \"ixClearTimeStamp return error.\"; set retCode $::TCL_ERROR};\
                        return $retCode" %
                        (tcl_ports_list, )) == "0"
        sniffing_start_timestamp = time.time()
        for iface in ifaces:
            _iface = _get_port_to_string(iface)
            self.sniff_ids[_iface]['start_time'] = sniffing_start_timestamp

        # Wait for assurance that sniffing is started
        time.sleep(1.5)

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
        def _stop_capture_on_port(iface):
            chassis, card, port = iface.split("/")
            assert self.tcl("ixStopPortCapture %s %s %s" % (chassis, card, port)) == "0"
            self.class_logger.debug("Stopped capture on iface: %s" % iface)

        def _get_captured_frames_count(iface):
            chassis, card, port = iface.split("/")

            tcl_cmd = []
            message = "Cannot process tcl command: stat get statAllStats %s %s %s" % (chassis, card, port)
            tcl_cmd.append("if {[stat get statAllStats %s %s %s]} {errorMsg \"%s\"; return \"ERROR\"} else" %
                           (chassis, card, port, message))
            if self.sniff_ids[iface]['layer'] is not None:
                tcl_cmd.append("{stat cget -captureFilter}")
            else:
                tcl_cmd.append("{stat cget -framesReceived}")
            result = self.tcl(" ".join(tcl_cmd))
            if result == "ERROR":
                self.class_logger.error(message)
                raise IxiaException(message)
            else:
                num_frames = int(result)

            return num_frames

        self.class_logger.debug("Stopping capturing on ifaces: %s ..." % (ifaces, ))
        capture_state = dict((self._get_port_to_string(iface), True) for iface in ifaces)

        while True in list(capture_state.values()):

            # This flag will True when we have timed out sniffer without packets count. And we have to make timeout between check.
            # In case sniffer with packets count we check numFrames and this procedure makes timeout.
            timeout_flag = True

            if force:
                for iface in list(capture_state.keys()):
                    if capture_state[iface]:
                        _stop_capture_on_port(iface)
                        capture_state[iface] = False

            for iface in list(capture_state.keys()):
                if capture_state[iface]:
                    # Stop ifaces that do not have time or count parameters
                    if not self.sniff_ids[iface]['time'] and not self.sniff_ids[iface]['count']:
                        _stop_capture_on_port(iface)
                        capture_state[iface] = False
                    # Stop ifaces if time is elapsed
                    if self.sniff_ids[iface]['time'] and (time.time() - self.sniff_ids[iface]['start_time']) >= self.sniff_ids[iface]['time']:
                        _stop_capture_on_port(iface)
                        capture_state[iface] = False

            for iface in list(capture_state.keys()):
                if capture_state[iface]:
                    # Stop if frames count reached
                    if self.sniff_ids[iface]['count'] != 0:
                        num_frames = _get_captured_frames_count(iface)
                        if num_frames > self.sniff_ids[iface]['count']:
                            _stop_capture_on_port(iface)
                            capture_state[iface] = False
                            timeout_flag = False

            if timeout_flag:
                time.sleep(0.15)

            # Loop prevention
            for iface in list(capture_state.keys()):
                if capture_state[iface]:
                    if not self.sniff_ids[iface]['time'] and (time.time() - self.sniff_ids[iface]['start_time']) >= self.DEFAULT_MAX_SNIFF_TIME:
                        _stop_capture_on_port(iface)
                        capture_state[iface] = False

        packet_dict = {}

        for iface in ifaces:
            _iface = self._get_port_to_string(iface)

            # After sniff finished we shouldn't use this method. Because statistics update is continuing
            # captured_packets_count = _get_captured_frames_count(iface)
            # Instead we check captureBuffer. (which stops capturing and we couldn't use it before)
            chassis, card, port = iface
            captured_packets_count = int(self.tcl("captureBuffer get %s %s %s; captureBuffer cget -numFrames;" %
                                                  (chassis, card, port)))
            self.class_logger.debug("Collected %s packets on %s interface (real count)" % (captured_packets_count, iface))

            if self.sniff_ids[_iface]['count'] != 0:
                if captured_packets_count < self.sniff_ids[_iface]['count']:
                    packet_count = captured_packets_count
                else:
                    packet_count = self.sniff_ids[_iface]['count']
            else:
                packet_count = captured_packets_count

            self.class_logger.debug("Collected %s packets on %s interface (count for processing)" % (packet_count, iface))

            packet_list = []

            if sniff_packet_count != 0 and sniff_packet_count < packet_count:
                packet_count = sniff_packet_count
            if packet_count and not drop_packets:
                # chassis, card, port = self._get_port_info(iface)
                assert self.tcl("capture get %(chassis)s %(card)s %(port)s; \
                                 captureBuffer get %(chassis)s %(card)s %(port)s 1 %(packet_count)s" % locals()) == "0"
                # self.tcl("captureBuffer get %s %s %s 1 %s" % (chassis, card, port, packet_count))
                for packet_num in range(1, packet_count + 1):
                    # self.class_logger.debug("Processing packet %s... " % (packet_num, ))
                    assert self.tcl("captureBuffer getframe %s" % (packet_num, )) == "0"
                    raw_packet = self.tcl("captureBuffer cget -frame").replace(" ", "")
                    timestamp = float(self.tcl("captureBuffer cget -timestamp").replace(" ", ""))
                    # self.class_logger.debug(raw_packet)
                    pkt = pypacker.ethernet.Ethernet(raw_packet.decode("hex"))  # pylint: disable=no-member
                    pkt.time = self.sniff_ids[_iface]['start_time'] + timestamp / 1000000000
                    packet_list.append(pkt)

                packet_dict[iface] = packet_list
            else:
                packet_dict[iface] = []

            self.sniff_ids.pop(_iface)

        return packet_dict

    def _set_filter_params(self, layer):
        """Configures filter parameters for specified layer.

        Args:
            Layer(str): compatible with pypacker "layers"

        Returns:
            None

        """
        def _set_user_pattern(ptrn_num, ptrn_cfg):
            _tcl_commands = ""
            _tcl_commands += "filterPallette config -pattern%s \"%s\";" % (ptrn_num, ptrn_cfg[0], )
            _tcl_commands += "filterPallette config -patternMask%s \"%s\";" % (ptrn_num, ptrn_cfg[1], )
            _tcl_commands += "filterPallette config -patternOffset%s \"%s\";" % (ptrn_num, ptrn_cfg[2], )
            if len(ptrn_cfg) > 3:
                _tcl_commands += "filterPallette config -patternOffsetType%s \"filterPalletteOffsetStartOf%s\";" % (ptrn_num, ptrn_cfg[3], )
            return _tcl_commands

        tcl_filter = ""
        if "ptrn1" in self.flt_patterns[layer]:
            tcl_filter += _set_user_pattern(1, self.flt_patterns[layer]['ptrn1'])
            tcl_filter += "filterPallette config -matchType1 %s;" % (self.flt_patterns[layer]['mt1'], )
        if "ptrn2" in self.flt_patterns[layer]:
            tcl_filter += _set_user_pattern(2, self.flt_patterns[layer]['ptrn2'])
            tcl_filter += "filterPallette config -matchType2 %s;" % (self.flt_patterns[layer]['mt2'], )
        tcl_filter += "filter config -captureFilterPattern %s;" % (self.flt_patterns[layer]['cfp'], )

        return tcl_filter


def _get_port_to_string(iface):
    """Simple helper which allows to get string representation for interface.

    Args:
        iface(list): Which IXIA interface to use for packet sending (list in format [chassis_id, card_id, port_id])

    Returns:
        str: string in format "chassis_id/card_id/port_id"

    """
    return "/".join(map(str, iface))


def _get_speed_ports():
    """Get ports with speed from config.

    Notes:
        This function check if port has speed in config file.

    Returns:
        list: List of ports used in real config

    """
    ports = []
    ports_list = []
    if 'ports' in IXNET_CONF:
        ports = [tuple(x) for x in IXNET_CONF["ports"]]
    if "port_list" in IXNET_CONF:
        ports = [tuple(x[0]) for x in IXNET_CONF["port_list"]]
        ports_list = [[tuple(x[0]), x[1]] for x in IXNET_CONF["port_list"]]

    return ports, ports_list


def _set_loopback(tg):
    iface = tg.ports[0]
    chassis, card, port = iface
    assert tg.tcl("ixClearPortStats %(chassis)s %(card)s %(port)s; \
                   port get %(chassis)s %(card)s %(port)s; \
                   port config -rxTxMode gigLoopback; \
                   port config -loopback portLoopback; \
                   port set %(chassis)s %(card)s %(port)s; \
                   port write %(chassis)s %(card)s %(port)s" %
                  {'chassis': chassis, 'card': card, 'port': port}) == '0'


@pytest.mark.skipif(True, reason="Temporary skip this TC on real environment")
def test_connect_disconnect(request):
    """
    """
    tg = Tg(IXNET_CONF, request.config.option)

    tg.create()
    tg.connect_hal()
    _set_loopback(tg)

    tg.disconnect_hal()
    tg.disconnect()


@pytest.mark.skipif(True, reason="Temporary skip this TC on real environment")
def test_stp(request):
    """
    """
    tg = Tg(IXNET_CONF, request.config.option)

    tg_port = _get_speed_ports()[0][0]

    tg.create()
    tg.connect_hal()
    _set_loopback(tg)

    tg.STP.configure_bridges(tg_port, auto_pick_bridge_mac="0", auto_pick_port="0",  # pylint: disable=no-member
                             bridge_mac="2234.5678.9abc", bridge_mac_step="0000.0000.0005", bridge_mode="mstp",
                             bridge_priority="8192", cist_external_root_cost="5",
                             cist_external_root_mac="aaaa.bbbb.cccc", cist_external_root_priority="4096",
                             cist_reg_root_cost="10", cist_reg_root_mac="abcd.abcd.abcd",
                             cist_reg_root_priority="16384", cist_remaining_hop="10", count="5", enable_jitter="1",
                             forward_delay="1000", hello_interval="1500", inter_bdpu_gap="10", intf_cost="7",
                             intf_count="3", jitter_percentage="20", link_type="shared",
                             mac_address_bridge_step="0000.0001.0000", mac_address_init="3111.2222.1111",
                             mac_address_intf_step="0000.1111.0000", max_age="12500", message_age="11520",
                             mstc_name="ixia", mstc_revision="3", mtu="576", port_no="1", port_no_bridge_step="0",
                             port_no_intf_step="1", port_priority="144", pvid="8", vlan="1", vlan_id="5,6,7",
                             vlan_id_intf_step="0,0,1", vlan_user_priority="3")

    tg.STP.configure_msti(tg_port, bridge_handler_id='1', count="5", msti_id="4",  # pylint: disable=no-member
                          msti_id_step="1", msti_hops="13", msti_internal_root_path_cost="17",
                          msti_mac="1234.1234.1234", msti_mac_step="0000.0002.0001", msti_name="msti-%",
                          msti_port_priority="176", msti_priority="61440", msti_vlan_start="7",
                          msti_vlan_start_step="2", msti_vlan_stop="13", msti_wildcard_percent_enable="1",
                          msti_wildcard_percent_start="10", msti_wildcard_percent_step="2")

    tg.STP.configure_bridges(tg_port, bridge_handler_id='1', vlan_msti_handler_id='1', mode="modify")  # pylint: disable=no-member

    tg.STP.configure_lans(tg_port, count="10", mac_address="000e.4cd7.c011",  # pylint: disable=no-member
                          mac_incr_enable="1", vlan_enable="1", vlan_id="2", vlan_incr_enable="1")

    tg.STP.control(tg_port, mode="start")  # pylint: disable=no-member
    time.sleep(10)

    iface = tg.ports[0]
    tg.start_sniff([iface], sniffing_time=25, packets_count=100, filter_layer="STP")

    data = tg.stop_sniff([iface])

    assert "STP" in data[iface]

    tg.STP.cleanup()  # pylint: disable=no-member

    tg.disconnect_hal()
    tg.disconnect()
