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

"""``IxiaHAL.py``

`TAF Ixia traffic generator based on IxTclHal API`

"""

import copy
import codecs
import os
import platform
import time
import struct

from tkinter import Tcl, TclError


from . import ixia_helpers
from ..custom_exceptions import IxiaException
import pypacker


class IxiaHALMixin(object):
    """IXIA interaction base class.

    """

    class_logger = None

    # Constants in seconds
    DEFAULT_MAX_SNIFF_TIME = 3600

    def __init__(self, config, opts):
        """Initializes connection to IXIA.

        Args:
            config(dict):  Configuration information
            opts(OptionParser):  py.test config.option object which contains all py.test cli options

        """
        self.__opts = opts
        self.__config = config

        self._init_tcl()

        self.id = config['id']
        self.type = config['instance_type']

        self.host = config['ip_host']

        self.owned_ifaces = []

        self.ownership_state = False
        self.connection_state = False

        self.stream_ids = {}
        self.sniff_ids = {}

        self.username = ""
        if "user" in config:
            self.username = config['user']

    def _convert_iface(self, iface):
        """Convert representation of TG port from tuple to string.

        Args:
            iface(tuple(int)):  TG port in format tuple(chassisID, cardId, portId)

        Returns:
            str: Representation of TG port in format {chassisID cardId portId}

        """
        return "{" + " ".join([str(x) for x in iface]) + "}"

    def _init_tcl(self):
        """Initialize Tcl interpreter.

        Returns:
            None

        """
        self.Tcl = Tcl()

        def tcl_puts(*args):
            """Enables logging for tcl output.

            Returns:
                None

            """
            if len(args) >= 2:
                stream = args[0]
                if stream == "stdout":
                    self.class_logger.debug(" ".join(args[1:]))
                elif stream == "stderr":
                    self.class_logger.error(" ".join(args[1:]))
                else:
                    self.class_logger.debug("stream <%s>: %s" % (args[0], " ".join(args[1:])))
            elif len(args) == 1:
                self.class_logger.debug(args[0])
            else:
                self.class_logger.error("Called puts without arguments.")
            return None

        self.Tcl.createcommand("tcl_puts", tcl_puts)
        self.class_logger.debug("Insert tcl script to catch puts output.")
        ixia_helpers.tcl_puts_replace(self.Tcl)

        ixia_helpers.ixtclhal_import(self.Tcl)

    def tcl(self, cmd):
        """Log end execute tcl code.

        Args:
            cmd(str):  Tcl command

        Returns:
            str: Result of execution

        """
        self.class_logger.debug("Run tcl command: %s", cmd)
        return self.Tcl.eval(cmd)

    def _get_version(self):
        """Get Ixia version.

        Returns:
            str: Version of product

        """
        return self.tcl('version cget -productVersion')

    def connect(self):
        """Logs in to IXIA and takes ports ownership.

        Raises:
            AssertionError:  error in executing tcl code
            Exception:  Connection error
            RuntimeError:  Error on taking/clearing port ownership

        Returns:
            None

        """
        try:
            if platform.system() == 'Linux':
                self.tcl('ixConnectToTclServer %s' % (self.host, ))
                if self.username == "":
                    try:
                        os_username = os.environ['SUDO_USER']
                    except KeyError:
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

        # Clear port ownership if option 'ixia_clear_ownership' enable
        if self.__opts.ixia_clear_ownership and not self.is_protocol_emulation_present:
            for iface in self.ports:
                iface = self._convert_iface(iface)
                try:
                    assert self.tcl('ixClearOwnership {%s} force' % (iface, )) == '0'
                except Exception as err:
                    self.class_logger.debug("Error clearing ownership on port %s" % (iface, ))
                    raise RuntimeError("Error clearing ownership: %s" % (errs, ))

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
            self.stop_all_streams()
        except Exception as err:
            self.class_logger.warning("Caught an exception while stopping streams on connection. Type %s. Err: %s" % (type(err), err))

        self._reset_ports()

        self.class_logger.info("Ixia startup complete.")

    __connect = connect

    def _reset_ports(self):
        """Reset TG ports configuration.

        Raises:
            AssertionError:  error in executing tcl code

        Returns:
            None

        """
        for iface in self.ports:
            chassis, card, port = iface
            self.class_logger.debug("Reseting config for port %s %s %s." % iface)
            assert self.tcl('port setFactoryDefaults %s %s %s' % (chassis, card, port)) == '0'
            self.tcl('port setDefault; port config -autonegotiate true; port config -duplex full; port config -numAddresses 1')
            self.tcl('port config -transmitMode portTxModeAdvancedScheduler')
            self.tcl('port set %s %s %s' % (chassis, card, port))
            self.tcl('port write %s %s %s' % (chassis, card, port))

    def disconnect(self, mode='fast'):
        """Logs out from IXIA and clears ports ownership.

        Args:
            mode(str):  Type of mode to execute

        Raises:
            AssertionError:  error in executing tcl code

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

    __disconnect = disconnect

    def disconnect_port(self, iface):
        """Simulate port link disconnecting (set it to admin down etc).

        Args:
            iface(str):  Interface to disconnect.

        Raises:
            NotImplementedError:  not implemented

        Returns:
            None or raise and exception.

        """
        chassis, card, port = iface
        self.class_logger.debug("Emulating disconnecting for port %s %s %s." % iface)
        self.tcl('port config -enableSimulateCableDisconnect true')
        self.tcl('port set %s %s %s' % (chassis, card, port))
        self.tcl('port write %s %s %s' % (chassis, card, port))

    def connect_port(self, iface):
        """Simulate port link connecting (set it to admin up etc).

        Args:
            iface(str):  Interface to connect.

        Raises:
            NotImplementedError:  not implemented

        Returns:
            None or raise and exception.

        """
        chassis, card, port = iface
        self.class_logger.debug("Emulating connecting for port %s %s %s." % iface)
        self.tcl('port config -enableSimulateCableDisconnect false')
        self.tcl('port set %s %s %s' % (chassis, card, port))
        self.tcl('port write %s %s %s' % (chassis, card, port))

    def check(self):
        """Check if TG object is alive and ready for processing.

        Returns:
            None or raise and exception.

        """
        try:
            self._get_version()
        except TclError:
            try:
                self.__disconnect()
            except TclError:
                pass
            self.__init__(self.__config, self.__opts)

    def create(self):
        """Perform all necessary procedures to initialize TG device and prepare it for interaction.

        Returns:
            None or raise and exception.

        Notes:
            Method has to check --get_only option. Set of steps to configure TG device is related to particular TG type.

        """
        return self.__connect()

    def destroy(self):
        """Perform all necessary procedures to uninitialize TG device.

        Returns:
            None or raise and exception.

        Notes:
            Method has to check --get_only and --leave_on options.
            Set of steps to unconfigure TG device is related to particular TG type.
            Method has to clear all connections and stop all captures and data streams.

        """
        self.cleanup(mode="fast")
        self.__disconnect()

    def cleanup(self, mode="complete"):
        """This method should do Ixia ports cleanup (remove streams etc).

        Args:
            mode(str): "fast" or "complete". If mode == "fast", method does not clear streams on the port, but stops them (str).

        Returns:
            None or raise and exception.

        """
        # TODO: Add stop_sniff etc
        # TODO: Handle errors more gracefully
        try:
            self.stop_streams()
        except Exception as err:
            self.class_logger.warning("Caught an exception while stopping streams. Type %s. Err: %s" % (type(err), err))
        if mode == "complete":
            self.sniff_ids = {}
            self.stream_ids = {}
            self._reset_ports()

    def sanitize(self):
        """This method has to clear all stuff which can cause device inconsistent state after exit or unexpected exception.

        Notes:
            E.g. clear connections, stop threads. This method is called from pytest.softexit

        """
        self.__disconnect()

    def clear_streams(self):
        """Stop and clear all traffic streams.

        """
        self.stream_ids = {}
        self._reset_ports()

    def _transmit_stream(self, chassis, card, port, ix_stream_id):
        """Transmit Ixia stream.

        Args:
            chassis(int):  Chassis id
            card(int):  Card id
            port(int):  Port id
            ix_stream_id(int):  Stream id

        Raises:
            AssertionError:  error in executing tcl code
            IxiaException:  Link is down

        Returns:
            None

        """
        # Check Link State before sending stream.
        if self.tcl("set linkToCheck {{%s %s %s}}; ixCheckLinkState linkToCheck" % (chassis, card, port)) != "0":
            raise IxiaException("Link {%s %s %s} is Down." % (chassis, card, port))

        # Get initial stream statistics
        self.tcl("streamTransmitStats get {chassis} {card} {port} {stream_id} {stream_id}; "
                 "set startCount{stream_id} [streamTransmitStats cget -framesSent]".format(chassis=chassis,
                                                                                           card=card,
                                                                                           port=port,
                                                                                           stream_id=ix_stream_id))

        # Enable stream.
        self._enable_stream(chassis, card, port, ix_stream_id)

        # Start transmission if it's disabled on the port.
        assert self.tcl("if {[stat getTransmitState %(chassis)s %(card)s %(port)s] != 1} \
                           {ixStartPortTransmit %(chassis)s %(card)s %(port)s} \
                        else \
                           {return \"0\"}" %
                        {'chassis': chassis, 'card': card, 'port': port}) == "0"

    def _enable_stream(self, chassis, card, port, ix_stream_id):
        """Enable Ixia stream.

        Args:
            chassis(int):  Chassis id
            card(int):  Card id
            port(int):  Port id
            ix_stream_id(int):  Stream id

        Returns:
            None

        """
        self.tcl("stream get %(chassis)s %(card)s %(port)s %(stream_id)s; \
                  stream config -enable true; \
                  stream set %(chassis)s %(card)s %(port)s %(stream_id)s; \
                  stream write %(chassis)s %(card)s %(port)s %(stream_id)s;" %
                 {'chassis': chassis, 'card': card, 'port': port, 'stream_id': ix_stream_id}) == "0"

    def _disable_stream(self, chassis, card, port, ix_stream_id):
        """Disable Ixia stream.

        Args:
            chassis(int):  Chassis id
            card(int):  Card id
            port(int):  Port id
            ix_stream_id(int):  Stream id

        Returns:
            None

        """
        self.tcl("stream get %(chassis)s %(card)s %(port)s %(stream_id)s; \
                  stream config -enable false; \
                  stream set %(chassis)s %(card)s %(port)s %(stream_id)s; \
                  stream write %(chassis)s %(card)s %(port)s %(stream_id)s;" %
                 {'chassis': chassis, 'card': card, 'port': port, 'stream_id': ix_stream_id}) == "0"

    def _check_increment(self, increment, name):
        """Verify that representation of increment is correct.

        Args:
            increment(tuple(int)):  Increment in format tuple(step, count)
            name(str):  Name of increment

        Raises:
            TypeError:  Incorrect type of parameters.

        Returns:
            tuple: Step and count.

        """
        if not isinstance(increment, tuple):
            raise TypeError("%s must be a tuple." % name)
        step = increment[0]
        count = increment[1]
        if not isinstance(step, int) or not isinstance(count, int):
            raise TypeError("%s must be a tuple of integers." % name)
        return step, count

    def _set_ixia_udf_field(self, udf_id=1, initval='1', offset=24, bit_offset=0, counter_type='c32', step=1, count=1, continuous=False):
        """Setup Ixia stream UDF.

        Args:
            udf_id(int):  UDF id
            initval(str):  Initial value
            offset(int):  offset value
            bit_offset(int):  bit_offset value
            counter_type(str):  number of bits to increment
            step(int):  increment step
            count(int):  increment count
            continuous(bool):  continuous increment

        Returns:
            list: Tcl commands.

        """
        tcl_commands = []
        if udf_id > 5:
            self.class_logger.warning("Increment will not be applied because udf_id is more than 5: %s" % udf_id)
        else:
            tcl_commands.append("udf setDefault; udf config -enable true; udf config -initval {0};".format(initval))
            tcl_commands.append("udf config -offset {0};".format(offset))
            tcl_commands.append("udf config -bitOffset {0};".format(bit_offset))
            tcl_commands.append("udf config -countertype {0};".format(counter_type))
            if continuous and count == 0:
                tcl_commands.append("udf config -continuousCount true;")
            else:
                tcl_commands.append("udf config -continuousCount false;")
            if step >= 0:
                tcl_commands.append("udf config -updown uuuu;")
            else:
                tcl_commands.append("udf config -updown dddd;")
            if count > 0:
                tcl_commands.append("udf config -repeat {0};".format(count))
            tcl_commands.append("udf config -step {0};".format(abs(step)))
            tcl_commands.append("udf set {0};".format(udf_id))
        return tcl_commands

    def _configure_vlan(self, payload, vlan_type, chassis, card, port, vlan_increment, in_vlan_increment, continuous):
        """Configure Dot1Q layer.

        Args:
            payload(pypacker.Packet):  Packet to analyze
            vlan_type(hex):  VLAN type
            chassis(int):  TG chassis id
            card(int):  TG card id
            port(int):  TG port id
            vlan_increment(tuple):  VLAN increment parameters for tagged packet
            in_vlan_increment(tuple):  Inner vlan ID increment parameters for double tagged frames
            continuous(bool):  Should stream be sent continuously or not

        Returns:
            tuple: Dot1Q payload, Tcl commands.

        """
        # TODO: Need to add processing QinQ and other VLAN fields

        if in_vlan_increment is not None:
            in_vlan_increment_step, in_vlan_increment_count = self._check_increment(in_vlan_increment, "in_vlan_increment")
        else:
            in_vlan_increment_step, in_vlan_increment_count = None, None

        if vlan_increment is not None:
            vlan_increment_step, vlan_increment_count = self._check_increment(vlan_increment, "vlan_increment")
        else:
            vlan_increment_step, vlan_increment_count = None, None

        def _set_vlan(payl, vtype, step, count):
            commands = []
            commands.append("vlan setDefault;")
            # if payl.id == 1:
            #     commands.append("vlan config -cfi setCFI;")
            # if vtype == 0x9100:
            #     commands.append("vlan config -protocolTagId vlanProtocolTag9100;")
            # elif vtype == 0x9200:
            #     commands.append("vlan config -protocolTagId vlanProtocolTag9200;")
            # elif vtype == 0x88A8:
            #     commands.append("vlan config -protocolTagId vlanProtocolTag88A8;")
            # elif vtype == 0x9300:
            #     commands.append("vlan config -protocolTagId vlanProtocolTag9300;")
            # commands.append("vlan config -userPriority {0};".format(payl.prio))
            commands.append("vlan config -vlanID {0};".format(vtype[1]))
            if step is not None:
                if step > 0 and continuous and count == 0:
                    incr_type = "vContIncrement"
                elif step < 0 and continuous and count == 0:
                    incr_type = "vContDecrement"
                elif step > 0:
                    incr_type = "vIncrement"
                elif step < 0:
                    incr_type = "vDecrement"
                commands.append("vlan config -mode {0};".format(incr_type))
                commands.append("vlan config -step {0};".format(abs(step)))
                if count > 0:
                    commands.append("vlan config -repeat {0};".format(count))
            return commands

        tcl_commands = []
        dot1 = payload
        # dot2 = payload.payload
        # if dot2.__class__.__name__ == "Dot1Q":
        #     tcl_commands.append("protocol config -enable802dot1qTag vlanStacked;")
        #     tcl_commands.append("stackedVlan setDefault;")
        # else:
        tcl_commands.append("protocol config -enable802dot1qTag vlanSingle;")

        tcl_commands.extend(_set_vlan(dot1, vlan_type, vlan_increment_step, vlan_increment_count))

        # if dot2.__class__.__name__ == "Dot1Q":
        #     tcl_commands.append("stackedVlan setVlan 1;")
        #     tcl_commands.extend(_set_vlan(dot2, dot1.type, in_vlan_increment_step, in_vlan_increment_count))
        #     tcl_commands.append("stackedVlan setVlan 2;")
        #     tcl_commands.append("stackedVlan set %(chassis)s %(card)s %(port)s ;" % {'chassis': chassis, 'card': card, 'port': port})
        #     dot2 = dot2.payload
        # else:
        tcl_commands.append("vlan set %(chassis)s %(card)s %(port)s ;" % {'chassis': chassis, 'card': card, 'port': port})

        return dot1, tcl_commands

    def _configure_ip(self, payload, chassis, card, port):
        """Configure IP layer.

        Args:
            payload(pypacker.Packet):  Packet to analyze
            chassis(int):  TG chassis id
            card(int):  TG card id
            port(int):  TG port id

        Returns:
            tuple: IP payload, Tcl commands.

        """
        tcl_commands = []
        tcl_commands.append("protocol config -name ipV4;")
        tcl_commands.append("ip setDefault;")

        # Set src address
        tcl_commands.append("ip config -sourceIpAddr {%s};" % (payload.src_s, ))
        # Set dst address
        tcl_commands.append("ip config -destIpAddr {%s};" % (payload.dst_s, ))

        # Set ToS
        tos = bin(int(payload.tos))[2:].zfill(8)
        if tos[:3] == '000':
            tcl_commands.append("ip config -precedence routine;")
        elif tos[:3] == '001':
            tcl_commands.append("ip config -precedence priority;")
        elif tos[:3] == '010':
            tcl_commands.append("ip config -precedence immediate;")
        elif tos[:3] == '011':
            tcl_commands.append("ip config -precedence flash;")
        elif tos[:3] == '100':
            tcl_commands.append("ip config -precedence flashOverride;")
        elif tos[:3] == '101':
            tcl_commands.append("ip config -precedence criticEcp;")
        elif tos[:3] == '110':
            tcl_commands.append("ip config -precedence internetControl;")
        elif tos[:3] == '111':
            tcl_commands.append("ip config -precedence networkControl;")

        if tos[3] == '0':
            tcl_commands.append("ip config -delay normalDelay;")
        else:
            tcl_commands.append("ip config -delay lowDelay;")

        if tos[4] == '0':
            tcl_commands.append("ip config -throughput normalThruput;")
        else:
            tcl_commands.append("ip config -throughput highThruput;")

        if tos[5] == '0':
            tcl_commands.append("ip config -reliability normalReliability;")
        else:
            tcl_commands.append("ip config -reliability highReliability;")

        if tos[6] == '0':
            tcl_commands.append("ip config -cost normalCost;")
        else:
            tcl_commands.append("ip config -cost lowCost;")

        tcl_commands.append("ip config -reserved {0};".format(tos[7]))

        # Set up identifier
        tcl_commands.append("ip config -identifier {0};".format(payload.id))

        # Set up fragment
        flags = bin(payload.off)[2:].zfill(2)
        if flags[0] == '0':
            tcl_commands.append("ip config -fragment may;")
        else:
            tcl_commands.append("ip config -fragment dont;")
        if flags[1] == '0':
            tcl_commands.append("ip config -lastFragment last;")
        else:
            tcl_commands.append("ip config -lastFragment more;")
        tcl_commands.append("ip config -fragmentOffset {%s};" % (payload.off, ))

        # Set up length
        # isssue header len is not updated
        _len = payload.__len__()
        if _len:
            tcl_commands.append("ip config -lengthOverride true;")
            tcl_commands.append("ip config -totalLength {%s};" % (_len, ))

        # Set up TTL
        ttl = payload.ttl
        tcl_commands.append("ip config -ttl {%s};" % (ttl, ))
        # Set up IP Options
        if not isinstance(payload.opts, list):
            options = codecs.encode(bytes(payload.options), 'hex_codec').decode()
        elif isinstance(payload.opts, list):
            options = ""
            for opt in payload.opts:
                options += codecs.encode(bytes(opt), "hex_codec").decode()
        tcl_commands.append("ip config -options {%s};" % (options, ))

        # Set up protocol
        proto = payload.p
        if proto == 1:
            tcl_commands.append("ip config -ipProtocol icmp;")
        elif proto == 2:
            tcl_commands.append("ip config -ipProtocol igmp;")
        elif proto == 6:
            tcl_commands.append("ip config -ipProtocol tcp;")
        elif proto == 17:
            tcl_commands.append("ip config -ipProtocol udp;")

        tcl_commands.append("ip set %(chassis)s %(card)s %(port)s ;" % {'chassis': chassis, 'card': card, 'port': port})

        payl = payload.upper_layer
        return payl, tcl_commands

    def _configure_arp(self, payload, chassis, card, port):
        """Configure ARP layer.

        Args:
            payload(pypacker.Packet):  Packet to analyze
            chassis(int):  TG chassis id
            card(int):  TG card id
            port(int):  TG port id

        Returns:
            tuple: ARP payload, Tcl commands.

        """

        tcl_commands = []
        tcl_commands.append("protocol config -name ipV4;")
        tcl_commands.append("protocol config -appName Arp;")
        tcl_commands.append("arp setDefault;")

        # Set up operation
        opcode = payload.op
        if opcode == 1:
            tcl_commands.append("arp config -operation arpRequest;")
        elif opcode == 2:
            tcl_commands.append("arp config -operation arpReply;")

        # Set psrc address
        tcl_commands.append("arp config -sourceProtocolAddr {%s};" % (payload.spa_s, ))
        # Set pdst address
        tcl_commands.append("arp config -destProtocolAddr {%s};" % (payload.tpa_s, ))
        # Set hwsrc address
        tcl_commands.append("arp config -sourceHardwareAddr {%s};" % (payload.sha_s, ))
        # Set hwdst address
        tcl_commands.append("arp config -destHardwareAddr {%s};" % (payload.tha_s, ))

        tcl_commands.append("arp set %(chassis)s %(card)s %(port)s ;" % {'chassis': chassis, 'card': card, 'port': port})

        payl = payload.upper_layer
        return payl, tcl_commands

    def _configure_tcp(self, payload, chassis, card, port):
        """Configure TCP layer.

        Args:
            payload(pypacker.Packet):  Packet to analyze
            chassis(int):  TG chassis id
            card(int):  TG card id
            port(int):  TG port id

        Returns:
            tuple: TCP payload, Tcl commands.

        """

        tcl_commands = []
        tcl_commands.append("tcp setDefault;")

        # Set src port
        tcl_commands.append("tcp config -sourcePort {%s};" % (payload.sport, ))
        # Set dst port
        tcl_commands.append("tcp config -destPort {%s};" % (payload.dport, ))
        # Set sequence number
        seq_num = hex(payload.seq)
        tcl_commands.append("tcp config -sequenceNumber {%s};" % (seq_num,))
        # Set ack number
        ack_num = hex(payload.ack)
        tcl_commands.append("tcp config -acknowledgementNumber {%s};" % (ack_num, ))
        # Set up window
        wind = hex(payload.win)
        tcl_commands.append("tcp config -window {%s};" % (wind, ))
        # Set up urgent pointer
        urg_pointer = hex(payload.urp)
        tcl_commands.append("tcp config -urgentPointer {%s};" % (urg_pointer, ))

        # Set Flags
        tos = bin(int(payload.flags))[2:].zfill(8)
        if tos[2] == '1':
            tcl_commands.append("tcp config -urgentPointerValid true;")
        elif tos[3] == '1':
            tcl_commands.append("tcp config -acknowledgeValid true;")
        elif tos[4] == '1':
            tcl_commands.append("tcp config -pushFunctionValid true;")
        elif tos[5] == '1':
            tcl_commands.append("tcp config -resetConnection true;")
        elif tos[6] == '1':
            tcl_commands.append("tcp config -synchronize true;")
        elif tos[7] == '1':
            tcl_commands.append("tcp config -finished true;")

        tcl_commands.append("tcp set %(chassis)s %(card)s %(port)s ;" % {'chassis': chassis, 'card': card, 'port': port})

        payl = payload.upper_layer
        return payl, tcl_commands

    def _configure_udp(self, payload, chassis, card, port):
        """Configure UDP layer.

        Args:
            payload(pypacker.Packet):  Packet to analyze
            chassis(int):  TG chassis id
            card(int):  TG card id
            port(int):  TG port id

        Returns:
            tuple: UDP payload, Tcl commands.

        """

        tcl_commands = []
        tcl_commands.append("udp setDefault;")

        # Set src port
        tcl_commands.append("udp config -sourcePort {%s};" % (payload.sport, ))
        # Set dst port
        tcl_commands.append("udp config -destPort {%s};" % (payload.dport, ))

        tcl_commands.append("udp set %(chassis)s %(card)s %(port)s ;" % {'chassis': chassis, 'card': card, 'port': port})

        payl = payload.upper_layer
        return payl, tcl_commands

    def _configure_igmp(self, payload, chassis, card, port):
        """Configure IGMP layer.

        Args:
            payload(pypacker.Packet):  Packet to analyze
            chassis(int):  TG chassis id
            card(int):  TG card id
            port(int):  TG port id

        Returns:
            tuple: IGMP payload, Tcl commands.

        """

        tcl_commands = []
        tcl_commands.append("igmp setDefault;")

        # Set type
        igmp_type = payload.type
        if igmp_type == 17:
            tcl_commands.append("igmp config -type membershipQuery;")
        elif igmp_type == 18:
            tcl_commands.append("igmp config -version igmpVersion1;")
            tcl_commands.append("igmp config -type membershipReport1;")
        elif igmp_type == 22:
            tcl_commands.append("igmp config -version igmpVersion2;")
            tcl_commands.append("igmp config -type membershipReport2;")
        elif igmp_type == 34:
            tcl_commands.append("igmp config -version igmpVersion3;")
            tcl_commands.append("igmp config -type membershipReport3;")
        elif igmp_type == 23:
            tcl_commands.append("igmp config -type leaveGroup;")
        # Set response time
        tcl_commands.append("igmp config -maxResponseTime {%s};" % (payload.mrtime,))
        # Set gaddr
        tcl_commands.append("igmp config -groupIpAddress {%s};" % (payload.gaddr, ))

        tcl_commands.append("igmp set %(chassis)s %(card)s %(port)s ;" % {'chassis': chassis, 'card': card, 'port': port})

        payl = payload.upper_layer
        return payl, tcl_commands

    def _configure_icmp(self, payload, chassis, card, port):
        """Configure ICMP layer.

        Args:
            payload(pypacker.Packet):  Packet to analyze
            chassis(int):  TG chassis id
            card(int):  TG card id
            port(int):  TG port id

        Returns:
            tuple: ICMP payload, Tcl commands.

        """
        tcl_commands = []
        tcl_commands.append("icmp setDefault;")

        # Set type
        icmp_type = payload.type
        if icmp_type == 0:
            tcl_commands.append("icmp config -type echoReply;")
        elif icmp_type == 3:
            tcl_commands.append("icmp config -type destUnreachable;")
        elif icmp_type == 4:
            tcl_commands.append("icmp config -type sourceQuench;")
        elif icmp_type == 5:
            tcl_commands.append("icmp config -type redirect;")
        elif icmp_type == 8:
            tcl_commands.append("icmp config -type echoRequest;")
        elif icmp_type == 11:
            tcl_commands.append("icmp config -type timeExceeded;")
        elif icmp_type == 12:
            tcl_commands.append("icmp config -type parameterProblem;")
        elif icmp_type == 13:
            tcl_commands.append("icmp config -type timeStampRequest;")
        elif icmp_type == 14:
            tcl_commands.append("icmp config -type timeStampReply;")
        elif icmp_type == 15:
            tcl_commands.append("icmp config -type infoRequest;")
        elif icmp_type == 16:
            tcl_commands.append("icmp config -type infoReply;")
        elif icmp_type == 17:
            tcl_commands.append("icmp config -type maskRequest;")
        elif icmp_type == 18:
            tcl_commands.append("icmp config -type maskReply;")

        # Set code
        tcl_commands.append("icmp config -code {0};".format(payload.code))

        # Set id
        tcl_commands.append("icmp config -id {0};".format(payload.upper_layer.id))

        # Set sequence
        tcl_commands.append("icmp config -sequence {0};".format(payload.upper_layer.seq))

        tcl_commands.append("icmp set %(chassis)s %(card)s %(port)s ;" % {'chassis': chassis, 'card': card, 'port': port})

        payl = payload.upper_layer
        return payl, tcl_commands

    def _set_increments(self, packet, sa_increment, da_increment, sip_increment, dip_increment, arp_sa_increment,
                        arp_sip_increment, igmp_ip_increment, lldp_sa_increment, sudp_increment, dudp_increment, stcp_increment, dtcp_increment,
                        vlan_increment, continuous, required_size, eth_type_increment, dscp_increment, protocol_increment, sipv6_increment,
                        dipv6_increment, fl_increment, dhcp_si_increment, in_vlan_increment, tc_increment, nh_increment, isis_lspid_increment, chassis, card, port, force_errors):
        """Set stream increments.

        Args:
            packet(pypacker.Packet):  Packet to analyze
            sa_increment(tuple):  Source MAC increment parameters. Tuple (<step>, <count>). Use count=0 for continuous increment.
            da_increment(tuple):  Destination MAC increment parameters. Tuple (<step>, <count>). Use count=0 for continuous increment.
            sip_increment(tuple):  Source IPv4 increment parameters. Tuple (<step>, <count>). Use count=0 for continuous increment.
            dip_increment(tuple):  Destination IPv4 increment parameters. Tuple (<step>, <count>). Use count=0 for continuous increment.
            arp_sa_increment(tuple):  Source MAC increment parameters for ARP packet. Tuple (<step>, <count>). Has to be used in pair with arp_sip_increment.
            arp_sip_increment(tuple):  Source IP increment parameters for ARP packet. Tuple (<step>, <count>). Has to be used in pair with arp_sa_increment.
            igmp_ip_increment(tuple):  Destination IP increment parameters for IGMP packet. Tuple (<step>, <count>).
            lldp_sa_increment(tuple):  Source MAC increment parameters for LLDP packet. Tuple (<step>, <count>).
            sudp_increment(tuple):  UDP source port increment parameters.
            dudp_increment(tuple):  UDP destination port increment parameters.
            stcp_increment(tuple):  source TCP address increment
            dtcp_increment(tuple):  destination TCP address increment
            vlan_increment(tuple):  VLAN increment parameters for tagged packet. Tuple (<step>, <count>).
            continuous(bool):  Should stream be sent continuously or not. Continuous streams have to be started using start_streams method.
            required_size (int or tuple):  Integer or tuple of parameters needed to be set when packet size should be incremented .
                                           Tuple examples: ('Increment', <step>, <min>, <max>), ('Random', <min>, <max>)
            dscp_increment(tuple):  DSCP increment parameters.
            protocol_increment(tuple):  IP protocol incrementation..
            sipv6_increment(tuple):  Source IPv6 increment parameters.
            dipv6_increment(tuple):  Destination IPv6 increment parameters.
            fl_increment(tuple):  Flow label increment parameters.
            dhcp_si_increment(tuple):  DHCP IP increment parameters.
            in_vlan_increment(tuple):  Inner vlan ID increment parameters for double tagged frames. Tuple (<step>, <count>).
            tc_increment(tuple):  IPv6 traffic class increment parameters.
            nh_increment(tuple):  Next header increment parameters.
            eth_type_increment(tuple):  Ethernet frame type increment parameters.
            isis_lspid_increment(tuple):  Dot3|LLC|ISIS_LSP LSP ID field increment parameters.
            chassis(int):  TG chassis id
            card(int):  TG card id
            port(int):  TG port id
            force_errors(str):  Emulate Errors for configured stream. Enum ("bad" /*streamErrorBadCRC, "none" /*streamErrorNoCRC,
                                "dribble" /*streamErrorDribble, "align" /*streamErrorAlignment)

        Returns:
            list: Tcl commands.

        Notes:
            For increments description see set_stream method().

        """
        tcl_commands = []
        # Set source address increment
        if sa_increment is not None:
            sa_increment_step, sa_increment_count = self._check_increment(sa_increment, "sa_increment")
            if continuous and sa_increment_count == 0:
                if sa_increment_step >= 0:
                    tcl_commands.append("stream config -saRepeatCounter contIncrement;")
                else:
                    tcl_commands.append("stream config -saRepeatCounter contDecrement;")
            else:
                if sa_increment_step >= 0:
                    tcl_commands.append("stream config -saRepeatCounter increment; stream config -numSA %s;" % (sa_increment_count, ))
                else:
                    tcl_commands.append("stream config -saRepeatCounter decrement; stream config -numSA %s;" % (sa_increment_count, ))
            tcl_commands.append("stream config -saStep %s;" % (abs(sa_increment_step), ))

        # Set destination address increment
        if da_increment is not None:
            da_increment_step, da_increment_count = self._check_increment(da_increment, "da_increment")
            if continuous and da_increment_count == 0:
                if da_increment_step >= 0:
                    tcl_commands.append("stream config -daRepeatCounter contIncrement;")
                else:
                    tcl_commands.append("stream config -daRepeatCounter contDecrement;")
            else:
                if da_increment_step >= 0:
                    tcl_commands.append("stream config -daRepeatCounter increment; stream config -numDA %s;" % (da_increment_count, ))
                else:
                    tcl_commands.append("stream config -daRepeatCounter decrement; stream config -numDA %s;" % (da_increment_count, ))
            tcl_commands.append("stream config -daStep %s;" % (abs(da_increment_step), ))

        tcl_commands.append("protocol setDefault;")

        self.udf_dict = {}
        pattern = None
        if (sip_increment is not None or dip_increment is not None or arp_sa_increment is not None or arp_sip_increment is not None or
                igmp_ip_increment is not None or sudp_increment is not None or dudp_increment is not None or stcp_increment is not None or
                dtcp_increment is not None or vlan_increment is not None or dscp_increment is not None or protocol_increment is not None or
                in_vlan_increment is not None):

            tcl_commands.append("protocol config -ethernetType ethernetII;")
            payl = copy.deepcopy(packet)
            while payl:
                class_name = payl.__class__.__name__
                if class_name == "Ethernet":
                    if payl.vlan:
                        vlan_type = struct.unpack('!HH', payl.vlan)
                        payl, commands = self._configure_vlan(payl, vlan_type, chassis, card, port, vlan_increment, in_vlan_increment, continuous)
                        tcl_commands.extend(commands)
                    payl = payl.upper_layer

                elif class_name == "IP":
                    payl, commands = self._configure_ip(payl, chassis, card, port)
                    tcl_commands.extend(commands)

                    # Set source ip address increment
                    if sip_increment is not None:
                        sip_increment_step, sip_increment_count = self._check_increment(sip_increment, "sip_increment")
                        udf_id = len(self.udf_dict) + 1
                        src_ip = packet[pypacker.layer3.ip.IP].src_s.split('.')
                        sip_initval = str(hex(int(src_ip[0])))[2:].zfill(2) + str(hex(int(src_ip[1])))[2:].zfill(2) + \
                            str(hex(int(src_ip[2])))[2:].zfill(2) + str(hex(int(src_ip[3])))[2:].zfill(2)
                        if packet.vlan:
                            offset = 30
                        else:
                            offset = 26
                        self.udf_dict["sip"] = {"udf_id": udf_id, "initval": sip_initval, "offset": offset, "counter_type": 'c32', "step": sip_increment_step,
                                                "count": sip_increment_count, "continuous": continuous}
                        tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["sip"]))
                    # TODO
                    # Set dscp increment
                    if dscp_increment is not None:
                        dscp_increment_step, dscp_increment_count = self._check_increment(dscp_increment, "dscp_increment")
                        udf_id = len(self.udf_dict) + 1
                        dscp = packet[pypacker.layer3.ip.IP].tos
                        dscp_initval = hex(int(dscp))[2:]
                        if packet.vlan:
                            offset = 19
                        else:
                            offset = 15
                        self.udf_dict["dscp"] = {"udf_id": udf_id, "initval": dscp_initval, "offset": offset, "counter_type": 'c8',
                                                 "step": dscp_increment_step * 4, "count": dscp_increment_count, "continuous": continuous}
                        tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["dscp"]))
                    # TODO
                    # Set protocol increment
                    if protocol_increment is not None:
                        protocol_increment_step, protocol_increment_count = self._check_increment(protocol_increment, "protocol_increment")
                        udf_id = len(self.udf_dict) + 1
                        protocol = packet[pypacker.layer3.ip.IP].p
                        protocol_initval = hex(int(protocol))[2:]
                        if packet.vlan:
                            offset = 27
                        else:
                            offset = 23
                        self.udf_dict["protocol"] = {"udf_id": udf_id, "initval": protocol_initval, "offset": offset, "counter_type": 'c8',
                                                     "step": protocol_increment_step, "count": protocol_increment_count, "continuous": continuous}
                        tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["protocol"]))

                    # Set destination ip address increment
                    if dip_increment is not None:
                        dip_increment_step, dip_increment_count = self._check_increment(dip_increment, "dip_increment")
                        udf_id = len(self.udf_dict) + 1
                        dst_ip = packet[pypacker.layer3.ip.IP].dst_s.split('.')
                        dip_initval = str(hex(int(dst_ip[0])))[2:].zfill(2) + str(hex(int(dst_ip[1])))[2:].zfill(2) + \
                            str(hex(int(dst_ip[2])))[2:].zfill(2) + str(hex(int(dst_ip[3])))[2:].zfill(2)
                        if packet.vlan:
                            offset = 34
                        else:
                            offset = 30
                        self.udf_dict["dip"] = {"udf_id": udf_id, "initval": dip_initval, "offset": offset, "counter_type": 'c32', "step": dip_increment_step,
                                                "count": dip_increment_count, "continuous": continuous}
                        tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["dip"]))

                elif class_name == "ARP":
                    payl, commands = self._configure_arp(payl, chassis, card, port)
                    tcl_commands.extend(commands)

                    # Set arp source mac address increment
                    if arp_sa_increment is not None:
                        sa_increment_step, sa_increment_count = self._check_increment(arp_sa_increment, "arp_sa_increment")
                        udf_id = len(self.udf_dict) + 1
                        arp_hwsrc = packet[pypacker.layer12.arp.ARP].sha_s
                        src_mac = arp_hwsrc.split(':')
                        sa_initval = str(hex(int(src_mac[2], 16)))[2:].zfill(2) + str(hex(int(src_mac[3], 16)))[2:].zfill(2) + \
                            str(hex(int(src_mac[4], 16)))[2:].zfill(2) + str(hex(int(src_mac[5], 16)))[2:].zfill(2)
                        # Define Ether.src increment via IXIA UDF
                        self.udf_dict["src"] = {"udf_id": udf_id, "initval": sa_initval, "offset": 8, "counter_type": 'c32', "step": sa_increment_step,
                                                "count": sa_increment_count, "continuous": continuous}
                        tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["src"]))

                        # Define ARP.hwsrc increment via IXIA UDF
                        udf_id += 1
                        if packet.vlan:
                            offset = 28
                        else:
                            offset = 24
                        self.udf_dict["arp_src"] = {"udf_id": udf_id, "initval": sa_initval, "offset": offset, "counter_type": 'c32', "step": sa_increment_step,
                                                    "count": sa_increment_count, "continuous": continuous}
                        tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["arp_src"]))

                    # Set arp source ip address increment
                    if arp_sip_increment is not None:
                        sip_increment_step, sip_increment_count = self._check_increment(arp_sip_increment, "arp_sip_increment")
                        udf_id = len(self.udf_dict) + 1
                        src_ip = packet[pypacker.layer12.arp.ARP].spa_s.split('.')
                        sip_initval = str(hex(int(src_ip[0])))[2:].zfill(2) + str(hex(int(src_ip[1])))[2:].zfill(2) + \
                            str(hex(int(src_ip[2])))[2:].zfill(2) + str(hex(int(src_ip[3])))[2:].zfill(2)
                        if packet.vlan:
                            offset = 32
                        else:
                            offset = 28
                        self.udf_dict["arp_ip"] = {"udf_id": udf_id, "initval": sip_initval, "offset": offset, "counter_type": 'c32',
                                                   "step": sip_increment_step, "count": sip_increment_count, "continuous": continuous}
                        tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["arp_ip"]))

                elif class_name == "TCP":
                    payl, commands = self._configure_tcp(payl, chassis, card, port)
                    tcl_commands.extend(commands)

                    # Set tcp source port increment
                    if stcp_increment is not None:
                        stcp_increment_step, stcp_increment_count = self._check_increment(stcp_increment, "stcp_increment")
                        udf_id = len(self.udf_dict) + 1
                        stcp = packet[pypacker.layer4.tcp.TCP].sport
                        stcp_initval = str(hex(stcp))[2:].zfill(4)
                        if packet.vlan:
                            offset = 38
                        else:
                            offset = 34
                        self.udf_dict["stcp"] = {"udf_id": udf_id, "initval": stcp_initval, "offset": offset, "counter_type": 'c16',
                                                 "step": stcp_increment_step, "count": stcp_increment_count, "continuous": continuous}
                        tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["stcp"]))

                    # Set tcp destination port increment
                    if dtcp_increment is not None:
                        dtcp_increment_step, dtcp_increment_count = self._check_increment(dtcp_increment, "dtcp_increment")
                        udf_id = len(self.udf_dict) + 1
                        dtcp = packet[pypacker.layer4.tcp.TCP].dport
                        dtcp_initval = str(hex(dtcp))[2:].zfill(4)
                        if packet.vlan:
                            offset = 40
                        else:
                            offset = 36
                        self.udf_dict["dtcp"] = {"udf_id": udf_id, "initval": dtcp_initval, "offset": offset, "counter_type": 'c16',
                                                 "step": dtcp_increment_step, "count": dtcp_increment_count, "continuous": continuous}
                        tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["dtcp"]))

                elif class_name == "UDP":
                    payl, commands = self._configure_udp(payl, chassis, card, port)
                    tcl_commands.extend(commands)

                    # Set udp source port increment
                    if sudp_increment is not None:
                        sudp_increment_step, sudp_increment_count = self._check_increment(sudp_increment, "sudp_increment")
                        udf_id = len(self.udf_dict) + 1
                        sudp = packet[pypacker.layer4.udp.UDP].sport
                        sudp_initval = str(hex(sudp))[2:].zfill(4)
                        if packet.vlan:
                            offset = 38
                        else:
                            offset = 34
                        self.udf_dict["sudp"] = {"udf_id": udf_id, "initval": sudp_initval, "offset": offset, "counter_type": 'c16',
                                                 "step": sudp_increment_step, "count": sudp_increment_count, "continuous": continuous}
                        tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["sudp"]))

                    # Set udp destination port increment
                    if dudp_increment is not None:
                        dudp_increment_step, dudp_increment_count = self._check_increment(dudp_increment, "dudp_increment")
                        udf_id = len(self.udf_dict) + 1
                        dudp = packet[pypacker.layer4.udp.UDP].dport
                        dudp_initval = str(hex(dudp))[2:].zfill(4)
                        if packet.vlan:
                            offset = 40
                        else:
                            offset = 36
                        self.udf_dict["dudp"] = {"udf_id": udf_id, "initval": dudp_initval, "offset": offset, "counter_type": 'c16',
                                                 "step": dudp_increment_step, "count": dudp_increment_count, "continuous": continuous}
                        tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["dudp"]))

                elif class_name == "IGMP":
                    payl, commands = self._configure_igmp(payl, chassis, card, port)
                    tcl_commands.extend(commands)
                    # Set IGMP increment
                    if igmp_ip_increment is not None:
                        igmp_ip_increment_step, igmp_ip_increment_count = self._check_increment(igmp_ip_increment, "igmp_ip_increment")
                        udf_id = len(self.udf_dict) + 1
                        dst_ip = packet[pypacker.layer3.igmp.IGMP].gaddr.split('.')
                        dip_initval = str(hex(int(dst_ip[0])))[2:].zfill(2) + str(hex(int(dst_ip[1])))[2:].zfill(2) + \
                            str(hex(int(dst_ip[2])))[2:].zfill(2) + str(hex(int(dst_ip[3])))[2:].zfill(2)
                        if packet.vlan:
                            offset = 46
                        else:
                            offset = 42
                        self.udf_dict["igmp_ip"] = {"udf_id": udf_id, "initval": dip_initval, "offset": offset, "counter_type": 'c32',
                                                    "step": igmp_ip_increment_step, "count": igmp_ip_increment_count, "continuous": continuous}
                        tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["igmp_ip"]))

                elif class_name == "ICMP":
                    payl, commands = self._configure_icmp(payl, chassis, card, port)
                    tcl_commands.extend(commands)
                # TODO: check this scenario
                else:
                    break

        else:
            hex_data = codecs.encode(packet.bin(), "hex_codec").decode()
            pattern = hex_data[24:]

            self.class_logger.debug("Packet data: %s" % (pattern, ))

        packet_size = len(packet) + 4
        if isinstance(required_size, int):
            if packet_size < 64:
                self.class_logger.warning("In case of AFS cross connect usage undersized packets less 64 bytes will be droped!!!")
                if packet_size >= 48:
                    tcl_commands.append("stream config -frameSizeMIN %s; stream config -frameSizeMAX %s;" % (packet_size, packet_size))
                else:
                    tcl_commands.append("stream config -frameSizeMIN 48; stream config -frameSizeMAX 48;")
                tcl_commands.append("stream config -frameSizeType sizeRandom;")
            else:
                tcl_commands.append("stream config -framesize %s;" % (packet_size, ))

        size_increment_type = ''
        if isinstance(required_size, tuple):
            if required_size[0] == 'Increment':
                size_increment_type = 'increment'
                try:
                    size_increment_step = required_size[1]
                    size_increment_min_val = required_size[2]
                    size_increment_max_val = required_size[3]
                except:
                    raise TypeError("'Increment' required_size must contain 3 integer values.")
                if size_increment_max_val < size_increment_min_val:
                    raise TypeError("'Increment' max_value is less than min_value.")
            elif required_size[0] == 'Random':
                size_increment_type = 'random'
                try:
                    size_increment_min_val = required_size[1]
                    size_increment_max_val = required_size[2]
                except:
                    raise TypeError("'Increment' required_size must contain 3 integer values.")
                if size_increment_max_val < size_increment_min_val:
                    raise TypeError("'Increment' max_value is less than min_value.")
            else:
                raise TypeError("required_size contains wrong values.")
        if size_increment_type == 'random':
            tcl_commands.append("stream config -frameSizeMIN %s; stream config -frameSizeMAX %s;" % (size_increment_min_val, size_increment_max_val))
            tcl_commands.append("stream config -frameSizeType sizeRandom;")
        elif size_increment_type == 'increment':
            tcl_commands.append("stream config -frameSizeMIN %s; stream config -frameSizeMAX %s;" % (size_increment_min_val, size_increment_max_val))
            tcl_commands.append("stream config -frameSizeStep %s;" % (size_increment_step,))
            tcl_commands.append("stream config -frameSizeType sizeIncr;")
            tcl_commands.append("stream config -enableIncrFrameBurstOverride true;")

        # Set source ipv6 address increment
        if sipv6_increment is not None:
            sipv6_increment_step, sipv6_increment_count = self._check_increment(sipv6_increment, "sipv6_increment")
            el_id = 0
            udf_id = len(self.udf_dict) + 1
            src_ipv6 = packet[pypacker.layer3.ip6.IP6].src_s.split(':')
            for i, v in enumerate(src_ipv6):
                if len(src_ipv6[i]) == 0:
                    el_id = src_ipv6.index(src_ipv6[i])
                    src_ipv6.remove(src_ipv6[i])
                    break
            while True:
                if len(src_ipv6) < 8:
                    src_ipv6.insert(el_id, '0000')
                else:
                    break
            sipv6_initval = str(src_ipv6[6]).zfill(4) + str(src_ipv6[7]).zfill(4)
            if packet.vlan:
                offset = 38
            else:
                offset = 34
            self.udf_dict["sipv6"] = {"udf_id": udf_id, "initval": sipv6_initval, "offset": offset, "counter_type": 'c32', "step": sipv6_increment_step,
                                      "count": sipv6_increment_count, "continuous": continuous}
            tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["sipv6"]))

        # Set destination ipv6 address increment
        if dipv6_increment is not None:
            dipv6_increment_step, dipv6_increment_count = self._check_increment(dipv6_increment, "dipv6_increment")
            el_id = 0
            udf_id = len(self.udf_dict) + 1
            dst_ipv6 = packet[pypacker.layer3.ip6.IP6].dst_s.split(':')
            for i, v in enumerate(dst_ipv6):
                if len(dst_ipv6[i]) == 0:
                    el_id = dst_ipv6.index(dst_ipv6[i])
                    dst_ipv6.remove(dst_ipv6[i])
                    break
            while True:
                if len(dst_ipv6) < 8:
                    dst_ipv6.insert(el_id, '0000')
                else:
                    break
            dipv6_initval = str(dst_ipv6[6]).zfill(4) + str(dst_ipv6[7]).zfill(4)
            if packet.vlan:
                offset = 54
            else:
                offset = 50
            self.udf_dict["dipv6"] = {"udf_id": udf_id, "initval": dipv6_initval, "offset": offset, "counter_type": 'c32', "step": dipv6_increment_step,
                                      "count": dipv6_increment_count, "continuous": continuous}
            tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["dipv6"]))

        # Set Flow Label increment
        if fl_increment is not None:
            fl_increment_step, fl_increment_count = self._check_increment(fl_increment, "fl_increment")
            if fl_increment_count > 1048575:
                self.class_logger.warning("IP.fl increment count decreased to 255 for proper IP checksum")
                fl_increment_count = 1048576
            udf_id = len(self.udf_dict) + 1
            fl = packet[pypacker.layer3.ip6.IP6].fl
            fl_initval = hex(int(fl))[2:]
            if packet.vlan:
                offset = 19
            else:
                offset = 15
            self.udf_dict["fl"] = {"udf_id": udf_id, "initval": fl_initval, "offset": offset, "counter_type": 'c24', "step": fl_increment_step,
                                   "count": fl_increment_count, "continuous": continuous}
            tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["fl"]))

        # Set lldp ip address increment
        if lldp_sa_increment is not None:
            lldp_increment_step, lldp_increment_count = self._check_increment(lldp_sa_increment, "lldp_sa_increment")
            udf_id = len(self.udf_dict) + 1
            lldp_tlv = hex_data[28:34]
            lldp_mac_initval = hex_data[38:46]
            if lldp_tlv == '020704':
                self.udf_dict["lldp_sa"] = {"udf_id": udf_id, "initval": lldp_mac_initval, "offset": 19, "counter_type": 'c32', "step": lldp_increment_step,
                                            "count": lldp_increment_count, "continuous": continuous}
                tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["lldp_sa"]))
            else:
                raise TypeError("lldp tlv is not '\\x02\\x07\\x04'.")

        # Set ether type increment
        if eth_type_increment is not None:
            eth_type_increment_step, eth_type_increment_count = self._check_increment(eth_type_increment, "eth_type_increment")
            udf_id = len(self.udf_dict) + 1
            eth_type = packet[pypacker.layer12.ethernet.Ethernet].type
            eth_type_initval = str(hex(eth_type))[2:].zfill(4)
            self.udf_dict["eth_type"] = {"udf_id": udf_id, "initval": eth_type_initval, "offset": 12, "counter_type": 'c16', "step": eth_type_increment_step,
                                         "count": eth_type_increment_count, "continuous": continuous}
            tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["eth_type"]))

        # Set dhcp siaddr increment
        if dhcp_si_increment is not None:
            dhcp_si_increment_step, dhcp_si_increment_count = self._check_increment(dhcp_si_increment, "dhcp_si_increment")
            udf_id = len(self.udf_dict) + 1
            dhcp_si = packet.getlayer(pypacker.BOOTP).siaddr.split('.')  # pylint: disable=no-member
            dhcp_si_initval = str(hex(int(dhcp_si[0])))[2:].zfill(2) + str(hex(int(dhcp_si[1])))[2:].zfill(2) + \
                str(hex(int(dhcp_si[2])))[2:].zfill(2) + str(hex(int(dhcp_si[3])))[2:].zfill(2)
            if packet.vlan:
                offset = 66
            else:
                offset = 62
            self.udf_dict["dhcp_si"] = {"udf_id": udf_id, "initval": dhcp_si_initval, "offset": offset, "counter_type": 'c32', "step": dhcp_si_increment_step,
                                        "count": dhcp_si_increment_count, "continuous": continuous}
            tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["dhcp_si"]))

        # Set IPv6 TC increment
        if tc_increment is not None:
            tc_increment_step, tc_increment_count = self._check_increment(tc_increment, "tc_increment")
            udf_id = len(self.udf_dict) + 1
            tc = packet[pypacker.layer3.ip6.IP6].tc
            tc_initval = tc
            bit_offset = 4
            if packet.vlan:
                offset = 18
            else:
                offset = 14
            self.udf_dict["ipv6_tc"] = {"udf_id": udf_id, "initval": tc_initval, "offset": offset, "counter_type": 'c8', "bit_offset": bit_offset,
                                        "step": tc_increment_step, "count": tc_increment_count, "continuous": continuous}
            tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["ipv6_tc"]))

        # Set IPv6 NH increment
        if nh_increment is not None:
            nh_increment_step, nh_increment_count = self._check_increment(nh_increment, "nh_increment")
            udf_id = len(self.udf_dict) + 1
            nh = packet[pypacker.layer3.ip6.IP6].nh
            nh_initval = nh
            if packet.vlan:
                offset = 24
            else:
                offset = 20
            self.udf_dict["ipv6_nh"] = {"udf_id": udf_id, "initval": nh_initval, "offset": offset, "counter_type": 'c8',
                                        "step": nh_increment_step, "count": nh_increment_count, "continuous": continuous}
            tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["ipv6_nh"]))

        # Set LSP ID increment
        if isis_lspid_increment is not None:
            lspid_increment_step, lspid_increment_count = self._check_increment(isis_lspid_increment, "isis_lspid_increment")
            udf_id = len(self.udf_dict) + 1
            lid_h = packet[pypacker.layer3.ip6.IP6].lspid
            try:
                lid_init = str(int(lid_h.split('.')[2]) + 1).zfill(4)
            except IndexError:
                lid_init = "0001"
            if packet.vlan:
                offset = 37
            else:
                offset = 33
            self.udf_dict["lspid"] = {"udf_id": udf_id, "initval": lid_init, "offset": offset, "counter_type": 'c16',
                                                        "step": lspid_increment_step, "count": lspid_increment_count, "continuous": continuous}
            tcl_commands.extend(self._set_ixia_udf_field(**self.udf_dict["lspid"]))

        # self.stream_ids[stream_id]['size'] = packet_size
        tcl_commands.append("stream config -dataPattern userpattern;")
        tcl_commands.append("stream config -patternType nonRepeat;")
        if pattern is not None:
            tcl_commands.append("stream config -pattern {%s};" % (pattern,))

        return tcl_commands

    def _set_ixia_stream(self, packet, count, inter, rate, sa_increment, da_increment, sip_increment, dip_increment, arp_sa_increment,
                         arp_sip_increment, igmp_ip_increment, lldp_sa_increment, sudp_increment, dudp_increment, stcp_increment,
                         dtcp_increment, vlan_increment, continuous, required_size, iface, chassis, card, port, stream_id, eth_type_increment,
                         dscp_increment, protocol_increment, sipv6_increment, dipv6_increment, fl_increment, dhcp_si_increment,
                         in_vlan_increment, tc_increment, nh_increment, isis_lspid_increment, cont_burst, force_errors, udf_dependancies):
        """Set traffic stream with specified parameters on specified TG port.

        Args:
            packet(pypacker.Packet):  Packet to analyze
            count(int):  How many packets to send in a stream.
            inter(int):  Interval between sending each packet.
            rate(int):  Interface rate in percents.
            continuous(bool):  Should stream be sent continuously or not. Continuous streams have to be started using start_streams method.
            iface(str, tuple):  Interface to use for packet sending (type depends on particular tg ports type).
            required_size(int, tuple):  Integer or tuple of parameters needed to be set when packet size should be incremented.
                                        Tuple examples: ('Increment', <step>, <min>, <max>), ('Random', <min>, <max>)
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
            chassis(int):  TG chassis id
            card(int):  TG card id
            port(int):  TG port id

        Returns:
            int: stream id

        Notes:
            It's not expected to configure a lot of incrementation options. Different traffic generator could have different limitations for these options.

        Example::

            stream_id_1 = tg.set_stream(pack_ip, count=100, iface=iface)
            stream_id_2 = tg.set_stream(pack_ip, continuous=True, inter=0.1, iface=iface)
            stream_id_3 = tg.set_stream(pack_ip_udp, count=5, protocol_increment=(3, 5), iface=iface)
            stream_id_4 = tg.set_stream(pack_ip_udp, count=18, sip_increment=(3, 3), dip_increment=(3, 3), iface=iface,
                                        udf_dependancies={'sip_increment': 'dip_increment'})

        """
        # Defining ix_stream_id
        iface_stream_ids = []
        if self.stream_ids:
            for stream_conf in list(self.stream_ids.values()):
                if stream_conf['iface'] == iface:
                    # iface_stream_ids.append(stream_conf['ix_stream_id'])
                    # Add all elements of stream_conf['ix_stream_id'] to iface_stream_ids
                    list(map(iface_stream_ids.append, stream_conf['ix_stream_id']))
            if iface_stream_ids:
                ix_stream_id = max(iface_stream_ids) + 1
            else:
                ix_stream_id = 1
        else:
            ix_stream_id = 1
        self.class_logger.debug("Stream IX_ID is: %s" % (ix_stream_id, ))

        # Set stream default parameters
        tcl_commands = []
        tcl_commands.append("stream setDefault;")
        tcl_commands.append("stream config -name \"TST%s\";" % stream_id)
        if continuous:
            tcl_commands.append("stream config -dma contPacket;")
        elif cont_burst:
            tcl_commands.append("stream config -dma contBurst;")
        else:
            tcl_commands.append("stream config -dma stopStream;")

        if force_errors == "bad":
            tcl_commands.append("stream config -fcs streamErrorBadCRC;")
        elif force_errors == "none":
            tcl_commands.append("stream config -fcs streamErrorNoCRC;")
        elif force_errors == "dribble":
            tcl_commands.append("stream config -fcs streamErrorDribble;")
        elif force_errors == "align":
            tcl_commands.append("stream config -fcs streamErrorAlignment;")
        else:
            tcl_commands.append("stream config -fcs streamErrorGood;")

        # Set frame per second rate
        if inter != 0:
            tcl_commands.append("stream config -rateMode streamRateModeFps; stream config -fpsRate %s;" % (1.0 / inter))
        else:
            # By default rate = 99% to avoid the issue with dropping frames on AFS. But here we can override default values
            tcl_commands.append("stream config -percentPacketRate %s;" % (rate, ))

        # Set source and destination MAC
        # TODO: Pypacker does not support Dot3(IEEE 802.3). Need to develop
        # try:
        #     tcl_commands.append("stream config -sa {%s}; stream config -da {%s};" % (packet.getlayer(pypacker.Dot3).src, packet.getlayer(pypacker.Dot3).dst))
        # except AttributeError:
        tcl_commands.append("stream config -sa {%s}; stream config -da {%s};" % (packet.src_s, packet.dst_s))

        tcl_commands.extend(
            self._set_increments(packet, sa_increment, da_increment, sip_increment, dip_increment,
                                 arp_sa_increment,
                                 arp_sip_increment, igmp_ip_increment, lldp_sa_increment,
                                 sudp_increment, dudp_increment, stcp_increment, dtcp_increment,
                                 vlan_increment, continuous, required_size, eth_type_increment,
                                 dscp_increment, protocol_increment, sipv6_increment,
                                 dipv6_increment, fl_increment, dhcp_si_increment,
                                 in_vlan_increment, tc_increment, nh_increment, isis_lspid_increment, chassis, card, port, force_errors))

        if not continuous:
            tcl_commands.append("stream config -numFrames %s;" % count)

        # Applying settings
        # self.class_logger.debug("tcl_commands:\n%s" % "\n".join(tcl_commands))
        self.tcl(" ".join(tcl_commands))

        # Setting stream (stream is disabled by default)
        assert self.tcl("stream config -enable false; \
                         stream set %(chassis)s %(card)s %(port)s %(stream_id)s; \
                         stream write %(chassis)s %(card)s %(port)s %(stream_id)s" %
                        {'chassis': chassis, 'card': card, 'port': port, 'stream_id': ix_stream_id}) == "0"

        # Set UDF dependencies
        tcl_commands = []
        self.tcl("stream get %(chassis)s %(card)s %(port)s %(stream_id)s;" %
                 {'chassis': chassis, 'card': card, 'port': port, 'stream_id': ix_stream_id})
        if udf_dependancies is not None:
            for _key, _value in udf_dependancies.items():
                tcl_commands.extend(self._set_udf_dependence(_key, _value))

        self.tcl(" ".join(tcl_commands))

        self.tcl("stream set %(chassis)s %(card)s %(port)s %(stream_id)s;" %
                 {'chassis': chassis, 'card': card, 'port': port, 'stream_id': ix_stream_id})

        return ix_stream_id

    def _set_udf_dependence(self, key, value):
        """Set UDF dependencies.

        Args:
            key(str):  increment name, e.g "vlan_increment", "sipv6_increment"
            value(str): increment name, e.g "vlan_increment", "sipv6_increment"

        Returns:
            list: Tcl commands

        """
        tcl_commands = []
        udf_id = self.udf_dict[key.replace("_increment", "")]["udf_id"]
        dep_udf_id = self.udf_dict[value.replace("_increment", "")]["udf_id"]

        tcl_commands.append("udf get %(udf_id)s;" % {'udf_id': udf_id, })
        tcl_commands.append("udf config -chainFrom udf%(dep_udf_id)s;" % {'dep_udf_id': dep_udf_id, })
        tcl_commands.append("udf set %(udf_id)s;" % {'udf_id': udf_id, })

        return tcl_commands

    def set_stream(self, packet_def=None, count=1, inter=0, rate=99, sa_increment=None, da_increment=None, sip_increment=None, dip_increment=None,
                   is_valid=False, arp_sa_increment=None, arp_sip_increment=None, igmp_ip_increment=None, lldp_sa_increment=None, vlan_increment=None,
                   sudp_increment=None, dudp_increment=None, stcp_increment=None, dtcp_increment=None, continuous=False, iface=None, adjust_size=True,
                   required_size=64, fragsize=None, build_packet=True, eth_type_increment=None, dscp_increment=None, protocol_increment=None,
                   sipv6_increment=None, dipv6_increment=None, fl_increment=None, dhcp_si_increment=None, in_vlan_increment=None,
                   tc_increment=None, nh_increment=None, isis_lspid_increment=None, cont_burst=False, force_errors=None, udf_dependancies=None):
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

        Example::

            stream_id_1 = tg.set_stream(pack_ip, count=100, iface=iface)
            stream_id_2 = tg.set_stream(pack_ip, continuous=True, inter=0.1, iface=iface)
            stream_id_3 = tg.set_stream(pack_ip_udp, count=5, protocol_increment=(3, 5), iface=iface)
            stream_id_4 = tg.set_stream(pack_ip_udp, count=18, sip_increment=(3, 3), dip_increment=(3, 3), iface=iface,
                                        udf_dependancies={'sip_increment': 'dip_increment'})

        """
        stream_id = max(self.stream_ids.keys()) + 1 if self.stream_ids else 1
        self.class_logger.debug("Stream ID is: %s" % (stream_id, ))

        if build_packet:
            if isinstance(required_size, int):
                packet = self._build_pypacker_packet(packet_def, adjust_size=adjust_size, required_size=required_size - 4)
            else:
                packet = self._build_pypacker_packet(packet_def, adjust_size=adjust_size)
        else:
            packet = packet_def
        if iface is not None:
            # pylint can't figure out that this might be a tuple
            chassis, card, port = iface  # pylint: disable=W0633

        rate = rate * self.rate[iface]

        self.stream_ids[stream_id] = \
            {'iface': iface, 'count': count, 'inter': inter, 'rate': rate, 'continuous': continuous, 'sa_increment': sa_increment,
             'da_increment': da_increment, 'sip_increment': sip_increment, 'dip_increment': dip_increment, 'arp_sa_increment': arp_sa_increment,
             'arp_sip_increment': arp_sip_increment, 'igmp_ip_increment': igmp_ip_increment, 'vlan_increment': vlan_increment, 'ix_stream_id': [],
             'sudp_increment': sudp_increment, 'dudp_increment': dudp_increment, 'stcp_increment': stcp_increment, 'dtcp_increment': dtcp_increment,
             'eth_type_increment': eth_type_increment, 'sipv6_increment': sipv6_increment, 'dipv6_increment': dipv6_increment, 'fl_increment': fl_increment,
             'dhcp_si_increment': dhcp_si_increment, 'in_vlan_increment': in_vlan_increment, 'tc_increment': tc_increment, 'nh_increment': nh_increment,
             'isis_lspid_increment': isis_lspid_increment, 'cont_burst': cont_burst, 'force_errors': force_errors,
             'udf_dependancies': udf_dependancies}
        kwargs = locals()
        kwargs.pop("self")
        kwargs.pop("packet_def")
        kwargs.pop("fragsize")
        kwargs.pop("adjust_size")
        kwargs.pop("is_valid")
        kwargs.pop("build_packet")
        if fragsize is not None:
            fragments = pypacker.fragment(packet, fragsize)  # pylint: disable=no-member
            for fragment in fragments:
                kwargs['packet'] = fragment
                self.stream_ids[stream_id]['ix_stream_id'].append(self._set_ixia_stream(**kwargs))
        else:
            kwargs['packet'] = packet
            self.stream_ids[stream_id]['ix_stream_id'].append(self._set_ixia_stream(**kwargs))

        self.class_logger.debug("Stream set done.")
        self.class_logger.debug("stream_id[%s]: %s" % (stream_id, self.stream_ids[stream_id]))
        self.class_logger.debug("stream_ids: %s" % ([_id for _id in self.stream_ids]))

        return stream_id

    def send_stream(self, stream_id=None):
        """Sends the stream created by 'set_stream' method.

        Args:
            stream_id(int):  ID of the stream to be send.

        Returns:
            float: timestamp.

        """
        def _send_ixia_stream(ix_stream_id, chassis, card, port, count):
            self.tcl("stream get %(chassis)s %(card)s %(port)s %(stream_id)s;" %
                     {'chassis': chassis, 'card': card, 'port': port, 'stream_id': ix_stream_id})
            _rate = float(self.tcl("stream cget -fpsRate;"))
            attempts = 10 + 1000 / (50 * _rate)
            self._transmit_stream(chassis, card, port, ix_stream_id)

            # Wait until all packets sent
            assert self.tcl("streamTransmitStats get %(chassis)s %(card)s %(port)s %(stream_id)s %(stream_id)s;\
                      set txCount [streamTransmitStats cget -framesSent];\
                      set endCount [expr {$startCount%(stream_id)s+%(count)s}];\
                      puts \"IXIA: Start sending %(count)s frames...\";\
                      set _tx_count 0;\
                      set attemptsCount 0;\
                      while {$txCount<$endCount} {\
                          after 50; \
                          streamTransmitStats get %(chassis)s %(card)s %(port)s 1 %(stream_id)s;\
                          streamTransmitStats getGroup %(stream_id)s;\
                          set txCount [streamTransmitStats cget -framesSent];\
                          if {$txCount > $_tx_count} {\
                              set _tx_count $txCount;\
                              set attemptsCount 0;\
                              } else {\
                              incr attemptsCount;\
                              }; \
                          if {$attemptsCount > %(attempts)s} {\
                              return 1;\
                              }; \
                          }; \
                      set sentCount [expr {$txCount-$startCount%(stream_id)s}];\
                      puts \"IXIA: Sent $sentCount frames.\";\
                      return 0;" %
                            {'chassis': chassis, 'card': card, 'port': port, 'stream_id': ix_stream_id, 'count': count, 'attempts': attempts}) == "0", \
                "Ixia: Not all packets were sent"

            # Disable stream
            self._disable_stream(chassis, card, port, ix_stream_id)

        # Sending IXIA stream or streams if frame fragmentation was performed
        self.class_logger.debug("Sending stream %s..." % stream_id)
        chassis, card, port = self.stream_ids[stream_id]['iface']
        for ix_stream_id in self.stream_ids[stream_id]['ix_stream_id']:
            _send_ixia_stream(ix_stream_id, chassis, card, port, self.stream_ids[stream_id]['count'])

    def start_streams(self, stream_list):
        """Enable and start streams from the list simultaneously.

        Args:
            stream_list(list[int]):  List of stream IDs.

        Returns:
            None

        """
        self.class_logger.debug("Starting streams %s..." % stream_list)

        # Enable streams and collect tx ports
        ports_list = set()
        for stream_id in stream_list:
            chassis, card, port = self.stream_ids[stream_id]['iface']
            for ix_stream_id in self.stream_ids[stream_id]['ix_stream_id']:
                self._enable_stream(chassis, card, port, ix_stream_id)
            ports_list.add(self.stream_ids[stream_id]['iface'])

        # Convert collected tx port to tcl representation
        tcl_ports_list = str(list(ports_list)).replace("(", "{").replace(")", "}").replace("[", "{").replace("]", "}").replace("'", "").replace(",", "")
        self.tcl("set txPortIdList %s" % tcl_ports_list) == "0"
        # Check Link State before sending stream.
        if self.tcl("ixCheckLinkState txPortIdList") != "0":
            raise IxiaException("Link is Down.")
        # Start transmission
        assert self.tcl("ixStartTransmit txPortIdList") == "0"

    def stop_streams(self, stream_list=None):
        """ Disable streams from the list.

        Args:
            stream_list(list[int]):  Stream IDs to stop. In case stream_list is not set all running streams will be stopped.

        Returns:
            None

        """
        # If stream_list not defined then stop all streams
        if not stream_list:
            stream_list = [key for key in list(self.stream_ids.keys())]

        self.class_logger.debug("Stopping streams %s..." % stream_list)

        for stream_id in stream_list:
            chassis, card, port = self.stream_ids[stream_id]['iface']
            for ix_stream_id in self.stream_ids[stream_id]['ix_stream_id']:
                self._disable_stream(chassis, card, port, ix_stream_id)

    def stop_all_streams(self):
        """Stop streams for all owned ports. ownedPortList variable creates on connect stage.

        Raises:
            AssertionError:  error in executing tcl code

        Returns:
            None

        """
        assert self.tcl("ixStopTransmit ownedPortList") == "0"

    @staticmethod
    def _get_port_info(iface):
        """Simple helper which allows to get interface info split.

        Args:
            iface(str): Which IXIA interface to use for packet sending (in format "{chassis_id card_id port_id}")

        Returns:
            list(str): [chassis_id, card_id, port_id]

        """
        return iface[1:-1].split(" ")

    @staticmethod
    def _get_port_to_string(iface):
        """Simple helper which allows to get string representation for interface.

        Args:
            iface(list):  Which IXIA interface to use for packet sending (in format [chassis_id, card_id, port_id])

        Returns:
            str: "chassis_id/card_id/port_id"

        """
        return "/".join(map(str, iface))

    def _set_filter_params(self, layer):
        """Configures filter parameters for specified layer.

        Args:
            layer(str):  Layer name.

        Returns:
            str: Tcl command.

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

        Example::

            env.tg[1].start_sniff(['eth0', ], filter_layer='IP', src_filter='00:00:00:01:01:01', dst_filter='00:00:00:22:22:22')

        """
        self.class_logger.debug("Starting capturing on ifaces: %s" % (ifaces, ))
        if filter_layer:
            if isinstance(filter_layer, tuple) and len(filter_layer) == 3:
                self.flt_patterns["Custom"] = {'ptrn1': [filter_layer[1], filter_layer[2], str(filter_layer[0])], 'mt1': "matchUser",
                                               'cfp': "pattern1"}
                filter_layer = "Custom"
            if filter_layer not in self.flt_patterns:
                raise IxiaException("Invalid filter_layer = %s. Allowed values: %s" % (filter_layer, list(self.flt_patterns.keys())))

        self.class_logger.debug("Sniff params: %s seconds, %s packets, %s filter layer, %s srcMac, %s dstMac." %
                                (sniffing_time, packets_count if packets_count != 0 else None, filter_layer, src_filter, dst_filter))

        # Store sniff settings per port to dictionary
        for iface in ifaces:
            _iface = self._get_port_to_string(iface)
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
        for iface in ifaces:
            tcl_cmd = ["set retCode $::TCL_OK;"]
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
            _iface = self._get_port_to_string(iface)
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
            captured_packets_count = int(self.tcl("captureBuffer get %s %s %s; \
                                                   captureBuffer cget -numFrames;" %
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

            # TODO: Develop user friendly format of packet list
            # packet_list = pypacker.PacketList()
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
                    # Add workaround for malformed packets (packet length less than 14)
                    # try:

                    pkt = pypacker.layer12.ethernet.Ethernet(codecs.decode(raw_packet, "hex_codec"))
                    # except StructError:
                    #     pkt = pypacker.Padding(codecs.decode(raw_packet, "hex_codec"))
                    pkt.time = self.sniff_ids[_iface]['start_time'] + timestamp / 1000000000
                    packet_list.append(pkt)

                packet_dict[iface] = packet_list
            else:
                packet_dict[iface] = []

            self.sniff_ids.pop(_iface)

        return packet_dict

    def get_received_frames_count(self, iface):
        """Read statistics - number of received valid frames.

        Args:
            iface(str):  Interface name.

        Returns:
            int: Number of received frames.

        """
        chassis, card, port = iface

        tcl_cmd = []
        tcl_cmd.append("stat get framesReceived %s %s %s;" % (chassis, card, port))
        tcl_cmd.append("stat cget -framesReceived")
        result = self.tcl(" ".join(tcl_cmd))
        return int(result)

    def get_filtered_frames_count(self, iface):
        """Read statistics - number of received frames which fit filter criteria.

        Args:
            iface(str):  Interface name.

        Returns:
            int: Number of filtered frames.

        """
        chassis, card, port = iface

        tcl_cmd = []
        tcl_cmd.append("stat get captureFilter %s %s %s;" % (chassis, card, port))
        tcl_cmd.append("stat cget -captureFilter")
        result = self.tcl(" ".join(tcl_cmd))
        return int(result)

    def get_uds_3_frames_count(self, iface):
        """Read statistics - number of non-filtered received frames (valid and invalid).

        Args:
            iface(str):  Interface name.

        Returns:
            int: Number of received frames

        """
        chassis, card, port = iface

        tcl_cmd = []
        tcl_cmd.append("stat get captureTrigger %s %s %s;" % (chassis, card, port))
        tcl_cmd.append("stat cget -captureTrigger")
        result = self.tcl(" ".join(tcl_cmd))
        return int(result)

    def get_sent_frames_count(self, iface):
        """Read statistics - number of sent frames.

        Args:
            iface(str):  Interface name.

        Returns:
            int: Number of sent frames.

        """
        chassis, card, port = iface

        tcl_cmd = []
        tcl_cmd.append("stat get framesSent %s %s %s;" % (chassis, card, port))
        tcl_cmd.append("stat cget -framesSent")
        result = self.tcl(" ".join(tcl_cmd))
        return int(result)

    def clear_statistics(self, sniff_port_list):
        """Clear statistics - number of frames.

        Args:
            sniff_port_list(list):  List of interface names.

        Returns:
            None

        """
        tcl_port_list = str(sniff_port_list).replace("(", "{").replace(")", "}").replace("[", "{").replace("]", "}").replace("'", "").replace(",", "")
        assert self.tcl("set rxPortIdList %s;\
                        set retCode $::TCL_OK;\
                        if {[ixClearStats rxPortIdList]} {errorMsg \"ixClearStats return error.\"; set retCode $::TCL_ERROR};\
                        return $retCode" %
                        (tcl_port_list, )) == "0"

    def set_flow_control(self, iface, mode):
        """Enable/Disable flow control on the port.

        Args:
            iface(str):  Interface name.
            mode(bool):  True/False.

        Returns:
            None

        """
        chassis, card, port = iface
        self.tcl("port config -flowControl $::%s" % (str(mode).lower(), ))
        assert self.tcl("port set %s %s %s" % (chassis, card, port)) == "0"
        assert self.tcl("port write %s %s %s" % (chassis, card, port)) == "0"

    def set_qos_stat_type(self, iface, ptype):
        """Set the QoS counters to look for priority bits for given packets type.

        Args:
            iface(str):  Interface name.
            ptype(str):  Priority type: VLAN/IP.

        Returns:
            None

        """
        if ptype == "VLAN":
            _ptype = "vlan"
        elif ptype == "IP":
            _ptype = "ipEthernetII"
        else:
            raise IxiaException("Invalid packet type for QoS setup: %s" % (ptype, ))
        chassis, card, port = iface
        self.tcl("stat config -mode statQos")
        assert self.tcl("stat set %s %s %s" % (chassis, card, port)) == "0"
        assert self.tcl("stat write %s %s %s" % (chassis, card, port)) == "0"
        self.tcl("qos setup %s" % (_ptype, ))
        if ptype == "IP":
            self.tcl("qos config -packetType ipEthernetII;" +
                     "qos config -byteOffset 15;" +
                     "qos config -patternMatch \"08 00\"")
        assert self.tcl("qos set %s %s %s" % (chassis, card, port)) == "0"
        assert self.tcl("qos write %s %s %s" % (chassis, card, port)) == "0"

    def get_qos_frames_count(self, iface, prio):
        """Get captured QoS frames count.

        Args:
            iface(str):  Interface name.
            prio(int):  Priority.

        Returns:
            int: captured QoS frames count.

        """
        chassis, card, port = iface

        tcl_cmd = []
        tcl_cmd.append("stat get allStats %s %s %s;" %
                       (chassis, card, port))
        tcl_cmd.append("stat cget -qualityOfService%d" % (prio, ))
        result = self.tcl(" ".join(tcl_cmd))
        return int(result)

    def get_port_txrate(self, iface):
        """Return port transmission rate.

        Args:
            iface(str):  Interface name.

        Returns:
            int: Frames per second.

        """
        chassis, card, port = iface

        tcl_cmd = []
        tcl_cmd.append("stat getRate statAllStats %s %s %s;" %
                       (chassis, card, port))
        tcl_cmd.append("stat cget -framesSent")
        result = self.tcl(" ".join(tcl_cmd))
        return int(result)

    def get_port_rxrate(self, iface):
        """Return port receiving rate.

        Args:
            iface(str):  Interface name.

        Returns:
            int: Frames per second.

        """
        chassis, card, port = iface

        tcl_cmd = []
        tcl_cmd.append("stat getRate statAllStats %s %s %s;" %
                       (chassis, card, port))
        tcl_cmd.append("stat cget -framesReceived")
        result = self.tcl(" ".join(tcl_cmd))
        return int(result)

    def get_port_qos_rxrate(self, iface, qos):
        """Return port receiving rate for specific qos.

        Args:
            iface(str):  Interface name.
            qos(int):  Qos value.

        Returns:
            int: Frames per second (int)

        """
        chassis, card, port = iface

        tcl_cmd = []
        tcl_cmd.append("stat getRate statAllStats %s %s %s;" %
                       (chassis, card, port))
        tcl_cmd.append("stat cget -qualityOfService%s" % qos)
        result = self.tcl(" ".join(tcl_cmd))
        return int(result)
