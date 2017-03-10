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

"""``switch_general.py``

`General switches-specific functionality`

"""

import sys
import time
import traceback
from abc import abstractmethod
from collections import namedtuple
import ipaddress as ipaddr

import pytest

from . import clissh
from . import loggers
from . import entry_template
from . import ui_ons_xmlrpc
from . import ui_ons_cli
from . import ui_onpss_shell
from . import ui_iss_cli
from . import ui_onpss_jsonrpc
from . import lab
from .custom_exceptions import SwitchException

UI_MAP = {
    "ons_cli": ui_ons_cli.UiOnsCli,
    "ons_xmlrpc": ui_ons_xmlrpc.UiOnsXmlrpc,
    "onpss_shell": ui_onpss_shell.UiOnpssShell,
    "onpss_jsonrpc": ui_onpss_jsonrpc.UiOnpssJsonrpc,
    "iss_cli": ui_iss_cli.UiIssCli,
}

PortsOrder = namedtuple('PortsOrder', 'masters, slaves')


class SwitchGeneral(entry_template.GenericEntry):
    """General Switch object functionality.

    Configuration examples::

        {
         "name": "simswitch2_lxc",
         "entry_type": "switch",
         "instance_type": "lxc",
         "id": 31,
         "ip_host": "10.0.5.103",
         "ip_port": "8083",
         "use_sshtun": 1,
         "sshtun_user": "admin",
         "sshtun_pass": "admin",
         "sshtun_port": 22,
         "default_gw": "127.0.0.1",
         "net_mask": "255.255.255.0",
         "ports_count": 32,
         "pwboard_host": "1.1.1.100",
         "pwboard_port": "15",
         "pwboard_snmp_rw_community_string": "private",
         "use_serial": false,
         "cli_user": "lxc_admin",
         "cli_user_passw": "lxc_admin",
         "cli_user_prompt": "Switch",
         "telnet_user": "admin",
         "telnet_pass": "password",
         "telnet_prompt": "localhost:~$",
         "ports": [20, 21, 1, 16],
         "port_list": [[35, 10000], [36, 2500]],
         "ports_map": [[51, [51, 52, 53, 54]], [55, [55, 56, 57, 58]]],
         "mgmt_ports": [47, 50],
         "related_id": ["33"]
        }

    Where::

        \b entry_type and \b instance_type are mandatory values and cannot be changed for current device type.
        \n\b id - int or str uniq device ID (mandatory)
        \n\b name - User defined device name (optional)
        \n\b ip_host - uniq device IP (mandatory).
        \n\b ip_port - uniq device IP port for XML-RPC commands (mandatory)
        \n\b use_sshtun - set if TAF will use ssh connection for XML-RPC commands (0 or 1) (mandatory)
        \n\b sshtun_user, \b sshtun_pass and \b sshtun_port - uniq ssh user credentials and port to establish ssh connection (optional).
        \n\b default_gw and \b net_mask -
        \n\b ports_count - length of Ports table in default configuration (mandatory)
        \n\b pwboard_host and \b pwboard_port - PDU IP address and port to perform powercycle device reboot (mandatory).
        \n\b pwboard_snmp_rw_community_string - PDU SNMP Read/Write community string (optional).
        \n\b use_serial - set up if telnet connection used for clear config (optional)
        \n\b cli_user and \b cli_user_passw - uniq CLI user credentials (optional).
        \n\b cli_user_prompt - default CLI prompt on device (optional).
        \n\b telnet_user and \b telnet_pass - uniq telnet user credentials (optional).
        \n\b telnet_prompt - default telnet prompt on device (optional).
        \n\b ports - list of port ids used in tests (mandatory).
        \n\b port_list - list of port id and port speed used in tests for speed preconfiguration (optional).
        \n\b ports_map - mapping of master/slave ports for speed preconfiguration (optional).
        \n\b mgmt_ports - port ids of management ports in Ports table. Used to avoid setting of adminMode into Down state for these ports (optional).
        \n\b related_id - list of ids of related devices or services (optional).

    """
    class_logger = None  # defined in subclasses

    def __init__(self, config, opts):
        """Initialize SwitchGeneral class.

        Args:
            config(dict):  Configuration information.
            opts(OptionParser):  py.test config.option object which contains all py.test cli options.

        """
        super(SwitchGeneral, self).__init__(config, opts)
        self.name = config.get('name', 'noname')

        self.ipaddr = config['ip_host']
        self.port = config['ip_port']
        self.ports_count = config['ports_count']
        self.id = config['id']
        self.type = config['instance_type']
        self.config = config
        self.opts = opts
        self.ports, self.speed_ports, self.ports_map = self._get_speed_ports()
        self.port_list = self.speed_ports[:]
        self.mgmt_ports = self.config.get("mgmt_ports", [])
        self.default_restart_type = "powercycle"
        self.waiton_err_message = ""  # defined in subclasses

        # Use serial console for real devices or not.
        self._use_serial = config.get('use_serial', True)

        self._sshtun_port = config.get('sshtun_port', 22)

        # Update status to On(True) in case --get_only option is selected.
        self.status = self.opts.get_only

        # Initialize UI based on UI_MAP and cli --ui option
        self.ui = UI_MAP[self.opts.ui](self)
        self.class_logger.debug("ui = %s", self.ui)

        # Flag to indicate if Switch configuration DB is damaged.
        self.db_corruption = False

        self.instance_prop = None

    def _get_speed_ports(self):
        """Get slave and master ports from config.

        Returns:
            list: List of ports (slave and master) used in real config

        Notes:
            This function check if master port should be split into slave ports.

        """
        speed_ports = self.config.get("port_list", [])
        ports_map = self.config.get("ports_map", [])

        # speed_ports expected format: [[port1_num, port1_speed], ...]
        if speed_ports:
            ports = [x[0] for x in speed_ports]
        else:
            ports = self.config.get("ports", [])

        return ports, speed_ports, ports_map

    def _get_port_for_probe(self):
        """Get port ID.

        Returns:
            int:  ssh tunnel ports ID

        """
        return int(self._sshtun_port)

    def enable_ports(self):
        """Enable ports if Ports table is empty.

        """
        pass

    def probe(self):
        """Probe switch with UI call.

        Returns:
            dict:  Dictionary (_object) with switchpp status parameters or raise an exception.

        """
        _object = {
            'isup': False,
            'type': "unknown",
            'prop': {}
        }

        if clissh.probe_port(self.ipaddr, self._get_port_for_probe(), self.class_logger):
            _object['isup'] = True
            try:
                # Try to wait until device is ready to process
                self.ui.check_device_state()
                # Get switch properties only once
                if not self.instance_prop:
                    self.instance_prop = self.ui.get_table_platform()[0]
            except Exception as err:
                self.class_logger.error("Caught an exception while probing the device: Error type: %s. Error msg: %s" %
                                        (type(err), err))
            else:
                _object['type'] = "switchpp"
                # Define _object['prop'] only if switch has started correctly
                _object['prop'] = self.instance_prop
                message = "Switch %s(%s) is processing: " % (self.name, self.ipaddr)
                instance_props = ", ".join("{} - {}".format(key, val) for key, val in
                                           sorted(self.instance_prop.items()))
                self.class_logger.info(message + instance_props)
                time.sleep(1)
                self.class_logger.info(message)
        return _object

    def waiton(self, timeout=90):
        """Wait until switch if fully operational.

        Args:
            timeout(int):  Wait timeout

        Raises:
            SwitchException:  device doesn't response

        Returns:
            dict:  Status dictionary from probe method or raise an exception.

        """
        status = None
        message = "Waiting until switch %s(%s) is up." % (self.name, self.ipaddr)
        self.class_logger.info(message)
        stop_flag = False
        end_time = time.time() + timeout
        while not stop_flag:
            if loggers.LOG_STREAM:
                sys.stdout.write(".")
                sys.stdout.flush()
            if time.time() < end_time:
                # While time isn't elapsed continue probing switch.
                try:
                    status = self.probe()
                except KeyboardInterrupt:
                    message = "KeyboardInterrupt while checking switch %s(%s)..." % (self.name, self.ipaddr)
                    self.class_logger.info(message)
                    self.sanitize()
                    pytest.exit(message)
                if status["isup"] and status["type"] == "switchpp":
                    stop_flag = True
                    if status['prop'] == {}:
                        # If type == switchpp but prop == empty dict then Platform table return incorrect data.
                        message = "Found running switchpp on %s but Platform data is corrupted." % (self.ipaddr, )
                        self.class_logger.warning(message)
                        raise SwitchException(message)
                    self.class_logger.info("Switch instance on %s(%s) is OK." % (self.name, self.ipaddr))
            else:
                # Time is elapsed.
                if status["isup"] and status["type"] != "switchpp":
                    message = ("Port %s on host %s is opened but doesn't response queries." +
                               " %s Check your environment!") % (self.port, self.ipaddr, self.waiton_err_message)
                else:
                    port = self._get_port_for_probe()
                    message = "Timeout exceeded. IP address %s port %s doesn't respond" % (self.ipaddr, port)
                self.class_logger.warning(message)
                raise SwitchException(message)
            if not stop_flag:
                time.sleep(0.75)
        return status

    def waitoff(self, timeout=30):
        """Wait for switch stop listening on ssh port.

        Args:
            timeout(int):  Wait timeout

        Raises:
            SwitchException:  device is still alive

        Returns:
            bool:  True or raise an exception.

        """
        status = True
        message = "Waiting until switch %s(%s) is down." % (self.name, self.ipaddr)
        self.class_logger.info(message)
        stop_flag = False
        end_time = time.time() + timeout
        while not stop_flag:
            if loggers.LOG_STREAM:
                sys.stdout.write(".")
                sys.stdout.flush()
            if time.time() < end_time:
                status = clissh.probe_port(self.ipaddr, self._get_port_for_probe(), self.class_logger)
                if not status:
                    stop_flag = True
            else:
                if status:
                    message = "Timeout exceeded. The port %s on host %s is still open." % (self._sshtun_port, self.ipaddr)
                    self.class_logger.warning(message)
                    raise SwitchException(message)
            time.sleep(1)
        return not status

    def clearconfig(self):
        """Perform switchpp clearConfig query and raise an exception if it fails.

        Returns:
            None

        """
        try:
            self.ui.clear_config()
        except Exception as err:
            message = "Error clearing switch id:%s config: %s." % (self.id, err, )
            self.class_logger.error(message)
            pytest.fail(message)

    def cleanup(self):
        """Check if switch is operational and perform clearConfig procedure.

        Returns:
            None

        """
        if not self.status:
            self.class_logger.info("Skip cleanup of switch id:%s due to Off status." % (self.id, ))
            return
        self.get()
        self.clearconfig()

    @abstractmethod
    def start(self, wait_on=True):
        """Mandatory method for environment specific switch classes.

        Args:
            wait_on(bool):  Indicates if wait for device status

        """
        pass

    @abstractmethod
    def stop(self):
        """Mandatory method for environment specific switch classes.

        """
        pass

    @abstractmethod
    def restart(self, wait_on=True, mode=""):
        """Mandatory method for environment specific switch classes.

        Args:
            wait_on(bool):  Indicates if wait for device status
            mode(str):  Restart mode. powercycle|ui

        """
        pass

    def get(self, init_start=False, retry_count=7):
        """Get or start switch instance.

        Args:
            init_start(bool):  Perform switch start operation or not
            retry_count(int):  Number of retries to start(restart) switch

        Returns:
            None or raise an exception.

        Notes:
            Also self.opts.fail_ctrl attribute affects logic of this method.
            fail_ctrl is set in py.test command line options (read py.test --help for more information).

        """
        # If fail_ctrl != "restart", restart retries won't be performed
        if self.opts.fail_ctrl != "restart":
            retry_count = 1

        for retry in range(retry_count):
            try:
                if retry == 0:
                    if init_start:
                        self.start()
                    else:
                        self.waiton()
                else:
                    self.restart(mode=self.default_restart_type)
                break
            except KeyboardInterrupt:
                message = "KeyboardInterrupt while checking switch %s(%s)..." % (self.name, self.ipaddr)
                self.class_logger.info(message)
                self.sanitize()
                pytest.exit(message)
            except Exception:
                self.class_logger.warning("Error while checking switch %s(%s)..." % (self.name, self.ipaddr))
                retry += 1
                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback_message = traceback.format_exception(exc_type, exc_value, exc_traceback)
                message = "Error while checking switch %s(%s):\n%s" % (self.name, self.ipaddr, "".join(traceback_message))
                sys.stderr.write(message)
                sys.stderr.flush()
                self.class_logger.error(message)
                if retry > 4:
                    self.class_logger.warning(
                        "Could not complete switch start method for the fourth time. Trying to "
                        "reset the DB...")
                    self.db_corruption = True
                if retry >= retry_count + 1:
                    message = "Could not complete start switch method after {0} retries. Something " \
                              "went wrong...\n".format(retry_count)
                    sys.stderr.write(message)
                    sys.stderr.flush()
                    self.class_logger.error(message)
                    if self.opts.fail_ctrl != "ignore":
                        pytest.exit(message)
                    else:
                        pytest.fail(message)

    def check(self):
        """Check if switch is operational using waiton method.

        Notes:
            This mandatory method for all environment classes.

        """
        if not self.status:
            self.class_logger.info("Skip switch id:%s(%s) check because it's has Off status." % (self.id, self.name))
            return
        status = self.waiton()
        # Verify Ports table is not empty
        if self.ui.get_table_ports() == []:
            if self.opts.fail_ctrl == 'stop':
                self.class_logger.debug("Exit switch check. Ports table is empty!")
                pytest.exit('Ports table is empty!')
            else:
                self.class_logger.debug("Fail switch check. Ports table is empty!")
                pytest.fail('Ports table is empty!')
        return status

    def create(self):
        """Start switch or get running one.

        Notes:
            This is mandatory method for all environment classes.
            Also self.opts.get_only attribute affects logic of this method.
            get_only is set in py.test command line options (read py.test --help for more information).

        """
        init_start = not self.opts.get_only
        return self.get(init_start=init_start)

    def destroy(self):
        """Stop or release switch.

        Notes:
            This is mandatory method for all environment classes.
            Also self.opts.leave_on and get_only  attributes affect logic of this method.
            leave_on and get_only are set in py.test command line options (read py.test --help for more information).

        """
        if not self.status:
            self.class_logger.info("Skip switch id:%s(%s) destroying because it's has already Off status." % (self.id, self.name))
            return
        if not self.opts.leave_on and not self.opts.get_only:
            self.stop()

        self.sanitize()

    def sanitize(self):
        """Perform any necessary operations to leave environment in normal state.

        """
        # Close sshtun to prevent hanging threads.
        self.ui.disconnect()

    def connect_port(self, port_id):
        """Emulate port connection via setting adminMode into Up state.

        Args:
            port_id(int):  Port number

        """
        self.class_logger.debug("Emulating connecting for port ID = {0}".format(port_id))
        _port = self.ui.get_table_ports([int(port_id)])[0]
        if _port['operationalStatus'] != "NotPresent":
            # Check if port is LAG member
            if _port["type"] == "LAGMember":
                # Use lag id as port id
                lag_table = self.ui.get_table_ports2lag()
                port_id = [x["lagId"] for x in lag_table if x["portId"] == port_id][0]
            self.ui.modify_ports([int(port_id)], adminMode="Up")

    def disconnect_port(self, port_id):
        """Emulate port disconnection via setting adminMode into Down state.

        Args:
            port_id(int):  Port number

        """
        self.class_logger.debug("Emulating disconnecting for port ID = {0}".format(port_id))
        _port = self.ui.get_table_ports([int(port_id)])[0]
        if _port['operationalStatus'] != "NotPresent":
            # Check if port is LAG member
            if _port["type"] == "LAGMember":
                # Use lag id as port id
                lag_table = self.ui.get_table_ports2lag()
                port_id = [x["lagId"] for x in lag_table if x["portId"] == port_id][0]
            self.ui.modify_ports([int(port_id)], adminMode="Down")

    def ssh_connect(self, host, port, login, passw):
        """Make ssh connection to the device.

        Args:
            host(str):  Device ssh IP address
            port(int):  Device ssh port
            login(str):  ssh username
            passw(str):  ssh password

        """
        self.ssh_conn = clissh.CLISSH(host, port=port, username=login, password=passw)
        self.ssh_conn.login()
        self.ssh_conn.open_shell()

    def disabled_stp_on_management_ports(self):
        """Disable STP on management ports.

        """
        pass

    def get_env_prop(self, param):
        """Read properties from all devices.

        """
        return self.instance_prop[param]


class SwitchReal(SwitchGeneral):
    """Real devices class.

    """

    class_logger = loggers.ClassLogger()
    UI_RESTART_TIMEOUT = 5

    def __init__(self, config, opts):
        """Initialize SwitchReal class.

        Args:
            config(dict):  Configuration information.
            opts(OptionParser):  py.test config.option object which contains all py.test cli options.

        """
        from . import powerboard
        self.powerboard = powerboard
        self.powercycle_timeout = config.get('reboot_latency', 1)
        self.pwboard_snmp_rw_community_string = 'private'

        super(SwitchReal, self).__init__(config, opts)
        self.pwboard = config["pwboard_host"]
        self.pwport = config["pwboard_port"]
        self._sshtun_user = config['sshtun_user']
        self._sshtun_pass = config['sshtun_pass']

        self.pwboard_snmp_rw_community_string = config.get('pwboard_snmp_rw_community_string', 'private')

        # conditional init, this should be set in concrete Switch platform classes
        self.mgmt_iface = getattr(self, "mgmt_iface", "eth0")

        self._default_gw = config['default_gw']
        self._net_mask = config['net_mask']

        self.waiton_err_message = "Device is started but does not respond to queries."
        self.telnet = None
        self.telnet_prompt = None

        self.startup_time = 180

        # create ssh object:
        self.ssh = clissh.CLISSH(self.ipaddr, self._sshtun_port, self._sshtun_user,
                                 self._sshtun_pass, sudo_prompt="Password:")

        # Create CLI in subclasses
        self.netconf = None
        # TODO: update env file
        if self.netconf:
            from . import netconfcmd
            self.netconf = netconfcmd.NETCONF(config)

    def start(self, wait_on=True):
        """Power on switch or perform power cycle if it is already On.

        Args:
            wait_on(bool):  Check if switch boot successfully

        Raises:
            SwitchException:  unknown device status

        """
        self.class_logger.info("Starting Real switch device %s(%s) ..." % (self.name, self.ipaddr))
        self.class_logger.debug("Checking device status on powerboard...")
        status = self.powerboard.get_status(self.pwboard, self.pwport, self.pwboard_snmp_rw_community_string)
        self.class_logger.debug("Current status %s." % status)
        if status == "On":
            # Turn Off Seacliff with halt.
            if "halt" in self.config and self.config["halt"]:
                self.halt()
            self.powerboard.do_action(self.pwboard, self.pwport, self.pwboard_snmp_rw_community_string, self.powerboard.commands["Off"])
            self.class_logger.info("Powercyle latency: {}".format(self.powercycle_timeout))
            time.sleep(self.powercycle_timeout)
            self.powerboard.do_action(self.pwboard, self.pwport, self.pwboard_snmp_rw_community_string, self.powerboard.commands["On"])
        elif status == "Off":
            self.powerboard.do_action(self.pwboard, self.pwport, self.pwboard_snmp_rw_community_string, self.powerboard.commands["On"])
        else:
            raise SwitchException("Cannot determine device status.")

        # After snmp command is sent APC could restart switch
        # in few seconds. Terefore it's good to wait a little
        # to prevent fail login prompt detection.
        time.sleep(1)

        if wait_on:
            self.waiton(timeout=self.startup_time)

        # Set status to On(True)
        self.status = True

        # Perform syslog configuration if one exists.
        self.setup_syslog()

        # Set initial ports speed
        self.speed_preconfig()

    def stop(self):
        """Power Off real switch.

        Raises:
            SwitchException:  unknown device status

        """
        self.ui.disconnect()

        self.class_logger.info("Stopping Real switch device %s(%s) ..." % (self.name, self.ipaddr))
        self.class_logger.debug("Checking device status on powerboard...")
        status = self.powerboard.get_status(self.pwboard, self.pwport, self.pwboard_snmp_rw_community_string)
        self.class_logger.debug("Current status %s." % status)
        if status == "On":
            # WORKAROUND BEGIN: Turn Off the device with halt
            if "halt" in self.config and self.config["halt"]:
                self.halt()
            # WORKAROUND END
            self.powerboard.do_action(self.pwboard, self.pwport, self.pwboard_snmp_rw_community_string, self.powerboard.commands["Off"])
        elif status == "Off":
            self.class_logger.info("Nothing to do. Switch is already off.")
        else:
            raise SwitchException("Cannot determine device status.")
        self.waitoff(timeout=15)

        # Set Off(False) status
        self.status = False

        return True

    def restart(self, wait_on=True, mode="powercycle"):
        """Perform switch power cycle.

        Args:
            wait_on(bool):  Check if switch boot properly.
            mode(str):  set type of reboot, by default it's powercycle.

        Raises:
            SwitchException:  incorrect restart mode

        Notes:
            By default start method performs power cycle in case switch is already On.
            Therefore this method is just link to start().

        """
        if mode == 'powercycle':
            self.class_logger.info("Perform powercycle device reboot")
            self.stop()
            self.class_logger.info("Powercyle latency: {}".format(self.powercycle_timeout))
            time.sleep(self.powercycle_timeout)
            self.start(wait_on)

        elif mode == 'ui':
            self.class_logger.info("Perform graceful device reboot")
            self.ui.restart()
            self.status = False
            self.waitoff(60)
            self.class_logger.info("Powercyle latency: {}".format(self.UI_RESTART_TIMEOUT))
            time.sleep(self.UI_RESTART_TIMEOUT)
            self.waiton(300)
            self.status = True
            # Set initial ports speed
            self.speed_preconfig()
            return
        else:
            message = "Incorrect restart mode was specified: %s" % (mode, )
            self.class_logger.error(message)
            raise SwitchException(message)

    def get_serial(self, timeout=90, with_login=None, wait_login=0):
        """Connect to switch via serial.

        Args:
            timeout(int):  time out to wait connection
            with_login(bool):  Perform login procedure or not.
                               If param isn't set try automatically determine login necessity. (True|False|None)
            wait_login(int):  time to wait login before sending <Enter>.
                              <Enter> is necessary if login is already appiered.

        Notes:
            Create(or check) class attribute telnet with active telnet connection to switch and do login.

        """
        self.telnet = lab.ConsoleServer(self.config)
        self.telnet.get_serial(timeout=timeout, with_login=with_login, wait_login=wait_login)

    def close_serial(self):
        """Close telnet connection to switch.

        """
        self.telnet.close_serial()
        del self.telnet
        self.telnet = None

    def halt(self):
        """Do halt before shutdown.

        Raises:
            SwitchException:  error on device halt

        """
        if not self._use_serial:
            self.class_logger.warning("Skipping halt procedure because serial access is disabled.")
            return

        # Connect and halt switch
        try:
            self.class_logger.debug("Halting switch...")
            self.get_serial(with_login=None, wait_login=0)
            self.class_logger.debug("Telnet connection - OK...")
            output, err, _ = self.telnet.exec_command("halt", "System halted.")

            if err:
                message = "Cannot halt the device.\nStdOut: %s\nStdErr: %s" % (output, err)
                self.class_logger.error(message)
                raise SwitchException(message)
            time.sleep(5)
            self.class_logger.debug("Switch terminal output:\n%s" % output)
        except Exception as err:
            self.class_logger.error(err)
        finally:
            self.close_serial()

    @staticmethod
    def _netmsk_to_cidr(ip_addr, netmask):
        """CIDR conversion.

        Args:
            ip_addr(str):  IP address
            netmask(int):  netmask value

        """
        cidr = ipaddr.IPv4Network('{0}/{1}'.format(ip_addr, netmask), strict=False)
        return cidr.with_prefixlen

    def clearconfig(self):
        """Perform clearConfig query on switch using telnet.

        And try to configure management interface.

        """
        self.class_logger.debug("Performing clearConfig on real switch.")
        super(SwitchReal, self).clearconfig()

        self.setup_syslog()

        # Set initial ports speed
        self.speed_preconfig()

    def setup_syslog(self):
        """Setup remote syslog server settings.

        """
        if 'related_id' in self.config:
            for val in self.config['related_id']:
                if self.config['related_conf'][val]['instance_type'] == "syslog_settings":
                    syslog_set_id = val
                    # TODO check on first 1.1 build syslog parameters value
                    syslog_ip = self.config['related_conf'][syslog_set_id]['ip']
                    syslog_proto = self.config['related_conf'][syslog_set_id]['proto']
                    syslog_port = self.config['related_conf'][syslog_set_id]['port']
                    syslog_localport = self.config['related_conf'][syslog_set_id]['localport']
                    syslog_transport = self.config['related_conf'][syslog_set_id]['transport']
                    syslog_facility = self.config['related_conf'][syslog_set_id]['facility']
                    syslog_severity = self.config['related_conf'][syslog_set_id]['severity']
                    try:
                        self.ui.create_syslog(syslog_proto, syslog_ip, syslog_port, syslog_localport, syslog_transport, syslog_facility, syslog_severity)
                        self.class_logger.debug("Syslog configuration finished. Syslog server: %s, proto: %s" % (syslog_ip, syslog_proto))
                        return
                    except Exception as err:
                        self.class_logger.debug("Syslog configuration skipped. Some error occurs %s" % (err, ))
        self.class_logger.debug("Syslog configuration skipped. Syslog settings not found.")

    def speed_preconfig(self, wait_for_ports=False):
        """Function for ports speed preconfiguration.

        Args:
            wait_for_ports(int):  wait for Ports table changes size

        """

        def _normalize_port_list(ports_list):
            """Get lists of Master and Slave ports.

            """
            master_ports = set()
            ports = set()
            for _port in ports_list:
                m_port = _get_master_port(_port)
                master_ports.add(m_port)
                if m_port != _port:
                    ports.add(_port)

            m_list = list(master_ports)
            p_list = list(ports)
            return PortsOrder(m_list, p_list)

        def _get_master_port(port):
            """Get Master port.

            """
            try:
                return next(r for r, s in self.ports_map if port in s)
            except StopIteration:
                return port

        # Separate ports per preconfigured speed
        if self.speed_ports:
            speed_dict = {}
            for port, speed in self.speed_ports:
                speed_dict.setdefault(speed, []).append(port)

            normalized_speed_dict = {}
            for speed, ports in speed_dict.items():
                normalized_speed_dict[speed] = _normalize_port_list(ports)

            for speed, ports in normalized_speed_dict.items():
                self.setup_ports_speed_configuration(ports.masters, speed)
                self.setup_ports_speed_configuration(ports.slaves, speed)

            # Wait for Ports table has expected size
            if wait_for_ports:
                table_size = len(self.ui.get_table_ports())
                _start_time = time.time()
                while table_size != self.ports_count:
                    if time.time() > _start_time + 10:
                        pytest.fail("Ports table doesn't have expected ports count")
                    time.sleep(0.2)
                    table_size = len(self.ui.get_table_ports())
            else:
                # WORKAROUND for ONS-254496
                time.sleep(3)

    def setup_ports_speed_configuration(self, ports=None, speed=10000):
        """Configure ports speed.

        Args:
            ports(list[int]):  list of ports to set speed value
            speed(int):  speed value

        """
        if ports:
            self.class_logger.debug("Performing ports speed configuration on real switch.")
            err_message = "Cannot perform ports speed configuration.\nDescription: %s\nERROR: %s"

            try:
                self.ui.modify_ports(ports=ports, speed=int(speed))
                ports_table = self.ui.get_table_ports(ports)
                for port_table in ports_table:
                    assert port_table["speed"] == speed
            except AssertionError as err:
                message = err_message % ("Switch doesn't accept commands.", err, )
                self.class_logger.error(message)
                pytest.fail(message)
            except Exception as err:
                message = err_message % ("Unknown.", err, )
                self.class_logger.error(message)
                pytest.fail(message)
            else:
                self.class_logger.debug("Ports speed configuration - OK")
