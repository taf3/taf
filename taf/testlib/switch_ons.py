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

"""``switch_ons.py``

`ONS switches-specific functionality`

"""
from os.path import isfile as os_path_isfile
from os.path import join as os_path_join
import shutil
from subprocess import Popen, PIPE
import time

import paramiko
import pexpect
import pytest

from . import environment
from . import loggers
from . import sshtun
from .switch_general import SwitchGeneral, SwitchReal
from .xmlrpc_proxy import TimeoutServerProxy as xmlrpcProxy
from .custom_exceptions import SwitchException


class SwitchONSGeneralMixin(object):

    def __init__(self, *args, **kwargs):
        super(SwitchONSGeneralMixin, self).__init__(*args, **kwargs)
        self.xmlproxy = xmlrpcProxy("http://%s:%s/RPC2" % (self.ipaddr, self.port), timeout=180)
        self.sshtun = None
        self._use_sshtun = False

    def _get_port_for_probe(self):
        """Get port ID.

        Returns:
            int:  ssh tunnel ports ID

        """
        # In case using sshtun check device by ssh port.
        if self._use_sshtun:
            return self._sshtun_port
        else:
            return int(self.port)

    def getprop(self, table, param, row_id, dst="nb"):
        """Return switchpp property.

        Args:
            table(str):  Name of table where necessary parameter is stored
            param(str):  Name of necessary parameter
            row_id(int):  Row index in switch table
            dst(str):  Querry destination. E.g. nb, system, onsps

        Returns:
            str, int:  Parameter value

        Notes:
            This is just wrapper for xmlrpc nb call.

        Examples::

            switch_instance.getprop("Ports", "operationalStatus", 5)
            env.switch[1].getprop("SpanningTree", "mode", 1)

        """
        return getattr(self.xmlproxy, "%s.%s.get.%s" % (dst, table, param))(row_id)

    def getprop_row(self, table, row_id, dst="nb"):
        """Return switchpp table row.

        Args:
            table(str):  Name of table
            row_id(int):  Row index in switch table
            dst(str):  Querry destination. E.g. nb, system, onsps

        Returns:
            dict:  Table row

        Notes:
            This is just wrapper for xmlrpc nb call.

        Examples::

            switch_instance.getprop("Ports", 5)
            env.switch[1].getprop("Platform", 1)

        """
        return getattr(self.xmlproxy, "%s.%s.getRow" % (dst, table))(row_id)

    def getprop_table(self, table, dst="nb"):
        """Return switchpp table.

        Args:
            table(str):  Name of table
            dst(str):  Querry destination. E.g. nb, system, onsps

        Returns:
            list[dict]: Table

        Notes:
            This is just wrapper for xmlrpc nb call.

        Examples::

            switch_instance.getprop("SpanningTree")
            env.switch[1].getprop("RSTPPorts")

        """
        table_size = self.getprop_size(table, dst=dst)
        if table_size <= 1000:
            return getattr(self.xmlproxy, "%s.%s.getTable" % (dst, table))()
        else:
            table_content = []
            subset_size = 200

            # Create table list:
            start_point = 0
            subset = getattr(self.xmlproxy, "%s.%s.getTableSubset" % (dst, table))(start_point, subset_size)
            table_content.extend(subset)
            while len(subset) == 200:
                start_point = subset[-1]["rowId"]
                subset = getattr(self.xmlproxy, "%s.%s.getTableSubset" % (dst, table))(start_point, subset_size)
                table_content.extend(subset)
            return table_content

    def getprop_size(self, table, dst="nb"):
        """Return switchpp table length.

        Args:
            table(str):  Name of table
            dst(str):  Querry destination. E.g. nb, system, onsps

        Returns:
            int:  Table size

        Notes:
            This is just wrapper for xmlrpc nb call.

        Examples::

            switch_instance.getprop_size("SpanningTree")
            env.switch[1].getprop_size("RSTPPorts")

        """
        return getattr(self.xmlproxy, "%s.%s.size" % (dst, table))()

    def getprop_table_info(self, table, dst="nb"):
        """Return switchpp table info.

        Args:
            table(str):  Name of table
            dst(str):  Querry destination. E.g. nb, system, onsps

        Returns:
            dict:  Table info

        Notes:
            This is just wrapper for xmlrpc nb call.

        Examples::

            switch_instance.getprop_table_info("SpanningTree")
            env.switch[1].getprop_table_info("RSTPPorts")

        """
        return getattr(self.xmlproxy, "%s.%s.getInfo" % (dst, table))()

    def getprop_field_info(self, table, field, dst="nb"):
        """Return switchpp table field info.

        Args:
            table(str):  Name of table
            dst(str):  Querry destination. E.g. nb, system, onsps
            field(str):  Name of field

        Returns:
            dict: Field info

        Notes:
            This is just wrapper for xmlrpc nb call.

        Examples::

            switch_instance.getprop_field_info("Vlans", "vlanId")
            env.switch[1].getprop_field_info("Vlans", "name")

        """
        return getattr(self.xmlproxy, "%s.%s.getInfo.%s" % (dst, table, field))()

    def getprop_method_help(self, method):
        """Return switchpp table info.

        Args:
            method(str):  xmlrpc method

        Returns:
            str:  Method help information

        Notes:
            This is just wrapper for xmlrpc call.

        Examples::

            switch_instance.getprop_method_help("nb.StaticARP.addRow")
            env.switch[1].getprop_method_help("nb.StaticARP.addRow")

        """
        return getattr(self.xmlproxy, "system.methodHelp")(method)

    def setprop(self, table, param, values, dst="nb"):
        """Set switchpp property.

        Args:
            table(str):  Name of table where necessary parameter is stored
            param(str):  Name of necessary parameter
            values(list):  List on necessary set parameters
            dst(str):  Querry destination. E.g. nb, system, onsps

        Raises:
            xmlrpclib.Fault

        Returns:
            int:  Set operation status (int or xmlrpclib.Fault exception)

        Notes:
            This is just wrapper for xmlrpc nb call.

        Examples::

            switch_instance.setprop("Ports", "adminMode", [10, "Up"])
            env.switch[1].setprop("SpanningTree", "mode", [1, "MSTP"])

        """
        return getattr(self.xmlproxy, "%s.%s.set.%s" % (dst, table, param))(*values)

    def setprop_row(self, table, values, dst="nb"):
        """Add row to switchpp table.

        Args:
            table(str):  Name of table
            values(list):  List on necessary addRow parameters
            dst(str):  Querry destination. E.g. nb, system, onsps

        Raises:
            xmlrpclib.Fault

        Returns:
            int:  addRow operation status (int or xmlrpclib.Fault exception)

        Notes:
            This is just wrapper for xmlrpc nb call.

        Examples::

            switch_instance.setprop_row("Vlans", [7, "TestVlan"])
            port_id = 1
            vlan_id = 7
            env.switch[1].setprop_row("Ports2Vlans", [port_id, vlan_id, "Tagged"])

        """
        return getattr(self.xmlproxy, "%s.%s.addRow" % (dst, table))(*values)

    def unsetprop(self, table, param, values, dst="nb"):
        """Unset switchpp property.

        Args:
            table(str):  Name of table where necessary parameter is stored
            param(str):  Name of necessary parameter
            values(list):  List on necessary set parameters
            dst(str):  Query destination. E.g. nb, system, onsps

        Raises:
            xmlrpclib.Fault

        Returns:
            int:  Unset operation status (int or xmlrpclib.Fault exception)

        Notes:
            This is just wrapper for xmlrpc nb call.

        Examples::

            switch_instance.setprop("Ports", "adminMode", [10, "Up"])
            env.switch[1].unsetprop("SpanningTree", "mode", [1, "MSTP"])

        """
        return getattr(self.xmlproxy, "%s.%s.unset.%s" % (dst, table, param))(*values)

    def delprop_row(self, table, row_id, dst="nb"):
        """Delete row from switchpp table.

        Args:
            table(str):  Name of table
            row_id(int):  Row ID in switch table
            dst(str):  Querry destination. E.g. nb, system, onsps

        Raises:
            xmlrpclib.Fault

        Returns:
            int:  delRow operation status (int or xmlrpclib.Fault exception)

        Notes:
            This is just wrapper for xmlrpc nb call.

        Examples::

            switch_instance.delprop_row("Vlans", 8)
            port_id = 1
            vlan_id = 7
            env.switch[1].delprop_row("Ports2Vlans", 4)

        """
        return getattr(self.xmlproxy, "%s.%s.delRow" % (dst, table))(row_id)

    def findprop(self, table, values, dst="nb"):
        """Find switchpp property id.

        Args:
            table(str):  Name of table where necessary parameter is stored
            values(list):  List on necessary find parameters
            dst(str):  Querry destination. E.g. nb, system, onsps

        Raises:
            xmlrpclib.Fault

        Returns:
            int:  Query reply (row id).

        Notes:
            This is just wrapper for xmlrpc nb call.

        Examples::

            switch_instance.findprop("Vlans", [7, ])
            env.switch[1].findprop("Applications", [1, 1, 'ONSNameServer'])

        """
        return getattr(self.xmlproxy, "%s.%s.find" % (dst, table))(*values)

    def existsprop(self, table, values, dst="nb"):
        """Check switchpp property existence.

        Args:
            table(str):  Name of table where necessary parameter is stored
            values(str):  List on necessary find parameters
            dst(str):  Querry destination. E.g. nb, system, onsps

        Returns:
            bool:  Query reply.

        Notes:
            This is just wrapper for xmlrpc nb call.

        Examples::

            switch_instance.existsprop("StaticARP", ["10.10.10.10", 0])

        """
        return getattr(self.xmlproxy, "%s.%s.exists" % (dst, table))(*values)

    def multicall(self, calls_list):
        """Execute switchpp multicall.

        Args:
            calls_list(list(dict)):  List of dictionaries for necessary XML-RPC calls

        Raises:
            SwitchException:  incorrect parameters

        Returns:
            List of executed operations statuses and return values

        Notes:
            This is just wrapper for xmlrpc system call.

        Examples::

            env.switch[1].multicall([{'methodName': 'nb.Vlans.addRow', 'params': [(10, 'Vlan_10'), (20, 'Vlan_20'), (30, 'Vlan_30'), (40, 'Vlan_40'), ]}, ])
            env.switch[1].multicall([{'methodName': 'nb.Vlans.addRow', 'params': [(100, 'Vlan_100'), ]},
                                     {'methodName': 'nb.Ports2Vlans.addRow', 'params': [(1, 100, "Untagged"), ]},
                                     {'methodName': 'nb.Ports.set.pvid', 'params': [(1, 100), ]}])
            env.switch[1].multicall([{'methodName': 'nb.Ports.get.operationalStatus', 'params': [(1, ), (2, ), (3, ), (4, ), (5, )]}, ])

        """
        multicalls_list = []
        for row in calls_list:
            try:
                methodname = row['methodName']
                # use extend with an iterables instead of appending each one
                multicalls_list.extend(
                    {'methodName': methodname, 'params': params} for params in row['params'])
            except KeyError as err:
                raise SwitchException("Incorrect key is transmitted in calls_list row dictionary: %s" % err)

        return_values = getattr(self.xmlproxy, "system.multicall")(multicalls_list)

        assert len(return_values) == len(multicalls_list), "Return values list has different length than multicall list"

        i = 0
        while i < len(return_values):
            if isinstance(return_values[i], list):
                multicalls_list[i]["result"] = str(return_values[i][0])
            else:
                multicalls_list[i]["result"] = str(return_values[i])
            i += 1

        return multicalls_list

    def set_app_log_level(self, loglevel="Notice"):
        """Set application log level for switch.

        Args:
            loglevel(str):  value of set log level

        """
        for i in self.ui.get_table_applications():
            self.ui.configure_application(i['name'], loglevel)

    def check_app_table(self):
        """Check if Application table contains all expected items in admin Up state.

        Returns:
            bool:  True or False

        """
        # TODO update application list
        expapp_list = {'ONSCoreServer',
                       'ONSApplicationServer',
                       'ONSNorthboundServer'}

        expapp_list.union(self.SWITCH_APPS)

        app_table = self.getprop_table("Applications")
        app_list = set([_x['name'] for _x in app_table])
        app_state = set([(x['adminState'] == x['operationalState']) for x in app_table])
        app_no_ready = set(x['name'] for x in app_table if x['adminState'] != x['operationalState'])

        # Verify that app_list contains all members from expapp_list
        if expapp_list.issubset(app_list):
            if len(app_state) == 1 and app_state.pop():
                return True
            else:
                self.class_logger.debug("Applications that aren't ready: %s" % (app_no_ready, ))
                return False
        else:
            self.class_logger.debug("Applications that aren't registered yet: %s" % (expapp_list - app_list, ))
            return False


class SwitchONS(SwitchONSGeneralMixin, SwitchReal):

    SWITCH_APPS = {"FulcrumApp", "onsps"}
    UI_RESTART_TIMEOUT = 25

    def __init__(self, config, opts):
        self.build_path = None
        self.cli_img_path = None
        self.cli_delay = None
        self.xmlrpcport = None
        super(SwitchONS, self).__init__(config, opts)
        self.xmlproxy = xmlrpcProxy("http://%s:%s/RPC2" % (self.ipaddr, self.port), timeout=180)
        self.local_xmlrpc_port = None
        if "use_sshtun" in self.config and self.config['use_sshtun'] > 0:
            self.class_logger.info("Using secure xmlrpc connection.")
            self._use_sshtun = True

        # devices are booted via netboot if parameter is True in config
        self.netboot = config.get("netboot", False)

    def _get_port_for_probe(self):
        return SwitchONSGeneralMixin._get_port_for_probe(self)

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
            time.sleep(1)
            self.powerboard.do_action(self.pwboard, self.pwport, self.pwboard_snmp_rw_community_string, self.powerboard.commands["On"])
        elif status == "Off":
            self.powerboard.do_action(self.pwboard, self.pwport, self.pwboard_snmp_rw_community_string, self.powerboard.commands["On"])
        else:
            raise SwitchException("Cannot determine device status.")

        if self.netboot:
            self.exec_netboot()

        # After snmp command is sent APC could restart switch
        # in few seconds. Terefore it's good to wait a little
        # to prevent fail login prompt detection.
        time.sleep(1)

        if self._use_serial:
            # Check if mgmt interface already configured.
            # Let's wait until device is up and running:
            # For real devices we have to check boot status on telnet.
            self.class_logger.debug("Waiting for telnet prompt and login...")
            self.get_serial(timeout=100, with_login=True, wait_login=30)
            self.close_serial()
        else:
            self.class_logger.debug("Waiting 10 seconds to allow device HW load...")
            time.sleep(10)

        # The switch loads really very long time.
        # Wait to reduce number of unsuccessful queries.
        # Also this could help to avoid entering boot shell after unexpected device reboot
        self.class_logger.debug("Waiting 15 seconds to allow device load all services...")
        time.sleep(15)

        if self.db_corruption and self._use_serial:
            self.class_logger.warning("Switch configuration DB is damaged. Performing emergency DB reset.")
            self.forced_clearconfig()
        elif self.db_corruption and not self._use_serial:
            self.class_logger.warning("Switch configuration DB is damaged. DB reset is skipped since serial access is disabled.")

        if self._use_serial:
            # Configure management interface before any further operations.
            self.get_serial(timeout=100, with_login=True, wait_login=0.1)
            if not self.check_mgmt_iface():
                self.setup_mgmt_iface()
            self.close_serial()

        if wait_on:
            # Set huge timeout because of issue ONS-3170
            self.waiton(timeout=self.startup_time)

        # Set status to On(True)
        self.status = True

        # Perform syslog configuration if one exists.
        self.setup_syslog()

        # Set initial ports speed
        self.speed_preconfig()

    def clearconfig(self):
        """Perform clearConfig query on switch using telnet.

        And try to configure management interface.

        """
        # If serial is disabled using default clearconfig function.
        if not self._use_serial:
            if self.db_corruption:
                self.class_logger.warning("Switch configuration DB is damaged. DB reset is skipped since serial access is disabled.")
            super(SwitchONS, self).clearconfig()
            return

        if self.db_corruption:
            self.class_logger.warning("Switch configuration DB is damaged. Performing emergency DB reset.")
            self.forced_clearconfig(wait_on=True)
            # Set initial ports speed
            self.speed_preconfig()
            self.setup_syslog()
            return

        self.class_logger.debug("Performing clearConfig on real switch.")
        self.class_logger.debug("Wait telnet prompt and login.")
        self.get_serial(timeout=240, with_login=None, wait_login=0.1)

        # Check that console is OK
        output, err, _ = self.telnet.exec_command(" ")

        try:
            self.console_clear_config()

            if not self.check_mgmt_iface():
                self.setup_mgmt_iface()

            self.setup_syslog()

            # Set initial ports speed
            self.speed_preconfig()

        finally:
            self.close_serial()

    def exec_netboot(self):
        """Method to execute netboot on device start.

        """
        trm = pexpect.spawn('telnet %s %d' % (self.config["portserv_host"], self.config["portserv_port"]))
        trm.expect_exact('Hit a key to start the shell...', 150)
        trm.sendline('')
        trm.expect_exact('shell> ', 10)
        trm.sendline('netboot\n')
        trm.close()
        trm.kill(0)

    def open_sshtun(self):
        """Establish ssh tunnel.

        """
        if self.sshtun is None:
            self.class_logger.debug("Creating sshtun instance ...")
            self.sshtun = sshtun.SSHTunnel((self.ipaddr, self._sshtun_port),
                                           self._sshtun_user, self._sshtun_pass,
                                           ("127.0.0.1", int(self.port)))

        if not self.sshtun.check():
            self.class_logger.debug("Establishing ssh tunnel ...")
            self.local_xmlrpc_port = self.sshtun.establish()
            self.xmlproxy = xmlrpcProxy("http://%s:%s/RPC2" %
                                        ("127.0.0.1", self.local_xmlrpc_port), timeout=180)

    def close_sstun(self):
        """Close ssh tunnel.

        """
        if self.sshtun is not None and self.sshtun.check():
            self.class_logger.debug("Closing ssh tunnel ...")
            self.sshtun.close()

    def get_env_prop(self, param):
        """Read properties from all devices.

        """
        if getattr(getattr(self, "rag", None), "role", "") == "slave":
            return "Slave_%s" % param
        else:
            if param == 'chipName':
                return getattr(self, 'jira_platform_name', self.instance_prop[param])
            return self.instance_prop[param]

    def get_processes(self, tc_name, skip_prcheck=None):
        """Procedure of getting processes on switch.

        Args:
            tc_name(str):  test case name
            skip_prcheck(list[str]):  list of processes to skip PID verification

        """
        return self.supervisorctl(tc_name, cmd="status", ssh=self.ssh, skip_prcheck=skip_prcheck)

    def supervisorctl(self, tc_name, cmd="status", ssh=None, skip_prcheck=None):
        """Procedure of calling supervisorctl tool on switch.

        Args:
            tc_name(str):  test case name
            cmd(str):  supervisorctl command
            ssh(CLISSH):  ssh object
            skip_prcheck(list[str]):  list of processes to skip PID verification

        """
        self.class_logger.debug("Supervisor procedure of getting processes is on.")
        p2pid = {}

        # Make dictionary of process to pid
        command = "sudo supervisorctl {0}".format(cmd)
        alternatives = [("Password:", "admin", False, False), ("password for", "admin", False, False), ]
        output, err = ssh.shell_command(command, alternatives=alternatives, timeout=25, ret_code=True, quiet=True)

        processes = [line for line in output.split("\n") if "pid" in line and
                     "platform:syslogd" not in line]

        for line in processes:
            pr_check = True
            if skip_prcheck:
                for pr in skip_prcheck:
                    if pr in line:
                        pr_check = False
            if pr_check:
                p2pid[line.split(" ")[0]] = line.split("pid ")[1].split(",")[0]
        return p2pid

    def check_mgmt_iface(self):
        """Check if management interface is configured on switch.

        Raises:
            SwitchException:  error on command execution

        Returns:
            bool:  True or False

        """
        self.class_logger.debug("Check if management interface is configured.")
        command = "ip addr show dev %s | grep 'inet ' --color=never" % self.mgmt_iface
        output, err, _ = self.telnet.exec_command(command.encode("ascii"),
                                                  sudo=True)
        if err:
            message = "Cannot check management interface status. Command '%s'.\nStdOut: %s\nStdErr: %s" % (command, output, err)
            self.class_logger.error(message)
            raise SwitchException(message)
        if output is not None and "inet " in output:
            try:
                found_ip = output.split("inet ")[1].split("/")[0].strip()
            except IndexError:
                found_ip = "<cannot recognize>"
            self.class_logger.debug("Switch has already configured management interface %s with IP:%s" % (self.mgmt_iface, found_ip, ))
            if found_ip != self.ipaddr:
                self.class_logger.debug("Switch management interface IP doesn't answer setup configuration and will be reconfigured.")
                return False
            else:
                return True
        else:
            self.class_logger.debug("Switch doesn't have configured management interface %s" % (self.mgmt_iface, ))
            return False

    def setup_mgmt_iface(self):
        """Configure management interface on switch.

        Raises:
            SwitchException:  error on command execution, timeout exceeded

        """

        self.class_logger.debug("Configure management interface %s." % self.mgmt_iface)
        # Wait until switch starts listening on port 8081
        command = "netstat -tnl | grep %s" % (self.port, )
        end_time = time.time() + 20
        wait_flag = True
        while time.time() <= end_time and wait_flag:
            err, output = None, None
            output, err, _ = self.telnet.exec_command(command.encode("ascii"))
            self.class_logger.debug("TelnetCMD StdOut:\n%s" % (output, ))
            if err:
                raise SwitchException("Cannot execute command '%s'. StdErr: %s" % (command, err))
            if output is not None and "LISTEN" in output:
                wait_flag = False
            else:
                time.sleep(0.5)
        # In case time is elapsed but wait_flag isn't set raise Timeout Exception
        if wait_flag:
            raise SwitchException("TimeOut exceeded. Switch isn't listening port %s on localhost." % (self.port, ))

        # Stabilization interval
        # Without this nb server cannot handle eth0 up status.
        time.sleep(10)

        cmd = [
            "import xmlrpclib", "rc = 'FAILED'",
            "s = xmlrpclib.ServerProxy('http://127.0.0.1:%s')" % (self.port, ),
            "rc = s.nb.MgmtPort.set.mode(1, 'Static')",
            "rc = s.nb.MgmtPort.set.address(1, '%s')" % (
                self._netmsk_to_cidr(self.ipaddr, self._net_mask), ),
            "rc = s.nb.MgmtPort.set.gateway(1, '%s')" % (self._default_gw, ),
            "rc = s.nb.Methods.applyMgmtPortConfig()",
            "rc = s.nb.MgmtPort.set.adminstate(1, 'Down')",
            "rc = s.nb.Methods.applyMgmtPortConfig()",
            "rc = s.nb.MgmtPort.set.adminstate(1, 'Up')",
            "rc = s.nb.Methods.applyMgmtPortConfig()",
            "print 'eth0 setup returnCode={0}'.format(rc)"]

        command = "python -c \"" + "; ".join(cmd) + "\""

        err, output = None, None
        output, err, _ = self.telnet.exec_command(command.encode("ascii"))
        self.class_logger.debug("Eth0 setup console output:\n%s" % (output, ))
        if err or "returnCode=FAILED" in output:
            message = "Cannot configure management interface. StdErr: %s, StdOut: %s" % (err, output, )
            self.class_logger.error(message)
            raise SwitchException(message)

    def rm_configdb(self, close_serial=True):
        """Remove configuration database.

        Args:
            close_serial(bool):  Close telnet session in the end.

        Returns:
            None

        """
        self.get_serial(timeout=15, with_login=True, wait_login=1)
        self.class_logger.info("Removing configuration data base of %s(%s)." % (self.name, self.ipaddr))
        output_r, err = self.telnet.shell_command("cd /persistent", sudo=False)
        self.class_logger.debug("Database removing output, error %s, output: %s" % (err, output_r))
        output_r, err = self.telnet.shell_command("ls | grep -v \"default-cfg\" | xargs -i -t sudo rm -rf {}", sudo=False)
        self.class_logger.debug("Database removing output, error %s, output: %s" % (err, output_r))
        output_r, err = self.telnet.shell_command("ls -la /persistent/", sudo=True)
        self.class_logger.debug("DB directory after rm, error %s, output: %s" % (err, output_r))
        if close_serial:
            self.close_serial()
        self.db_corruption = False

    def console_clear_config(self):
        """Clear device configuration using console connection

        """
        cmd = [
            "from xmlrpclib import ServerProxy", "rc = -1",
            "rc = ServerProxy('http://127.0.0.1:8081/RPC2').nb.clearConfig()",
            "print 'clearConfig() returnCode={0}.'.format(rc)"]
        command = "python -c \"" + "; ".join(cmd) + "\""

        output, err, _ = self.telnet.exec_command(command.encode("ascii"))
        if err:
            message = "Cannot perform clearConfig.\nCommand: %s.\nStdout: %s\nStdErr: %s" % (command, output, err)
            self.class_logger.error(message)
            self.db_corruption = True
            pytest.fail(message)
        else:
            if "returnCode=0." in output:
                self.class_logger.debug("ClearConfig finished. StdOut:\n%s" % (output, ))
            else:
                message = "ClearConfig failed. StdOut:\n%s" % (output, )
                self.class_logger.error(message)
                pytest.fail(message)

    def forced_clearconfig(self, wait_on=False, timeout=60):
        """Remove DB and restart necessary processes.

        Args:
            wait_on(bool):  Wait untill necessary apps are in run state after processes restart.
            timeout(int):  Time to wait until necessary apps are in run state.

        """
        # Removing configuration data base.
        self.rm_configdb(close_serial=False)
        self.class_logger.info("Stopping switchpp processes...")
        self.telnet.exec_command("supervisorctl stop all", sudo=True)
        self.class_logger.info("Starting switchpp processes...")
        self.telnet.exec_command("supervisorctl start all", sudo=True)
        self.close_serial()

        if wait_on:
            self.waiton(timeout=timeout)

        # Set initial ports speed
        self.speed_preconfig()


class SwitchSimulated(SwitchONSGeneralMixin, SwitchGeneral):
    """Simulated Switch in LXC containers class.

    """
    class_logger = loggers.ClassLogger()

    def __init__(self, config, opts):
        """Initialize SwitchSimulated class.

        Args:
            config(dict):  Configuration information.
            opts(OptionParser):  py.test config.option object which contains all py.test cli options.

        Raises:
            SwitchException:  incorrect switch path

        """
        self.build_path = environment.get_absolute_build_path(opts.build_path)
        if self.build_path is None:
            raise SwitchException("Could not find path to switch binaries - %s." % (opts.build_path, ))
        self.class_logger.info("SimSwitch binaries path: %s." % self.build_path)
        self.cli_img_path = config['cli_img_path']
        self.xmlrpcport = config['ip_port']
        self.cli_delay = 0.5

        super(SwitchSimulated, self).__init__(config, opts)
        for device_id in list(config['related_conf'].keys()):
            if config['related_conf'][device_id]['instance_type'] == "vlab":
                self.vlab_ip = config['related_conf'][device_id]['ip_host']
                self.vlab_iface = config['related_conf'][device_id]['ip_iface']
                break

        self.waiton_err_message = "LXC container is started but switch does not response on xmlrpc queries."

        self.popen_logfile = "switchpp%s.output.log" % (self.id, )

        # SSH connection credentials:
        self.ssh_user = config['cli_user']
        self.ssh_user_pass = config['cli_user_passw']
        self.ssh_user_prompt = config['cli_user_prompt']

        self.startup_time = 90

    def _get_port_for_probe(self):
        return SwitchONSGeneralMixin._get_port_for_probe(self)

    def start(self, wait_on=True):
        """Create and launch LXC container with switchpp.

        Args:
            wait_on(bool):  Indicates if wait for device status

        """
        self.class_logger.info("Starting LXC for switch with ip:%s port:%s..." % (self.ipaddr, self.port))

        # Check if it is an altamodel.
        if os_path_isfile(os_path_join(self.build_path, "bin", "ons-fulcrum")):
            self.class_logger.info("AltaModel is found.")
            self.__class__.SWITCH_APP = {"FulcrumApp"}

        log_wrap_out, log_wrap_err = loggers.pipe_loggers("switchpp%s" % (self.id, ), self.popen_logfile)

        # sudo env LD_LIBRARY_PATH=$PWD/lib ./bin/ons-lxc -n 1 -i br0 -a 10.0.5.101/24 -p 52
        lxc_id = str(int(self.port) - 8080)
        command = ["./ons-ctl",
                   "start",
                   "-n", lxc_id,
                   "-i", self.vlab_iface,
                   "-a", "%s/24" % self.ipaddr,
                   "-p", str(self.ports_count)]
        self.class_logger.debug("LXC start command: %s" % (" ".join(command)))
        process = Popen(command, stdout=log_wrap_out, stderr=log_wrap_err, close_fds=True,
                        cwd=os_path_join(self.build_path, "bin"))
        process = Popen(['lxc-wait', '-n', lxc_id, '-s', 'RUNNING'],
                        stdout=log_wrap_out, stderr=log_wrap_err, close_fds=True)
        process.wait()

        # let's wait until device is up and running:
        if wait_on:
            time.sleep(5)
            self.waiton(timeout=self.startup_time)

        # Set On(True) status
        self.status = True

        return self.xmlproxy

    def stop(self):
        """Terminate LXC container.

        """
        lxc_id = str(int(self.port) - 8080)
        process = Popen(["lxc-stop", "-n", lxc_id], stdout=PIPE, close_fds=True)
        process.wait()
        process = Popen(['lxc-wait', '-n', lxc_id, '-s', 'STOPPED'], stdout=PIPE, close_fds=True)
        process.wait()
        # try to remove LXC containers files in case lxc-wait did not do this for some reason
        try:
            lxc_env = os_path_join(self.build_path, "lxc", str(self.id))
            shutil.rmtree(lxc_env)
        except Exception:
            pass
        # try to restore tty settings
        try:
            Popen(["stty", "sane"])
        except Exception:
            pass

        self.waitoff(timeout=60)

        self.status = False

        return True

    def restart(self, wait_on=True, mode='powercycle'):
        """Restart LXC container.

        Args:
            wait_on(bool):  Indicates if wait for device status
            mode(bool):  restart mode. powercycle|ui

        """
        self.stop()
        return self.start(wait_on)
        self.ui.connect()

    def rm_configdb(self):
        """Remove configuration database.

        Raises:
            SwitchException:  not implemented

        """
        # TODO implement this for Simulated switch
        message = "This methods is not implemented for Simulated switch"
        raise SwitchException(message)

    def get_processes(self, tc_name, skip_prcheck=None):
        """Gets procecces-to-PID dictionary.

        Args:
            tc_name(str):  test case name
            skip_prcheck(list[str]):  list of processes to skip PID verification

        """
        p2pid = {}
        fpath = self.build_path + "/bin"

        # Create process-to-PID dictionary.
        output = list(self.execute_ssh_command("ps -aux"))
        processes = [line for line in output[0].split("\n") if fpath in line]

        for process in processes:
            clear_proc = []
            for proc_elem in process.split(' '):
                if proc_elem is not '':
                    clear_proc.append(proc_elem)
            for pname in clear_proc:
                if fpath in pname:
                    p2pid[pname.split('/')[-1]] = clear_proc[1]
        return p2pid

    def execute_ssh_command(self, command):
        """Executes command on switch.

        Args:
            command(str):  ssh command to execute

        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Make connection and create shell.
        client.connect(self.ipaddr, self._sshtun_port, self.ssh_user, self.ssh_user_pass)
        shell = client.invoke_shell()

        # Execute command and get results.
        _, stdout, stderr = client.exec_command(command)
        data = self._read_command_output(stdout, stderr, 'both')

        # Close connection.
        shell.close()
        client.close()

        return data

    def _read_command_output(self, stdout, stderr, ret_mode):
        """Read result of not-interactive command execution.

        Args:
            stdout(str):  StdOut info
            stderr(str):  StdErr info
            ret_mode(str):  return mode. both|stderr|stdout

        """
        if ret_mode.lower() == 'both':
            return stdout.read(), stderr.read()
        elif ret_mode.lower() == 'stderr':
            return stderr.read()
        else:
            return stdout.read()
