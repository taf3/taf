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


"""``dev_linux_host.py``

`Linux host device related functionality`

"""

import re
import sys
import time
import traceback
import operator
from itertools import chain, zip_longest

import pytest

from . import clissh
from . import clinns
from . import entry_template
from . import linux_host_bash
from . import loggers
from .custom_exceptions import ArgumentError


UI_MAP = {
    "linux_bash": linux_host_bash.LinuxHostBash,
}



class NICHelper(object):
    @staticmethod
    def NICS_IF_NO_LO(nic):
        return 'lo' != nic['name']

    @staticmethod
    def NICS_IF_NO_MGMT(nic):
        """TODO

        """
        pass

    @staticmethod
    def NIC_OBJ(nic):
        return nic

    NIC_NAME = operator.itemgetter('name')
    NIC_IP_ADDR = operator.itemgetter('ip_addr')


def autologin(function):
    """Decorator: performs login for self.ssh object.

    """
    def wrapper(*args, **kwargs):
        logout = False
        if not args[0].ssh.login_status:
            logout = True
            args[0].ssh.login()
        try:
            result = function(*args, **kwargs)
        finally:
            if logout:
                args[0].ssh.close()
        return result

    return wrapper


def autoshell(function):
    """Decorator: performs login and opens shell for self.ssh object.

    """
    def wrapper(*args, **kwargs):
        logout = False
        if not args[0].ssh.login_status:
            logout = True
            args[0].ssh.login()
        if not args[0].ssh.check_shell():
            args[0].ssh.open_shell()
        try:
            result = function(*args, **kwargs)
        finally:
            if logout:
                args[0].ssh.close()
        return result

    return wrapper


class GenericLinuxHost(entry_template.GenericEntry):
    """Generic Linux host pattern class.

    """

    class_logger = loggers.ClassLogger()

    ipaddr = None
    ssh_user = None
    ssh_pass = None
    ssh_pkey = None
    ssh_pkey_file = None
    ssh_port = 22

    DEFAULT_SERVER_WAIT_ON_TIMEOUT = 90

    def __init__(self, config, opts):
        """Initialize GenericLinuxHost class.

        Args:
            config(dict):  Configuration information.
            opts(OptionParser):  py.test config.option object which contains all py.test cli options.

        """
        super(GenericLinuxHost, self).__init__(config, opts)
        self.name = config['name'] if "name" in config else "noname"
        self.id = config['id']
        self.type = config['instance_type']
        self.nics = None
        self.ports, self.speed_ports, self.ports_map = self._get_speed_ports()
        self.port_list = self.speed_ports[:]

        # This should be set during start()
        self.mgmt_iface = None

        # ssh configs
        for cfg_item in ("ipaddr", "ssh_user", "ssh_pass", "ssh_port", "ssh_pkey", "ssh_pkey_file"):
            setattr(self, cfg_item, config.get(cfg_item, getattr(self.__class__, cfg_item)))
        if self.ipaddr and self.ssh_user and (self.ssh_pass or self.ssh_pkey or self.ssh_pkey_file):
            self.ssh = clissh.CLISSH(self.ipaddr, self.ssh_port, self.ssh_user, self.ssh_pass,
                                     pkey=self.ssh_pkey, key_filename=self.ssh_pkey_file)

        self.ssh_su_pass = config.get('ssh_su_pass')

        self.config_file = config.get('config_file')

        self.class_logger.info("Init Generic Linux Host: %s", self.ipaddr)

        self.status = False

        # Status dicts (are used to cleanup configuration).
        # Created bridge ifaces. (list of bridge names)
        self.bridges = []
        # Created vlan ifaces. (dict, key=iface, value=list of vlans)
        self.vlans = {}
        # Check if system supports VLAN creation.
        self.vlan_enabled = False
        # Created routes. (list of routes)
        self.route_list = []
        # Set address. (list of set address)
        self.ifconf_addrs = []

        # Initialize UI based on UI_MAP and cli --ui option
        self.ui = UI_MAP[self.opts.lhost_ui](self)
        self.class_logger.debug("ui = %s", self.ui)

    def _set_mgmt_interface(self, mgmt_ip):

        raw_data = self.exec_cmd(command="ip address show to {0}".format(mgmt_ip)).stdout
        if not raw_data:
            raise AttributeError("No management iface matches IP {0}.".format(mgmt_ip))
        row = re.search(r'(?P<index>\d*):\s(?P<name>[\w-]*)[@:]', raw_data)
        self.mgmt_iface = row.group('name')

    def connect_port(self, port_id):
        """Emulate port connection via setting adminMode into Up state.

        Args:
            port_id(int | str):  Port number

        """
        # Set initial ports speed
        self.speed_preconfig()

        self.class_logger.debug("Emulating connecting for port ID = %s", port_id)
        _port = self.ui.get_table_ports([port_id])[0]
        if _port['operationalStatus'] != "NotPresent":
            # Check if port is LAG member
            if _port["type"] == "LAGMember":
                # Use lag id as port id
                lag_table = self.ui.get_table_ports2lag()
                port_id = [x["lagId"] for x in lag_table if x["portId"] == port_id][0]
            self.ui.modify_ports([port_id], adminMode="Up")

    def exec_cmd(self, command, check_root=True):
        """Exec shell command with root privileges and print warning message in case StdErr isn't empty.

        Args:
            command(str):  Command to be executed
            check_root(bool):  Flag indicates root privileges

        Returns:
            tuple(str, str, int) | CmdStatus:  Returns CmdStatus namedtuple of stdout, stderr, return code

        Examples::

            env.lhost[1].ssh.exec_cmd('sudo brctl addbr br0')

        """
        if check_root and self.ssh_user != "root":
            # requires password less sudo config
            command = "sudo {}".format(command)
        cmd_status = self.ssh.exec_command(command)
        return cmd_status

    # @autologin
    def ifconfig(self, mode=None, ports=None, ipaddr=None, ip6addr=None, mac=None):
        """Assign an address to a network interface and/or configure network interface parameters.

        Args:
            mode(str):  Flag 'up/down' activates/deactivates the specified network interface, flag 'stats' displays tx/rx statistic of the given interface
            ports(list):  Specific interface name parameter
            ipaddr(list):  IPv4 address to be assigned to the specific interface
            ip6addr(list):  IPv6 address to be assigned to the specific interface
            mac(list):  Set the hardware address on the interface

        Raises:
            ArgumentError:  ports value is None, mode is not in {"up", "down"}, length of ports, ipaddr, ip6addr or mac not equal if set

        Returns:
            dict:  if mode='stats', return interface statistic

        Examples::

            env.tg[1].ifconfig("up", ports=[ports[("tg1", "lh1")][1]], ipaddr=["193.160.0.1/24"], ip6addr=["1000:160::2/64"], mac=["00:12:14:00:10:13"])

        """
        # Validate that params list corresponds with ports list.
        def validate_params(var, name):
            if not len(var) == len(ports):
                raise ArgumentError("The lengths of the {0} and ports lists are not equal.".format(name))

        if mode not in ["up", "down", "stats"]:
            raise ArgumentError("Unknown mode parameter value - {0}".format(mode))

        self.ui.generate_port_name_mapping()
        if mode in ["up", "down"]:
            if ports is None:
                ports = ["lo", ] + self.ports

            if ipaddr:
                validate_params(ipaddr, "ipaddr")
                for ipaddress, port in zip(ipaddr, ports):
                    if ipaddress is not None:
                        if ipaddress == "0.0.0.0":
                            self.ui.modify_ports([port], ipAddr=None)
                        else:
                            self.ui.modify_ports([port], ipAddr=ipaddress)
                            self.ifconf_addrs.append('ip addr del {1} dev {0}'.format(port, ipaddress))

            if ip6addr:
                validate_params(ip6addr, "ip6addr")
                for ip6address, port in zip(ip6addr, ports):
                    if ip6address is not None:
                        self.ui.modify_ports([port], ipAddr=ip6address)
                        self.ifconf_addrs.append('ip addr del {1} dev {0}'.format(port, ip6address))
            if mac:
                validate_params(mac, "mac")
            else:
                mac = []
            for macaddress, port in zip_longest(mac, ports):
                if macaddress is None:
                    self.ui.modify_ports([port], adminMode=mode.capitalize())
                else:
                    self.ui.modify_ports([port], macAddress=macaddress, adminMode=mode.capitalize())

        elif mode == "stats":
            stats = {}
            for port in ports:
                command = "ifconfig -s -a {0}".format(port)
                so = self.exec_cmd(command).stdout
                if so:
                    raw_stat = [x.split("\t") for x in re.sub("[\t]+", "\t", so).split("\n")]
                    raw_stat_params = raw_stat[0][0].split(" ")
                    raw_stat_values = raw_stat[1][0].split(" ")
                    while raw_stat_values.count('') > 0:
                        raw_stat_values.remove('')
                    while raw_stat_params.count('') > 0:
                        raw_stat_params.remove('')
                    stats[port] = {}
                    for i, v in enumerate(raw_stat_params):
                        stats[port][raw_stat_params[i]] = raw_stat_values[i]
            return stats


    @autologin
    def routes(self, mode=None, netwrk=None, netwrk6=None, ports=None, next_hop=None,
               next_hop6=None, option=None, metric=None, prefixtoroute=None, lo=None):
        """Assign routes to specific hosts or networks via an interface after it has been configured with the ifconfig utility.

        Args
            mode(str):  Flag 'up/down' change state of the interface to up or down.
            netwrk(list):  List of v4 routes to be assigned on the device.
            netwrk6(list):  List of v6 routes to be assigned on the device.
            ports(list):  List of Port ID
            next_hop(list):  List of v4 nexthop router parameters
            next_hop6(list):  List of v6 nexthop router parameters
            option(bool):  Flag indicates to validate params
            metric(bool):  Allow to configure metric
            prefixtoroute(str):  Prefixtoroute value
            lo(str):  IPv4 local address

        Raises:
            Exception:  mode is not in {"up", "down"}

        Returns:
            None

        Examples::

            env.tg[1].routes(netwrk6=["default"], next_hop6=["1000:160::1"])

        """
        # Validate that params list corresponds with ports list.
        def validate_params(var, var_2, name, name_2):
            if not len(var) == len(var_2):
                raise Exception("The lengths of the lists {0} and {1} is not equal.".format(name, name_2))

        commands = []

        if mode in ["up", "down"]:
            if ports:
                for port in ports:
                    command_list = ["ip", "link", "set", "dev", port, mode]
                    commands.append(' '.join(command_list))
            else:
                ports = ["lo", ] + self.ports
                for port in ports:
                    command_list = ["ip", "link", "set", "dev", port, mode]
                    commands.append(' '.join(command_list))

            device = ""
            if next_hop is not None and next_hop[0] == '0.0.0.0' and len(next_hop) == 1 and len(netwrk) == 1 and len(ports) == 1:
                device = "dev {0}".format(ports[0])

            if next_hop:
                for i, v in enumerate(ports):
                    if netwrk[i] and next_hop[i]:
                        version = "-4"
                        if netwrk[i] == "default":
                            validate_params(next_hop, ports, "nexthop", "ports")
                            command_list = ["ip", version, "default", "via", next_hop[i], "dev", ports[i],
                                            device]
                            if device == "":
                                command_list.pop()
                            commands.append(' '.join(command_list))
                        else:
                            validate_params(next_hop, netwrk, "nexthop", "netwrk")
                            command_list = ["ip", version, "route", "add", netwrk[i], "via", next_hop[i], "dev", ports[i]]
                            commands.append(' '.join(command_list))

            if next_hop6:
                for i, v in enumerate(next_hop6):
                    if netwrk6[i] and next_hop6[i]:
                        version = "-6"
                        if netwrk6[i] == "default":
                            if not option:
                                command_list = ["ip", version, "route", "add", "default", "via", next_hop6[i], "dev", ports[i]]
                                commands.append(' '.join(command_list))
                            else:
                                validate_params(next_hop6, ports, "nexthop6", "ports6")
                                command_list = ["ip", version, "route", "add", "default", "via", next_hop6[i], "dev", ports[i]]
                                commands.append(' '.join(command_list))
                        else:
                            validate_params(next_hop6, netwrk6, "nexthop6", "netwrk6")
                            command_list = ["ip", version, "route", "add", netwrk6[i], "via", next_hop6[i], "dev", ports[i]]
                            commands.append(' '.join(command_list))

            if metric:
                command_list = ["ip", "-6", "route", "add", prefixtoroute, "via", lo, "dev", "sit1", "metric", "1"]
                commands.append(' '.join(command_list))

            del_commands = [command.replace("add", "del").replace("up", "down") for command in commands]
            self.route_list.extend(del_commands)

            for command in commands:
                self.exec_cmd(command)
        else:
            raise Exception("Unknown mode parameter value - {0}".format(mode))

    @autologin
    def ipforward(self, version=None):
        """Enabling ipv4 and ipv6 forwarding.

        Args:
            version(list):  List of v4/v6 versions

        Raises:
            Exception:  incorrect IP version

        Returns:
            None

        Examples::

            env.tg[1].ipforward(version=["-4", "-6"])

        """
        allowed_versions = ["-4", "-6"]
        if version is None:
            version = ["-4"]
        # Verificaton:
        for _v in version:
            if _v not in allowed_versions:
                raise Exception("Incorrect version value: {0}. Allowed values is: {1}".format(version, allowed_versions))
        for i, v in enumerate(version):
            if version[i] == "-4":
                command_list = ["sysctl", "-w", "net.ipv4.ip_forward=1"]
                command_forward = ' '.join(command_list)
                self.exec_cmd(command_forward)
            if version[i] == "-6":
                command_list = ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"]
                command_forward = ' '.join(command_list)
                self.exec_cmd(command_forward)

    @autologin
    def brctl(self, mode="add", ports=None, brname=None, stp=None, stp_cfg=None):
        """Create/delete/configure bridge interface.

        Args:
            mode(str):  Allowed values: add, cfg, del, stpstat, macs
                        - add - allow to create new instance of the eth bridge
                        - cfg - allow to change previously set specific configurations
                        - del - allow to delete the instance of the ethernet bridges
                        - delif - allow to delete interface from bridge
                        - stpstat - allow to show current interfaces stp status
                        - macs - allow to show a list of a learned MAC address for the bridge
            ports(list):  List of interfaces
            brname(str):  Name of the instance of the ethernet bridges
            stp(str): Flag  'up/down' enable/disable stp on the bridges
            stp_cfg(str):  Dictionary of settings,
                           keys:
                           - 'bprio' - bridge priority parameter
                           - 'pathcost' - list of tupples with ports and pathcosts(to be assigned on the port) values
                           - 'hello' - set bridge's the hello time
                           - 'maxage' - set bridge's maximum message age
                           - 'fwdelay' - set bridge's forward delay
                           - 'pprio' - lists of tuples with ports and port priorities(to be assigned on the port) value

        Raises:
            Exception:  brname is None, unknown mode.

        Returns:
            str:  bridge name if mode='add', or stp bridge status if mode='stpstat'

        Examples::

            env.tg[1].brctl("add", ports=[p1, p2], stp=True, stp_cfg={"bprio": 1000, "pathcost": [(p1, 10), (p2, 100)], "hello":300, "maxage":10,
            "fwdelay":30, "pprio":[(p1, 10)]})
            env.tg[1].brctl("stpstat", brname=br0)
            env.tg[1].brctl("delif", ports=[p2], brname=br0)

        """
        def stp_cfg_processing():
            for key in stp_cfg:
                if key == "bprio":
                    commands.append("brctl setbridgeprio {0} {1}".format(brname, stp_cfg[key]))
                elif key == "pathcost":
                    for port, cost in stp_cfg[key]:
                        commands.append("brctl setpathcost {0} {1} {2}".format(brname, port, cost))
                elif key == "hello":
                    commands.append("brctl sethello {0} {1}".format(brname, stp_cfg[key]))
                elif key == "maxage":
                    commands.append("brctl setmaxage {0} {1}".format(brname, stp_cfg[key]))
                elif key == "fwdelay":
                    commands.append("brctl setfd {0} {1}".format(brname, stp_cfg[key]))
                elif key == "pprio":
                    for port, prio in stp_cfg[key]:
                        commands.append("brctl setportprio {0} {1} {2}".format(brname, port, prio))

        def add_ports():
            for port in ports:
                commands.append("brctl addif {0} {1}".format(brname, port))

        if mode == "add":
            bridges = self.ssh.exec_command("ifconfig -s -a | grep "
                                            "^lhbr | awk '{print "
                                            "$1}'").stdout
            bridges = bridges.split("\n") if bridges else []
            max_id = max([int(x[4:]) if x[4:].isdigit() else None for x in bridges]) if bridges else 0
            brname = "lhbr" + str(max_id + 1)

            commands = ["brctl addbr " + brname]
            if ports:
                add_ports()
            stp = stp if stp is not None else False
            commands.append("brctl stp {0} {1}".format(brname, "on" if stp else "off"))
            if stp_cfg is not None:
                stp_cfg_processing()
            commands.append("ifconfig {0} up".format(brname))

            for command in commands:
                self.exec_cmd(command)

            self.bridges.append(brname)

            return brname

        elif mode == "del":
            if brname is None:
                raise Exception("Bridge name is not set.")
            commands = ["ifconfig {0} down".format(brname),
                        "brctl delbr {0}".format(brname)]

            for command in commands:
                self.exec_cmd(command)

        elif mode == "delif":
            if brname is None or ports is None:
                raise Exception("Bridge name or port is not set.")
            commands = []
            for port in ports:
                commands.append("brctl delif {0} {1}".format(brname, port))
            for command in commands:
                self.exec_cmd(command)

        elif mode == "cfg":
            if brname is None:
                raise Exception("Bridge name is not set.")
            commands = []
            if stp is not None:
                stp_cmd = "on" if stp else "off"
                commands.append("brctl stp {0} {1}".format(brname, stp_cmd))
            if ports:
                add_ports()
            if stp_cfg is not None:
                stp_cfg_processing()

            for command in commands:
                self.exec_cmd(command)

        elif mode == "stpstat":
            if brname is None:
                raise Exception("Bridge name is not set.")
            command = "brctl showstp {0}".format(brname)
            so = self.exec_cmd(command).stdout
            stats = {}
            if so:
                # Remove repeated \t and split stdout by \t and \n.
                raw_stat = [x.split("\t") for x in re.sub("[\t]+", "\t", so).split("\n")]
                key = None
                for item in raw_stat:
                    if len(item) == 1:
                        # Port or empty line found
                        key = item[0].strip()
                        # In case it's port, it should contain it's own number. E.g. 'eth0 (1)'.
                        name_num = key.split(" ")
                        port_num = None
                        if len(name_num) == 2:
                            key = name_num[0]
                            port_num = name_num[1]
                        stats[key] = {}
                        if port_num is not None:
                            stats[key]['port number'] = port_num.strip("(").strip(")")
                        continue
                    if len(item) >= 2:
                        # 2 elements: key    value
                        stats[key][item[0].strip()] = item[1].strip()
                    if len(item) >= 4:
                        # 4 elements: key    value    key    value
                        # Skip reading of the first pair because it has to be read in previous if-block.
                        stats[key][item[2].strip()] = item[3].strip()
            return stats

        elif mode == "macs":
            if brname is None:
                raise Exception("Bridge name is not set.")
            command = "brctl showmacs {0}".format(brname)
            so = self.exec_cmd(command).stdout
            macs = {}
            if so:
                # Remove repeated \t and split stdout by \t and \n.
                raw_macs = [x.split("\t") for x in re.sub("[\t]+", "\t", so).split("\n")]
                keys = raw_macs[0]
                for line in raw_macs[1:]:
                    pnum = line[0].strip()
                    if pnum not in macs:
                        macs[pnum] = []
                    macs[pnum].append({k.strip(): v.strip() for k, v in zip(keys[1:], line[1:])})
                # Drop empty key.
                macs.pop("")
            return macs

        else:
            message = "Unknown mode for brctl method."
            self.class_logger.error(message)
            raise Exception(message)

    @autologin
    def getmac(self, port):
        """Return port's MAC address.

        Args:
            port(str/tuple for Ixia):  Traffic generator's porta

        Returns:
            str:  Mac address of the device

        Examples::

            stp_env.tg[4].getmac(ports[("tg4", "tg3")][1])

        """
        command = "ip link show {0}".format(port)
        so = self.exec_cmd(command).stdout
        mac = None
        if so:
            lines = so.split("\n")[1].split(" ")
            lines = list(filter(len, lines))
            mac = lines[1]
        return mac.strip()

    @autologin
    def enable_8021q(self):
        """Check and enable VLANs if system supports 802.1q.

        Raises:
            Exception:  unsupported 802.1q feature

        Notes:
            Method searchs 8021q kernel module and tries to load them.

        """
        # Check if system supports 8021q
        so = self.ssh.exec_command("modprobe -l | grep 8021q").stdout
        if not so or "8021q" not in so:
            raise Exception("Current OS doesn't support 802.1q.")
        # Check if 8021q is already loaded and try to load it if not.
        so = self.ssh.exec_command("lsmod | grep ^8021q").stdout
        if not so or "8021q" not in so:
            command = "modprobe 8021q 2>&1"
            if self.ssh_user != "root":
                command = "sudo " + command
            so_load = self.ssh.exec_command(command).stdout
            so = self.ssh.exec_command("lsmod | grep ^8021q").stdout
            if not so or "8021q" not in so:
                raise Exception("Fail to load 8021q:\n{0}".format(so_load))
        self.vlan_enabled = True

    @autologin
    def vconfig(self, mode, port, vlan):
        """Perform VLAN configuration.

        Args:
            mode(str):  Flag add/rem allow to create/remove vlan-devices
            port(str):  Name of the ethernet card that hosts the VLAN
            vlan(int):  Vlan-device which represents the virtual lan on the physical lan

        Raises:
            Exception:  mode not in {"add", "rem"}, port is already in vlan

        Returns:
            str:  Vlan-device value in format 'port.vlan'

        Examples::

            env.tg[1].vconfig("add", port=ports[("tg1", "tg2")][1], vlan=3)
            env.tg[1].vconfig("rem", port=ports[("tg1", "tg2")][1], vlan=3)

        """
        if not self.vlan_enabled:
            self.enable_8021q()

        if mode in "add":
            if port in self.vlans and vlan in self.vlans[port]:
                raise Exception("Port {0} already in {1} vlan".format(port, vlan))
            command = "vconfig add {0} {1}".format(port, vlan)
            self.exec_cmd(command)
            if port not in self.vlans:
                self.vlans[port] = []
            self.vlans[port].append(vlan)
            return "{0}.{1}".format(port, vlan)

        elif mode == "rem":
            command = "vconfig rem {0}.{1}".format(port, vlan)
            self.exec_cmd(command)
            self.vlans[port].remove(vlan)
            if not self.vlans[port]:
                self.vlans.pop(port)
            return "{0}.{1}".format(port, vlan)

        else:
            raise Exception("Incorrect mode={0}".format(mode))

    @autologin
    def ethtool(self, port, mode, **kwargs):
        """Perform ethtool configuration.

        Args:
            port(str):  Name of the interface
            mode(str):  Flag allows to configure interface ('generic')
            kwargs(dict):  Interface configuration key/value pairs

        Raises:
            Exception:  mode is not "generic"

        """
        if mode in "generic":
            args = " ".join(["{0} {1}".format(*i) for i in list(kwargs.items())])
            command = "ethtool -s {0} {1}".format(port, args)
            self.exec_cmd(command)

        else:
            raise Exception("Incorrect mode={0}".format(mode))

    def _get_nics(self, force_check=False):
        """Returns list of detected network adapterrs in the system

        Notes:
            Order of the adapters is very important. It should be according to how the
            networks are defined when VM is created. Proper order is in self.os_networks

        Args:
            force_check(bool): force re-reading nics

        Returns:
            list: list of nics

        """
        if self.nics is None or force_check:
            detected_nics = self.ui.get_table_ports(ip_addr=True)
            # filter out interfaces with no IP
            self.nics = [nic for nic in detected_nics if nic['ip_addr']]
        return self.nics

    def get_nics_if(self, f, force_check=False):
        if f:
            return list(filter(f, self._get_nics(force_check)))
        return self._get_nics()

    def map_nics_if(self, f, mapper=NICHelper.NIC_OBJ, force_check=False):
        nics = self.get_nics_if(f, force_check)
        if mapper:
            return list(map(mapper, nics))
        return nics

    def get_nics(self, no_lo=True, mapper=None, force_check=False):
        f = NICHelper.NICS_IF_NO_LO if no_lo else None
        return self.map_nics_if(f=f, mapper=mapper, force_check=force_check)

    def get_nics_names(self, no_lo=True, force_check=False):
        f = NICHelper.NICS_IF_NO_LO if no_lo else None
        mapper = NICHelper.NIC_NAME
        return self.map_nics_if(f=f, mapper=mapper, force_check=force_check)

    def get_nics_ips(self, no_lo=True, force_check=False):
        f = NICHelper.NICS_IF_NO_LO if no_lo else None
        mapper = NICHelper.NIC_IP_ADDR
        return self.map_nics_if(f=f, mapper=mapper, force_check=force_check)

    def get(self, init_start=False, retry_count=1):
        """Get or start linux host instance.

        Args:
            init_start(bool):  Perform switch start operation or not
            retry_count(int):  Number of retries to start(restart) linux host

        Returns:
            None or raise an exception.

        Notes:
            Also self.opts.fail_ctrl attribute affects logic of this method.
            fail_ctrl is set in py.test command line options (read py.test --help for more information).

        """
        # If fail_ctrl != "restart", restart retries won't be performed
        # as restart is not implemented for lhosts, retries makes no sense.
        # if self.opts.fail_ctrl != "restart":
        #    retry_count = 1

        try:
            if init_start:
                self.start()
            else:
                self.waiton()
        except KeyboardInterrupt as ex:
            message = "KeyboardInterrupt while checking device {0}({1})...".format(
                    self.name, self.ipaddr)
            self.class_logger.info(message)
            self.sanitize()
            pytest.exit(message)
        except Exception:
            self.class_logger.error(
                "Error while checking device %s(%s)...", self.name, self.ipaddr)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback_message = traceback.format_exception(exc_type, exc_value, exc_traceback)
            message = "Error while checking device {0}({1}):\n{2}".format(
                self.name, self.ipaddr, "".join(traceback_message))
            sys.stderr.write(message)
            sys.stderr.flush()
            pytest.fail(message)

    def waiton(self, timeout=DEFAULT_SERVER_WAIT_ON_TIMEOUT):
        """Wait until device is fully operational.

        Args:
            timeout(int):  Wait timeout

        Raises:
            SwitchException:  device doesn't response

        Returns:
            dict:  Status dictionary from probe method or raise an exception.

        """
        status = None
        message = "Waiting until device {0}({1}) is up.".format(self.name, self.ipaddr)
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
                    message = "KeyboardInterrupt while checking switch {0}({1})...".format(
                            self.name, self.ipaddr)
                    self.class_logger.info(message)
                    self.sanitize()
                    pytest.exit(message)
                if status["isup"]:
                    stop_flag = True
            else:
                # Time is elapsed.

                port = self._get_port_for_probe()
                message = "Timeout exceeded. IP address {0} port {1} doesn't respond.".format(
                    self.ipaddr, port)
                self.class_logger.warning(message)
                raise Exception(message)
            if not stop_flag:
                time.sleep(0.75)

        return status

    def probe(self):
        """Probe linux host with UI call.

        Returns:
            dict:  Dictionary (_object) with switchpp status parameters or raise an exception.

        """
        _object = {
            'isup': False,
            'type': "unknown",
            'prop': {}
        }

        if clissh.probe_port(self.ipaddr, self._get_port_for_probe(), self.class_logger):
            try:
                # Try to wait until device is ready to process
                self.ui.check_device_state()
                _object['isup'] = True
            except Exception as err:
                self.class_logger.info(
                    "Caught an exception while probing the device: "
                    "Error type: %s. Error msg: %s", type(err), err)
        return _object

    def start(self, wait_on=True):
        """Mandatory method for environment specific classes.

        Args:
            wait_on(bool):  Wait for device is loaded

        """
        # Optionally put power board information here for restart
        if wait_on:
            self.waiton()
        self.speed_preconfig()
        self._set_mgmt_interface(self.config['ipaddr'])

    def stop(self, with_cleanup=True):
        """Mandatory method for environment specific classes.

        Args:
            with_cleanup(bool):  Flag to perform cleanup

        """
        if not self.status:
            self.class_logger.info(
                "GenericLinuxHost %s:%s is already stopped.", self.name, self.id)
        else:
            if with_cleanup:
                self.cleanup()

    def cleanup(self):
        """Remove created configuration.

        """
        if self.bridges:
            for brname in self.bridges[:]:
                self.brctl("del", brname=brname)
        if self.vlans:
            for port in list(self.vlans):
                for vlan in self.vlans[port][:]:
                    self.vconfig("rem", port, vlan)
        if self.route_list:
            for command in self.route_list[:]:
                self.exec_cmd(command)
                self.route_list.remove(command)
        if self.ifconf_addrs:
            for command in self.ifconf_addrs[:]:
                self.exec_cmd(command)
                self.ifconf_addrs.remove(command)
        self.ui.clear_config()

    def restart(self, wait_on=True):
        """Mandatory method for environment specific classes.

        Args:
            wait_on(bool):  Wait for device is loaded

        """
        pass

    def create(self):
        """Start linux host or get running one.

        Notes:
            This is mandatory method for all environment classes.
            Also self.opts.get_only attribute affects logic of this method.
            get_only is set in py.test command line options (read py.test --help for more information).

        """
        init_start = not self.opts.get_only
        return self.get(init_start=init_start)

    def destroy(self):
        """Stop or release linux host.

        Notes:
            This is mandatory method for all environment classes.
            Also self.opts.leave_on and get_only  attributes affect logic of this method.
            leave_on and get_only are set in py.test command line options (read py.test --help for more information).

        """
        if not self.status:
            self.class_logger.info(
                "Skip Linux Host id:%s(%s) destroying because it already has Off status.", self.id, self.name)
            return
        if not self.opts.leave_on and not self.opts.get_only:
            self.stop()

        self.sanitize()

    def sanitize(self):
        """Perform any necessary operations to leave environment in normal state.

        """
        pass

    def check(self):
        """Mandatory method for environment specific classes.

        """
        pass

    def _get_port_for_probe(self):
        """Get port ID.

        Returns:
            int:  ssh tunnel ports ID

        """
        return int(self.ssh_port)

    def _get_speed_ports(self):
        """Get slave and master ports from config.

        Returns:
            list:  List of ports (slave and master) used in real config

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

    def speed_preconfig(self, wait_for_ports=False):
        """Function for ports speed preconfiguration.

        Args:
            wait_for_ports(int):  wait for Ports table changes size

        """

        def _normalize_port_list(ports_list):
            """Get list of Master ports.

            """
            master_ports = set()
            ports = set()
            for _port in ports_list:
                m_port = _get_master_port(_port)
                master_ports.add(m_port)
                if m_port != _port:
                    ports.add(_port)

            return list(chain(master_ports, ports))

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
            for key, ports in speed_dict.items():
                normalized_speed_dict[key] = _normalize_port_list(ports)

            for speed, ports in normalized_speed_dict.items():
                self.setup_ports_speed_configuration(ports, speed)

    def setup_ports_speed_configuration(self, ports=None, speed=10000):
        """Configure ports speed.

        Args:
            ports(list[int]):  list of ports to set speed value
            speed(int):  speed value

        """
        if ports is not None:
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


class IpNetworkNamespace(GenericLinuxHost):
    """Namespace simulated class.

    """

    class_logger = loggers.ClassLogger()

    def __init__(self, config, opts):
        """Initialize IpNetworkNamespace class.

        Args:
            config(dict):  Configuration information.
            opts(OptionParser):  py.test config.option object which contains all py.test cli options.

        """
        self.class_logger.info("Init namespace started.")
        super(IpNetworkNamespace, self).__init__(config, opts)
        self.name = config['name']
        # SSH emulator
        # Sudo prompt is required parameter for CLISSHNetNS and it is set to default Ubuntu sudo prompt.
        # But in most cases TAF has to be started with sudo and password shouldn't be asked.
        self.ssh = clinns.CLISSHNetNS(self.name, self.ipaddr, self.ssh_port or 22,
                                      self.ssh_user, self.ssh_pass,
                                      sudo_prompt="[sudo] password for {0}:".format(self.ssh_user))
        # Mgmt br ip is always the last host ip in network
        self.mgmt_ip = self.ipaddr[0:self.ipaddr.rfind(".")] + ".254"
        # Set up management ifaces
        self.mgmt_br = "mbr{0}".format(self.mgmt_ip.replace(".", ""))
        # Management iface
        self.mgmt_if = "veth{0}".format(self.id)

    def start(self, wait_on=True):
        """Method for network namespace create.

        Args:
            wait_on(bool):  Wait for device is loaded

        Raises:
            Exception:  error on namespace creating

        """
        command = "ip netns list"
        so, _, rc = self.ssh.native_cmd(command)
        if self.name in so.split():
            message = "Namespace is already created"
            raise Exception(message)

        command = "ip netns add " + self.name

        so, se, rc = self.ssh.native_cmd(command)
        if rc != "0":
            message = "Cannot create network namespace. Return code = {0}".format(rc)
            self.class_logger.error(message)
            raise Exception(message)

        self.add_mgmt_bridge()
        self.add_mgmt_iface()

        self.status = True

    def stop(self, with_cleanup=True, del_mgmt_br=False):
        """Method for namespace restore.

        Args:
            with_cleanup(bool):  Flag to perform cleanup
            del_mgmt_br(bool):  Flag to delete management bridge

        """
        if self.opts.get_only or self.opts.leave_on:
            # Skipping stop in case get_only or leave_on
            return

        if not self.status:
            self.class_logger.info(
                "IpNetworkNamespace %s:%s is already stopped.", self.name, self.id)
            return

        if with_cleanup:
            self.cleanup()
        if del_mgmt_br:
            self.del_mgmt_bridge()

        command = "ip netns delete " + self.name
        so, se, rc = self.ssh.native_cmd(command)

        self.status = False

    def check_mgmt_bridge(self):
        """Check if mgmt bridge is created.

        """
        command = "ifconfig " + self.mgmt_br
        so, _, _ = self.ssh.native_cmd(command)
        if so:
            return True
        else:
            return False

    def add_mgmt_bridge(self):
        """Create mgmt bridge on host.

        Raises:
            Exception:  error on bridge creating

        """
        so, se, rc = None, None, "0"
        if not self.check_mgmt_bridge():
            command = "brctl addbr " + self.mgmt_br
            so, se, rc = self.ssh.native_cmd(command)
        if rc != "0" or not self.check_mgmt_bridge():
            message = ("Failed to create management bridge for Network namespaces.\n" +
                       "Stdout: {0}, Stderr: {1}".format(so, se))
            self.class_logger.error(message)
            raise Exception(message)
        else:
            command = "ifconfig {0} {1} up".format(self.mgmt_br, self.mgmt_ip)
            self.ssh.native_cmd(command)

    def del_mgmt_bridge(self):
        """Delete mgmt bridge on host.

        Raises:
            Exception:  error on bridge deleting

        """
        if self.check_mgmt_bridge():
            command = "ifconfig {0} down".format(self.mgmt_br)
            self.ssh.native_cmd(command)
            command = "brctl delbr " + self.mgmt_br
            so, se, rc = self.ssh.native_cmd(command)
        if rc != "0" or not self.check_mgmt_bridge():
            message = ("Failed to delete management bridge for Network namespaces.\n" +
                       "Stdout: {0}, Stderr: {1}".format(so, se))
            self.class_logger.error(message)
            raise Exception(message)

    def add_mgmt_iface(self):
        """Create management iface and add it to host level bridge.

        Raises:
            Exception:  error on creating management interface

        """
        command = "ip link add {0} type veth peer name {0} netns {1}".format(self.mgmt_if, self.name)
        so, se, rc = self.ssh.native_cmd(command)
        if rc != "0":
            message = ("Failed to create management iface for {0}.\n".format(self.name))
            self.class_logger.error(message)
            raise Exception(message)
        else:
            self.ssh.native_cmd("brctl addif {0} {1}".format(self.mgmt_br, self.mgmt_if))
            self.ssh.native_cmd("ifconfig {0} up".format(self.mgmt_if))
            self.ssh.exec_command("ifconfig {0} {1} up".format(self.mgmt_if, self.ipaddr))

    def del_mgmt_iface(self):
        """Delete management iface and add it to host level bridge.

        Raises:
            Exception:  error on deleting management interface

        """
        command = "ip link delete {0}".format(self.mgmt_if)
        so, se, rc = self.ssh.native_cmd(command)
        if rc != "0":
            message = ("Failed to delete management iface for {0}.\n".format(self.name))
            self.class_logger.error(message)
            raise Exception(message)

    def create(self):
        """Start Linux host or get running one.

        Notes:
             This is mandatory method for all environment classes.
             Also self.opts.get_only attribute affects logic of this method.
             get_only is set in py.test command line options (read py.test --help for more information).

        """
        if not self.opts.get_only:
            return self.start()

    def destroy(self):
        """Stop or release Linux host.

        Notes:
            This is mandatory method for all environment classes.
            Also self.opts.leave_on and get_only  attributes affect logic of this method.
            leave_on and get_only are set in py.test command line options (read py.test --help for more information).

        """
        if not self.status:
            self.class_logger.info(
                "Skip Linux Host:%s(%s) destroying because it's has already Off status.", self.id, self.name)
            return
        if not self.opts.leave_on and not self.opts.get_only:
            self.stop()

        self.sanitize()

    def sanitize(self):
        """Perform any necessary operations to leave environment in normal state.

        """
        pass


ENTRY_TYPE = "linux_host"
INSTANCES = {"generic": GenericLinuxHost, "netns": IpNetworkNamespace}
NAME = "lhost"
LINK_NAME = "lh"
