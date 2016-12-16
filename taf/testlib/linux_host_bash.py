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

@file  linux_host_bash.py

@summary  Linux Host UI wrappers Implementation
"""
import re
import json
import time
import itertools
import ipaddress as ipaddr
from collections import ChainMap

import pytest

from testlib.helpers import group_get
from testlib.linux_host_interface import LinuxHostInterface
from testlib.custom_exceptions import SwitchException, UICmdException, UIException
from testlib.custom_exceptions import AccessError, ArgumentError, BoundaryError
from testlib.custom_exceptions import ExistsError, NotExistsError, InvalidCommandError
from testlib.linux.commands import mkdir_cmd
from testlib.linux import lldp
from testlib.lldp import Tlv
from testlib.linux import networkd
from testlib.linux import maa
from testlib import multicall
from testlib.cli_template import CmdStatus
from testlib.linux import iperf
from testlib.linux import testpmd
from testlib.linux import collectd
from testlib.linux import hugepages
from testlib.linux import openvswitch
from testlib.linux import dpdk


ENABLE_DISABLE_MAP = {
    0: "Disabled",
    1: "Enabled",
    "Disabled": 0,
    "Enabled": 1,
}


STAT_MAP = {
    "RxUcstPktsIPv4": "cntRxUcstPktsIPv4",
    "RxUcstPktsIPv6": "cntRxUcstPktsIPv6",
    "RxUcstPktsNonIP": "cntRxUcstPktsNonIP",
    "TxUcstPktsIPv4": "cntTxUcstPkts"
}


class LinuxHostBash(LinuxHostInterface):
    """
    @description  Class with UiOnpssShell wrappers
    """
    # cpu_port is a onpss_shell ONP specific number, it is
    # an index into self.port_map based on the portid
    # field in ip link show
    cpu_port = 0
    MULTICALL_THRESHOLD = 100
    # max bash exit status
    MAX_EXIT_STATUS = 256
    # statistics mapping table (generic name -> Bash UI specific name)
    SSH_NO_EXIT_STATUS = -1

    def __init__(self, host):
        """

        @brief  Initialize UiOnpssShell class
        @param  host:  Switch instance
        @type  host:  SwitchGeneral
        """
        self.host = host
        self.networks = []

        self.lag_map = {}
        self.switch_map = {}
        self.name_to_switchid_map = {}
        self.name_to_lagid_map = {}
        self.port_map = ChainMap(self.switch_map, self.lag_map)
        self.name_to_portid_map = ChainMap(self.name_to_switchid_map, self.name_to_lagid_map)
        self.networkd = networkd.NetworkD(self.cli_send_command, [self.host.mgmt_iface])
        self.lldp = lldp.Lldp(self.cli_send_command)
        self.maa = maa.MatchActionAcceleration(self.cli_send_command)
        self.iperf = iperf.Iperf(self.cli_send_command)
        self.testpmd = testpmd.TestPmd(self.host)
        # Collectd tool
        self.collectd = collectd.Collectd(self.cli_send_command, self.cli_set,
                                          self.host.config.get('collectd_conf_path'))
        # Hugepages
        self.hugepages = hugepages.HugePages(self.cli_send_command)

        # OpenvSwitch
        self.openvswitch = openvswitch.OpenvSwitch(self.cli_send_command, self.port_map, self.name_to_switchid_map)

        # DPDK
        self.dpdk = dpdk.Dpdk(self.cli_send_command)

        # Initialize lag/vlan map
        self.vlans = [{"vlanId": 1, "name": "VLAN-1"}]
        self.command_prefix = ''

        # Database of default static FDB entries
        self.default_fdb = {}

        # Read NTP server value
        self.ntp_server = next((x['ip_host'] for x in host.config.get('related_conf', {}).values()
                                if x.get('name') == 'ntp'), None)

    def reinit(self):
        """
        @brief  Re-initialize class attributes
        """
        # Clear 'fake' Vlans table
        self.vlans = [{"vlanId": 1, "name": "VLAN-1"}]
        self.command_prefix = ''
        # Clear lag_map
        self.lag_map.clear()
        self.name_to_lagid_map.clear()

        # Generate the default FDB table
        self.default_fdb = self.get_table_fdb(table='static')

    def connect(self):
        """
        @brief  Attempts to create a ssh session to the switch
        """
        self.host.ssh.login()
        self.host.ssh.open_shell()
        # need to detect switch before we can get port info
        # in case we need to restart it

    def disconnect(self):
        """
        @brief  Disconnects the ssh session from the switch
        """
        try:
            if self.host.ssh:
                self.host.ssh.close()
        except Exception as err:
            raise UIException(err)

    def start_switchd(self):
        """
        @brief  Restarts the switchd instance of the switch
        """
        # Re-initialize class attributes
        self.reinit()

    def restart(self):
        """
        @brief  Restarts the switch via command line 'reboot' command.
        """
        self.cli_send_command('reboot', expected_rcs={self.SSH_NO_EXIT_STATUS})  # pylint: disable=no-member
        time.sleep(2)
        self.disconnect()

    def _return_user_mode(self, results):
        """
        @brief  Maintained for abstraction compatibility.
        Method that returns to user mode of a switch.
        @param  results:  list of command execution results
        @type  results:  list
        """
        pass

    def generate_port_name(self, port):
        """
        @brief  Attempts to translate port in the port_map
        @type  port: int | str
        @raise  UIException
        @rtype: int | str
        """
        try:
            port_name = self.port_map[port]
        except KeyError:
            raise UIException('Port {0} is not in the port map.'.format(port))

        return port_name

    def generate_port_name_mapping(self):
        """
        @brief  Returns the device name (e.g. sw0p1), given a port number and vice versa.
        """
        try:
            _ports = self.get_table_ports(all_params=False)
        except SwitchException:
            self.start_switchd()
            _ports = self.get_table_ports(all_params=False)

        # got here because of kernel panic made ip list show empty
        assert _ports != [], "Ports table is empty"

        self.switch_map = {x['portId']: x['name'] for x in _ports if x['type'] in {'Physical', 'LAGMember'}}
        self.port_map.maps[0] = self.switch_map
        self.lag_map = {x['portId']: x['name'] for x in _ports if x['type'] == 'LAG'}
        self.port_map.maps[1] = self.lag_map
        self.name_to_switchid_map = {x['name']: x['portId'] for x in _ports if x['type'] in {'Physical', 'LAGMember'}}
        self.name_to_portid_map.maps[0] = self.name_to_switchid_map
        self.name_to_lagid_map = {x['name']: x['portId'] for x in _ports if x['type'] == 'LAG'}
        self.name_to_portid_map.maps[1] = self.name_to_lagid_map

    def cli_set(self, commands, timeout=None, split_lines=True, expected_rcs=frozenset({0}),
                multicall_treshold=MULTICALL_THRESHOLD):
        """
        @brief  Sends a list of commands.
                Will halt on exception from cli_send_command.
        @param  commands:  list of commands to be executed
        @type  commands:  list[list[str]]
        @param  timeout:  command execution timeout
        @type  timeout:  int
        @param  split_lines:  split command execution results by lines or not
        @type  split_lines:  bool
        @param  expected_rcs:  expected return code
        @type  expected_rcs:  int | set | list | frozenset
        @param  multicall_treshold: minimum number of commands to be executed using multicall
        @type  multicall_treshold: int
        @rtype:  list[list[tuple(str | list, str, int)]]
        @return: list of execution statuses for each command
        @raises UICmdException: when rc not in expected_rcs
        """
        if len(commands) > multicall_treshold:
            # convert
            commands = [c[0] for c in commands]
            res = self.cli_multicall(commands, timeout, expected_rcs)
            results = [[r[1]] for r in res]
        else:
            results = [[
                self.cli_send_command(
                    command=com[0], timeout=timeout,
                    expected_rcs=expected_rcs)] for com in commands]
        if split_lines:
            results = [[CmdStatus(r[0].stdout.splitlines(), r[0].stderr, r[0].rc)] for r in results]
        return results

    def cli_send_command(self, command, timeout=None, expected_rcs=frozenset({0})):
        """
        @brief  Sends a single bash command
        @param  command:  command to be executed
        @type  command:  str
        @param  timeout:  command execution timeout
        @type  timeout:  int
        @param  expected_rcs:  expected return code
        @type  expected_rcs:  int | set | list | frozenset
        @raise  UIException:  unexpected return code
        @rtype tuple(str, str, int) | CmdStatus
        @return  Returns CmdStatus namedtuple of stdout, stderr, return code
        """
        if self.command_prefix:
            command = self.command_prefix + command
        cmd_status = self.host.ssh.exec_command(command, timeout)
        if isinstance(expected_rcs, int):
            expected_rcs = {expected_rcs}
        if int(cmd_status.rc) not in expected_rcs:
            raise UICmdException(
                "Return code is {0}, expected {1} on command '{2}'.".format(
                    cmd_status.rc, expected_rcs, command),
                command, cmd_status.stdout, cmd_status.stderr, cmd_status.rc)
        return cmd_status

    def cli_multicall(self, commands, timeout=None, expected_rcs=frozenset({0})):
        """
        @brief  Sends a list of commands
        @param  commands:  list of commands to be executed
        @type  commands:  list[str]
        @param  timeout:  command execution timeout
        @type  timeout:  int
        @param  expected_rcs:  expected return code
        @type  expected_rcs:  int | set | list | frozenset
        @rtype:  list[tuple(str, tuple(str, str, int))]
        @raises UICmdException: when rc not in expected_rcs
        """
        if timeout is None:
            # The default clissh timeout was 10 seconds, now 60 seconds
            # multicalls take longer because they are running more commands
            # remotely, so increase the timeout even more
            timeout = 300
        results = []
        if self.command_prefix:
            commands = [self.command_prefix + c for c in commands]
        # cmds are full strings, so we have to split in remote_multicall_template
        for cmd in multicall.generate_calls(commands):
            cmd_status = self.host.ssh.exec_command(cmd, timeout)
            # convert to CmdStatus objects
            if cmd_status.stdout:
                results.extend(
                    (result[0], CmdStatus(*result[1:])) for result in json.loads(cmd_status.stdout))
        for r in results:
            # JSON should deserialize r[1].rc as int, but convert to be safe
            if int(r[1].rc) not in expected_rcs:
                raise UICmdException(
                    "Return code is {0}, expected {1} on command '{2}'.".format(
                        r[1].rc, expected_rcs, r[0]),
                    r[0], r[1].stdout, r[1].stderr, r[1].rc)
        return results

    def cli_get_all(self, commands, timeout=None, split_lines=True, expected_rcs=frozenset({0}),
                    multicall_treshold=MULTICALL_THRESHOLD):
        """
        @brief  Sends a list of commands, will return [''] if exception
        @param  commands:  list of commands to be executed
        @type  commands:  list[list[str]
        @param  timeout:  command execution timeout
        @type  timeout:  int
        @param  split_lines:  split command execution results by lines or not
        @type  split_lines:  bool
        @param  expected_rcs:  expected return code
        @type  expected_rcs:  int | set | list | frozenset
        @param  multicall_treshold: minimum number of commands to be executed using multicall
        @type  multicall_treshold: int
        @rtype:  list[list[str]]
        @return:  list of outputs for each command
        """
        if len(commands) > multicall_treshold:
            # convert
            commands = [c[0] for c in commands]
            res = self.cli_multicall(commands, timeout,
                                     expected_rcs=frozenset(list(range(self.MAX_EXIT_STATUS))))
            # replace errors with empty strings
            results = [[r[1].stdout if int(r[1].rc) in expected_rcs else ""] for r in res]
        else:
            results = []
            for com in commands:
                try:
                    results.append(
                        [self.cli_send_command(
                            command=com[0],
                            timeout=timeout,
                            expected_rcs=expected_rcs).stdout]
                    )
                except UIException:
                    results.append([''])
        if split_lines:
            results = [r[0].splitlines() for r in results]
        return results

    def process_table_data(self, data, table_keys_mapping):
        """
        @brief  Returns dictionary of items, given a table of elements.
        @param  data:  Command execution return data
        @type  data:  list[str]
        @param  table_keys_mapping:  User column name to output column name mapping
        @type  table_keys_mapping:  dict
        @rtype:  dict
        """
        table = []
        for row in data:
            _row = {}
            if row:
                rowsplit = row.split()
                for table_key in table_keys_mapping:
                    prop = table_keys_mapping[table_key]
                    _row[prop] = rowsplit[table_key]
                table.append(_row)
        return table

# Clear Config
    def clear_config(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::clear_config()
        """
        # WORKAROUND: restart switchd
        self.start_switchd()
        self.generate_port_name_mapping()

    def save_config(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::save_config()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def restore_config(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::restore_config()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

# Application Check
    def check_device_state(self):
        """
        @brief  Attempts to connect to the shell retries number of times
        @raise  SwitchException:  device is not ready
        """
        # time.sleep(15)

        if (not (self.host.ssh.check_client() and
                 self.host.ssh.check_shell())):

            try:
                self.connect()
                # Generate ports mapping after initialization of inherited UIs
                self.generate_port_name_mapping()
            except:
                self.disconnect()
                # Don't erase exception context, always raise the original exception
                # otherwise how will we know why we failed to connect?
                raise

# Platform
    def get_table_platform(self):
        """
        @copydoc testlib::ui_wrapper::UiInterface::get_table_platform()
        """
        # Note: No central area to pull stats; this is for display only
        return [{"ethernetSwitchType": "Fulcrum Switch",
                 "name": self.cli_send_command('uname').stdout.strip(),
                 "model": "NA",
                 "chipVersion": "NA",
                 "chipSubType": "NA",
                 "apiVersion": "NA",
                 "switchppVersion":
                 self.cli_send_command('cat /etc/ONPSS_VERSION').stdout.strip(),
                 "cpu": "NA",
                 "cpuArchitecture": "NA",
                 "osType":
                 self.cli_send_command('uname --kernel-name').stdout.strip(),
                 "osVersion":
                 self.cli_send_command('uname --kernel-release').stdout.strip(),
                 "chipName": getattr(self.host, "jira_platform_name", self.host.__class__.__name__),
                 "serialNumber": "NA"}]

# /proc/meminfo
    def get_proc_mem_info(self):
        """
        @brief  Get proc mem info
        @rtype:  dict
        @return:  Returns /proc/meminfo dictionary
        """
        output = self.cli_send_command(command='cat /proc/meminfo').stdout
        return dict(re.findall(r'(.*):\s+(\d+)', output))

    def get_cpu_cores(self):
        """
            @brief  Return number of CPU cores.
            @rtype:  int
            @return:  Number of cpu cores
        """
        command = 'nproc'
        output = self.cli_send_command(command=command).stdout
        return int(output)

    def is_process_active(self, process_name):
        """
            @brief  Check if process active or not
            @param  process_name:  name of process
            @type  process_name:  str
            @rtype:  bool
            @return:  bool
        """
        command = 'pgrep {}'.format(process_name)
        try:
            output = self.cli_send_command(command=command, expected_rcs=0).stdout.splitlines()
            if output:
                return True
        except UICmdException:
            return False

# Get current date
    def get_current_date(self, date_format='+%Y-%m-%d %T'):
        """
        @brief  Returns current date on device
        @param date_format: Date format to be returned
        @type date_format: str
        @rtype:  str
        @return:  Current date on device
        """
        try:
            cur_date = self.cli_send_command("date '{}'".format(date_format)).stdout.strip()
        except UICmdException as err:
            raise UIException('Invalid date format is specified ({0}). {1}.'.format(date_format,
                                                                                    err))
        return cur_date

# Syslog configuration
    def create_syslog(self, syslog_proto, syslog_ip, syslog_port,
                      syslog_localport, syslog_transport, syslog_facility, syslog_severity):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_syslog()
        @raise  SwitchException:  not implemented
        """
        pass

    def logs_add_message(self, level, message):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::logs_add_message()
        @raise  SwitchException:  not implemented
        """
        level_map = {"Notice": "user.notice"}
        # if not found in map, default to original string
        self.cli_send_command("logger -p '{0}' '{1}'".format(level_map.get(level, level), message))

# Temperature information
    def get_temperature(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_temperature()
        """
        return []

# System information
    def get_memory(self, mem_type='usedMemory'):
        """
        @brief  Returns free cached/buffered memory from switch
        @param  mem_type:  memory type
        @type  mem_type:  str
        @rtype:  float
        @return:  memory size
        """
        show_command = [['free']]
        _table = self.cli_get_all(show_command)
        mem_values = _table[0][1].split()
        if mem_type == "bufferedMemory":
            mem = mem_values[5]
        elif mem_type == "cachedMemory":
            mem = mem_values[6]
        elif mem_type == "freeMemory":
            mem = mem_values[3]
        else:
            mem = mem_values[2]
        mem = float(mem)
        return mem

    def get_cpu(self):
        """
        @brief  Returns cpu utilization from switch
        @rtype:  float
        @return:  cpu utilization from switch
        """
        commands = [['top -bn 1']]
        res_list = self.cli_get_all(commands)

        for row in res_list[0]:
            if "%Cpu(s):" in row:
                cpu_list = row.split(", ")
        cpu_list[0] = cpu_list[0][len("%Cpu(s):"):].strip()
        total_cpu = 0
        for item in cpu_list:
            if 'id' in item:
                item = item.strip()
                end = item.find(" ")
                total_cpu = 100 - float(item[0:end])
        return total_cpu

# Ports configuration
    def set_all_ports_admin_disabled(self):
        """
        @brief  Disables all ports in port_map on switch.
        """
        ports_table = self.get_table_ports()
        ports = [x['portId'] for x in ports_table if x["portId"] not in self.host.mgmt_ports]
        self.modify_ports(ports, adminMode="Down")

    def wait_all_ports_admin_disabled(self):
        """
        @brief  Checks if all the ports are set to down
        """
        def _retry(ports_list):
            start_time = time.time()
            _table = self.get_table_ports(ports_list)
            up_ports = [x['portId'] for x in _table if x['operationalStatus'] == 'Up']
            end_time = time.time()
            while end_time < start_time + 30 and len(up_ports) > 0:
                time.sleep(1)
                _table = self.get_table_ports(up_ports)
                up_ports = [x['portId'] for x in _table if x['operationalStatus'] == 'Up']
                end_time = time.time()
            return up_ports

        ports_table = self.get_table_ports(ports=None)

        # define multicall params for Ports.find method
        port_ids = [x["portId"] for x in ports_table if x["operationalStatus"] not in {
            'Unknown', 'Down'} and x["portId"] not in self.host.mgmt_ports]

        if port_ids:
            up_ports = _retry(port_ids)

            attempts = 0

            while up_ports and attempts < 3:
                # retry: set adminMode in Up/Down
                # define multicall params for nb.Ports.set.adminMode method
                self.host.ui.modify_ports(up_ports, adminMode='Up')
                self.host.ui.modify_ports(up_ports, adminMode='Down')
                up_ports = _retry(up_ports)
                attempts += 1

            if up_ports:
                pytest.fail("Not all ports are in down state: %s" % up_ports)

    def get_port_configuration(self, port, **kwargs):
        """
        @brief  Returns attribute value (int) for given port
        @param  port:  port ID
        @type  port:  int | str
        @param  expected_rcs:  expected return code
        @type  expected_rcs:  int | set | list | frozenset
        @param  kwargs:  Possible parameters: "getPortAttr", "getPortStats"
        @type  kwargs:  dict
        @rtype:  int | str
        @raise:  AccessError
        @return:  port attribute value
        """
        port_name = self.generate_port_name(port=port)
        if 'getPortAttr' in kwargs:
            command = "cat /sys/class/net/{0}/switch/{1}".format(
                port_name, kwargs['getPortAttr'])
        if 'getPortStats' in kwargs:
            command = "cat /sys/class/net/{0}/statistics/{1}".format(
                port_name, kwargs['getPortStats'])

        try:
            attr_val = self.cli_send_command(command=command).stdout
        except UICmdException as e:
            if e.rc == 1:
                raise AccessError(e.stderr)
            else:
                raise

        attr_val = attr_val.strip()
        # convert integers to integers, otherwise return the raw string
        try:
            return int(attr_val)
        except ValueError:
            return attr_val

    def get_port_configuration_snapshot(self, port, stats='attributes', skip_list=frozenset({0})):
        """
        @brief  Get a list of port attributes and their values
        @param  port:  port id
        @type  port:  int
        @param  stats:  stats to retrieve (attributes only currently)
        @type  stats: str
        @param  skip_list:  names to skip
        @type  skip_list:  list | set
        @rtype:  dict
        """
        port_name = self.generate_port_name(port=port)

        attribute_raw_list = []
        if stats == 'attributes':
            attribute_raw_list = self.cli_send_command(
                command=r'find /sys/class/net/{0}/switch/ -maxdepth 1 -type f -printf '
                        r'"%f\0"'.format(port_name)).stdout.split('\x00')

        attribute_in_class = (r for r in attribute_raw_list if getattr(self.host.hw, r, False))
        attribute_list = (r for r in attribute_in_class if r not in skip_list)

        if port == self.cpu_port:
            attribute_list_filtered = (r for r in attribute_list if getattr(
                self.host.hw, r, False).cpu_port is not None)
        else:
            attribute_list_filtered = (r for r in attribute_list if getattr(
                self.host.hw, r, False).cpu_port != 'cpu_port_only')

        return {r: self.get_port_configuration(
            port=port, getPortAttr=r) for r in attribute_list_filtered}

    def modify_ports(self, ports, expected_rcs=frozenset({0}), **kwargs):
        """
        @brief  Modifies settings on a list of ports
        @param  ports:  list of port IDs
        @type  ports:  list[int | str]
        @param  expected_rcs:  expected return code
        @type  expected_rcs:  int | list | set | frozenset
        @param  kwargs:  Possible parameters
        @type  kwargs:  dict
        @raise:  BoundaryError | AccessError
        @return:  None
        """
        commands = []
        for port_id in ports:
            port = self.generate_port_name(port=port_id)
            _adminMode = kwargs.get('adminMode', '').lower()
            if _adminMode in ['up', 'down']:
                port_info = self.get_table_ports([port_id])[0]
                if port_info['type'] == 'LAG':
                    # Get LAG ports
                    _ports = [x['portId'] for x in self.get_table_lags()
                              if x['lagId'] == port_id]
                    # Set admin mode of enslaved ports
                    self.modify_ports(_ports, adminMode=_adminMode)
                # Set admin mode of team interface
                commands.append("ip link set {} {}".format(port, _adminMode))
            if 'pvid' in kwargs:
                self.modify_vlan_ports([port_id], [int(kwargs['pvid'])], 'pvid')
            if 'pvpt' in kwargs:
                commands.append("ip link set dev {0} swattr def_swpri {1}".format(
                    port, kwargs['pvpt']))
                commands.append("ip link set dev {0} swattr def_pri {1}".format(
                    port, kwargs['pvpt']))
            if 'mtu' in kwargs:
                commands.append("ip link set dev {0} mtu {1}".format(port, kwargs['mtu']))
            if 'maxFrameSize' in kwargs:
                commands.append("ip link set dev {0} swattr {1} {2}".format(
                    port, 'max_frame_size', kwargs['maxFrameSize']))
            if 'learnMode' in kwargs:
                if kwargs['learnMode'] == 'None':
                    commands.append("ip link set dev {0} swattr learning 0".format(port))
                if kwargs['learnMode'] == 'Hardware':
                    commands.append("ip link set dev {0} swattr learning 1".format(port))
            if 'setPortAttr' in kwargs:
                if 'index' in kwargs:
                    commands.append(
                        "ip link set dev {0} swattr {1} {2} index {3}".format(
                            port, kwargs['setPortAttr'], kwargs['attrVal'], kwargs['index']
                        ))
                else:
                    commands.append("ip link set dev {0} swattr {1} {2}".format(
                        port, kwargs['setPortAttr'], kwargs['attrVal']))
            if 'macAddress' in kwargs:
                commands.append("ip link set dev {0} address {1}".format(port, kwargs['macAddress']))
            if 'speed' in kwargs:
                commands.append("ethtool -s {0} speed {1}".format(port, kwargs['speed']))

            if 'ipAddr' in kwargs:
                if not kwargs['ipAddr']:
                    commands.append("ip addr flush dev {0}".format(port))
                else:
                    commands.append("ip addr add {0} dev {1}".format(kwargs['ipAddr'], port))

            if 'cutThrough' in kwargs:
                commands.append("ip link set dev {0} swattr rx_cut_through {1}".format(
                    port, ENABLE_DISABLE_MAP[kwargs['cutThrough']]))
                kwargs['tx_cutThrough'] = kwargs['cutThrough']
            if 'tx_cutThrough' in kwargs:
                commands.append("ip link set dev {0} swattr tx_cut_through {1}".format(
                    port, ENABLE_DISABLE_MAP[kwargs['tx_cutThrough']]))
            if 'discardMode' in kwargs:
                if kwargs['discardMode'] == "Untagged":
                    kwargs['dropUntagged'] = "Enabled"
                elif kwargs['discardMode'] == "Tagged":
                    kwargs['dropTagged'] = "Enabled"
            if 'dropTagged' in kwargs:
                commands.append("ip link set dev {0} swattr drop_tagged {1}"
                                .format(port, ENABLE_DISABLE_MAP[kwargs['dropTagged']]))
            if 'dropUntagged' in kwargs:
                commands.append("ip link set dev {0} swattr drop_untagged {1}"
                                .format(port, ENABLE_DISABLE_MAP[kwargs['dropUntagged']]))
            if 'ucastPruning' in kwargs:
                commands.append("ip link set dev {0} swattr ucast_pruning {1}"
                                .format(port, ENABLE_DISABLE_MAP[kwargs['ucastPruning']]))
            if 'mcastPruning' in kwargs:
                commands.append("ip link set dev {0} swattr mcast_pruning {1}"
                                .format(port, ENABLE_DISABLE_MAP[kwargs['mcastPruning']]))
            if 'bcastPruning' in kwargs:
                commands.append("ip link set dev {0} swattr bcast_pruning {1}"
                                .format(port, ENABLE_DISABLE_MAP[kwargs['bcastPruning']]))
            if 'flowControl' in kwargs:
                # NOS does not support flowControl configuration yet.
                pass
            if 'ingressFiltering' in kwargs:
                commands.append("ip link set {0} swattr drop_bv {1}".format(
                    port, ENABLE_DISABLE_MAP[kwargs['ingressFiltering']]))
            if 'netns' in kwargs:
                commands.append("ip link set dev {0} netns {1}".format(port, kwargs['netns']))
        try:
            commands = [[c] for c in commands]
            results = self.cli_set(commands, expected_rcs=expected_rcs, multicall_treshold=1)
        except UICmdException as e:
            if e.rc in {-1, 2, 255}:
                raise BoundaryError(e.stderr)
            elif e.rc == 1:
                if re.search("inet6? prefix is expected", e.stderr):
                    raise BoundaryError(e.stderr)
                else:
                    raise AccessError(e.stderr)
            else:
                raise
        else:
            for cmdstatus in results:
                if 'Cannot set new settings' in cmdstatus[0].stderr:
                    raise InvalidCommandError(cmdstatus[0].stderr)

    INDEX_NAME_RE = re.compile(r'(?P<index>\d*):\s(?P<name>\w*)[@:]')

    @classmethod
    def parse_table_ports(cls, ports_table):
        """
        @brief  Returns list of dictionary of port properties.
        @param  ports_table:  port information
        @type  ports_table:  list[str]
        @rtype:  dict
        @return:  port properties
        """
        # Compile regular expression for validating output
        for row in ports_table:
            _row = {}
            row = row.strip()
            row_head = cls.INDEX_NAME_RE.search(row)
            if row_head:
                _row['portId'] = row_head.group('name')
                _row['master'] = None
                _row['name'] = row_head.group('name')
                row_prop = re.search(
                    # dashes allowed, e.g. master ovs-system
                    r'(?<=mtu\s)(?P<mtu>\d*)(\s[\w-]*)*'
                    r'(?<=state\s)(?P<adminMode>[\w-]*)', row)
                _row['mtu'] = int(row_prop.group('mtu'))
                # state may be absent for some reason
                _row['adminMode'] = group_get(row_prop, 'adminMode', default='Down').title()
                _row['operationalStatus'] = _row['adminMode']
                row_prop = re.search(r'(?<=link/ether\s)([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', row)
                _row['macAddress'] = group_get(row_prop, 0, default='Unknown')
                row_master = re.search(r'(?<=master\s)\w*', row)
                if row_master:
                    _row['master'] = row_master.group()
                    _row['type'] = 'LAGMember'
                else:
                    _row['type'] = 'Physical'
            else:
                continue
            yield _row

    def get_table_ports(self, ports=None, all_params=False, ip_addr=False):
        """
        @brief  Returns the table ports dictionary
        @param  ports:  list of port IDs
        @type  ports:  list[int] | None
        @param  all_params:  get additional port properties
        @type  all_params:  bool
        @param  ip_addr:  Get IP address
        @type  ip_addr:  bool
        @raise  SwitchException:  No switch ports found
        @rtype:  list[dict]
        @return:  ports table
        """
        # We must default to --details since we can't change the function signature
        # without breaking compatibility with other UIs
        iplink_params = "--details"
        ip_cmd = '/sbin/ip'
        if ports:
            command_list = [['{} -o {} link show {}'.format(ip_cmd,
                iplink_params, self.generate_port_name(port=p))] for p in ports]
        else:
            command_list = [['{} -o {} link show'.format(ip_cmd, iplink_params)], ]

        raw_data = self.cli_get_all(command_list, multicall_treshold=1)
        all_port_dicts = (self.parse_table_ports(r) for r in raw_data)
        ports = list(itertools.chain.from_iterable(all_port_dicts))

        command_list = [["readlink /sys/class/net/{0}".format(_port['name'])] for _port in ports]
        pci_list = self.cli_get_all(command_list, multicall_treshold=1, split_lines=False)

        command_list = [["cat /sys/class/net/{0}/{1}".format(
                            _port['name'], 'mtu')] for _port in ports]
        frame_sizes = self.cli_get_all(command_list, multicall_treshold=1)
        command_list = [["ethtool {0}".format(_port['name'])] for _port in ports]
        ethtool_info = self.cli_get_all(command_list, multicall_treshold=1)

        # iterate all three tables together
        for _port, _table, _frame_size, _pci in zip(ports, ethtool_info, frame_sizes, pci_list):
            if _frame_size and _frame_size[0]:
                _port['maxFrameSize'] = int(_frame_size[0])
            speed = next((x for x in _table if 'Speed' in x), 'Unknown')
            _port['duplex'] = next((x for x in _table if 'Duplex' in x), 'Unknown').split(':')[-1]
            _port['duplex'] = _port['duplex'].strip().lower()

            link_status = next((x for x in _table if 'Link detected' in x), '').split(':')[-1]
            link_status = link_status.strip().lower()
            _port['operationalStatus'] = 'Up' if link_status == 'yes' else 'Down'

            if 'Unknown' in speed:
                _port['speed'] = 0
            else:
                # find first string of digits after a colon
                _port['speed'] = int(
                    re.search(r"(?!:)\d+", speed).group(0))
            match = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-9A-Fa-f]{1,2})/(?:virt.+|net)/', _pci[0])
            _port['pci'] = 'Unknown'
            if match:
                _port['pci'] = match.group(1)

        if all_params:
            for _port in ports:
                if _port['type'] == 'Physical':
                    _port['cutThrough'] = ENABLE_DISABLE_MAP[
                        self.get_port_configuration(
                            _port['portId'], getPortAttr='rx_cut_through')]
                    _port['tx_cutThrough'] = ENABLE_DISABLE_MAP[
                        self.get_port_configuration(
                            _port['portId'], getPortAttr='tx_cut_through')]

                    # Temporary added setting flowControl feature to 'None' value since
                    # NOS does not support flowControl yet.
                    _port['flowControl'] = 'None'

                _port['pvpt'] = self.get_port_configuration(
                    _port['portId'], getPortAttr='def_swpri')

        # Get Ip address
        if ip_addr:
            try:
                command_list = [['{} -o addr show {}'.format(ip_cmd, self.port_map[_port['portId']])]
                                for _port in ports]
                ip_addresses = self.cli_get_all(command_list, multicall_treshold=1)
                for _port, _table in zip(ports, ip_addresses):
                    _port['ip_addr'] = re.findall(
                        r'inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', " ".join(_table))
                    for index, value in enumerate(_port['ip_addr']):
                        _port['ip_addr'][index] = str(ipaddr.IPv4Address(value))
            except ValueError:
                raise SwitchException('Configured IP Address does not appear to be valid')
            except:
                raise SwitchException('No switch ports found.')

        return ports

# Flow Control configuration (pause frames)
    def _configure_fc_mode(self, ports=None, tx_mode='normal', traffic_class=255):
        """
        @brief  Determines 802.3x pause frame format used.
        Maps priorities to traffic classes.
        @param  ports:  list of port ids
        @type  ports:  list[int]
        @param  tx_mode:  transmit mode (normal or class based)
        @type  tx_mode:  str
        @param traffic_class: traffic class bitmask
        @type  traffic_class:  int
        """
        if tx_mode == 'normal':
            # Enable legacy pause mode
            self.modify_ports(ports, setPortAttr="pause_mode",
                              attrVal=self.host.hw.pause_mode.min)
        elif tx_mode == 'class_based':
            # Enable class based tx pause mode
            self.modify_ports(ports, setPortAttr="pause_mode",
                              attrVal=self.host.hw.pause_mode.max)
            self.modify_ports(ports, setPortAttr="tx_class_pause",
                              attrVal=traffic_class)

    def _disable_rx_fc(self, ports=None):
        """
        @brief  Disables receive of 802.3x pause frames.
        @param  ports:  list of port ids
        @type  ports:  list[int]
        """
        # Disable rx pause on all TCs/Queues
        self.modify_ports(ports, setPortAttr="rx_class_pause", attrVal=0)

    def _enable_rx_fc(self, ports=None, tc=1):
        """
        @brief  Enables receive of 802.3x pause frames.
        @param  ports:  list of port ids
        @type  ports:  list[int]
        @param  tc:  traffic class
        @type  tc:  int
        """
        # Enable rx pause on TC/Queue 0
        self.modify_ports(ports, setPortAttr="rx_class_pause", attrVal=tc)

    def _disable_tx_fc(self, ports=None):
        """
        @brief  Disables transmit of 802.3x pause frames per port.
        @param  ports:  list of port ids
        @type  ports:  list[int]
        """
        # Disable tx pause frame generation
        self.modify_ports(ports, setPortAttr="smp_lossless_pause",
                          attrVal=self.host.hw.smp_lossless_pause.min)

    def _enable_tx_fc(self, ports=None):
        """
        @brief  Enables transmit of 802.3x pause frames per port.
        @param  ports:  list of port ids
        @type  ports:  list[int]
        """
        self.modify_ports(ports, setPortAttr="smp_lossless_pause",
                          attrVal=self.host.hw.smp_lossless_pause.max)

    def set_flow_control_type(self, ports=None, control_type=None, tx_mode='normal', tc=None):
        """
        @brief  Sets the flow control type
        @param  ports:  list of port ids
        @type  ports:  list[int]
        @param  control_type:  flow control type
        @type  control_type:  str
        @param  tx_mode:  transmit mode (normal or class based)
        @type  tx_mode:  str
        @param  tc:  traffic class
        @type  tc:  int
        """
        if tc is None:
            tc_2_bitmask_convert = 1
        else:
            tc_2_bitmask_convert = 0
            for x in tc:
                tc_2_bitmask_convert |= (1 << x)

        self._configure_fc_mode(ports, tx_mode=tx_mode, traffic_class=tc_2_bitmask_convert)

        if control_type == 'None':
            self._disable_rx_fc(ports)
            self._disable_tx_fc(ports)
        elif control_type == 'Rx':
            self._enable_rx_fc(ports, tc_2_bitmask_convert)
            self._disable_tx_fc(ports)
        elif control_type == 'Tx':
            self._disable_rx_fc(ports)
            self._enable_tx_fc(ports)
        elif control_type == 'RxTx':
            self._enable_rx_fc(ports, tc_2_bitmask_convert)
            self._enable_tx_fc(ports)

# Vlan configuration
    def create_vlans(self, vlans=None):
        """
        @brief  Add vlans to the 'fake' Vlans table
        """

        # NOS does not support creating a VLAN in a VLAN database. WW42'14
        for v in vlans:
            self.vlans.append({"vlanId": v, "name": "VLAN-{}".format(v)})

    def delete_vlans(self, vlans=None):
        """
        @brief  Remove vlans from the 'fake' Vlans table
        """

        # NOS does not support deleting a VLAN in a VLAN database. WW42'14
        for vlan in vlans:
            try:
                record = [x for x in self.vlans if x['vlanId'] == vlan][0]
                self.vlans.remove(record)
            except IndexError:
                pass

    def get_table_vlans(self):
        """
        @brief  Returns the 'fake' Vlans table
        """

        # NOS does not support getting a VLAN database. WW42'14
        return self.vlans

    BRIDGE_VLAN_COMMAND_STRING = 'bridge vlan {command} vid {vlan} dev {port} self {tagged}'

    @classmethod
    def _generate_bridge_vlan_commands(
            cls, command, ports, vlans, tagged=''):
        """
        @brief  Generate Bridge VLAN commands.
        @param  command:  Bridge VLAN command
        @type  command:  str
        @param  ports:  list of port IDs
        @type  ports:  list[str]
        @param  vlans:  list of VLAN IDs
        @type  vlans:  list[int]
        @param  tagged:  port tagging attribute
        @type  tagged:  str
        @rtype:  list[str]
        @return:  list of Bridge VLAN commands
        """
        return [
            cls.BRIDGE_VLAN_COMMAND_STRING.format(
                command=command, vlan=vlan, port=port, tagged=tagged)
            for vlan in vlans for port in ports]

    def create_vlan_ports(self, ports=None, vlans=None, tagged='Tagged'):
        """
        @brief  Creates VLANs on ports using tagged, untagged, or pvid
        @param  ports:  list of port IDs
        @type  ports:  list[int] | set(int)
        @param  vlans:  list of VLAN IDs
        @type  vlans:  list[int] | set(int)
        @param  tagged:  port tagging attribute
        @type  tagged:  str
        @raise  ValueError:  invalid tagged type
        """
        valid_tagged_args = {'tagged', 'untagged', 'pvid', 'pvid tagged', 'pvid untagged'}
        tagged = tagged.lower()

        if not (ports is None or vlans is None):
            if tagged in valid_tagged_args:
                port_names = [self.port_map[p] for p in ports]

                command_list = self._generate_bridge_vlan_commands(
                    "add", port_names, vlans, tagged=tagged)
                if len(command_list) > self.MULTICALL_THRESHOLD:
                    self.cli_multicall(command_list)
                else:
                    for c in command_list:
                        self.cli_send_command(command=c)
            else:
                raise ValueError('Invalid argument for tagged type, {0}.'.format(tagged))

    def delete_vlan_ports(self, ports=None, vlans=None):
        """
        @brief  Removes vlans from ports
        @param  ports:  list of port IDs
        @type  ports:  list[int]
        @param  vlans:  list of VLAN IDs
        @type  vlans:  list[int]
        """
        if not (ports is None or vlans is None):
            port_names = [self.port_map[p] for p in ports]
            command_list = self._generate_bridge_vlan_commands(
                "del", port_names, vlans, tagged='')
            if len(command_list) > self.MULTICALL_THRESHOLD:
                self.cli_multicall(command_list)
            else:
                for c in command_list:
                    self.cli_send_command(command=c)

    def modify_vlan_ports(self, ports=None, vlans=None, tagged='tagged'):
        """
        @brief  Changes vlan classification. Since no modify method exists in NOS,
        we need to delete the origin entry and re-add.
        @param  ports:  list of port IDs
        @type  ports:  list[int]
        @param  vlans:  list of VLAN IDs
        @type  vlans:  list[int]
        @param  tagged:  port tagging attribute
        @type  tagged:  str
        """
        if not (ports is None or vlans is None):
            # Convert to set as finding membership in set is much faster than list
            vlans = set(vlans)
            ports = set(ports)
            table_vlan = self.get_table_ports2vlans()

            vlans_found = (r for r in table_vlan if r['vlanId']in vlans)
            vlans_and_ports_found = (r for r in vlans_found if r['portId'] in ports)
            for row in vlans_and_ports_found:
                self.delete_vlan_ports(ports=[row['portId']], vlans=[row['vlanId']])

            self.create_vlan_ports(ports=ports, vlans=vlans, tagged=tagged)

    def parse_table_vlan(self, vlan_table):
        """
        @brief  Parses the vlan table. This needs to be a loop because previous the table
        is built based on previous entries.
        @param  vlan_table:  List of vlan raw output
        @type  vlan_table:  list[str] | iter()
        @return  A dictionary containing the portId, vlanId, and tagged state for each vlan
        @rtype:  iter()
        """
        for row in vlan_table:
            match = re.search(
                r"(?P<portId>\S*\d+)?\s*(?P<vlanId>\d+)\s*(?P<pvid>PVID)?\s*(?:Egress)?\s*(?P<tagged>\D+)?", row)
            if match:
                row = match.groupdict()
                row['vlanId'] = int(row['vlanId'])
                if row['tagged'] is None:
                    row['tagged'] = 'Tagged'
                row['pvid'] = (row['pvid'] == 'PVID')
                if row['portId'] is not None:
                    # Set portId on the first line and use that value for following lines
                    row['portId'] = self.name_to_portid_map[row['portId']]
                    port_id = row['portId']
                else:
                    # This row doesn't have a portId because it implicitly uses the previous
                    row['portId'] = port_id
                yield row

    def get_table_ports2vlans(self):
        """
        @brief  Gets the ports to vlan table
        @rtype:  list[dict]
        """
        vlan_output = self.cli_send_command('bridge vlan show').stdout.splitlines()

        # Remove the table header
        vlan_output = (r for r in vlan_output[1:] if r and 'None' not in r)
        vlan_table = list(self.parse_table_vlan(vlan_output))
        return vlan_table

    @staticmethod
    def row_with_header(header, data):
        """
        @brief  Returns dictionary per row of values for 'ip show stats'.
        @param  header:  output header
        @type  header:  str
        @param  data:  output data
        @type  data:  str
        @rtype:  dict
        @return:  dictionary per row of values for 'ip show stats'
        """
        prefix, columns = header.strip().split(':')
        column_names = ["{0}:{1}".format(prefix, h) for h in columns.split()]
        return dict(list(zip(column_names, data.strip().split())))

    RX_TX_RE = re.compile(r"\s+[RT]X[^:]*:")

    @classmethod
    def parse_ip_show_stats(cls, input_lines):
        """
        @brief  Returns list of IP statistics.
        @param  input_lines:  command output
        @type  input_lines:  list[str]
        @rtype:  dict
        @return:  list of IP statistics
        """
        table = {}
        for n, row in enumerate(input_lines):
            if cls.RX_TX_RE.match(row):
                # use pairs of rows, header and data
                table.update(cls.row_with_header(*input_lines[n:n + 2]))
        return table

# Statistics configuration
    def get_table_basic_statistics(self, port, stat_name=None):
        """
        @brief  Returns a list of basic statistics found in /sys/class/net/
        @param  port:  Port ID
        @type  port:  int
        @param  stat_name:  Statistics name
        @type  stat_name:  str
        @rtype:  dict | int
        @return:  Statistics table or specific statistics value
        """
        cli_keys = ["collisions", "multicast", "rx_bytes", "rx_compressed",
                    "rx_dropped", "rx_errors", "rx_fifo_errors",
                    "rx_missed_errors", "rx_length_errors", "rx_over_errors",
                    "rx_crc_errors", "rx_packets", "rx_frame_errors",
                    "tx_aborted_errors", "tx_bytes", "tx_carrier_errors",
                    "tx_compressed", "tx_dropped", "tx_errors",
                    "tx_fifo_errors", "tx_heartbeat_errors", "tx_packets",
                    "tx_window_errors"]

        if not stat_name:
            stat_table = {
                key: self.get_port_configuration(
                    port, getPortStats=key) for key in cli_keys}
            return stat_table
        else:
            stat_table = {
                stat_name: self.get_port_configuration(
                    port, getPortStats=stat_name)}
            return stat_table[stat_name]

    def map_stat_name(self, generic_name):
        """
        @brief  Returns actual counter name
        @param  generic_name:  counter Name
        @type  generic_name:   str
        @rtype:  str
        """
        return STAT_MAP.get(generic_name, generic_name)

    @staticmethod
    def parse_table_statistics(stats_table):
        table = stats_table.splitlines()
        splits = (line.split(":") for line in table if 'NIC statistics' not in line)
        return {k.strip(): int(v.strip()) for k, v in splits}

    def get_table_statistics(self, port=None, stat_name=None):
        """
        @brief  Returns port statistics via ethtool -S command
        @param  port:  Port ID
        @type  port:  int
        @param  stat_name:  Statistics name
        @type  stat_name:  str
        @raise  KeyError:  invalid port ID
        @rtype:  dict | str
        @return:  Statistics table or specific statistics value
        """
        dev = self.generate_port_name(port=port)
        stat_name = self.map_stat_name(stat_name)

        try:
            table = self.cli_send_command('ethtool -S {0}'.format(dev)).stdout
        except UICmdException as e:
            if e.rc == 94 and 'no stats available' in e.stderr:
                raise ArgumentError('Detailed statistics not supported on LAG ports.')
            else:
                raise

        formatted_table = self.parse_table_statistics(stats_table=table)

        if not stat_name:
            return formatted_table
        else:
            stat_name = self.map_stat_name(stat_name)
            return formatted_table[stat_name]

    def clear_statistics(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::clear_statistics()
        """
        pass

# DHCP Configurations
    def get_table_dhcp_config(self, file_name="/etc/dhcp/dhcpd.conf",
                              options=None):
        """
        @brief  Gets configuration from file
        @param file_name:  File name
        @type  file_name:  str
        @param options:  Name of options to get
        @type  options:  str
        @rtype:  dict
        @return:  DHCP configuration
        @steps
            -# Using sftp client open the config file in read only mode
            -# Store the configurations in dictionary format
            -# Return the entire dictionary or a particular key's value based on
               the options provided
        @endsteps
        """
        dhcp_table_keys = ["ddns-update-style", "default-lease-time",
                           "max-lease-time", "option subnet-mask",
                           "option broadcast-address", "option routers",
                           "option domain-name-servers", "option domain-name",
                           "subnet", "range", "host", "hardware ethernet",
                           "fixed-address"]
        with self.host.ssh.client.open_sftp() as sftp_client:
            with sftp_client.open(file_name, 'r') as remote_file:
                lines = remote_file.readlines()
                dhcp_config_table = {
                    key: line.strip(key).strip().strip(';')
                    for key in dhcp_table_keys for line in lines
                    if line.startswith(key)
                }
        if options is not None:
            return dhcp_config_table[options]
        else:
            return dhcp_config_table

    def create_dhcp_config_file(self, lines, file_name="/etc/dhcp/dhcpd.conf"):
        """
        @brief  Writes configuration required to file
        @param lines:  Configuration
        @type  lines:  str
        @param file_name:  File name
        @type  file_name:  str
        @return:  None
        @steps
            -# Using sftp client open the config file in write mode
            -# Write the minimum configuration required by DHCP Server to the file
        @endsteps
        """
        with self.host.ssh.client.open_sftp() as sftp_client:
            with sftp_client.open(file_name, 'w') as remote_file:
                remote_file.writelines(lines)

    def modify_dhcp_status(self, ps_name="dhcpd", operation="start"):
        """
        @brief  Changes DHCP status
        @param ps_name:  Service name
        @type  ps_name:  str
        @param operation:  Operations "start" | "stop"
        @type  operation:  str
        @rtype:  str
        @return:  Result of execution
        @steps
            -# Execute the command to start/stop the "dhcpd" service
            -# Return the result
        @endsteps
        """
        command = ([["systemctl {1} {0}".format(ps_name, operation)]])
        result = self.cli_get_all(command)
        return result

    def create_dhcp_client_lease(self, file_name="/var/lib/dhcpd/dhcpd.leases"):
        """
        @brief  Creates a lease file via SFTP
        @param file_name:  File name
        @type  file_name:  str
        @return:  None
        @steps
            -# Create a lease file when DHCP Server is started
        @endsteps
        """
        with self.host.ssh.client.open_sftp() as sftp_client:
            with sftp_client.open(file_name, 'w'):
                pass

    def get_table_dhcp_client_lease(self, file_name="/var/lib/dhcpd/dhcpd.leases"):
        """
        @brief  Gets data from a lease file
        @param file_name:  File name
        @type  file_name:  str
        @rtype:  dict
        @return:  dictionary or a particular key's value based on the options provided
        @steps
            -# Using sftp client open the config file in read only mode
            -# Store the configurations in dictionary format
            -# Return the entire dictionary or a particular key's value based on
               the options provided
        @endsteps
        """
        with self.host.ssh.client.open_sftp() as sftp_client:
            with sftp_client.open(file_name, 'r') as remote_file:
                lines = remote_file.readlines()
                table_keys = [line.strip().split()[1] for line in lines
                              if line.strip().startswith('lease')]

                table_values = [line.strip().split()[2].strip(';')
                                for line in lines
                                if line.strip().startswith('binding state')]
                client_lease_table = dict(list(zip(table_keys, table_values)))

        return client_lease_table

    def get_dhcp_status(self, ps_name="dhcpd"):
        """
        @brief  Gets DHCP status
        @param ps_name:  Service name
        @type  ps_name:  str
        @rtype:  str
        @return:  Values 'active'|'unknown'
        @steps
            -# Execute the command to get the status of "dhcpd" service
            -# Return the result
        @endsteps
        """
        # use systemctl is-active, it returns 'active' or 'unknown'
        command = "systemctl is-active {0}".format(ps_name)
        # rc = 3, stdout = 'failed\n'
        out, err, rc = self.cli_send_command(command=command, expected_rcs={0, 3})
        # use exact compare, not in
        # possible values are 'active' or 'unknown' or failed with rc 3.
        # only return true if we get 'active'
        return out.strip() == "active"

    def get_table_dhcp_server_ip_list(self, pool=None):
        """
        @brief  Gets configured range of ip address
        @param pool:  "range"
        @type  pool:  str
        @rtype:  list
        @return:  Range of ip address
        @steps
            -# From server configuration file get the range
            -# Return the list
        @endsteps
        """
        if pool == "range":
            range_list = self.get_table_dhcp_config(options="range").split()
            return range_list

    def get_dhcp_client_lease_time(self, ports=None):
        """
        @brief  Returns the lease time configured for the interfaces, will raise
                exception on any error
        @param  ports:  List of port ids which denotes the switch interfaces
        @type  ports:  list[int]
        @raise:  SwitchException:  no switch ports found
        @rtype:  dict
        @return:  Dictionary with port id as key and lease time as value
        """
        try:
            result = {}
            for _port in ports:
                table = self.cli_send_command(
                    'ip -o addr show {0}'.format(self.port_map[_port])).stdout
                match = re.findall(r'valid_lft (\d+)s', table)
                result[_port] = match
        except:
            raise SwitchException('No switch ports found.')
        return result

# Bridge Info configuration
    def get_table_bridge_info(self, param=None, port=None):
        """
        @brief  Retrieves switch properties organized under ONS 1.x
        @param  param:  parameter name
        @type  param:  str
        @param  port:  port ID
        @type  port:  int
        @raise  KeyError | UIException:  port/management port info required
        @rtype:  str | int
        @return:  switch properties
        """
        cli_keys = {'operationalStatus': 'operstate',
                    'maxFrameSize': 'mtu',
                    'macAddress': 'address',
                    'duplex': 'duplex',
                    'speed': 'speed'}
        if port is None:
            if self.host.mgmt_iface is not None:
                iface = self.host.mgmt_iface
            else:
                raise UIException('Management port should be provided.')
        elif isinstance(port, int):
            iface = self.port_map[port]
        elif isinstance(port, str):
            iface = port
        else:
            raise UIException(
                'Port should be provided or managements ports info should be available in '
                'config file.')
        if param == 'agingTime':
            res_list = self.get_port_configuration(
                self.cpu_port,
                getPortAttr='mac_table_address_aging_time')
            return int(res_list)
        elif param is not None:
            show_command = 'cat /sys/class/net/%s/%s' % (iface,
                                                         cli_keys[param])
            # rc 1 = cat: /sys/class/net/sw0p4/duplex: Invalid argument
            res_list = self.cli_send_command(show_command, expected_rcs={0, 1}).stdout.strip()
            return res_list
        else:
            port_row = {
                parameter: self.cli_send_command(
                    'cat /sys/class/net/{0}/{1}'.format(iface, value),
                    expected_rcs={0, 1}).stdout.strip()
                for parameter, value in cli_keys.items()
            }
            port_row["portId"] = iface
            return [port_row]

    def modify_bridge_info(self, **kwargs):
        """
        @brief  Used for mac aging time, maintained for ONS 1.x compatibility
        @raise  KeyError:  cpu port is not defined
        """
        port_name = self.generate_port_name(port=self.cpu_port)
        try:
            command = 'ip link set {0} swattr mac_table_address_aging_time {1}'.format(
                port_name, kwargs['agingTime'])
        except KeyError:
            pass
        else:
            self.cli_send_command(command=command)

# LAG configuration
    def create_lag(self, lag=None, key=0, lag_type='Static', hash_mode='None'):
        """
        @brief  Creates a lag group
        @param  lag:  lag ID|name
        @type  lag:  str|int
        @param  key:  lag key
        @type  key:  int
        @param  lag_type:  lag type. Static | Dynamic
        @type  lag_type:  str
        @param  hash_mode:  lag hash mode
        @type  hash_mode:  str
        @raise  ExistsError
        @rtype:  None
        """
        if lag_type == 'Static' and lag:
            command = 'teamd -d -t {0}'.format(lag)
        elif lag_type == 'Dynamic' and lag:
            lacp_config = json.dumps(
                {"device": "{0}".format(lag),
                 "runner": {"name": "lacp", "active": True, "fast_rate": True}})
            command = "teamd -d -r --config='{0}'".format(lacp_config)
            # Skip following call if no CPU port present on this node
            if self.cpu_port in self.port_map:
                self.modify_ports(ports=[self.cpu_port], setPortAttr="lag_mode",
                                  attrVal=ENABLE_DISABLE_MAP["Enabled"])
        else:
            raise ArgumentError("Only Static and Dynamic LAG type supported.")

        try:
            self.cli_send_command(command=command)
        except UICmdException as e:
            if e.rc == 1:
                if 'File exists' in e.stderr:
                    # LAG already exists.
                    raise ExistsError(e.stderr)
                elif 'option requires an argument' in e.stderr:
                    raise ArgumentError(e.stderr)
            else:
                raise

        # Set lag port up, otherwise it will default down (with ports added)
        self.cli_send_command('ip link set {0} up'.format(lag))

    def create_lag_ports(self, ports, lag, lag_mode='Passive', timeout='Long'):
        """
        @brief  Set port to a LAG.
        @rtype  ports: list[int]
        @rtype  lag: int | str
        @raise:  NotExistsError | AccessError
        """
        # Need to set port to admin down before joining
        self.modify_ports(ports=ports, adminMode='Down')
        time.sleep(1)

        lag_mode_map = {"Passive": False, "Active": True, }
        lag_timeout_map = {"Long": False, "Short": True, }
        # If lag type has properties changed, we need to recreate the lag.
        get_lag = next((row for row in self.get_table_lags() if row["lagId"] == lag), None)
        if get_lag and get_lag["lagControlType"] == "Dynamic":
            self.delete_lags(lags=[lag, ])
        try:
            lacp_config = json.dumps(
                {"device": "{0}".format(lag),
                 "runner": {"name": "lacp", "active": lag_mode_map[lag_mode],
                            "fast_rate": lag_timeout_map[timeout]}})
        except KeyError:
            raise ArgumentError("Unexpected argument in timeout or lag_mode field.")

        self.cli_send_command("teamd -d -r --config='{}'".format(lacp_config))

        # Set lag port up, otherwise it will default down (with ports added)
        self.cli_send_command('ip link set {0} up'.format(lag))

        command_list = ['ip link set {0} master {1}'.format(
            self.switch_map[port], lag) for port in ports]

        for c in command_list:
            try:
                self.cli_send_command(command=c)
            except UICmdException as e:
                if e.rc == 255:
                    # Team does not exist
                    raise NotExistsError(e.stderr)
                elif e.rc == 2:
                    # Port is busy
                    raise AccessError(e.stderr)
                else:
                    raise
        self.generate_port_name_mapping()

    def delete_lags(self, lags=None):
        """
        @brief  Delete lag groups
        @param  lags:  list of lag IDs
        @type lags:  iter() | str | list[str|int]
        @raise:  NotExistsError
        @rtype:  None
        """
        if lags is not None:
            if isinstance(lags, str):
                lags = [lags]

            command_list = ['teamd -k -t {0}'.format(lag) for lag in lags]

            for c in command_list:
                try:
                    self.cli_send_command(command=c)
                except UICmdException as e:
                    if e.rc == 1:
                        if 'Daemon not running' in e.stderr:
                            raise NotExistsError(e.stderr)
                        elif 'option requires an argument' in e.stderr:
                            raise ArgumentError(e.stderr)
                    else:
                        raise
        self.generate_port_name_mapping()

    def delete_lag_ports(self, ports):
        """
        @brief  Deletes ports from a lag
        @type  ports:  list[int]
        @type  lag:  str|int
        @raise  UIException:
        @rtype:  None
        """
        command_list = ['ip link set {0} nomaster'.format(port) for port in ports]

        # No other known rc's known (even deleting non-existent entry)
        for c in command_list:
            self.cli_send_command(command=c)

    @classmethod
    def parse_row_lag(cls, row):
        """
        @brief  Yield lag group information.
                Will convert lagId to int for
                ONS 1.x compatibility.
        @type  row:  dict
        @rtype:  dict
        """
        if 'team' not in row['name']:
            lag_name = 'lag' + str(row['name'])
        else:
            lag_name = str(row['name'])
        _row = {
            'name': lag_name,

            # Feature not implemented WW05'15
            'actorAdminLagKey': 0,

            # Only static is supported WW05'15
            'lagControlType': 'Static',

            # Feature not implemented WW05'15
            'hashMode': 'None'
        }

        # ONPSS 2.x does not have separate lagId/Name field
        # ONS 1.x lagId field is int only
        try:
            _row['lagId'] = int(row['name'])
        except ValueError:
            _row['lagId'] = row['name']

        return _row

    def get_table_lags(self):
        """
        @brief  Get lag group information.
        Note: we can also use networkctl lag command
        @rtype:  list[dict]
        """
        table_ports = self.get_table_ports()
        table_lags = (r for r in table_ports if r['type'] == 'LAG')
        table_lags = [self.parse_row_lag(r) for r in table_lags]

        for row in table_lags:
            for lag in self.cli_send_command('teamdctl {0} state'.format(row["lagId"])).stdout.splitlines():
                if 'lacp' in lag:
                    row['lagControlType'] = 'Dynamic'

        return table_lags

    def modify_lags(self, lag, key=None, lag_type=None, hash_mode=None):
        """
        @copydoc testlib::ui_wrapper::UiInterface::modify_lags()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_link_aggregation(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_link_aggregation()
        @rtype:  list[dict]
        """
        lacp_enable = "Disabled"
        if self.get_port_configuration(port=self.cpu_port, getPortAttr="lag_mode") == 1:
            lacp_enable = "Enabled"
        _row = {
            'lacpEnable': lacp_enable,

            # Feature not implemented WW05'15
            'macAddress': 0,

            # Only static is supported WW05'15
            'priority': 'Static',
            'globalEnable': '',
            'globalHashMode': '',
            'globalHash': '',

            # Feature not implemented WW05'15
            'collectorMaxDelay': 'None'
        }
        return [_row]

    def configure_arp(self, garp=None, refresh_period=None, delay=None, secure_mode=None,
                      age_time=None, attemptes=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_arp()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_arp(self, ip, mac, port):
        """
        @brief  Create StaticARP record
        @param ip:  ARP ip address
        @type  ip:  str
        @param mac:  ARP mac address
        @type  mac:  str
        @param port:  port id
        @type  port:  int
        @return:  None
        """
        port_name = self.port_map[port]
        command = 'ip neigh add {0} lladdr {1} dev {2} nud perm'.format(ip, mac, port_name)
        self.cli_send_command(command=command)

    def delete_arp(self, ip, network, mode='arp'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_arp()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_arp(self, mode='arp'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_arp()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_static_route(self, ip, nexthop, network, distance=-1, mode='ip'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_static_route()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def delete_static_route(self, network):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_static_route()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_static_route(self, mode='ip'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_static_route()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

# HWOA configuration
    def create_match_api_tcam_subtable(self, source_id, table_id, table_name,
                                       max_table_entries, match_field_type_pairs,
                                       actions):

        """
        @brief  create a sub-table of tcam using the method defined in maa.py
        @param  source_id:  the source id in the tcam table.
        @type  source_id:  int
        @param  table_id:  a given table id.
                           If switchd running, table id starts from 5
                           If matchd is running, table id starts from 4
        @type  table_id:  int
        @param  table_name:  a given table name.
        @type  table_name:  str
        @param  max_table_entries:  maximum number of rules can be set.
        @type  max_table_entries:  int
        @param  match_field_type_pairs:  list of given match field with match type
        @type  match_field_type_pairs:  list[tuple(str, str)]
        @param  actions:  list of actions for configurable matches
        @type  actions:  list[str]
        """
        self.maa.create_maa_tcam_subtable(source_id, table_id, table_name,
                                          max_table_entries, match_field_type_pairs,
                                          actions)

    def create_match_api_rule(self, prio_id, handle_id, table_id,
                              match_field_value_mask_list, action, action_value=None):
        """
        @brief set a rule into the table using the method defined in maa.py
        @param  prio_id:  Higher id has a higher priority.
        @type  prio_id:  int
        @param  handle_id:  handle for match.
        @type  handle_id:  int
        @param  table_id:  the source table id where match to be set.
        @type  table_id:  int
        @param  match_field_value_mask_list:  field with match field, value and mask.
        @type  match_field_value_mask_list:  list[tuple(str, str, str)]
        @param  action:  given action for source table
        @type  action:  str
        @param  action_value:  action value for a specified action
        @type  action_value:  int
        """
        self.maa.create_maa_rule(prio_id,
                                 handle_id, table_id,
                                 match_field_value_mask_list,
                                 action,
                                 action_value)

    def get_table_match_api(self, table_id=None):
        """
        @brief  Lists the match api tables using the method defined in maa.py
        @param  table_id:  table ID
        @type  table_id:  int
        @rtype:  list[dict]
        """
        return self.maa.get_maa_table(table_id)

    def get_rules_match_api(self, table_id, handle_id=None):
        """
        @brief  Lists the match api rules of the table using the method defined in maa.py
        @params  table_id:  table ID (mandatory parameter)
        @type  table_id:  int
        @params  handle_id:  optional parameter
        @type  handle_id:   int
        @rtype:  list[dict]
        """
        return self.maa.get_maa_rules(table_id, handle_id)

    def delete_match_api_rule(self, handle_id, table_id):
        """
        @brief delete a match from the table using the method defined in maa.py
        @param  handle_id:  handle for match.[MANDATORY]
        @type  handle_id:  int
        @param  table_id:  the source table id where match to be set.[MANDATORY]
        @type  table_id:  int
        """
        self.maa.delete_maa_rule(handle_id, table_id)

    def delete_match_api_tcam_subtable(self, source_id, table_id=0, table_name=None):
        """
        @brief  Destroy a sub-table of tcam using the method defined in maa.py
        @param  source_id:  the source id in the tcam table.[MANDATORY]
        @type  source_id:  int
        @param  table_id:  a given table id.[MANDATORY if table_name not specified]
        @type  table_id:  int
        @param  table_name:  a given table name.[MANDATORY if table_id not specified]
        @type  table_name:  str
        """
        self.maa.delete_maa_tcam_subtable(source_id,
                                          table_id,
                                          table_name)

# OVS configuration
    def create_ovs_bridge(self, bridge_name):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_bridge()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_ovs_bridges(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_bridges()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def delete_ovs_bridge(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_ovs_bridge()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_ovs_port(self, port, bridge_name):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_port()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_ovs_ports(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_ports()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_ovs_rules(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_rules()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_ovs_bridge_controller(self, bridge_name, controller):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_bridge_controller()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_ovs_controllers(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_controllers()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_ovs_flow_rules(self, bridge_id, table_id, flow_id, priority, enabled):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_flow_rules()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def delete_ovs_flow_rules(self, bridge_id, table_id, flow_id, priority):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_ovs_flow_rules()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def configure_ovs_resources(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_ovs_resources()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_ovs_flow_actions(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_flow_actions()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_ovs_flow_actions(self, bridge_id, table_id, flow_id, action, param, priority=2000):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_flow_actions()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def delete_ovs_flow_actions(self, bridge_id, table_id, flow_id, action, priority=2000):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_ovs_flow_actions()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_ovs_flow_qualifiers(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ovs_flow_qualifiers()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_ovs_flow_qualifiers(self, bridge_id, table_id, flow_id, field, data, priority=2000):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ovs_flow_qualifiers
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def delete_ovs_flow_qualifiers(self, bridge_id, table_id, flow_id, field, priority=2000):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_ovs_flow_qualifiers
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

# LLDP configuration

    def clear_lldp_config(self):
        self.lldp.clear_settings()

    def configure_global_lldp_parameters(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_global_lldp_parameters()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    LLDP_ADMINSTATUS = {"TxOnly": "tx",
                        'RxOnly': "rx",
                        'TxAndRx': "rxtx",
                        'Disabled': "disabled"}

    def configure_lldp_ports(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_lldp_ports()
        @raise  SwitchException:  not implemented
        """
        cli_keys = {
            'adminStatus': self.LLDP_ADMINSTATUS,
            'tlvManAddrTxEnable': 'mngAddr',
            'tlvPortDescTxEnable': 'portDesc',
            'tlvSysCapTxEnable': 'sysCap',
            'tlvSysDescTxEnable': 'sysDesc',
            'tlvSysNameTxEnable': 'sysName'
        }

        # Select only allowed parameters for configuration
        params = {key: value for key,
                  value in kwargs.items() if key in cli_keys}

        for port in ports:
            # TODO: replace with generate_port_name
            port_name = self.port_map[port]

            for param, value in params.items():
                # admin status in CLI is handled differently: both Tx or Rx
                # mode can be banned or allowed
                if param == "adminStatus":
                    self.lldp.set_adminstatus(port_name, cli_keys[param][value])
                else:
                    # add 'no' command prefix to disable tlv
                    enable_tx = "no" if value == "Disabled" else "yes"
                    self.lldp.set_enable_tx(port_name, cli_keys[param], enable_tx)

    def get_table_lldp(self, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lldp()
        """
        # TODO: something with global settings which may not be supported yet
        raise SwitchException("Not implemented")

    def get_table_lldp_ports(self, port=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lldp_ports()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_lldp_ports_stats(self, port=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lldp_ports_stats()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_lldp_remotes(self, port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lldp_remotes()
        @raise  SwitchException:  not implemented
        """
        if port is not None:
            port_names = [self.port_map[port]]
        else:
            port_names = iter(self.port_map.values())
        tlvs_list = ((port_name, self.lldp.get_remote_tlvs(port_name)) for port_name in port_names)
        _table = []
        for p, tlvs in tlvs_list:
            row = {
                "remLocalPortNum": self.name_to_portid_map[p],
            }
            for tlv, value in tlvs:
                if tlv == lldp.TlvNames.CHASSIS_ID:
                    row.update(Tlv.get_chassis_tlv_row(value))
                elif tlv == lldp.TlvNames.PORT_ID:
                    row.update(Tlv.get_port_tlv_row(value))
                elif tlv == lldp.TlvNames.SYSTEM_DESCRIPTION:
                    row.update(Tlv.get_simple_tlv_row("remSysDesc", value))
                elif tlv == lldp.TlvNames.SYSTEM_NAME:
                    row.update(Tlv.get_simple_tlv_row("remSysDesc", value))
                elif tlv == lldp.TlvNames.PORT_DESCRIPTION:
                    row.update(Tlv.get_simple_tlv_row("remPortDesc", value))
                elif tlv == lldp.TlvNames.SYSTEM_CAPABILITIES:
                    row.update(Tlv.get_sys_cap_tlv_row(value))
            _table.append(row)

        return _table

    def get_table_remotes_mgmt_addresses(self, port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_remotes_mgmt_addresses()
        @rtype: list[dict]
        """
        if port is not None:
            port_names = [self.port_map[port]]
        else:
            port_names = iter(self.port_map.values())
        tlvs = ((port_name, self.lldp.get_remote_tlvs(port_name)) for port_name in
                port_names)

        mgmt_tlvs = (
            (p, Tlv.get_tlv_from_list(ts, lambda x: x == lldp.TlvNames.MANAGEMENT_ADDRESS))
            for p, ts in tlvs
        )

        _table = [dict(Tlv.get_mgmt_row(t),
                       remLocalPortNum=self.name_to_portid_map[p])
                  for p, t in mgmt_tlvs]
        return _table

    def disable_lldp_on_device_ports(self, ports=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::disable_lldp_on_device_ports()
        """
        if ports is None:
            port_names = list(self.port_map.values())
        else:
            values = (self.port_map.get(p) for p in ports)
            port_names = [v for v in values if v is not None]
        for port_name in port_names:
            try:
                self.lldp.set_adminstatus(port_name, self.LLDP_ADMINSTATUS["Disabled"])
            except UICmdException as e:
                # ignore failures on down ports
                if e.stdout != 'Device not found or inactive \n':
                    raise

# DCBX configuration
    def set_dcb_admin_mode(self, ports, mode='Enabled'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::set_dcb_admin_mode()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def enable_dcbx_tlv_transmission(self, ports, dcbx_tlvs="all", mode="Enabled"):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::enable_dcbx_tlv_transmission()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_dcbx_ports(self, port=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_ports()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_dcbx_app_maps(self, table_type="Admin", port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_app_maps()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def configure_application_priority_rules(self, ports, app_prio_rules):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_application_priority_rules()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def configure_dcbx_ets(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_dcbx_ets()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def configure_dcbx_cn(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_dcbx_cn()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def configure_dcbx_pfc(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_dcbx_pfc()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def configure_dcbx_app(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_dcbx_app()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_dcbx_remotes(self, port=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_remotes()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_dcbx_pfc(self, table_type="Local", port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_pfc()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

# UFD configuration

    def get_table_ufd_config(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ufd_config()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def restart_networkd_service(self):
        """
        @brief  Restarting systemd-networkd process
        @rtype:  bool
        @return:  True if result is none otherwise false
        @raise UiCmdException: when restart fails
        """
        return self.networkd.restart()

    def clear_networkd_settings(self):
        """
        @brief  Clear networkd settings
        @raise UiCmdException: when restart fails

        """
        self.networkd.clear_settings()

    def get_ufd_networkctl_status(self, ports):
        """
        @brief  Checking networkctl status
        @param  ports:  ports to check networkctl status
        @type  ports:  list[int]
        @return:  Returns Port Status as Dictionary format for list of Ports with attribute
                  as key and attribute value as value
                  If Uplink port -> Returns Values for Keys {'Carrier Bound By', 'Link File',
                  'Driver', 'MTU', 'Network File', 'State', 'Address', 'Type'}
                  If Downlink port-> Returns Values for Keys {'Carrier Bound To', 'Link File',
                  'Driver', 'MTU', 'Network File', 'State', 'Address', 'Type'}
        @rtype:  dict
        """
        network_dict = {}
        for port in ports:
            port_name = self.port_map[port]
            command = 'networkctl status {0}'.format(port_name)
            result = self.cli_send_command(command=command).stdout
            network_dict[port] = self._parse_networkctl(result)
        return network_dict

    def _parse_networkctl(self, res):
        """
        @brief  Parsing networkctl status output.
        @param  res:  command output
        @type  res:  str
        @return: Returns networkctl status in dictionary format
        @rtype: dict
        """
        result = res.splitlines()
        stripped = (line.strip() for line in result)
        temp_list = []

        # Lines which doesn't have ":" will be appended on previous line
        for line in stripped:
            if ': ' in line:
                temp_list.append(line)
            else:
                temp_list[-1] += " " + line

        # Split on ": "  and set max splits to about messing up
        # MAC address and IPv6 addresses that contain colon
        network_dict = {line.split(':', 1)[0].strip(): line.split(':', 1)[1].strip() for
                        line in temp_list if line}

        if 'Carrier Bound By' in network_dict:
            network_dict['downlink'] = network_dict.pop('Carrier Bound By')
            network_dict['downlink'] = [
                self.name_to_portid_map[name] for name in network_dict['downlink'].split(' ')]

        if 'Carrier Bound To' in network_dict:
            network_dict['uplink'] = network_dict.pop('Carrier Bound To')
            network_dict['uplink'] = [
                self.name_to_portid_map[name] for name in network_dict['uplink'].split(' ')]
        return network_dict


# DHCP Relay configuration

    def create_dhcp_relay(self, iface_name='global', server_ip=None, fwd_iface_name=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_dhcp_relay()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_dhcp_relay(self, dhcp_relay_ipv6=False):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dhcp_relay()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

# VxLAN configuration

    def configure_tunneling_global(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_tunneling_global()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_tunnels(self, tunnel_id=None, destination_ip=None, vrf=0, encap_type=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_tunnels()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_tunnels_admin(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_tunnels_admin()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

# ICMP Ping configuration
    def icmp_ping_request(self, ip_addr, ip_version, options="",
                          timeout=None, expected_rcs=frozenset({0})):
        """
        @brief  execute ping command
        @param  ip_addr:  the destination ip address to be pinged
        @type  ip_addr:  str
        @param  ip_version:  user specified ip address version
        @type  ip_version: int
        @param  options:  options for the ping command
        @type  options:  str
        @type  timeout:  int
        @type  expected_rcs:  int | set | list | frozenset
        @rtype:  str
        """
        ping_cmd_map = {4: 'ping', 6: 'ping6'}
        ping = ping_cmd_map[ip_version]
        result = None
        try:
            result = self.cli_send_command(
                '{0} {1} {2}'.format(ping, options, ip_addr), timeout, expected_rcs)
        except UICmdException as e:
            if e.rc == 2:
                raise BoundaryError(e.stderr)
            raise e
        return result

    @classmethod
    def parse_icmp_ping_result(cls, ping_output):
        """
        @brief  parses the output of ping command
        @type  ping_output:  str
        @rtype:  dict
        """
        pattern = re.compile(r'\((?P<ip_addr>.+?)\)\s'
                             r'(from (?P<source_ip>.*?) (?P<mgmt_interface>.*?):\s)?'
                             r'(?P<bytes>\d*)[\(\d*\)]*\s\w.*\n'
                             r'(?P<transmitted>\d*) packets transmitted,\s'
                             r'(?P<received>\d*) received,\s'
                             r'(\+(?P<error>\d*) errors,\s)?'
                             r'(?P<lost>\d*)% packet loss,\s'
                             r'time (?P<time>\d*)ms', re.DOTALL)
        res = pattern.search(ping_output).groupdict()

        ts_result = re.search(r'TS:\s+(\d+)', ping_output)
        if ts_result:
            res['time_stamp'] = ts_result.group(1)

        p_result = re.search(r'PATTERN:\s(\w+)', ping_output)
        if p_result:
            res['pattern'] = p_result.group(1)

        stat_keys = {"bytes", "transmitted", "received", "lost", "time"}
        res = {k: int(v) if k in stat_keys else v for k, v in res.items()}
        return res

    def get_icmp_ping_result(self, ip_addr, ip_version, options="",
                             timeout=None, expected_rcs=frozenset({0})):
        """
        @brief  return parsed result of ping command
        @param  ip_addr:  the destination ip address to be pinged
        @type  ip_addr:  str
        @param  ip_version:  user specified ip address version
        @type  ip_version: int
        @param  options:  options for the ping command
        @type  options:  str
        @type  timeout:  int
        @type  expected_rcs:  int | set | list | frozenset
        @return:  a dictionary containing various statistics related to a ping command
        @rtype:  dict
        """
        icmp_args = [ip_addr, ip_version]
        icmp_kwargs = {
            'options': options,
            'timeout': timeout,
            'expected_rcs': expected_rcs
        }
        output = self.icmp_ping_request(*icmp_args, **icmp_kwargs).stdout
        return self.parse_icmp_ping_result(output)

# iputils version
    def iputils_version(self, options=""):
        """
        @brief  Verify the versions of ping and ping6 in the iputils package.
        @type  options:  str
        @rtype:  str
        """
        cmd = ('rpm {0} iputils'.format(options))
        result = self.cli_send_command(command=cmd).stdout
        return result

    def create_invalid_ports(self, ports=None, num=1):
        """

        @brief creates port name if port id is passed say [Swop100, if 100 is passed as port id]
        Else creates port name with a value incremented to 10 to existing length of ports
        Ex[sw0p34 , currently sw0p24 is last port]
        @param ports: list of port_ids to generate port_names for
        @type ports: iter()
        @param num: generate num new invalid ports
        @type num: int
        """
        port_name = self.port_map.get(1, 'sw0p1')[:-1]
        if ports is not None:
            port_ids = {port_id: port_name + str(port_id) for port_id in ports}
        else:
            base = len(self.get_table_ports()) + 10
            # an invalid range will return an empty list and thus
            # an empty dict
            new_port_ids = (base + p for p in range(num))
            port_ids = {port_id: port_name + str(port_id) for port_id in new_port_ids}
        return InvalidPortContext(self, port_ids)

# NTP update
    def ntp_update(self):
        """
        @brief  Update date and time stamp using NTP server.
        @return:  status of operation (bool) or None if ntp_server not set
        @rtype:  bool | None
        """
        status = None
        if self.ntp_server is not None:
            status = (self.cli_send_command('ntpdate -u {}'.format(self.ntp_server)).rc == 0)
        return status

# Netns functionality
    def create_namespace(self, name):
        """
        @copydoc  testlib::linux_host_interface::LinuxHostInterface::create_namespace()
        """
        cmd = ("ip netns add {}".format(name))
        self.cli_send_command(command=cmd)

    def enter_namespace(self, name):
        """
        @copydoc  testlib::linux_host_interface::LinuxHostInterface::enter_namespace()
        """
        self.command_prefix = "ip netns exec {} ".format(name)

    def exit_namespace(self):
        """
        @copydoc  testlib::linux_host_interface::LinuxHostInterface::exit_namespace()
        """
        self.command_prefix = ""

    def delete_namespace(self, name):
        """
        @copydoc  testlib::linux_host_interface::LinuxHostInterface::delete_namespace()
        """
        cmd = ("ip netns delete {}".format(name))
        self.cli_send_command(command=cmd)

# Work with files and folder
    def create_folder(self, name, options=None, command=None, **kwargs):
        """
        @copydoc  testlib::linux_host_interface::LinuxHostInterface::create_folder()
        """
        cmd = mkdir_cmd.CmdMkdir(name=name, **kwargs)
        if options:
            _cmd_opts = mkdir_cmd.CmdMkdir(options)
            cmd.update(_cmd_opts)

        if command:
            cmd.update(command)

        if cmd:
            self.cli_send_command(command='mkdir {}'.format(str(cmd)))

    def delete_folder(self, name):
        """
        @copydoc  testlib::linux_host_interface::LinuxHostInterface::delete_folder()
        """
        cmd = ("rm -rf {}".format(name))
        self.cli_send_command(command=cmd)


class InvalidPortContext(object):
    """
    @description  Class to create a invalid por
    """
    def __init__(self, ui, ports):
        """"

        @brief intialize Invalidport class
        @param  ui:  instance of switch
        @type  ui:  UiOnpssShell
        @param  ports:  port id of invalid port
        @type  ports:  iter()
        """
        super(InvalidPortContext, self).__init__()
        self.ports = ports
        self.ui = ui

    def __enter__(self):
        """
        @return: list of ports
        @rtype: list
        """
        self.ui.port_map.update(self.ports)
        # just return the port list
        return list(self.ports.keys())

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        @brief deletes invalid port created
        """
        for key in self.ports:
            self.ui.port_map.pop(key)
