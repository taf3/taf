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

@file  ui_onpss_shell.py

@summary  ONPSS Shell UI wrappers Implementation
"""
import json
import os
import time
import re
import itertools
import ipaddress as ipaddr
from collections import ChainMap

import pytest

from .switch_driver import SwitchDriver
from testlib.ui_helpers import UiHelperMixin
from testlib.ui_wrapper import UiInterface
from testlib.custom_exceptions import SwitchException, UICmdException, UIException
from testlib.custom_exceptions import AccessError, ArgumentError, BoundaryError
from testlib.custom_exceptions import ExistsError, NotExistsError, InvalidCommandError
from testlib.linux_app_host import SwitchdSharedApp, TestPointApp
from testlib.linux import lldp
from testlib.lldp import Tlv
from testlib.linux.dcrpd import Dcrpd
from testlib.linux import networkd
from testlib.linux import maa
from testlib import multicall
from testlib.cli_template import CmdStatus
from testlib.linux import service_lib
from testlib.linux import stresstool
from testlib.linux import collectd
from testlib.linux import hugepages

ENABLE_DISABLE_MAP = {
    0: "Disabled",
    1: "Enabled",
    "Disabled": 0,
    "Enabled": 1,
}

LAG_HASH_MODES = {
    'SrcMac': 'l2_hash_key_smac_mask', 'DstMac': 'l2_hash_key_dmac_mask',
    'SrcIp': 'l3_hash_config_sip_mask', 'DstIp': 'l3_hash_config_dip_mask',
    'L4SrcPort': 'l3_hash_config_l4_src_mask', 'L4DstPort': 'l3_hash_config_l4_dst_mask',
    'Protocol': 'l3_hash_config_protocol_mask', 'L2ifip': 'l2_hash_key_use_l2_if_ip',
    'UseL3hash': 'l2_hash_key_use_l3_hash', 'UseTcp': 'l3_hash_config_use_tcp',
    'UseUdp': 'l3_hash_config_use_udp', 'Dscp': 'l3_hash_config_dscp_mask',
    'EtherType': 'l2_hash_key_ethertype_mask', 'Ip6Flow': 'l3_hash_config_flow_mask',
    'SymmetrizeL3': 'l3_hash_config_symmetrize_l3_fields',
    'OuterVlanId': 'l2_hash_key_vlan_id_1_mask', 'VlanId': 'l2_hash_key_vlan_id_1_mask'
}


STAT_MAP = {
    "RxUcstPktsIPv4": "cntRxUcstPktsIPv4",
    "RxUcstPktsIPv6": "cntRxUcstPktsIPv6",
    "RxUcstPktsNonIP": "cntRxUcstPktsNonIP",
    "TxUcstPktsIPv4": "cntTxUcstPkts"
}


class UiOnpssShell(UiHelperMixin, UiInterface):
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
    # dcrp constants
    DCRP_CFG_FILE = '/etc/dcrpd.conf'
    DCRP_CFG_CPP_KEY = 'cppname'
    DCRP_CFG_MESH_KEY = 'mesh_port'
    DCRP_CFG_MLAG_UPLINKS = 'uplink_port'
    DCRP_CFG_MLAG_MAC = 'lag_mac'
    DCRP_SRVC = 'dcrpd'
    DCRP_SRVCS = [DCRP_SRVC, 'isisd', 'zebra']
    DCRP_CFG_PORTS_DEFAULT = '("sw0p1","sw0p5")'
    DCRP_CFG_MAC_DEFAULT = 'aa:bb:cc:dd:ee:ff'
    COLLECTD_SRVC = 'collectd'

    def __init__(self, switch):
        """
        @brief  Initialize UiOnpssShell class
        @param  switch:  Switch instance
        @type  switch:  SwitchGeneral
        """
        self.switch = switch
        self.ris = {}
        self.networks = []
        self.mode_prompt = self.switch.config['cli_user_prompt']

        self.lag_map = {}
        self.switch_map = {}
        self.name_to_switchid_map = {}
        self.name_to_lagid_map = {}
        self.port_map = ChainMap(self.switch_map, self.lag_map)
        self.name_to_portid_map = ChainMap(self.name_to_switchid_map, self.name_to_lagid_map)
        self.switch_driver = SwitchDriver(self, self.switch)
        self.dcrpd = Dcrpd(self.cli_send_command, self.switch)
        self.hw = self.import_hw_module(self.switch.hw)
        self.lldp = lldp.Lldp(self.cli_send_command)
        self.networkd = networkd.NetworkD(self.cli_send_command, [self.switch.mgmt_iface])
        self.maa = maa.MatchActionAcceleration(self.cli_send_command)
        self.stresstool = stresstool.StressTool(self.cli_send_command)
        # Collectd tool
        self.collectd = collectd.Collectd(self.cli_send_command, self.cli_set,
                                          self.switch.config.get('collectd_conf_path'))
        # Hugepages
        self.hugepages = hugepages.HugePages(self.cli_send_command)

        # Initialize lag/vlan map
        self.vlans = [{"vlanId": 1, "name": "VLAN-1"}]

        # Database of default static FDB entries
        self.default_fdb = {}

        # Read NTP server value
        self.ntp_server = None
        try:
            for x in switch.config['related_conf'].values():
                if x['name'] == 'ntp':
                    self.ntp_server = x['ip_host']
        except KeyError:
            pass

    def reinit(self):
        """
        @brief  Re-initialize class attributes
        """
        # Clear 'fake' Vlans table
        self.vlans = [{"vlanId": 1, "name": "VLAN-1"}]

        # Clear lag_map
        self.lag_map.clear()
        self.name_to_lagid_map.clear()

        # Generate the default FDB table
        self.default_fdb = self.get_table_fdb(table='static')
        # Set MAC addresses to all switch ports
        switch_id = self.switch.config['id'].zfill(6)
        table_ports = self.get_table_ports(ports=self.switch_map)
        for row in table_ports:
            if row.get("macAddress") == "00:00:00:00:00:00":
                self.modify_ports(ports=[row['portId']], macAddress="00:00:{0}:{1}:{2}:{3}".format(
                        switch_id[0:2], switch_id[2:4], switch_id[4:6], row['portId']))

        # Restart lldpad to advertise new TLV's due to MAC address change above
        # self.clear_lldp_config()

    def import_hw_module(self, hw):
        """

        @param hw: Switch
        @return: UiOnpssShell specific hardware module
        @rtype:  module
        """
        module_name = hw.__class__.__name__.lower().replace("silicon", "")
        # use __import__ instead of importlib so we don't have to guess the
        # actual absolute module name in sys.modules
        return __import__(module_name, globals(), locals(), [], 1)

    def connect(self):
        """
        @brief  Attempts to create a ssh session to the switch
        """
        self.switch.ssh.login()
        self.switch.ssh.open_shell()
        # need to detect switch before we can get port info
        # in case we need to restart it
        self.switch_driver.autodetect()
        self.test_point = TestPointApp(self.switch.ipaddr, self.switch._sshtun_port,
                                       self.switch._sshtun_user, self.switch._sshtun_pass,
                                       self.mode_prompt)
        self.switchd = SwitchdSharedApp(self.switch.ipaddr, self.switch._sshtun_port,
                                        self.switch._sshtun_user, self.switch._sshtun_pass,
                                        self.mode_prompt, self.switch_driver.name)

    def disconnect(self):
        """
        @brief  Disconnects the ssh session from the switch
        """
        try:
            if self.switch.ssh:
                self.switch.ssh.close()
        except Exception as err:
            raise UIException(err)

    def start_switchd(self):
        """
        @brief  Restarts the switchd instance of the switch
        """
        self.switch_driver.force_reload()
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
        If the command hasn't finished yet, this method will wait until
        it does, or until the channel is closed.  If no exit status is
        provided by the server, -1 is returned.


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
        cmd_status = self.switch.ssh.exec_command(command, timeout)
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
        # cmds are full strings, so we have to split in remote_multicall_template
        for cmd in multicall.generate_calls(commands):
            cmd_status = self.switch.ssh.exec_command(cmd, timeout)
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
                                     expected_rcs=frozenset(range(self.MAX_EXIT_STATUS)))
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
        self.networkd.stop()
        self.networkd.clear_settings()
        self.start_switchd()
        self.networkd.start()
        # Clear LLDP
        self.clear_lldp_config()
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

        if (not (self.switch.ssh.check_client() and
                 self.switch.ssh.check_shell())):

            try:
                self.connect()
                # Generate ports mapping after initialization of inherited UIs
                self.generate_port_name_mapping()
            except:
                self.disconnect()
                raise SwitchException("Device is not ready.")

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
                 "cpuArchitecture":
                 self.cli_send_command('uname --hardware-platform').stdout.strip(),
                 "osType":
                 self.cli_send_command('uname --kernel-name').stdout.strip(),
                 "osVersion":
                 self.cli_send_command('uname --kernel-release').stdout.strip(),
                 "chipName": getattr(self.switch, "jira_platform_name", self.switch.__class__.__name__),
                 "serialNumber": "NA"}]

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
        show_command = [['free'], ]
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
        commands = [['top -bn 1'], ]
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

    def get_journalctl_log(self, date_since=None, date_until=None, boot_id='', additional_args=''):
        """
        @brief  Returns journalctl log
        @param date_since: Date to return log since
        @type date_since: str
        @param date_until: Date to return log until
        @type date_until: str
        @param boot_id: Boot id to show data from
        @type date_until: str
        @param additional_args: Additional options to be passed if required
        @type additional_args: str
        @rtype:  generator
        @return:  Generator of dicts of journalctl log
        """
        arg_since, arg_until = '', ''
        if date_since:
            arg_since = "--since='{0}'".format(date_since)
        if date_until:
            arg_until = "--until='{0}'".format(date_until)
        command = "journalctl -o json --no-pager -b {0} {1} {2} {3}".format(boot_id, arg_since,
                                                                            arg_until,
                                                                            additional_args)
        try:
            jctl_raw = self.cli_send_command(command)
        except UICmdException as err:
            raise UIException("Incorrect arguments passed to method. {}".format(err.stderr))

        return (json.loads(x, encoding='utf-8') for x in jctl_raw.stdout.splitlines())

# STP configuration
    def configure_spanning_tree(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_spanning_tree()
        """
        pass

    def create_stp_instance(self, instance, priority):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_stp_instance()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def configure_stp_instance(self, instance, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_stp_instance()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_spanning_tree(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_spanning_tree()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_spanning_tree_mst(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_spanning_tree_mst()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_mstp_ports(self, ports=None, instance=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_mstp_ports()
        @raise  SwitchException:  not implemented
        """
        # NOS does not support MSTP protocol. WW13'15

    def modify_mstp_ports(self, ports, instance=0, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_mstp_ports()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def modify_rstp_ports(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_rstp_ports()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_rstp_ports(self, ports=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_rstp_ports()
        @raise  SwitchException:  not implemented
        """
        # NOS does not support RSTP protocol. WW13'15
        return [{'state': 'Forwarding'}]

# Ports configuration
    def set_all_ports_admin_disabled(self):
        """
        @brief  Disables all ports in port_map on switch.
        """
        ports_table = self.get_table_ports()
        ports = [x['portId'] for x in ports_table if x["portId"] not in self.switch.mgmt_ports]
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
            'Unknown', 'Down'} and x["portId"] not in self.switch.mgmt_ports]

        if port_ids:
            up_ports = _retry(port_ids)

            attempts = 0

            while up_ports and attempts < 3:
                # retry: set adminMode in Up/Down
                # define multicall params for nb.Ports.set.adminMode method
                self.switch.ui.modify_ports(up_ports, adminMode='Up')
                self.switch.ui.modify_ports(up_ports, adminMode='Down')
                up_ports = _retry(up_ports)
                attempts += 1

            if up_ports:
                pytest.fail("Not all ports are in down state: %s" % up_ports)

    def get_available_switch_ports(self, ports=None):
        """
        @brief: Check list of ports to see which are available

        @param ports: list of port IDs
        @type ports: list[int | str]
        @return: list of port IDs that are available
        @rtype: list[int | str]
        """
        if ports is None:
            port_names = list(self.port_map.values())
        else:
            port_names = [self.generate_port_name(port_id) for port_id in ports]
        commands_list = [[r'find /sys/class/net/{}/switch -type d'.format(port)]
                         for port in port_names]
        results = self.cli_set(commands_list, multicall_treshold=1, expected_rcs=frozenset({0, 1}))
        return [self.name_to_portid_map[name] for name, r in zip(port_names, results) if
                r[0].rc == 0]

    def is_port_switch_available(self, port):
        """
        @brief:  Check to see if the port has sysfs switch/ available
        @raise:  UiCmdException
        @rtype:  bool
        """
        try:
            self.cli_send_command(
                command=r'find /sys/class/net/{}/switch -type d'.format(port))
        except UICmdException as e:
            if e.rc == 1:
                return False
            else:
                raise

        return True

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
        @raise:  AccessError | SwitchException
        @return:  port attribute value
        """
        port_name = self.generate_port_name(port=port)
        if not self.is_port_switch_available(port=port_name):
            raise SwitchException("Switching not available on port {}.".format(port_name))

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
        @raise:  SwitchException
        @rtype:  dict
        """
        port_name = self.generate_port_name(port=port)

        if not self.is_port_switch_available(port=port_name):
            raise SwitchException("Switching not available on port {}.".format(port_name))

        attribute_raw_list = []
        if stats == 'attributes':
            attribute_raw_list = self.cli_send_command(
                command=r'find /sys/class/net/{0}/switch/ -maxdepth 1 -type f -printf '
                        r'"%f\0"'.format(port_name)).stdout.split('\x00')

        attribute_in_class = (r for r in attribute_raw_list if getattr(self.switch.hw, r, False))
        attribute_list = (r for r in attribute_in_class if r not in skip_list)

        if port in self.lag_map:
            attribute_list = (r for r in attribute_list if getattr(getattr(
                self.switch.hw, r, False), 'is_perlag', False))

        if port == self.cpu_port:
            attribute_list_filtered = (r for r in attribute_list if getattr(
                self.switch.hw, r, False).cpu_port is not None)
        else:
            attribute_list_filtered = (r for r in attribute_list if getattr(
                self.switch.hw, r, False).cpu_port != 'cpu_port_only')

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
        available_switch_ports = self.get_available_switch_ports(ports)
        for port_id in available_switch_ports:
            port = self.generate_port_name(port=port_id)
            _adminMode = kwargs.get('adminMode', '').lower()
            if _adminMode in ['up', 'down']:
                port_info = self.get_table_ports([port_id])[0]
                if port_info['type'] == 'LAG':
                    # Get LAG ports
                    _ports = [x['portId'] for x in self.get_table_ports2lag()
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
                    self.cli_send_command(command="ip addr flush dev {0}".format(port))
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
        @brief  Returns generator of dictionaries of port properties.
        @param  ports_table:  port information
        @type  ports_table:  list[str]
        @rtype:  generator
        @return:  generator of dicts of port properties
        """
        # Compile regular expression for validating output
        for row in ports_table:
            _row = {}
            row = row.strip()
            row_head = cls.INDEX_NAME_RE.search(row)
            if row_head:
                _row['portId'] = int(row_head.group('index'))
                _row['master'] = None
                if re.search(r"sw0p\d*", row_head.group('name')):
                    # ovs use master ovs-system so include dash
                    row_master = re.search(r'(?<=master\s)[\w-]*', row)
                    if row_master:
                        _row['master'] = row_master.group()
                        _row['type'] = 'LAGMember'
                    else:
                        _row['type'] = 'Physical'
                    row_id = re.search(r'(?<=portid\s)\w*', row)
                    if row_id:
                        _row['portId'] = int(row_id.group(), 16)
                elif re.search(r'team(\s|$)(?!:)', row):
                    _row['type'] = 'LAG'
                    try:
                        _row['portId'] = int(row_head.group('name'))
                    except ValueError:
                        _row['portId'] = row_head.group('name')
                else:
                    continue
                _row['name'] = row_head.group('name')
                _row['macAddress'] = re.search(
                    r'(?<=link/ether\s)(\w*:)+\w*', row).group()
                row_prop = re.search(
                    r'(?<=mtu\s)(?P<mtu>\d*)(\s[\w-]*)*'
                    r'(?<=state\s)(?P<adminMode>[\w-]*)', row)
                _row['mtu'] = int(row_prop.group('mtu'))
                _row['adminMode'] = row_prop.group('adminMode').title()
                if 'NO-CARRIER' in row:
                    _row['adminMode'] = "Up"
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
        if ports:
            command_list = [['ip -o {0} link show {1}'.format(
                iplink_params, self.generate_port_name(port=p))] for p in ports]
        else:
            command_list = [['ip -o {0} link show'.format(iplink_params)], ]

        raw_data = self.cli_get_all(command_list, multicall_treshold=1)
        all_port_dicts = (self.parse_table_ports(r) for r in raw_data)
        ports = list(itertools.chain.from_iterable(all_port_dicts))

        command_list = [["cat /sys/class/net/{0}/switch/{1}".format(
                            _port['name'], 'max_frame_size')] for _port in ports]
        frame_sizes = self.cli_get_all(command_list, multicall_treshold=1)

        command_list = [["ethtool {0}".format(_port['name'])] for _port in ports]
        ethtool_info = self.cli_get_all(command_list, multicall_treshold=1)

        # iterate all three tables together
        for _port, _table, _frame_size in zip(ports, ethtool_info, frame_sizes):
            if _frame_size and _frame_size[0]:
                _port['maxFrameSize'] = int(_frame_size[0])
            else:
                _port['maxFrameSize'] = self.switch.hw.default_max_frame_size
            speed = next(x for x in _table if 'Speed' in x)
            _port['duplex'] = next(x for x in _table if 'Duplex' in x).split(':')[-1]
            _port['duplex'] = _port['duplex'].strip().lower()

            link_status = next(x for x in _table if 'Link detected' in x).split(':')[-1]
            link_status = link_status.strip().lower()
            _port['operationalStatus'] = ('Up' if link_status == 'yes' else 'Down')

            if 'Unknown' in speed:
                _port['speed'] = 0
            else:
                # find first string of digits after a colon
                _port['speed'] = int(
                    re.search(r"(?!:)\d+", speed).group(0))

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
                command_list = [['ip -o addr show {0}'.format(self.port_map[_port['portId']])]
                                for _port in ports]
                ip_addresses = self.cli_get_all(command_list, multicall_treshold=1)

                for _port, _table in zip(ports, [" ".join(ip_addresses[0])]):
                    _port['ip_addr'] = re.findall(
                        r'inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', _table)
                    if _port['ip_addr']:
                        for index, value in enumerate(_port['ip_addr']):
                            _port['ip_addr'][index] = str(ipaddr.IPv4Address(value))

                    _port['ipv6_addr'] = re.findall(
                        r'inet6 ((?:[0-9a-f]{1,4}(?:::)?){0,7}::[0-9a-f]+)', _table)
                    if _port['ipv6_addr']:
                        for index, value in enumerate(_port['ipv6_addr']):
                            _port['ipv6_addr'][index] = str(ipaddr.IPv6Address(value))

            except ValueError:
                raise SwitchException('Configured IP Address does not appear to be valid')
            except:
                raise SwitchException('No switch ports found.')

        # Raise exception if no switchports or LAGs found
        if not any(r for r in ports if 'sw0p' in r['name'] or r['type'] == 'LAG'):
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
                              attrVal=self.switch.hw.pause_mode.min)
        elif tx_mode == 'class_based':
            # Enable class based tx pause mode
            self.modify_ports(ports, setPortAttr="pause_mode",
                              attrVal=self.switch.hw.pause_mode.max)
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
                          attrVal=self.switch.hw.smp_lossless_pause.min)

    def _enable_tx_fc(self, ports=None):
        """
        @brief  Enables transmit of 802.3x pause frames per port.
        @param  ports:  list of port ids
        @type  ports:  list[int]
        """
        self.modify_ports(ports, setPortAttr="smp_lossless_pause",
                          attrVal=self.switch.hw.smp_lossless_pause.max)

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

# Ustack configuration
    def start_ustack_with_given_mesh_ports(self, mesh_ports=tuple(),
                                           dbglevel=0):
        """
        @brief  Starts ustack mesh given ports
        @param  mesh_ports:  list of port IDs
        @type  mesh_ports:  list[int]
        @param  dbglevel:  dbglevel value
        @type  dbglevel:  int
        @raise  UIException:  dbglevel is either 1 or 0
        @rtype:  list[list[str]]
        @return:  ustack mesh command results
        """
        mesh_ports_name_list = [self.port_map[port_id] for port_id in
                                mesh_ports]
        mesh_ports_name_str = ','.join(mesh_ports_name_list)

        # save this for later, use the current time to make it unique
        self._ustack_output_file = "/tmp/ustack-{0}.out".format(
            int(time.time()))

        if dbglevel == 0:
            dbglevel = ""
        elif dbglevel == 1:
            dbglevel = "-dbglevel=1"
        else:
            raise UIException('dbglevel is either 1 or 0')
        # use nohup so ustackd will not receive SIGHUP if session
        # disconnects
        ustack_start_command = \
            "nohup ustackd -mesh={0} {1} -d " \
            "</dev/null &>{2} &".format(
                mesh_ports_name_str, dbglevel, self._ustack_output_file)

        cmd_result = self.cli_get_all([[ustack_start_command]])
        return cmd_result[0]

    def start_dcrp_with_given_mesh_ports(self, mesh_ports=None, timeout=30, mlag_conf=None):
        """
        @brief  Starts dcrp service with given mesh ports
        @param  mesh_ports:  list of port IDs
        @type  mesh_ports:  list[int]
        @param  timeout:  time limit for DCRP startup
        @type  timeout:  int
        @param  mlag_conf:  a dictionary containing MLAG uplink ports and MLAG MAC address
                            example:
                            {'uplink_port': ['sw0p1', 'sw0p2' ], 'lag_mac': '00:55:ea:ea:ea:e1'}
        @type  mlag_conf:  dict
        """
        cpp_port = self.port_map[self.cpu_port]

        if not mesh_ports:
            raise UIException("No mesh ports specified.")
        mesh_ports_name_list = [self.port_map[port_id] for port_id in
                                mesh_ports]
        mesh_ports_name_str = '("' + '","'.join(mesh_ports_name_list) + '")'

        cpp_set_cmd = 'sed -i \'s/^{0}.*/{0}="{1}"/\' {2}'\
                      .format(self.DCRP_CFG_CPP_KEY, cpp_port,
                              self.DCRP_CFG_FILE)
        port_set_cmd = 'sed -i \'s/^{0}.*/{0}={1}/\' {2}'\
                       .format(self.DCRP_CFG_MESH_KEY, mesh_ports_name_str,
                               self.DCRP_CFG_FILE)

        if mlag_conf is not None:
            mlag_port_names = [self.port_map[port_id] for port_id in
                               mlag_conf[self.DCRP_CFG_MLAG_UPLINKS]]
            mlag_ports_str = '("' + '","'.join(mlag_port_names) + '")'
            mlag_set_ports_cmd = ('sed -i \'s/.*{0}.*/{0}={1}/\' {2}'.
                                  format(self.DCRP_CFG_MLAG_UPLINKS, mlag_ports_str,
                                         self.DCRP_CFG_FILE))
            mlag_set_mac_cmd = ('sed -i \'s/.*{0}.*/{0}="{1}"/\' {2}'.
                                format(self.DCRP_CFG_MLAG_MAC,
                                       mlag_conf[self.DCRP_CFG_MLAG_MAC],
                                       self.DCRP_CFG_FILE))
            self.cli_send_command(mlag_set_ports_cmd)
            self.cli_send_command(mlag_set_mac_cmd)

        self.cli_send_command(cpp_set_cmd)
        self.cli_send_command(port_set_cmd)
        dcrp_srvc_manager = service_lib.specific_service_manager_factory(
            self.DCRP_SRVC, self.cli_send_command)
        dcrp_srvc_manager.restart(expected_rcs={0})

        # wait timeout until all daemons are running
        srvcs_enabled = False
        start_time = time.time()
        while not srvcs_enabled and (time.time() < start_time + timeout):
            if len(self.cli_send_command('pidof ' + ' '.join(self.DCRP_SRVCS))[0].
                   split(' ')) == len(self.DCRP_SRVCS):
                srvcs_enabled = True
                break
            time.sleep(1)

    def stop_dcrp(self):
        """
        @brief  Stopping DCRP service
        @return:  None
        """
        dcrp_srvc_manager = service_lib.specific_service_manager_factory(
            self.DCRP_SRVC, self.cli_send_command)
        dcrp_srvc_manager.stop(expected_rcs={0})

    def clear_config_dcrp(self):
        """
        @brief  Restoring default DCRP config entries
        @return:  None
        """
        cpp_revert_cmd = ('sed -i \'s/^{0}.*/{0}="{1}"/\' {2}'
                          .format(self.DCRP_CFG_CPP_KEY, self.port_map[self.cpu_port],
                                  self.DCRP_CFG_FILE))
        port_revert_cmd = ('sed -i \'s/^{0}.*/{0}={1}/\' {2}'
                           .format(self.DCRP_CFG_MESH_KEY, self.DCRP_CFG_PORTS_DEFAULT,
                                   self.DCRP_CFG_FILE))
        mlag_revert_ports_cmd = ('sed -i \'s/.*{0}.*/# {0}={1}/\' {2}'
                                 .format(self.DCRP_CFG_MLAG_UPLINKS, self.DCRP_CFG_PORTS_DEFAULT,
                                         self.DCRP_CFG_FILE))
        mlag_revert_mac_cmd = ('sed -i \'s/.*{0}.*/# {0}="{1}"/\' {2}'
                               .format(self.DCRP_CFG_MLAG_MAC, self.DCRP_CFG_MAC_DEFAULT,
                                       self.DCRP_CFG_FILE))
        self.cli_send_command(cpp_revert_cmd)
        self.cli_send_command(port_revert_cmd)
        self.cli_send_command(mlag_revert_ports_cmd)
        self.cli_send_command(mlag_revert_mac_cmd)

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
        valid_tagged_args = {'tagged', 'untagged', 'pvid', 'pvid untagged'}
        tagged = tagged.lower()

        if not (ports is None or vlans is None):
            if tagged in valid_tagged_args:
                port_names = [self.port_map[p] for p in ports]

                command_list = self._generate_bridge_vlan_commands(
                    "add", port_names, vlans, tagged=tagged if tagged != 'tagged' else "")
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

            # Generate dictionary {portId: current_tagged_value}
            ports_tagged_dict = {}
            for row in vlans_and_ports_found:
                self.delete_vlan_ports(ports=[row['portId']], vlans=[row['vlanId']])
                # replace True/False values with string 'pvid'/''
                row['pvid'] = 'pvid' if row['pvid'] or tagged == 'pvid' else ''
                if tagged != 'pvid':
                    row['tagged'] = tagged
                if row['tagged'] == 'Tagged':
                    row['tagged'] = ''
                ports_tagged_dict[row['portId']] =tagged if row['pvid'] == '' else ' '.join([row['pvid'], row['tagged']]).strip()
                ports.remove(row['portId'])

            # Group records in ports_tagged_dict by values
            tagged_ports_dict = {}
            for key, value in ports_tagged_dict.items():
                tagged_ports_dict.setdefault(value, []).append(key)

            for _tagged, _ports in tagged_ports_dict.items():
                self.create_vlan_ports(ports=_ports, vlans=vlans, tagged=_tagged)
            if ports:
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

# ACL configuration
    def create_acl_name(self, acl_name=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_acl_name()
        """
        self.cli_send_command('acl create {}'.format(acl_name))

    def add_acl_rule_to_acl(self, acl_name=None, rule_id='', action=None, conditions=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::add_acl_rule_to_acl()
        """
        port_str = ''
        if 'mirror' in action[0]:
            split_p = action[1].split(',')
            port_str = ','.join([self.port_map[int(x)] for x in split_p[1:]]) + ' ' + \
                       self.port_map[int(split_p[0])]
        elif action[0] == 'forward':
            port_str = self.port_map[int(action[1])]
        command = 'acl create-rule {0} {1} {2} {3} {4}'.format(acl_name, rule_id,
                                                               action[0],
                                                               port_str,
                                                               ' '.join([' '.join(x)
                                                                         for x in conditions]))
        self.cli_send_command(command)

    def bind_acl_to_ports(self, acl_name=None, ports=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::bind_acl_to_ports()
        """
        ports_str = ','.join([self.port_map[int(x)] for x in ports])
        self.cli_send_command('acl bind-ports {0} {1}'.format(acl_name, ports_str))

    def unbind_acl(self, acl_name=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::unbind_acl()
        """
        self.cli_send_command('acl unbind {0}'.format(acl_name))

    def create_acl(self, ports=None, expressions=None, actions=None, rules=None, acl_name='Test-ACL'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_acl()
        """
        expression_map = {'SrcMac': 'mac-source',
                          'DstMac': 'mac-dest',
                          'SrcIp': 'ip-source',
                          'DstIp': 'ip-dest',
                          'L4SrcPort': 'l4-source',
                          'L4DstPort': 'l4-dest',
                          'OuterVlanId': 'vid',
                          'IpProtocol': 'protocol'}
        action_map = {'Allow': 'permit',
                      'Drop': 'deny',
                      'Redirect': 'forward',
                      'MirrorIngress': 'mirror ingress',
                      'MirrorEgress': 'mirror egress',
                      'MirrorBidirectional': 'mirror bidirectional',
                      'MirrorRedirect': 'mirror redirect'}

        # Create ACL
        exist_acl = [x for x in self.get_acl_names() if x["aclName"] == acl_name]
        if not exist_acl:
            self.create_acl_name(acl_name)

        # Generate pairs rule-action-expression based on ids
        if rules and actions and expressions and ports:
            # Convert L4Port masks from hex to decimal:
            for x in expressions:
                if x[1] in {'L4SrcPort', 'L4DstPort'}:
                    x[2] = str(int(x[2], 16))
                elif x[1] == 'OuterVlanId':
                    x[2] = str(int(x[2], 16))
                    x[3] = str(int(x[3], 16))
                elif x[1] == 'IpProtocol':
                    x[2] = ''
                    x[3] = str(int(x[3], 16))
            # Generate source ports for MirrorIngress action:
            for x in actions:
                if x[1] == 'MirrorIngress':
                    x[2] += ',' + ','.join([str(x) for x in ports])
            for rule in rules:
                try:
                    # related expression:
                    related_expression = [[expression_map[expr[1]], expr[3], expr[2]]
                                          for expr in expressions if expr[0] == rule[0]]

                    # related action:
                    related_action = [[action_map[x[1]], x[2]] for x in actions if x[0] == rule[0]]
                    assert len(related_action) == 1, "Only one ACl action " \
                                                     "is possible to be added to the same acl rule"
                    self.add_acl_rule_to_acl(acl_name=acl_name,
                                             rule_id=rule[0],
                                             action=related_action[0],
                                             conditions=related_expression)
                except KeyError as err:
                    pytest.fail("Unsupported input ACL data is passed to function create_acl."
                                "{}".format(err))

            self.bind_acl_to_ports(acl_name, ports)
        else:
            pytest.fail("Missed input ACL data")

    def delete_acl(self, ports=None, expression_ids=None, action_ids=None, rule_ids=None, acl_name=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_acl()
        """
        if rule_ids is None:
            self.cli_send_command('acl delete {0}'.format(acl_name))
        else:
            [self.cli_send_command('acl delete-rule {0} {1}'.format(acl_name, rule_id))
             for rule_id in rule_ids]

    def get_table_acl(self, table=None, acl_name=None):
        """
        @brief  Get ACL table
        @param table:  ACL table name to be returned. None
        @type  table:  str
        @param acl_name:  ACL name
        @type  acl_name:  str
        @rtype:  dict
        @return:  table (dictionary)
        @raise  UIException: Only ONP specific table is supported
        @par Example:
        @code
        env.switch[1].ui.get_table_acl(acl_name='Test-1')
        @endcode
        """
        if table in ['ACLStatistics', 'ACLExpressions', 'ACLActions', 'ACLRules']:
            raise UIException("Specified table "
                              "is not supported on current platform: {0}".format(table))
        bound_ports = None
        rules_list = []
        acl_name_compile = re.compile(r'ACL name: (.*)\n')
        bound_ports_compile = re.compile(r'Bound Ports:\n(.*)\n', re.DOTALL)
        rule_id_compile = re.compile(r': (.*)\n')
        action_compile = re.compile(r'Action: (.*)Conditions:', re.DOTALL)
        mirror_type_compile = re.compile(r'Type: (.*)\n')
        source_p_compile = re.compile(r'Source Ports:\n(.*)Destination Port:', re.DOTALL)
        dest_p_compile = re.compile(r'Destination Port:(.*)Conditions:', re.DOTALL)
        cond_compile = re.compile(r'Conditions:\n(.*)\n\n', re.DOTALL)
        cond_val_mask = re.compile(r'(.*): (.*)\((.*)\)')
        cond_val__without_mask = re.compile(r'(.*): (.*)')

        output = self.cli_send_command('acl show {0}'.format(acl_name)).stdout

        list_of_rules = output.split('Rule ID')
        for rule in list_of_rules[1:]:
            rule_id = None
            action = None
            conditions = []
            rule_id_found = rule_id_compile.search(rule)
            if rule_id_found:
                rule_id = int(rule_id_found.group(1))
            action_found = action_compile.search(rule)
            if action_found:
                parsed_action = action_found.group(1)
                action = [parsed_action.splitlines()[0], '']
                if 'mirror' in parsed_action:
                    mirror_type_found = mirror_type_compile.search(rule)
                    if mirror_type_found:
                        action[0] += ' ' + mirror_type_found.group(1)
                    source_p_found = source_p_compile.search(rule)
                    dest_p_found = dest_p_compile.search(rule)
                    if source_p_found and dest_p_found:
                        action[1] = str(self.name_to_portid_map[dest_p_found.group(1).strip()]) + \
                                    ',' + ','.join([str(self.name_to_portid_map[x.strip()]) for x in source_p_found.group(1).strip().splitlines()])
                elif 'forward' in parsed_action:
                    dest_p_found = dest_p_compile.search(rule)
                    if dest_p_found:
                        action[1] = str(self.name_to_portid_map[dest_p_found.group(1).strip()])
            cond_found = cond_compile.search(rule)
            if cond_found:
                for cond in cond_found.group(1).splitlines():
                    if 'protocol' in cond:
                        parsed_cond = cond_val__without_mask.search(cond)
                    else:
                        parsed_cond = cond_val_mask.search(cond)
                    if parsed_cond:
                        if 'protocol' in cond:
                            conditions.append([parsed_cond.group(1).strip(),
                                               parsed_cond.group(2).strip(),
                                               None])
                        else:
                            conditions.append([parsed_cond.group(1).strip(),
                                               parsed_cond.group(2).strip(),
                                               parsed_cond.group(3)])

            rules_list.append({'ruleId': rule_id,
                               'action': action,
                               'conditions': conditions})

        parsed_acl_name = None
        acl_name_found = acl_name_compile.search(output)
        bound_ports_found = bound_ports_compile.search(output)
        if acl_name_found:
            parsed_acl_name = acl_name_found.group(1)

        if bound_ports_found:
            bound_ports = [self.name_to_portid_map[x.strip()]
                           for x in bound_ports_found.group(1).splitlines()]

        rules_table = {'aclName': parsed_acl_name, 'boundPorts': bound_ports,
                       'rules': rules_list}
        return rules_table

    def get_acl_names(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_acl_names()
        """
        ret_table = []
        output = self.cli_send_command('acl show').stdout.split('ACL name')
        if len(output) == 1:
            return ret_table
        else:
            name_compile = re.compile(r': (.*)\n')
            ports_compile = re.compile(r'Bound Ports:\n(.*)\n', re.DOTALL)
            for acl in output[1:]:
                acl_name_search = name_compile.search(acl)
                bound_ports = ports_compile.search(acl, re.M)
                if acl_name_search:
                    acl_name = acl_name_search.group(1)
                else:
                    acl_name = None
                if bound_ports:
                    port_ids = [self.name_to_portid_map[x.strip()] for x in bound_ports.group(1).splitlines()]
                else:
                    port_ids = None
                ret_table.append({"aclName": acl_name, "boundPorts": port_ids})
            return ret_table

# FDB configuration
    def create_static_macs(self, port=None, vlans=None, macs=None):
        """
        @brief  Adds static MAC entries
        @param  port:  port ID
        @type  port:  int | str
        @param  vlans:  list of VLAN IDs
        @type  vlans:  int | list[int]
        @param  macs:  list of MACs
        @type  macs:  str | list[str]
        @raise  ExistsError
        @rtype:  None
        """
        if not (port is None or vlans is None or macs is None):
            if isinstance(vlans, int):
                vlans = [vlans]
            if isinstance(macs, str):
                macs = [macs]

            dev = self.generate_port_name(port=port)
            command_list = ['bridge fdb add {0} dev {1} vlan {2}'.format(
                m, dev, v) for m in macs for v in vlans]

            if len(command_list) > self.MULTICALL_THRESHOLD:
                self.cli_multicall(command_list, expected_rcs={0})
            else:
                for c in command_list:
                    try:
                        self.cli_send_command(command=c, expected_rcs={0})
                    except UICmdException as e:
                        if e.rc == 2:
                            # FDB entry already exists.
                            raise ExistsError(e.stderr)
                        else:
                            raise

    def delete_static_mac(self, port=None, mac=None, vlan=None):
        """
        @brief  Removes static MAC entries from FDB table
        @param  port:  port ID
        @type  port:  int | str
        @param  mac:  MAC address
        @type  mac:  str
        @param  vlan:  VLAN ID
        @type  vlan:  int
        @raise  NotExistsError
        @rtype:  None
        """
        if not (port is None or mac is None or vlan is None):
            dev = self.generate_port_name(port=port)
            command = 'bridge fdb del {0} dev {1} vlan {2}'.format(mac, dev, vlan)

            try:
                self.cli_send_command(command=command)
            except UICmdException as e:
                if e.rc == 2:
                    # Non-existent FDB entry
                    raise NotExistsError(e.stderr)
                else:
                    raise

    @classmethod
    def parse_row_fdb(cls, row, portid_map):
        """
        @brief  Get parsed dictionary of fdb properties for devices in portid_map
        @param  row:  FDB record
        @type  row:  str
        @param  portid_map:  port ID to port name mapping
        @type  portid_map:  ChainMap
        @rtype:  dict
        @return:  FDB record in format {"portId": portId, "macAddress", macAddress, "vlanId": vlanId, "type": type}
        """
        _row = {}
        row_header = re.search(
            r'(?P<mac>(\w*:)+\w*)\sdev\s(?P<dev>\w*)',
            row).groupdict()
        if row_header['dev'] not in portid_map:
            return
        else:
            _row['portId'] = portid_map[row_header['dev']]
            _row['macAddress'] = row_header['mac']
            if 'vlan' in row:
                row_stats = re.search(
                    r'(?<=vlan\s)(?P<vlanId>\d*)\sself_?(\s(?P<type>\w*))?',
                    row).groupdict()
                _row['vlanId'] = int(row_stats['vlanId'])
            else:
                row_stats = re.search(
                    r'(?<=self\s)(?P<type>\w*)', row).groupdict()
            if row_stats['type'] == 'permanent':
                _row['type'] = 'Static'
            else:
                _row['type'] = 'Dynamic'
            return _row

    def get_table_fdb(self, table='fdb'):
        """
        @brief  Getting FDB table
        @param  table:  FDB table type, static | dynamic | fdb
        @type  table:  str
        @raise  UIException:  invalid table name
        @rtype:  list[dict]
        @return:  FDB table
        """
        valid_table_args = {'static', 'dynamic', 'fdb'}
        table = table.lower()

        if table not in valid_table_args:
            raise UIException('Invalid FDB table argument ({0}).'.format(table))
        command = 'bridge fdb show'
        fdb_table = self.cli_send_command(command=command).stdout.splitlines()
        fdb_dict = [self.parse_row_fdb(r, self.name_to_portid_map) for r in fdb_table]
        fdb_dict = [r for r in fdb_dict if r is not None]

        if table == 'dynamic':
            fdb_dict = [r for r in fdb_dict if r['type'] == 'Dynamic']
        elif table == 'static':
            fdb_dict = [r for r in fdb_dict if r['type'] == 'Static']
            for r in fdb_dict:
                del r['type']

        return fdb_dict

    def clear_table_fdb(self, table='Static'):
        """
        @brief Clear the the static FDB table for devices sw0p##
        @param  table:  FDB table type
        @type  table:  str
        """
        if table == 'Static':
            entries = self.get_table_fdb(table=table)
        else:
            raise SwitchException("Cannot clear non-static FDB table.")
        for entry in entries:
            if entry['macAddress'] != "33:33:00:00:00:01" and entry not in self.default_fdb:
                self.cli_send_command('bridge fdb del {0} dev {1} self vlan {2}'.format(
                    entry['macAddress'], self.port_map[entry['portId']], entry['vlanId']))

# QoS configuration
    def get_table_ports_qos_scheduling(self, port=None, indexes=None, **kwargs):
        """
        @brief  Get PortsQoS scheduling information
        @param port:  port Id to get info about
        @type  port:  int
        @param indexes:  QOS index to get info about
        @type  indexes:  list
        @param kwargs:  Possible parameters
        @type  kwargs:  dict
        @rtype:  list[dict] | str | int
        @return  table (list of dictionaries) or dictionary or param value
        @raise  SwitchException:  not implemented
        """
        # Define ports QoS table with default parameters.
        bits_in_kbits = 1000
        percentage = 100
        ports_qos = {}
        index_list = []
        port_id = self.port_map[port]
        port_speed = self.get_table_ports(ports=[port, ], all_params=True)[0]["speed"]

        # Get port ID.
        ports_qos['portId'] = port_id

        # Get schedMode
        strict = 0
        wrr = 0
        qos_output = str(self.get_port_configuration(port, getPortAttr='sched_group_strict')).splitlines()
        if indexes:
            index_list = indexes
        else:
            index_list = list(range(8))
        for row in qos_output:
            for index in index_list:
                if 'index ' + str(index) in row:
                    if int(row[0]) == self.switch.hw.SchedMode.strict.value:
                        strict += 1
                    elif int(row[0]) == self.switch.hw.SchedMode.weighted_round_robin.value:
                        wrr += 1
        if strict == len(index_list):
            ports_qos['schedMode'] = 'Strict'
        elif wrr == len(index_list):
            ports_qos['schedMode'] = 'WeightedDeficitRoundRobin'

        # Get trustMode
        qos_output = self.get_port_configuration(port, getPortAttr='swpri_source')
        if qos_output == self.switch.hw.TrustMode.dot1p.value:
            ports_qos['trustMode'] = "Dot1p"
        elif qos_output == self.switch.hw.TrustMode.dscp.value:
            ports_qos['trustMode'] = "Dscp"
        elif qos_output == self.switch.hw.TrustMode.isl_tag.value:
            ports_qos['trustMode'] = "None"

        # Get CoS bandwidth
        qos_output = str(self.get_port_configuration(port, getPortAttr='shaping_group_max_rate')).splitlines()
        for row in qos_output:
            if 'index ' in row:
                rate = row.split()
                ports_qos['cos{0}Bandwidth'.format(rate[2])] = int(round(round(int(rate[0]) * percentage) / (port_speed * bits_in_kbits * bits_in_kbits)))

        # Get schedWeight
        qos_output = str(self.get_port_configuration(port, getPortAttr='sched_group_weight')).splitlines()
        for row in qos_output:
            if 'index ' in row:
                weight = row.split()
                ports_qos['schedWeight{0}'.format(weight[2])] = int(weight[0])

        return ports_qos

    def get_table_ports_dot1p2cos(self, port=None, rx_attr_flag=True):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ports_dot1p2cos()
        @raise  SwitchException:  not implemented
        """
        prio_map = [{"0": (0, 1)},
                    {"1": (2, 3)},
                    {"2": (4, 5)},
                    {"3": (6, 7)},
                    {"4": (8, 9)},
                    {"5": (10, 11)},
                    {"6": (12, 13)},
                    {"7": (14, 15)}]
        ports_dot1p2cos = []
        dot1p2cos = {}
        if port == "All" or not port:
            dot1p2cos_gl_output = str(self.get_port_configuration(self.cpu_port, getPortAttr='swpri_tc_map')).splitlines()
            for row in dot1p2cos_gl_output:
                if 'index' in row:
                    row_values = row.split()
                    if int(row_values[-1]) < len(prio_map):
                        dot1p2cos = {}
                        dot1p2cos['portId'] = -1
                        dot1p2cos['CoS'] = int(row_values[0])
                        dot1p2cos['Dot1p'] = int(row_values[-1])
                    if dot1p2cos not in ports_dot1p2cos:
                        ports_dot1p2cos.append(dot1p2cos)

        else:
            if rx_attr_flag:
                dot1p2cos_output = str(self.get_port_configuration(port, getPortAttr='rx_priority_map')).splitlines()
            else:
                dot1p2cos_output = str(self.get_port_configuration(port, getPortAttr='tx_priority_map')).splitlines()
            for row in dot1p2cos_output:
                dot1p2cos = {}
                if 'index' in row:
                    row_values = row.split()
                    for index_id, value in enumerate(prio_map):
                        if int(row_values[0]) in prio_map[index_id][str(index_id)]:
                            dot1p2cos['CoS'] = int(index_id)
                        if int(row_values[-1]) in prio_map[index_id][str(index_id)]:
                            dot1p2cos['Dot1p'] = int(index_id)
                    dot1p2cos['portId'] = int(port)
                if dot1p2cos not in ports_dot1p2cos:
                    ports_dot1p2cos.append(dot1p2cos)

        return ports_dot1p2cos

    def configure_cos_global(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_cos_global()
        @raise  SwitchException:  not implemented
        """
        port = self.port_map[self.cpu_port]
        prio_map = [{"0": (0, 1)},
                    {"1": (2, 3)},
                    {"2": (4, 5)},
                    {"3": (6, 7)},
                    {"4": (8, 9)},
                    {"5": (10, 11)},
                    {"6": (12, 13)},
                    {"7": (14, 15)}]
        prio_map_swpri = [{"0": (0, 8)},
                          {"1": (1, 9)},
                          {"2": (2, 10)},
                          {"3": (3, 11)},
                          {"4": (4, 12)},
                          {"5": (5, 13)},
                          {"6": (6, 14)},
                          {"7": (7, 15)}]
        commands = []

        for key, value in kwargs.items():
            if key.startswith("dotp"):
                tc = int(key.split("dotp")[1][0])
                prio_index = 0
                for index in prio_map_swpri[value][str(value)]:
                    commands.append("ip link set dev {0} swattr swpri_tc_map {1} index {2}".format(port, value,
                                                                                                   prio_map_swpri[tc][str(tc)][prio_index]))
                    prio_index += 1

            if key.startswith("vpri"):
                swpri = int(key.split("vpri")[1][0])
                prio_index = 0
                for index in prio_map[value][str(value)]:
                    commands.append("ip link set dev {0} swattr vpri_swpri_map {1} index {2}".format(port, value,
                                                                                                     prio_map[swpri][str(swpri)][prio_index]))
                    prio_index += 1

        if len(commands) > self.MULTICALL_THRESHOLD:
            self.cli_multicall(commands)
        else:
            for c in commands:
                self.cli_send_command(c)

    def configure_dscp_to_cos_mapping_global(self, set_to_default=False, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_dscp_to_cos_mapping_global()
        @param set_to_default:  Flag indicates to set default values
        @type  set_to_default:  bool
        """

        port = self.port_map[self.cpu_port]
        if set_to_default:
            # set dscp to switch priority mapping to default values
            prio_map = {"0": (0, 1, 2, 3, 4, 5, 6, 7),
                        "1": (8, 9, 10, 11, 12, 13, 14, 15),
                        "2": (16, 17, 18, 19, 20, 21, 22, 23),
                        "3": (24, 25, 26, 27, 28, 29, 30, 31),
                        "4": (32, 33, 34, 35, 36, 37, 38, 39),
                        "5": (40, 41, 42, 43, 44, 45, 46, 47),
                        "6": (48, 49, 50, 51, 52, 53, 54, 55),
                        "7": (56, 57, 58, 59, 60, 61, 62, 63)}

            def_commands = [
                "ip link set dev {0} swattr dscp_swpri_map {1} index {2}".format(port,
                                                                                 sw_prio_value,
                                                                                 dscp_value)
                for sw_prio_value, dscp_values in prio_map.items()
                for dscp_value in dscp_values
            ]
            if len(def_commands) > self.MULTICALL_THRESHOLD:
                self.cli_multicall(def_commands)
            else:
                for default_c in def_commands:
                    self.cli_send_command(default_c)
        else:
            dscp_kwargs = (
                (int(key.split("dscp")[1][0]), val) for key, val in kwargs.items() if
                key.startswith("dscp")
            )
            commands = [
                "ip link set dev {0} swattr dscp_swpri_map {1} index {2}".format(port, sw_prio, val)
                for sw_prio, val in dscp_kwargs
            ]

            if len(commands) > self.MULTICALL_THRESHOLD:
                self.cli_multicall(commands)
            else:
                for c in commands:
                    self.cli_send_command(c)

    def get_table_ports_dscp2cos(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ports_dscp2cos()
        """
        ports_dscp2cos = []
        dscp2cos = {}
        dscp2cos_output = str(self.get_port_configuration(self.cpu_port, getPortAttr='dscp_swpri_map')).splitlines()

        for row in dscp2cos_output:
            dscp2cos = {}
            if 'index' in row:
                row_values = row.split()
                dscp2cos['CoS'] = int(row_values[0])
                dscp2cos['DSCP'] = int(row_values[-1])
                dscp2cos['portId'] = -1

            if dscp2cos not in ports_dscp2cos:
                ports_dscp2cos.append(dscp2cos)

        return ports_dscp2cos

    def configure_schedweight_to_cos_mapping(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_schedweight_to_cos_mapping()
        """
        commands = []
        for port_id in ports:
            port = self.port_map[port_id]
            for key in kwargs:
                if key.startswith("schedWeight"):
                    sw_prio = int(key[-1])
                    commands.append("ip link set dev {0} swattr sched_group_weight {1} index {2}".format(port, kwargs[key], sw_prio))

        for c in commands:
            self.cli_send_command(c)

    def configure_port_cos(self, ports=None, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_port_cos()
        @raise  SwitchException:  not implemented
        """
        bits_in_kbits = 1000
        percentage = 100
        commands = []
        for port_id in ports:
            port_speed = self.get_table_ports(ports=[port_id, ], all_params=True)
            port = self.port_map[port_id]

            if 'schedMode' in kwargs:
                command = "ip link set dev {0} swattr sched_group_strict {1} index {2}"
                if 'index' in kwargs:
                    for index in kwargs['index']:
                        if kwargs['schedMode'] == 'Strict':
                            commands.append(command.format(port, self.switch.hw.SchedMode.strict.value, index))
                        if kwargs['schedMode'] == 'WeightedDeficitRoundRobin':
                            commands.append(command.format(port, self.switch.hw.SchedMode.weighted_round_robin.value, index))
                else:
                    for index in range(8):
                        if kwargs['schedMode'] == 'Strict':
                            commands.append(command.format(port, self.switch.hw.SchedMode.strict.value, index))
                        if kwargs['schedMode'] == 'WeightedDeficitRoundRobin':
                            commands.append(command.format(port, self.switch.hw.SchedMode.weighted_round_robin.value, index))

            if 'trustMode' in kwargs:
                command = "ip link set dev {0} swattr swpri_source {1}"
                if kwargs['trustMode'] == 'Dot1p':
                    commands.append(command.format(port, self.switch.hw.TrustMode.dot1p.value))
                if kwargs['trustMode'] == 'Dscp':
                    commands.append(command.format(port, self.switch.hw.TrustMode.dscp.value))
                if kwargs['trustMode'] == 'None':
                    commands.append(command.format(port, self.switch.hw.TrustMode.isl_tag.value))
                if kwargs['trustMode'] == 'dot1p_and_dscp':
                    commands.append(command.format(port, self.switch.hw.TrustMode.dot1p_and_dscp.value))

            for key in kwargs:
                if key.startswith("cos"):
                    rate = ((port_speed[0]["speed"] * bits_in_kbits * bits_in_kbits) * kwargs[key]) // percentage
                    index = int(key.split("cos")[1][0])
                    commands.append("ip link set dev {0} swattr shaping_group_max_rate {1} index {2}".format(port, rate, index))

        # Set DSCP to Switch priority mapping to default values if trustMode=Dscp since switch priority is set to 0 by default.
        if 'trustMode' in kwargs:
            if kwargs['trustMode'] in ['Dscp', 'dot1p_and_dscp']:
                self.configure_dscp_to_cos_mapping_global(set_to_default=True)

        for c in commands:
            self.cli_send_command(c)

    def create_dot1p_to_cos_mapping(self, ports, rx_attr_flag=False, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_dot1p_to_cos_mapping()
        @raise  SwitchException:  not implemented
        """
        cos_list = ["dotp%sCoS" % idx for idx in range(8)]
        for cos in cos_list:
            assert cos in list(kwargs.keys()), "Not all eight CoS values transmitted for configuring CoS per port"

        self.modify_dot1p_to_cos_mapping(ports, rx_attr_flag, **kwargs)

    def modify_dot1p_to_cos_mapping(self, ports, rx_attr_flag=False, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_dot1p_to_cos_mapping()
        @raise  SwitchException:  not implemented
        """
        prio_map = [{"0": (0, 1)},
                    {"1": (2, 3)},
                    {"2": (4, 5)},
                    {"3": (6, 7)},
                    {"4": (8, 9)},
                    {"5": (10, 11)},
                    {"6": (12, 13)},
                    {"7": (14, 15)}]
        commands = []
        if rx_attr_flag:
            attr_name = "rx_priority_map"
        else:
            attr_name = "tx_priority_map"

        for port_id in ports:
            port = self.port_map[port_id]
            for key in kwargs:
                if key.startswith("dotp"):
                    sw_prio = int(key.split("dotp")[1][0])
                    prio_index = 0
                    for index in prio_map[kwargs[key]][str(kwargs[key])]:
                        commands.append("ip link set dev {0} swattr {1} {2} index {3}".format(port, attr_name, index,
                                                                                              prio_map[sw_prio][str(sw_prio)][prio_index]))
                        prio_index += 1

        for c in commands:
            self.cli_send_command(c)

    def clear_per_port_dot1p_cos_mapping(self, ports, rx_attr_flag=False, dot1p=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::clear_per_port_dot1p_cos_mapping()
        """
        dot1p_to_cos_params = dict(dotp0CoS=0, dotp1CoS=1, dotp2CoS=2, dotp3CoS=3, dotp4CoS=4, dotp5CoS=5, dotp6CoS=6, dotp7CoS=7)
        self.create_dot1p_to_cos_mapping(ports, rx_attr_flag, **dot1p_to_cos_params)

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
        with self.switch.ssh.client.open_sftp() as sftp_client:
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
        with self.switch.ssh.client.open_sftp() as sftp_client:
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
        with self.switch.ssh.client.open_sftp() as sftp_client:
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
        with self.switch.ssh.client.open_sftp() as sftp_client:
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
                match = re.search(r'valid_lft (\d+)s', table)
                if match:
                    result[_port] = int(match.group(1))
                else:
                    raise SwitchException('No switch ports found.')

        except:
            raise SwitchException('No switch ports found.')
        return result

# DCRP Configurations
    def get_table_dcrp_config(self, file_name="/etc/dcrpd.conf",
                              options=None):
        """
        @brief  Gets configuration from file
        @param file_name:  File name
        @type  file_name:  str
        @return:  DCRP configuration
        @steps
            -# Using sftp client open the config file in read only mode
            -# Return the contents of the file
        @endsteps
        """

        with self.switch.ssh.client.open_sftp() as sftp_client:
            with sftp_client.open(file_name, 'r') as remote_file:
                lines = remote_file.readlines()
        return lines

    def create_dcrp_config_file(self, lines, file_name="/etc/dcrpd.conf"):
        """
        @brief  Writes configuration required to file
        @param lines:  Configuration
        @type  lines:  str
        @param file_name:  File name
        @type  file_name:  str
        @return:  None
        @steps
            -# Using sftp client open the config file in write mode
            -# Write the configuration required for the DCRP Service.
        @endsteps
        """
        with self.switch.ssh.client.open_sftp() as sftp_client:
            with sftp_client.open(file_name, 'w') as remote_file:
                remote_file.writelines(lines)

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
            if self.switch.mgmt_iface is not None:
                iface = self.switch.mgmt_iface
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

        # Add value to lag_map if it isn't there
        self.lag_map.setdefault(lag, str(lag))
        self.name_to_lagid_map.setdefault(str(lag), lag)

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

            for lag in lags:
                try:
                    # Remove Static MAC's in LAG (ONP-2648)
                    self.delete_static_macs_from_port(port=lag)
                    self.cli_send_command(command='teamd -k -t {0}'.format(lag))
                except UICmdException as e:
                    if e.rc == 1:
                        if 'Daemon not running' in e.stderr:
                            raise NotExistsError(e.stderr)
                        elif 'option requires an argument' in e.stderr:
                            raise ArgumentError(e.stderr)
                    else:
                        raise

        # Delete value to lag_map
        for lag in lags:
            self.lag_map.pop(lag)
            self.name_to_lagid_map.pop(str(lag))

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
        table_ports = self.get_table_ports(all_params=False)
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

    def modify_link_aggregation(self, globalenable=None, collectormaxdelay=None,
                                globalhashmode=None, priority=None, lacpenable=None):
        """
        @brief:  Set the LAG hash mode attributes.
        @param  globalhashmode: hash mode attribute
        @type  globalhashmode:  str
        """
        try:
            if globalhashmode:
                self.modify_ports(
                    ports=[self.cpu_port], setPortAttr=LAG_HASH_MODES[globalhashmode],
                    attrVal=ENABLE_DISABLE_MAP[lacpenable])
            if lacpenable:
                self.modify_ports(
                    ports=[self.cpu_port], setPortAttr="lag_mode",
                    attrVal=ENABLE_DISABLE_MAP["Enabled"])
        except KeyError:
            raise ArgumentError("Expected only Enable or Disable arguments.")

    LAG_MODE_MAP = {"Passive": False, "Active": True, }
    LAG_TIMEOUT_MAP = {"Long": False, "Short": True, }

    def create_lag_ports(self, ports, lag, priority=1, key=None,
                         aggregation='Multiple', lag_mode='Passive',
                         timeout='Long', synchronization=False, collecting=False,
                         distributing=False, defaulting=False, expired=False,
                         partner_system='00:00:00:00:00:00', partner_syspri=32768,
                         partner_number=1, partner_key=0, partner_pri=32768):
        """
        @brief  Set port to a LAG. Most of the parameters don't work for ONPSS
        @rtype  ports: list[int]
        @rtype  lag: int | str
        @raise:  NotExistsError | AccessError
        """
        # Get date-time
        date_start = self.get_current_date()

        # Need to set port to admin down before joining
        self.modify_ports(ports=ports, adminMode='Down')
        time.sleep(1)

        # If lag type has properties changed, we need to recreate the lag.
        get_lag = [row for row in self.get_table_lags() if row["lagId"] == lag]
        if get_lag and get_lag[0]["lagControlType"] == "Dynamic":
            self.delete_lags(lags=[lag, ])
            try:
                lacp_config = json.dumps(
                    {"device": "{0}".format(lag),
                     "runner": {"name": "lacp", "active": self.LAG_MODE_MAP[lag_mode],
                                "fast_rate": self.LAG_TIMEOUT_MAP[timeout]}})
            except KeyError:
                raise ArgumentError("Unexpected argument in timeout or lag_mode field.")

            self.cli_send_command("teamd -d -r --config='{}'".format(lacp_config))
            # Add value to lag_map if it isn't there
            self.lag_map.setdefault(lag, str(lag))
            self.name_to_lagid_map.setdefault(str(lag), lag)

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

        # Check to journalctl or dmesg for errors.
        # ONPSS will return code 0 even on failed attempts, but error will be logged.
        json_lines = self.get_journalctl_log(date_since=date_start, additional_args='-k')
        for line in json_lines:
            # If we exceed the number of LAGs.
            #  Failed to create LAG in switching hardware
            if 'Failed to create LAG' in line['MESSAGE']:
                raise InvalidCommandError(line['MESSAGE'])
            if re.search(r"Port device sw0p\d* removed", line['MESSAGE']):
                raise InvalidCommandError(line['MESSAGE'])
            # If there is a speed mismatch between member ports.
            #  Port speed {} is not consistent with Lag
            if re.search(
                    r"Port speed \d* is not consistent with Lag {}".format(lag), line['MESSAGE']):
                raise InvalidCommandError(line['MESSAGE'])

    def modify_ports2lag(self, port, lag, priority=None, key=None, aggregation=None, lag_mode=None, timeout=None, synchronization=None,
                         collecting=None, distributing=None, defaulting=None, expired=None, partner_system=None, partner_syspri=None,
                         partner_number=None, partner_key=None, partner_pri=None):
        """
        @copydoc testlib::ui_wrapper::UiInterface::modify_ports2lag()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def delete_lag_ports(self, ports, lag=None):
        """
        @brief  Deletes ports from a lag
        @type  ports:  list[int]
        @type  lag:  str|int
        @raise  UIEXception:
        @rtype:  None
        """
        # lag parameter is required for ONS 1.x, but not for ONP 2.x
        command_list = ['ip link set {0} nomaster'.format(
            self.switch_map[port]) for port in ports]

        # No other known rc's known (even deleting non-existent entry)
        for c in command_list:
            self.cli_send_command(command=c)

    @classmethod
    def parse_row_ports2lag(cls, row):
        """
        @brief  Yield ports2lag group information.
                Will convert lagId to int for
                ONS 1.x compatibility.
        @type  row:  dict
        @raise  ValueError:
        @rtype:  dict
        """
        _row = {
            'portId': row['portId'],
            'actorPortPriority': 0
        }

        # ONS 1.x lagId is int
        try:
            _row['lagId'] = int(row['master'])
        except ValueError:
            _row['lagId'] = row['master']

        # Note: missing a lot of stuff from ONS
        return _row

    def get_table_ports2lag(self):
        """
        @brief  Retrieves ports to LAG information
        Note, we can also use networkctl lag command
        @rtype:  list[dict]
        """
        table = self.get_table_ports(all_params=False)
        table = (r for r in table if r['type'] == 'LAGMember')
        table_ports2lag = [self.parse_row_ports2lag(r) for r in table]
        return table_ports2lag

    def get_table_lags_local_ports(self, lag=None, expected_rcs=frozenset({0})):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lags_local_ports()
        @rtype:  list[dict]
        """
        ports_table = self.get_table_ports()
        table_ports2lag = self.get_table_ports2lag()
        lag_table = self.get_table_lags()
        res_list_1 = []
        row_ids = []
        get_lags_ports_all = []
        lags_info = [row["portId"] for row in ports_table if row["type"] == "LAG"]
        lag_mode = self.get_port_configuration(port=self.cpu_port, getPortAttr="lag_mode")
        for lag in lags_info:
            res_list_1.append(self.cli_send_command('teamdctl {0} state'.format(lag)).stdout.splitlines())
            get_lags_ports_all.append([row["portId"] for row in table_ports2lag if row["lagId"] == lag])
        lag_ports = {str(row["portId"]): lag for row in table_ports2lag for lag in lags_info if row["lagId"] == lag}
        ports_info_table = []
        ports_lags_local_table_all = []
        res_list = [i for i in itertools.chain.from_iterable(res_list_1)]
        get_lags_ports = [i for i in itertools.chain.from_iterable(get_lags_ports_all)]
        row_ids = [row_id for row_id, row in enumerate(res_list) for port in get_lags_ports if self.switch_map[port] in row]

        # Convert 'teamdctl state' information to dictionary for all members.
        if row_ids:
            for index, value in enumerate(row_ids):
                port_info = {}
                if value == row_ids[-1]:
                    end_index = len(res_list)
                else:
                    end_index = row_ids[index + 1]
                for table_row in res_list[value:end_index]:
                    if table_row[-1] == ":":
                        port_info[table_row.strip().strip(":")] = ""
                    else:
                        values = table_row.strip().split(":")
                        if len(values) >= 2:
                            # if values[0] != "runner" and values[0] != "active" and values[0] != "fast rate":
                            port_info[values[0]] = values[1].strip()
                        else:
                            port_info["portId"] = self.name_to_portid_map[values[0].strip()]
                port_info["lagId"] = lag_ports[str(port_info["portId"])]
                ports_info_table.append(port_info)

        # Generate ports2lag local table.
        # Note: not-supported variables are hard-coded.
        for row in ports_info_table:
            ports_lags_local_table = {}
            ports_lags_local_table["portId"] = row["portId"]
            ports_lags_local_table["lagId"] = row["lagId"]
            port_state = list("00000111")
            if "active" in row:
                if row["active"] == "no":
                    port_state[7] = "0"
            if "fast_rate" in row:
                if row["fast rate"] == "no":
                    port_state[6] = "0"

            # Get dynamic LAG members info:
            if [lag["lagControlType"] for lag in lag_table if lag["lagId"] == row["lagId"]][0] == "Dynamic":
                if "selected" in row:
                    if row["selected"] == "no":
                        ports_lags_local_table["selected"] = "Unselected"
                        ports_lags_local_table["ready"] = "False"
                        ports_lags_local_table["operationalConflict"] = "True"
                    else:
                        ports_lags_local_table["selected"] = "Selected"
                        ports_lags_local_table["ready"] = "True"
                        ports_lags_local_table["operationalConflict"] = "False"
                        port_state[4] = "1"
                if lag_mode == self.switch.hw.lag_mode.max:
                    ports_lags_local_table["lacpOperating"] = "Enabled"
                else:
                    ports_lags_local_table["lacpOperating"] = "Disabled"
                if "state" in row:
                    if row["state"] == "defaulted":
                        port_state[1] = "1"
                    if row["state"] == "expired":
                        port_state[0] = "1"
                ports_lags_local_table["actorOperPortState"] = ''.join(port_state)
            # Get static LAG members info:
            else:
                if self.get_table_ports(ports=[row["lagId"], ])[0]["operationalStatus"] == "Up":
                    ports_lags_local_table["selected"] = "Selected"
                    ports_lags_local_table["ready"] = "True"
                else:
                    ports_lags_local_table["selected"] = "Unselected"
                    ports_lags_local_table["ready"] = "False"
                ports_lags_local_table["lacpOperating"] = "Disabled"
                ports_lags_local_table["actorOperPortState"] = "00000100"
                ports_lags_local_table["operationalConflict"] = "False"

            if row["link"] == "up":
                ports_lags_local_table["portEnabled"] = "Enabled"
            else:
                ports_lags_local_table["portEnabled"] = "Disabled"

            ports_lags_local_table["actorChurn"] = "False"
            ports_lags_local_table["actorOperPortKey"] = 0
            ports_lags_local_table["rxCounter"] = None
            ports_lags_local_table["txCounter"] = None

            ports_lags_local_table_all.append(ports_lags_local_table)

        return ports_lags_local_table_all

    def get_table_lags_remote_ports(self, lag=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lags_remote_ports()
        @raise  UIException:  not implemented
        """
        raise UIException("Not implemented")

    def get_table_lags_local(self, lag=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lags_local()
        @rtype:  list[dict]
        """
        lags_local = []
        lag_row = {}

        ports_table = self.get_table_ports()
        lags_info = [{"lagId": row["portId"], "lagMacAddress": row["macAddress"]} for row in ports_table if row["type"] == "LAG"]

        if lags_info:
            for row in lags_info:
                lag_row["lagId"] = row["lagId"]
                lag_row["lagMacAddress"] = row["lagMacAddress"]
                lag_row["ready"] = "False"
                lag_row["transmitState"] = "Disabled"
                lag_row["receiveState"] = "Disabled"
                if (self.get_table_ports(ports=[row["lagId"], ])[0]["operationalStatus"] == "Up" and
                        [row for row in self.get_table_lags_local_ports(lag=row["lagId"]) if row["selected"] == "Selected"]):
                    lag_row["ready"] = "True"
                    lag_row["transmitState"] = "Enabled"
                    lag_row["receiveState"] = "Enabled"

        lags_local.append(lag_row)

        return lags_local

    def get_table_lags_remote(self, lag=None):
        """
        @copydoc testlib::ui_wrapper::UiInterface::get_table_lags_remote()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

# IGMP configuration
    def configure_igmp_global(self, mode='Enabled', router_alert=None, unknown_igmp_behavior=None,
                              query_interval=None, querier_robustness=None):
        """
        @copydoc testlib::ui_wrapper::UiInterface::configure_igmp_global()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def configure_igmp_per_ports(self, ports, mode='Enabled', router_port_mode=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_igmp_per_ports()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_multicast(self, port, vlans, macs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_multicast()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def delete_multicast(self, port=None, vlan=None, mac=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_multicast()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Method isn't implemented")

    def get_table_l2_multicast(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_l2_multicast()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_igmp_snooping_global_admin(self, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_igmp_snooping_global_admin()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_igmp_snooping_port_oper(self, port, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_igmp_snooping_port_oper()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def clear_l2_multicast(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::clear_l2_multicast()
        @raise  SwitchException:  not implemented.
        """
        raise SwitchException("Not implemented")

# L3 configuration
    def configure_routing(self, routing='Enabled', ospf=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_routing()
        @raise  SwitchException:  not implemented
        """
        pass

    def create_route_interface(self, vlan, ip, ip_type='InterVlan', bandwidth=1000, mtu=1500,
                               status='Enabled', vrf=0, mode='ip'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_route_interface()
        @raise  SwitchException:  not implemented
        """
        self.modify_ports(ports=[0, ], ipAddr=ip)

    def delete_route_interface(self, vlan, ip, bandwith=1000, mtu=1500, vrf=0, mode='ip'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_route_interface()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def modify_route_interface(self, vlan, ip, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_route_interface()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_route_interface(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_route_interface()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_route(self, mode='ip'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_route()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def configure_arp(self, garp=None, refresh_period=None, delay=None, secure_mode=None,
                      age_time=None, attemptes=None, arp_len=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_arp()
        @raise  SwitchException:  not implemented
        """
        if arp_len:
            commands = ['echo {} > /proc/sys/net/ipv4/neigh/default/gc_thresh2'.format(
                arp_len), 'echo {} > /proc/sys/net/ipv4/neigh/default/gc_thresh3'.format(
                arp_len), 'echo {} > /proc/sys/net/ipv6/neigh/default/gc_thresh2'.format(
                arp_len), 'echo {} > /proc/sys/net/ipv6/neigh/default/gc_thresh3'.format(
                arp_len)]
            self.cli_multicall(commands)

        if age_time:
            commands = ['echo {} > /proc/sys/net/ipv4/neigh/default/gc_stale_time'.format(
                age_time), 'echo {} > /proc/sys/net/ipv6/neigh/default/gc_stale_time'.format(
                age_time)]
            self.cli_multicall(commands)

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
        command = 'ip neigh add {0} lladdr {1} dev {2} nud perm'.format(
            ip, mac, port_name)
        self.cli_send_command(command=command)

    def delete_arp(self, port):
        """
        @brief  Delete StaticARP record
        @param port:  port id
        @type  port:  int
        @return:  None
        """
        port_name = self.port_map[port]
        # TODO: rework to be able to undo only records added by create_arp(), or custom records
        commands = 'ip link set arp off dev {0}; ip link set arp on dev {0}'.format(port_name)
        self.cli_send_command(command=commands)

    def get_table_arp(self, mode='arp'):
        """
        @brief  Getting ARP table
        @param  mode:  ARP table type, arp static | arp
        @type  mode:  str
        @rtype:  list[dict]
        @return:  ARP table
        """

        command = 'ip neigh show'
        arp_table = self.cli_send_command(command=command).stdout.splitlines()

        switch_ports = [self.generate_port_name(port=p) for p in self.get_available_switch_ports()]
        new_arp_table = []
        for row in arp_table:
            for el in row.split():
                if el in switch_ports:
                    res_v6 = re.search(r'((?:[0-9a-f]{1,4}(?:::)?){0,7}::[0-9a-f]+)', row)
                    arp_row = {}
                    if res_v6:
                        arp_row["netAddress"] = res_v6.group()
                        arp_row["phyAddress"] = re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', row, re.I).group()
                        arp_row["ifName"] = self.name_to_portid_map[el]
                        # Temporary defining as 'cat /proc/net/arp' does not show any types.
                        arp_row["type"] = "None"
                        if "PERMANENT" in row:
                            arp_row["type"] = "Static"
                        new_arp_table.append(arp_row)

                    res = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', row)
                    arp_row = {}
                    if res:
                        arp_row["netAddress"] = res.group()
                        arp_row["phyAddress"] = re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', row, re.I).group()
                        arp_row["ifName"] = self.name_to_portid_map[el]
                        # Temporary defining as 'cat /proc/net/arp' does not show any types.
                        arp_row["type"] = "None"
                        if "PERMANENT" in row:
                            arp_row["type"] = "Static"
                        new_arp_table.append(arp_row)

        return new_arp_table

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

    def configure_ospf_router(self, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_ospf_router()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_ospf_router(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ospf_router()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_ospf_area(self, area, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ospf_area()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_ospf_area(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ospf_area()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_network_2_area(self, network, area, mode):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_network_2_area()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_network_2_area(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_network_2_area()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_area_ranges(self, area, range_ip, range_mask, substitute_ip, substitute_mask):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_area_ranges()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_area_ranges(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_area_ranges()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_route_redistribute(self, mode):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_route_redistribute()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_route_redistribute(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_route_redistribute()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_interface_md5_key(self, vlan, network, key_id, key):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_interface_md5_key()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_interface_authentication(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_interface_authentication()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_ospf_interface(self, vlan, network, dead_interval=40, hello_interval=5,
                              network_type="Broadcast", hello_multiplier=3,
                              minimal='Enabled', priority=-1, retransmit_interval=-1):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ospf_interface()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_ospf_interface(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ospf_interface()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_area_virtual_link(self, area, link):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_area_virtual_link()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

# BGP configuration
    def configure_bgp_router(self, asn=65501, enabled='Enabled'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_bgp_router()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_bgp_neighbor_2_as(self, asn, ip, remote_as):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_neighbor_2_as()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_bgp_neighbor(self, asn=65501, ip='192.168.0.1'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_neighbor()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_bgp_neighbor_connection(self, asn=65501, ip='192.168.0.1', port=179):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_neighbor_connection()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_bgp_bgp(self, asn=65501, router_id="1.1.1.1"):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_bgp()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_bgp_peer_group(self, asn=65501, name="mypeergroup"):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_peer_group()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_bgp_peer_group_member(self, asn=65501, name="mypeergroup", ip="12.1.0.2"):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_peer_group_member()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_bgp_redistribute(self, asn=65501, rtype="OSPF"):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_redistribute()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_bgp_network(self, asn=65501, ip='10.0.0.0', mask='255.255.255.0',
                           route_map='routeMap'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_network()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_bgp_aggregate_address(self, asn=65501, ip='22.10.10.0', mask='255.255.255.0'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_aggregate_address()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_bgp_confederation_peers(self, asn=65501, peers=70000):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_confederation_peers()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_bgp_distance_network(self, asn=65501, ip="40.0.0.0/24", mask='255.255.255.0',
                                    distance=100, route_map='routeMap'):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_distance_network()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_bgp_distance_admin(self, asn=65501, ext_distance=100, int_distance=200,
                                  local_distance=50):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_bgp_distance_admin()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_bgp_neighbor(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_neighbor()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_bgp_neighbor_connections(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_neighbor_connections()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_bgp_aggregate_address(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_aggregate_address()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_bgp_confederation_peers(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_confederation_peers()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_bgp_distance_admin(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_distance_admin()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_bgp_distance_network(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_distance_network()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_bgp_network(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_network()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_bgp_peer_group_members(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_peer_group_members()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_bgp_peer_groups(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_peer_groups()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_bgp_redistribute(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_bgp_redistribute()
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
                    enable_tx = "enableTx=no" if value == "Disabled" else "enableTx=yes"
                    self.lldp.set_enable_tx(port_name, cli_keys[param], enable_tx)

    def get_table_lldp(self, port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lldp()
        """
        # TODO: something with global settings which may not be supported yet

        if port is not None:
            port_names = [self.port_map[port]]
        else:
            port_names = iter(self.port_map.values())
        tlvs_list = ((port_name, self.lldp.get_local_tlvs(port_name)) for port_name in port_names)
        _table = []
        for p, tlvs in tlvs_list:
            row = {
                "LocalPortNum": self.name_to_portid_map[p],
            }
            for tlv, value in tlvs:
                if tlv == lldp.TlvNames.CHASSIS_ID:
                    row.update(Tlv.get_chassis_tlv_row(value))
                elif tlv == lldp.TlvNames.SYSTEM_DESCRIPTION:
                    row.update(Tlv.get_simple_tlv_row("SysDesc", value))
                elif tlv == lldp.TlvNames.SYSTEM_NAME:
                    row.update(Tlv.get_simple_tlv_row("SysName", value))
                elif tlv == lldp.TlvNames.SYSTEM_CAPABILITIES:
                    row.update(Tlv.get_sys_cap_tlv_row(value))
            _table.append(row)

        return _table

    def get_table_lldp_ports(self, port=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_lldp_ports()
        @raise  SwitchException:  not implemented
        """
        if port is not None:
            port_names = [self.port_map[port]]
        else:
            port_names = iter(self.port_map.values())
        tlvs_list = ((port_name, self.lldp.get_local_tlvs(port_name), self.lldp.get_adminstatus(port_name)) for port_name in port_names)
        _table = []
        for p, tlvs, admin_status in tlvs_list:
            row = {
                "LocalPortNum": self.name_to_portid_map[p],
                "adminStatus": "Disabled"
            }
            for tlv, value in tlvs:
                if tlv == lldp.TlvNames.CHASSIS_ID:
                    row.update(Tlv.get_local_chassis_tlv_row(value))
                elif tlv == lldp.TlvNames.PORT_ID:
                    row.update(Tlv.get_local_port_tlv_row(value))
                elif tlv == lldp.TlvNames.TIME_TO_LIVE:
                    row.update(Tlv.get_simple_tlv_row("TTL", value))
                elif tlv == lldp.TlvNames.SYSTEM_DESCRIPTION:
                    row.update(Tlv.get_simple_tlv_row("SysDesc", value))
                elif tlv == lldp.TlvNames.SYSTEM_NAME:
                    row.update(Tlv.get_simple_tlv_row("SysName", value))
                elif tlv == lldp.TlvNames.PORT_DESCRIPTION:
                    row.update(Tlv.get_simple_tlv_row("PortDesc", value))
                elif tlv == lldp.TlvNames.SYSTEM_CAPABILITIES:
                    row.update(Tlv.get_local_cap_tlv_row(value))
            if admin_status:
                status = admin_status.split('=')[1]
                if 'tx' and 'rx' in status:
                    row["adminStatus"] = 'TxAndRx'
                elif 'tx' in status and 'rx' not in status:
                    row["adminStatus"] = 'TxOnly'
                elif 'rx' in status and 'tx' not in status:
                    row["adminStatus"] = 'RxOnly'
            _table.append(row)

        if port and param == "adminStatus":
            return row["adminStatus"]
        else:
            return _table

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
                    row.update(Tlv.get_simple_tlv_row("remSysName", value))
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

    def get_table_dcbx_app_remote(self, port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_app_remote()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_dcbx_app_ports(self, port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_app_ports()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_dcbx_app_maps(self, table_type="Admin", port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_app_maps()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def configure_application_priority_rules(self, ports, app_prio_rules, delete_params=False, update_params=False):
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

    def get_table_dcbx_ets_ports(self, table_type='Admin', port=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_dcbx_ets_ports()
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
        self.networkd.stop()
        self.networkd.clear_settings()
        self.networkd.start()

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

    def create_ufd_network_file(self, port_name, config_parser_instance=None):
        """
        @brief  Creating ufd network file
        @param  port_name:  name of the port, which network file to be created
        @type  port_name:  str
        @param  config_parser_instance:  configuration to be written in file
        @type  config_parser_instance:  instance of ConfigParser
        """
        file_name = '/etc/systemd/network/{0}.network'.format(port_name)
        with self.switch.ssh.client.open_sftp() as sftp_client:
            with sftp_client.open(file_name, 'w') as remote_file:
                if config_parser_instance is not None:
                    config_parser_instance.write(remote_file)

    def remove_ufd_network_files(self, ports=None):
        """
        @brief  Removing created ufd network files
        @param  ports:  Device port lists for which the network files created
        @type  ports:  list[int]
        """
        self.networkd.clear_settings(exclude_ports=ports)

    def create_ufd_group(self, group_id, threshold=None, enable=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ufd_group()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def delete_ufd_group(self, group_id):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_ufd_group()
        """
        raise SwitchException("Not implemented")

    def modify_ufd_group(self, group_id, threshold=None, enable=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_ufd_group()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_ufd_groups(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ufd_groups()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def create_ufd_ports(self, ports, port_type, group_id):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_ufd_ports()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_ufd_ports(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_ufd_ports()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

# QinQ configuration

    def configure_qinq_ports(self, ports, **kwargs):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_qinq_ports()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def configure_qinq_vlan_stacking(self, ports, provider_vlan_id, provider_vlan_priority):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_qinq_vlan_stacking()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_qinq_vlan_stacking(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_qinq_vlan_stacking()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def configure_qinq_vlan_mapping(self, ports, customer_vlan_id, customer_vlan_priority,
                                    provider_vlan_id, provider_vlan_priority):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::configure_qinq_vlan_mapping()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_qinq_customer_vlan_mapping(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_qinq_customer_vlan_mapping()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_qinq_provider_vlan_mapping(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_qinq_provider_vlan_mapping()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_qinq_ports(self, port=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_qinq_ports()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

# Errdisable configuration

    def get_table_errdisable_errors_config(self, app_name=None, app_error=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_errdisable_errors_config()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_table_errdisable_config(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_table_errdisable_config()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def modify_errdisable_errors_config(self, detect=None, recovery=None, app_name=None,
                                        app_error=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_errdisable_errors_config()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def modify_errdisable_config(self, interval=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::modify_errdisable_config()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_errdisable_ports(self, port=None, app_name=None, app_error=None, param=None):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_errdisable_ports()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

# Mirroring configuration

    def create_mirror_session(self, port, target, mode):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::create_mirror_session()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def get_mirroring_sessions(self):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::get_mirroring_sessions()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

    def delete_mirroring_session(self, port, target, mode):
        """
        @copydoc  testlib::ui_wrapper::UiInterface::delete_mirroring_session()
        @raise  SwitchException:  not implemented
        """
        raise SwitchException("Not implemented")

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

# TestPoint specific functionality
    def test_point_connect(self):
        """
        @brief  Connect to the device and start TestPointShared and switchdShared applications
        """
        if not self.test_point.login_status:
            self.test_point.connect()
        if not self.switchd.login_status:
            self.switchd.connect()

    def test_point_disconnect(self):
        """
        @brief  Close TestPointShared and switchdShared applications
        """
        self.switchd.disconnect()
        self.test_point.disconnect()

    def test_point_exec_command(self, command):
        """
        @brief  Execute command in TestPointShared
        @type  command:  str
        """
        return self.test_point.execute_command(command)

    def enable_cpu_rate_limit(self):
        """
        @brief  Stop switchd and start it with -c option.
        """
        self.switch_driver.stop_and_unload()
        assert not self.switch_driver.process_exists(), "Switchd is not stopped"
        self.switch_driver.stop_and_unload()
        self.switch_driver.modprobe()
        # need to wait until command is performed
        time.sleep(2)
        self.reinit()
        # use timestamp
        log_file = os.path.join("/tmp", "{0}-{1}.log".format(self.switch_driver.name,
                                                             int(time.time())))
        self.cli_set([[self.hw.gen_cpu_rate_limiting_command(self.switch_driver.name, log_file)], ])
        # need to wait until command is performed
        time.sleep(10)
        # Verify that switchd is started with enabled CPU Rate Limit option.
        output = self.switch.cli_send_command(
            "pgrep -ax {0}".format(self.switch_driver.name)).stdout.strip()
        assert "-c" in output, "CPU Rate Limit option is not enabled"
        return log_file

# ICMP Ping configuration
    def icmp_ping_request(self, ip_addr, ip_version, options="-c 4",
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
        try:
            result = self.cli_send_command(
                '{0} {1} {2}'.format(ping, options, ip_addr), timeout, expected_rcs)
        except UICmdException as e:
            if e.rc == 2:
                raise BoundaryError(e.stderr)
            else:
                raise
        else:
            return result.stdout

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
        output = self.icmp_ping_request(ip_addr, ip_version, options, timeout, expected_rcs)
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

# Workload functionality (stress tool)
    def start_workload(self, **kwargs):
        default_workers = {
            'cpu': kwargs.get('cpu', self.switch.hw.stress_tool_attributes.cpu),
            'vm': kwargs.get('vm', self.switch.hw.stress_tool_attributes.vm),
            'vm_bytes': kwargs.get('vm_bytes', self.switch.hw.stress_tool_attributes.vm_bytes),
            'io': kwargs.get('io', self.switch.hw.stress_tool_attributes.io),
            'disk': kwargs.get('disk', self.switch.hw.stress_tool_attributes.disk),
            'time': kwargs.get('time', None)
            }
        params = default_workers if not kwargs or \
                                    len(kwargs) == 1 and kwargs.get('time', None) else kwargs
        self.stresstool.start(**params)

    def get_active_workloads(self):
        return [inst for inst in self.stresstool.instances
                if self.stresstool.get_status(inst, check=False)]  # pylint: disable=no-member

    def get_workload_results(self, mode='empty'):
        results = []
        for inst in self.stresstool.instances:
            results.extend(self.stresstool.parse(self.stresstool.get_results(inst)))
        return results

    def stop_workload(self):
        for inst in list(self.stresstool.instances)[:]:
            self.stresstool.stop(inst, check=False)


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
