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

@file  ui_helpers.py

@summary  UiHelper class for mixin for switch.ui object.
"""
import time
import configparser
from itertools import chain
import xmlrpc.client

import pytest

from .custom_exceptions import SwitchException, BoundaryError, InvalidCommandError
from .custom_exceptions import ExistsError, NotExistsError, ArgumentError, CustomException
from .custom_exceptions import CLIException, UIException, UICmdException
from testlib import loggers
from testlib import helpers


# create logger for module
mod_logger = loggers.module_logger(name=__name__)


class UiHelperMixin(object):
    """
    @description  Mixing class for switch.ui
    """

# Port Helpers

    def wait_for_port_value_to_change(
            self, ports, port_parameter, value, interval=1, timeout=30):
        """
        @brief  Wait until value is changed in port table
        @type  ports: list[int | str]
        @type  port_parameter: str
        @type  value: int | str
        @type  step: int
        @type  timeout: int
        @raise: StandardError
        @rtype: none
        """
        end_time = time.time() + timeout
        while time.time() < end_time:
            table = self.get_table_ports(ports=ports, all_params=True, ip_addr=True)

            time.sleep(interval)
            if all(value in r[port_parameter] if isinstance(r[port_parameter], (list, tuple, dict, set))
                   else r[port_parameter] == value for r in table):
                time.sleep(3)
                return True

        raise Exception(
            ("Timeout exceeded: Port {0} does not have value {1} for {2}.").format(
                ports, value, port_parameter))

    def wait_until_ops_state(self, port=1, state="Up", timeout=30):
        """
        @brief  Obsoleted function. Use wait_until_value_is_changed with proper option instead.
        """
        end_time = time.time() + timeout
        while time.time() < end_time:
            table = self.get_table_ports([port, ])
            if table[0]['operationalStatus'] == state:
                return
            time.sleep(3)
        raise Exception(
            "Timeout exceeded: Port state wasn't changed during timeout %s into %s value" % (timeout, state))

    def ui_raises(self, method, *args, **values):
        """
        @brief  UI raises.
        @param method: method to call
        @type method: str
        """
        try:
            getattr(self, method)(*args, **values)
        except (AttributeError, BoundaryError, AssertionError, InvalidCommandError,
                NotExistsError, ExistsError, ArgumentError, xmlrpc.client.Fault, TypeError,
                UICmdException, CLIException, UIException):
            pass
        else:
            pytest.fail("Incorrect command has been executed.")

    def compose_unique_mac_addr(self, pckt_type='unicast', prefix=None, ports=None):
        """
        @brief  Creates unique mac addresses for given ports. Each addres is concatenation
                of packet type speecific prefix, switch own IP address and port number.
        @param  pck_type:  type of packet: 'unicast', 'multicast' or 'broadcast'
        @param  prefix:  custom packet prefix consisting of two octets,eg '01:80',
                         ignored if pck_type == 'broadcast'
        @param  ports:  list of port names or numbers
        @return  map of port names and mac adresses
        """
        type_prefix = {'unicast': 0x0, 'multicast': 0x1, 'broadcast': 0xff}
        port_mac = {}
        for port_id in ports:
            if pckt_type != 'broadcast':
                if prefix is None:
                    ip_split = self.switch.ipaddr.split('.')
                    prefix = '{oct_a:02x}:{oct_b:02x}'.format(oct_a=type_prefix[pckt_type], oct_b=int(ip_split[0]))
                mac = ':'.join([prefix] + ['{:02x}'.format(int(x)) for x in ip_split[1:4] + [str(port_id).replace('sw0p', '')]])
            else:
                mac = 'ff:ff:ff:ff:ff:ff'
            port_mac[port_id] = mac

        return port_mac

# FDB Helpers

    def delete_static_macs_from_port(self, port):
        """
        @brief  Deletes all static MAC addresses from port
        @type  port:  str | int
        """
        table_fdb = self.get_table_fdb(table="static")
        table_fdb_port = (r for r in table_fdb if r['portId'] == port)
        for entry in table_fdb_port:
            if 'vlanId' in entry:
                self.delete_static_mac(port=port, mac=entry['macAddress'], vlan=entry['vlanId'])

# LAG Helpers

    def wait_for_port_status(self, lag_id, state, value, interval):
        """
        @brief  Wait for LAG/port state to become value
        @param  lag_id: LAG/port id
        @param  state: state
        @param  value: expected value
        @param  interval: timeout
        @type  lag_id: int | str
        @type  state: str
        @type  value: int | str
        @type interval:  int
        @raise:  SwitchException
        @rtype:  None
        """
        end_time = time.time() + interval
        while time.time() < end_time:
            lag = self.get_table_ports(ports=[lag_id, ], all_params=True)
            lag_state = lag[0][state]
            if lag_state == value:
                return
            time.sleep(1)
        raise SwitchException(
            "Port {} is not changed to {} during timeout.".format(state, value))

    def clear_lag_table(self):
        """
        @brief  Removes all ports from LAG and clears LAG table
        """
        table = self.get_table_lags()
        table_ports2lag = self.get_table_ports2lag()

        for row in table_ports2lag:
            self.delete_lag_ports(ports=[row['portId']], lag=row['lagId'])
        lag_ids = [x['lagId'] for x in table]
        self.delete_lags(lag_ids)

    def is_lag_added(self, lag_id):
        """
        @brief  Check if lag has been added to LAG table.
        @type  lag_id:  str|int
        @rtype:  bool
        """
        table = self.get_table_lags()
        return any(r['lagId'] == lag_id for r in table)

    def is_port_added_to_lag(self, port, lag_id):
        """
        @brief  Check if port added to LAG.
        @type  port:  int
        @type  lag_id:  str|int
        @rtype:  bool
        """
        # Enforcing str for ONP/ONS compatibility
        table = self.get_table_ports2lag()
        return any(r['portId'] == port and r['lagId'] == lag_id for r in table)

    def set_admin_mode_for_slave_ports(self, admin_mode="Down"):
        """
        @brief  Set adminMode for logical ports.

        @param  admin_mode:  Ports adminMode(string)
        @return  True or raise exception
        @par  Example:
        @code
        assert ui_helpers.set_admin_mode_for_slave_ports(admin_mode="Up")
        @endco
        """
        timeout = 10
        end_time = time.time() + timeout
        # Temporary workaround according to ONS-28780.
        slave_ports_count = 4
        for port in self.switch.hw.master_ports:
            port_info = self.get_table_ports([port, ])
            if port_info[0]["speed"] == 10000:
                while True:
                    if time.time() < end_time:
                        # Need to wait until entry is appeared in Ports table.
                        time.sleep(1)
                        # break if get_table_ports is non-empty
                        if any(self.get_table_ports([port + i]) for i in
                               range(1, slave_ports_count)):
                            break
                    else:
                        pytest.fail(
                            "Slave ports are not available during timeout %s seconds" % timeout)
                for i in range(1, slave_ports_count):
                    self.modify_ports([port + i, ], adminMode="Down")
        return True

    def wait_for_state_lag_state(self, lag=None, port=1, state="Selected", timeout=30):
        """
        @brief  Wait until port state in RSTP table
        """
        end_time = time.time() + timeout
        while time.time() < end_time:
            table = [row for row in self.get_table_lags_local_ports(lag) if row["portId"] == port]
            if not table:
                return
            if table[0]['selected'] == state:
                return
            time.sleep(0.3)
        raise Exception(
            "Timeout exceeded: Port state wasn't changed during timeout %s into %s value" % (timeout, state))

# UFD Helpers

    def build_and_create_ufd_network_file(self, port_type, ports, bind_carrier=''):
        """
        @brief  Creating network file for uplink and downlink ports
        @param  port_type:  type of interface (uplink/downlink)
        @type  port_type:  str
        @param  ports:  ports to assign to UFD group
        @type  ports:  list[int | str]
        @param  bind_carrier:  which uplink ports are bound to specified downlink ports
        @type  bind_carrier:  str | list[int]
        @rtype:  None
        """
        # Get the Config Parser Instance
        config = configparser.RawConfigParser()

        # Preserve the Key Name Original Case
        config.optionxform = str

        # Add sections for config parser
        config.add_section('Match')
        config.add_section('Network')

        bind_port_names = [self.port_map[port] if isinstance(port, int)
                           else port for port in bind_carrier]
        bind_port_names = ' '.join(bind_port_names)

        for port in ports:
            port_name = self.port_map[port] if isinstance(port, int) else port

            # Set Match Section and Port name
            config.set('Match', 'Name', port_name)

            # Set Network Section and BindCarrier in case of Network Filetype downlink
            if port_type is 'downlink':
                config.set('Network', 'BindCarrier', bind_port_names)

            self.create_ufd_network_file(
                port_name=port_name, config_parser_instance=config)

    def start_traffic_ufd(self, tg_instance, port_list):
        """
        @brief  Start sending traffic to the ports
        @param  tg_instance:  TG instance object
        @type  tg_instance:  instance object
        @param  port_list:  List of interfaces to which traffic needs to be send
        @type  port_list:  list[dict]
        @return:  list of stream ids generated
        @rtype:  list[int]
        """
        stream_ids = []
        for port in port_list:
            # Define the packet
            packet = (
                {"Ether": {"dst": port["dst_mac"], "src": port['src_mac'], "type": 0x0800}},
                {"IP": {}},
                {"UDP": {}}, )

            # Create streams
            stream_id = tg_instance.set_stream(packet, continuous=True, iface=port['iface'])
            stream_ids.append(stream_id)

        # Clear statistics table
        self.clear_statistics()

        # Start streams
        tg_instance.start_streams(stream_ids)
        return stream_ids

    def get_and_validate_statistics_ufd(self, ingress_ports, egress_ports,
                                        tg_instance, sniff_params, time_out=30):
        """
        @brief  Get the port statistics and validate the counters
        @param  ingress_ports:  List of ingress ports that need to be validated
        @type  ingress_ports:  list[tuple(int, built-in function)]
        @param  egress_ports:  List of egress ports that need to be validated
        @type  egress_ports:  list[tuple(int, built-in function)]
        @param  tg_instance:  traffic generator instance object
        @type  tg_instance:  instance object
        @param  sniff_params:  parms used for validating packets in the TG
        @type  sniff_params:  dict{(int, int, int): list[tuple(str, str, bool)]}
        @param  time_out:  Time out requred for the counters to get updated
        @type  time_out:  int
        @rtype:  None
        """
        # Start packet sniffing
        sniff_ports = list(sniff_params.keys())
        tg_instance.start_sniff(sniff_ports)

        # Get start statistics value for all ingress ports
        start_ingress_port_statistics = [int(self.get_table_statistics(
            port[0], 'cntRxUcstPktsIPv4')) for port in ingress_ports]

        # Get start statistics value for all egress ports
        start_egress_port_statistics = [int(self.get_table_statistics(
            port[0], 'cntTxUcstPkts')) for port in egress_ports]

        # Wait for time_out  seconds for the packets to reach and counters to get updated
        time.sleep(time_out)

        # Get end statistics value for all ingress ports
        end_ingress_port_statistics = [int(self.get_table_statistics(
            port[0], 'cntRxUcstPktsIPv4')) for port in ingress_ports]

        # Get end statistics value for all egress ports
        end_egress_port_statistics = [int(self.get_table_statistics(
            port[0], 'cntTxUcstPkts')) for port in egress_ports]

        # Stop packet sniffing
        data = tg_instance.stop_sniff(sniff_ports)

        # Validate the counters
        for port, start_stat, end_stat in zip(
                chain(ingress_ports, egress_ports),
                chain(start_ingress_port_statistics, start_egress_port_statistics),
                chain(end_ingress_port_statistics, end_egress_port_statistics)):
            assert port[1](start_stat, end_stat), "Counter mismatch occured"

        # Validate the packet
        for tg_port in sniff_params:
            for param in sniff_params[tg_port]:
                helpers.is_packet_received(data=data, iface_1=tg_port, layer_1="Ether",
                                           field_1="dst", value_1=param[1],
                                           layer_2="Ether", field_2="src", value_2=param[0],
                                           tg_instance=tg_instance, result=param[2])

    def add_entry_to_fdb_ufd(self, vlan_id, fdb_entries):
        """
        @brief  Add static MAC to FDB
        @param  vlan_id:  vlan id to be used
        @type  vlan_id:  int
        @param  fdb_entries:  port and mac details that neeed to be added to FDB
        @type  fdb_entries:  list[tuple(int, str)]
        @rtype:  None
        """
        for entry in fdb_entries:
            self.create_static_macs(port=entry[0], vlans=[vlan_id], macs=[entry[1]])


# VLAN helpers

    def is_entry_added_to_vlan_table(self, vlan_id=1):
        """
        @brief  Check if entry is added to VLAN table

        @param  vlan_id:  vlan number from where packet was sent (integer)
        @type  vlan_id:  int
        @return:  True or False
        @rtype:  bool

        @par  Example:
        @code
        is_entry_added_to_vlan_table(vlan_id=vlan_id)
        """
        table = self.get_table_vlans()
        return any(row['vlanId'] == vlan_id for row in table)

    def is_entry_added_to_ports2vlan_table(self, port_id, vlan_id, tagged='Tagged',
                                           pvid=None, table_ports2vlan=None):
        """
        @brief  Check if entry is added to Ports2Vlan table

        @param  port_id:  port number
        @type  port_id:  int
        @param  vlan_id:  vlan number
        @type  vlan_id:  int
        @param  tagged:  tagged or untagged
        @type  tagged:  str
        @param  pvid:  true or false, if inputted vlan is pvid
        @type  pvid:  bool
        @param  table_ports2vlan:  table of ports2vlan
        @return:  True or False
        @rtype:  bool

        @par  Example:
        @code
        is_entry_added_to_ports2vlan_table(port_id=port_id, vlan_id=vlan_id, pvid=True,
        tagged=tagged
        """
        if table_ports2vlan is None:
            table_ports2vlan = self.get_table_ports2vlans()
        if pvid is not None:
            return any(row['portId'] == port_id and row['vlanId'] == vlan_id and
                       row['pvid'] == pvid and row['tagged'] == tagged for row in table_ports2vlan)
        else:
            return any(row['portId'] == port_id and row['vlanId'] == vlan_id and
                       row['tagged'] == tagged for row in table_ports2vlan)

# STP helpers

    def wait_until_stp_param(self, mode="STP", port=1, param='rootGuard',
                             value="Disabled", timeout=30, instance=0):
        """
        @brief  Wait until port role in xSTP table
        """
        end_time = time.time() + timeout
        while time.time() < end_time:
            if mode == 'RSTP' or mode == 'STP':
                table = self.get_table_rstp_ports([port, ])
            if mode == 'MSTP':
                table = self.get_table_mstp_ports([port, ], instance)
            if table[0][param] == value:
                return
            time.sleep(0.3)
        raise CustomException(
            "Timeout exceeded: Port %s wasn't changed during timeout %s into %s value" % (param, timeout, value))
