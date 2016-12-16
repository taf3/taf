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

@file  ui_dcrp_shell.py

@summary  DCRP Shell UI specific functionality.
"""

import re
import time
from functools import partial

import pytest

from .custom_exceptions import UIException, UICmdException
from .ui_helpers import UiHelperMixin
from . import loggers


DCRP_SERVICE_LIST = ["dcrpd", "isisd", "zebra"]
DCRP_CONF_FILE = "/etc/dcrpd.conf"

ISIS_TELNET_PORT = 2608
ISIS_USERNAME = "ustack"
ISIS_PASSWORD = "ustack"


def in_parallel(func):
    """
    @brief  Decorator function. Runs decorated function in parallel for all nodes.
            Decorated function must receive named parameter 'instance'.
    """
    def wrapper(*args, **kwargs):
        # Check if first parameter is UiDcrpShell instance
        if isinstance(args[0], UiDcrpShell):
            self = args[0]
        else:
            message = 'Decorated method must receive "UiDcrpShell" instance as first parameter'
            raise UIException(message)
        # If 'instance' is in kwargs, call decorated function directly
        if 'instance' in kwargs:
            return func(*args, **kwargs)
        # Else, call in parallel
        else:
            # If no instances is received, put nodes' UI instances
            kwargs['instances'] = kwargs.get('instances', list(self.ui_dict.values()))
            # Call function on parallel on instances
            return self.switch.parallel_call(func, *args, **kwargs)
    return wrapper


class UiDcrpShell(UiHelperMixin):
    """
    @description  UI class for DCRP domain.
    @note  When UiInterface class from ui_wrapper has abstraction methods,
           this class should also inherit from it.
    """

    class_logger = loggers.ClassLogger()

    def __init__(self, dcrp_domain):
        """
        @brief  Initiate UiDcrpShell class
        @param  dcrp_domain: DCRP Domain instance
        @type  dcrp_domain: SwitchDcrpDomain instance
        """
        self.switch = dcrp_domain

        # Make dictionary {1: node_1_ui_instance, 2: node_2_ui_instance}
        self.ui_dict = {key: node.ui for key, node in self.switch.node.items()}

        # Make dictionary {'0001': node_1_ui_instance, 2: '0015': node_15_ui_instance}
        self.ui_id_map = {node.id: node.ui for node in self.switch.node.values()}

        self.ports = dcrp_domain.ports
        self.dcrp_service_list = DCRP_SERVICE_LIST
        self.dcrp_conf_file = DCRP_CONF_FILE

        # Assign CPU port of the first node to self.cpu_port for compatibility with
        # common test cases
        self.cpu_port = "{0} {1}".format(self.switch.node[1].id, self.switch.node[1].ui.cpu_port)

        # Create node CPU ports map for DCRP specific test cases
        self.cpu_ports = {node.id: node.ui.cpu_port for node in self.switch.node.values()}

    def __getattr__(self, item):
        """
        @brief  Override all not implemented in this class UI methods' calls by
                calling them on all UI instances in parallel.
        @param  item: Name of called and not found in class item.
        @type  item: str
        @raise  AttributeError: error if UIs don't have called method.
        """
        if self.ui_id_map and hasattr(self.ui_dict[1], item) \
                and callable(getattr(self.ui_dict[1], item)):
            instances = list(self.ui_id_map.values())
            return partial(self.switch.parallel_call, item, instances=instances)
        else:
            raise AttributeError(item)

# Platform
    def get_table_platform(self):
        """
        @copydoc testlib::ui_wrapper::UiInterface::get_table_platform()
        """
        # Get unique values for fields from all nodes
        switchpp_version = set([ui.switch.get_env_prop('switchppVersion')
                                for ui in self.ui_dict.values()])
        cpu_architecture = set([ui.switch.get_env_prop('cpuArchitecture')
                                for ui in self.ui_dict.values()])
        os_type = set([ui.switch.get_env_prop('osType')
                       for ui in self.ui_dict.values()])
        os_ver = set([ui.switch.get_env_prop('osVersion')
                      for ui in self.ui_dict.values()])
        chip_name = set([ui.switch.get_env_prop('chipName') for ui in self.ui_dict.values()])

        # Note: No central area to pull stats; this is for display only
        return [{"ethernetSwitchType": "Fulcrum Switch",
                 "name": "DCRPDomain",
                 "model": "NA",
                 "chipVersion": "NA",
                 "chipSubType": "NA",
                 "apiVersion": "NA",
                 "switchppVersion": "_".join(switchpp_version),
                 "cpu": "NA",
                 "cpuArchitecture": "_".join(cpu_architecture),
                 "osType": "_".join(os_type),
                 "osVersion": "_".join(os_ver),
                 "chipName": "DCRPDomain_" + "_".join(chip_name),
                 "serialNumber": "NA"}]

    def get_table_ports(self, ports=None, all_params=False, ip_addr=False):
        """
        @brief  Wrapper for get_table_ports UI method.
        @param  ports: List of ports or None. Ports should be in format "node_id port_id".
                      Example: ["0013 10", "0014 20"]
        @type  ports: list[str]
        @param  all_params:  get additional port properties
        @type  all_params:  bool
        @param  ip_addr:  Get IP address
        @type  ip_addr:  bool
        """

        ports = ports if ports else self.ports
        ports_map = self.get_ports_map(ports)

        table_ports = []
        for node_id, ports in ports_map.items():
            node_ui = self.ui_id_map[node_id]
            ports_list = node_ui.get_table_ports(ports, all_params, ip_addr)
            # Add node_id to every port
            for port in ports_list:
                port['node_id'] = node_id
            table_ports.extend(ports_list)

        return table_ports

    @staticmethod
    def get_ports_map(ports_list):
        """
        @brief  Convert list of ports from format ["0013 10", "0013 13", "0014 15", "0015 15"]
                to {"0013": [10, 13], "0014": [15], "0015": [15]]
        @param  ports_list: List of port to be converted in format ["5555 1", "7777 2"]
        @type  ports_list: list[str]
        @return  Dictionary with node IDs as keys and lists of port IDs as values
        @rtype  dict
        """

        ports_map = {}
        for port in ports_list:
            node_id, port_id = port.split(" ")[0:2]
            try:
                port_id = int(port_id)
                # Append port to ports list for the specific node
                ports_map[node_id].append(port_id)
            except KeyError:
                # If node isn't in map yet, add node and port
                ports_map[node_id] = [port_id, ]
            except IndexError:
                raise UIException("Wrong port {0} in the given ports list.".format(port))
            except TypeError:
                message = "Wrong port ID {} in the given ports list.".format(port_id)
                raise UIException(message)

        return ports_map

    def modify_ports(self, ports, expected_rcs=frozenset({0}), **kwargs):
        """
        @brief  Wrapper for modify_ports UI method.
        @param  ports: List of ports or None. Ports should be in format "node_id port_id".
                       Example: ["0013 10", "0014 20"]
        @type  ports: list[str]
        @param  expected_rcs:  expected return code
        @type  expected_rcs:  int | list | set | frozenset
        """
        ports_map = self.get_ports_map(ports)

        for node_id, node_ports in ports_map.items():
            ui_instance = self.ui_id_map[node_id]
            ui_instance.modify_ports(node_ports, expected_rcs=expected_rcs, **kwargs)

    def wait_for_port_value_to_change(self, ports, port_parameter, value, interval=1, timeout=30):
        """
        @brief  Wrapper for waiting for port value to be changed.
        @param  ports: List of ports or None. Ports should be in format "node_id port_id".
                       Example: ["0013 10", "0014 20"]
        @type  ports: list[str]
        @param  port_parameter: Parameter name to be checked
        @type  port_parameter: str
        @param  value: Parameter value to be checked
        @type  value: int | str
        @param  interval: How often parameter should be checked (seconds)
        @type  interval: int
        @param  timeout: Time for checking value
        @type  timeout: int
        @raise: StandardError
        @rtype: none
        """
        ports_map = self.get_ports_map(ports)
        for node_id, node_ports in ports_map.items():
            ui_instance = self.ui_id_map[node_id]
            ui_instance.wait_for_port_value_to_change(ports=node_ports, port_parameter=port_parameter,
                                                      value=value, interval=interval, timeout=timeout)

    def create_vlan_ports(self, ports=None, vlans=None, tagged='Tagged'):
        """
        @brief  Wrapper for create_vlan_ports UI method.
                Method also adds VLAN to CPU and mesh ports.
        @param  ports: List of ports or None. Ports should be in format "node_id port_id".
                       Example: ["0013 10", "0014 20"]
                       Mandatory parameter.
        @param  vlans:  list of VLAN IDs. Mandatory parameter.
        @type  vlans:  list[int] | set(int)
        @param  tagged:  port tagging attribute
        @type  tagged:  str
        @raise  UIException: Error if not all mandatory parameters are specified.
        """
        if not ports or not vlans:
            raise UIException("Ports and vlans are mandatory parameters.")

        ports_map = self.get_ports_map(ports)

        for node_id, node_ports in ports_map.items():
            # Add nodes' mesh ports to list to make VLAN be added to them as well
            node_ports.extend(self.switch.mesh_ports[node_id])

            # Add node's CPU ports to list to make VLAN be added to it as well
            node_ports.append(self.cpu_ports[node_id])

            ui_instance = self.ui_id_map[node_id]
            ui_instance.create_vlan_ports(ports=node_ports, vlans=vlans, tagged=tagged)

    @in_parallel
    def set_all_ports_admin_disabled(self, instance=None):
        """
        @brief  Disables all ports in port_map on all nodes.
        """
        ports_table = instance.get_table_ports()

        # Make ports id list excluding mesh_ports
        node_id = instance.switch.config.get('id')
        node_mesh_ports = self.switch.mesh_ports[node_id][:]

        # Add CPU port to avoid its affecting
        node_mesh_ports.append(instance.cpu_port)

        ports = [x['portId'] for x in ports_table if x["portId"] not in node_mesh_ports]

        instance.modify_ports(ports, adminMode="Down")

    @in_parallel
    def wait_all_ports_admin_disabled(self, instance=None):
        """
        @brief  Checks if all the ports on all nodes are set to down
        """
        def _retry(ports_list):
            start_time = time.time()
            _table = self.get_table_ports(ports_list)
            up_ports = [x['portId'] for x in _table if x['operationalStatus'] == 'Up']
            end_time = time.time()
            while end_time < start_time + 30 and len(up_ports) > 0:
                time.sleep(2)
                _table = self.get_table_ports(up_ports)
                up_ports = [x['portId'] for x in _table if x['operationalStatus'] == 'Up']
                end_time = time.time()
            return up_ports

        # for node_ui in self.ui_id_map.itervalues():
        ports_table = self.get_table_ports(ports=None)

        # Make ports id list excluding mesh_ports
        node_id = instance.switch.config.get('id')
        node_mesh_ports = self.switch.mesh_ports[node_id][:]

        # Add CPU port to avoid its affecting
        node_mesh_ports.append(instance.cpu_port)

        port_ids = [x["portId"] for x in ports_table if x["operationalStatus"]
                    not in ['Unknown', 'Down'] and x["portId"] not in node_mesh_ports]

        if port_ids:
            up_ports = _retry(port_ids)

            attempts = 0

            while up_ports and attempts < 3:
                # retry: set adminMode in Up/Down
                self.switch.ui.modify_ports(up_ports, adminMode='Up')
                self.switch.ui.modify_ports(up_ports, adminMode='Down')
                up_ports = _retry(up_ports)
                attempts += 1

            if up_ports:
                pytest.fail("Not all ports are in down state: %s" % up_ports)

    def check_dcrpd_service(self, instance=None, services=None):
        """
        @brief  Check status of DCRP services on the specified node
        @param  instance: UI instance to restart DCRP services with
        @type  instance: UI instance
        @param  services: List of services' names
        @type  services: list[str]
        @rtype:  dict
        @return:  Dictionary with service names as keys
                  and bool status as values
        """
        if instance:
            services = services if services else self.dcrp_service_list

            # Get all processes launched on the node
            cmd = 'ps {} co command --no-headers'.format(' '.join('-C '+x for x in services))
            processes = instance.cli_send_command(cmd, expected_rcs={0, 1}).stdout.splitlines()

            return set(processes) == set(services)
        else:
            raise UIException("UI instance isn't specified.")

    @in_parallel
    def stop_dcrpd_service(self, instance=None):
        """
        @brief  Stop DCRP services on specified nodes.
        @param  instance: UI instance to restart DCRP services with
        @type  instance: UI instance
        @param  services: List of services' names
        @type  services: list[str]
        @param  force: Forced killing service. If services isn't stopped for the first time
                       it will be automatically forced stopped.
        @type force: bool
        @raise  UIException: Error if not all services on at least one node are stopped
        """
        if instance:
            instance.dcrpd.stop()
        else:
            raise UIException("UI instance isn't specified.")

    @in_parallel
    def start_dcrpd_service(self, instance=None, restart=False, wait_on=True):
        """
        @brief  Start DCRP services on specified nodes.
        @param  instance: UI instance to restart DCRP services with
        @type  instance: UI instance
        @param  restart: Should method restart already launched services or not
        @type  restart: bool
        @param  wait_on: Wait for services started or not
        @type  wait_on: bool
        @raise  UIException: Error if not all services on at least one node are started
                             or if no flag "restart" and at least one service is already launched
        """
        if not instance:
            raise UIException("UI instance isn't specified.")

        if restart:
            instance.dcrpd.restart()
        else:
            instance.dcrpd.start()

        if wait_on:
            # Wait for DCRP services become launched
            self.wait_on_dcrpd_service(instance=instance)

    def restart_dcrpd_service(self):
        """
        @brief  Wrapper for self.start_dcrpd_service method with True "restart" parameter
        @param  instance: UI instance to restart DCRP services with
        @type  instance: UI instance
        """
        self.start_dcrpd_service(restart=True)

    def _get_ui_instance(self, node_id):
        """
        @brief  Get UI instance of specified node
        @param  node_id: ID of node for getting it's UI instance
        @type  node_id: int | str
        @raise  UIException: Error if wrong node_id was given
        @rtype:  Device UI instance
        @return:  UI instance of the given node
        """
        if isinstance(node_id, int) and node_id in self.ui_dict:
            ui_instance = self.ui_dict[node_id]
        elif isinstance(node_id, str) and node_id in self.ui_id_map:
            ui_instance = self.ui_id_map[node_id]
        else:
            raise UIException("Given node ID {0} wasn't found!".format(node_id))

        return ui_instance

    def configure_dcrpd(self, node_id, mesh_ports=None, cpu_mac_address=None, file_name=None):
        """
        @brief  Configure mesh ports for using by DCRP services.
                Edit DCRP service configuration file ("/etc/dcrpd.conf" by default)
                by adding given ports as mesh ports. Set given MAC address for given ports
                and bring them UP.
        @param  node_id: node ID for configuring on
        @type  node_id: int | str
        @param  mesh_ports: Dictionary with mesh port names as keys and dictionary with
                            additional parameters, such as port MAC address, as values.
        @type  mesh_ports: dict[dict]
        @param  cpu_mac_address: MAC address to be set to CPU port. Format: "FF:FF:FF:FF:FF:FF"
        @type  cpu_mac_address: str
        @param  file_name: DCRP configuration file name.
                           If omitted self.dcrp_conf_file will be used.
        @type  file_name: str
        """
        file_name = file_name if file_name else self.dcrp_conf_file
        ui_instance = self._get_ui_instance(node_id)
        parameters = dict()

        # Create dictionary with parameters for configuring in remote dcrp config file
        parameters['cppname'] = '"{0}"'.format(ui_instance.port_map[ui_instance.cpu_port])

        # Get parameters from arguments or switch config
        mesh_ports = mesh_ports if mesh_ports else ui_instance.switch.config.get('mesh_ports')
        if cpu_mac_address is None:
            cpu_mac_address = ui_instance.switch.config.get('cpu_mac_address')

        if not (mesh_ports or cpu_mac_address):
            raise UIException('"{}" was not found in arguments or in switch config.'.format(
                mesh_ports if mesh_ports else cpu_mac_address))

        mesh_ports_names = list(mesh_ports.keys())
        parameters['mesh_port'] = '("{0}")'.format('", "'.join(mesh_ports_names))

        # Edit remote DCRP configuration file
        self.update_remote_config(node_id, parameters, file_name, clean=True)

        # Configure CPU port
        ui_instance.modify_ports([ui_instance.cpu_port], macAddress=cpu_mac_address)

        # Configure mesh ports
        for mesh_port_name in mesh_ports_names:
            port_id = ui_instance.name_to_portid_map.get(mesh_port_name)
            port_mac_address = mesh_ports[mesh_port_name].get('mac_address')
            if not port_mac_address:
                raise UIException('Setup is missing mesh port MAC address.')
            ui_instance.modify_ports([port_id, ], macAddress=port_mac_address)

    def configure_mlag(self, uplink_port, lag_mac, team_name=None, file_name=None):
        """
        @brief  Configure DCRP MLAG on specified node.
                Edit DCRP service configuration file ("/etc/dcrpd.conf" by default)
                by adding given port(s) as uplink ports. Set given MAC address as lag mac address.
        @param  uplink_port: List of ports to configure them as uplink ports.
                             Ports should be in format "node_id port_id".
                             Example: ["0013 10", "0014 20"]
        @type  uplink_port: list[str]
        @param  lag_mac: MAC address to configure as MLAG MAC address. Same for each node
        @type  lag_mac: str
        @param  team_name: MLAG interface name, skip if None
        @type  team_name: str
        @param  file_name: DCRP configuration file name. If omitted self.dcrp_conf_file is used.
        @type  file_name: str
        """
        file_name = file_name if file_name else self.dcrp_conf_file

        uplink_port_dict = self.get_ports_map(uplink_port)

        for node_id, nodes_ports_list in uplink_port_dict.items():
            # Get UI instance for specific node
            ui_instance = self._get_ui_instance(node_id)

            # Convert ports ID list into ports name list
            ports_name_list = [ui_instance.port_map[port_id] for port_id in nodes_ports_list]

            # Prepare dictionary with parameters for configuration file update
            params = {'uplink_port': '("{}")'.format('", "'.join(ports_name_list)),
                      'lag_mac': '"{}"'.format(lag_mac)}
            if team_name:
                params["team_name"] = '"{}"'.format(team_name)

            # Update remote DCRP configuration file for specific node
            self.update_remote_config(node_id, params, file_name)

    def update_remote_config(self, node_id, parameters, file_name, clean=False):
        """
        @brief  Edit or add parameters in remote configuration file
                which contains "key = value" pairs.
        @param  node_id: node ID for configuring on
        @type  node_id: int | str
        @param  parameters: Dictionary with key: value pair for editing or adding
                            to remote configuration file
        @type  dict
        @param  file_name: Full name (path + name) of remote configuration file
        @type  str
        @param  clean: Empty configuration file before editing.
        @type  bool
        """
        ui_instance = self._get_ui_instance(node_id)

        try:
            with ui_instance.switch.ssh.client.open_sftp() as sftp,\
                    sftp.open(file_name, "r+") as remote_conf_file:

                # Read configuration from remote file
                remote_conf = remote_conf_file.read() if not clean else ''

                # Empty configuration file before editing
                remote_conf_file.seek(0)
                remote_conf_file.truncate(0)

                # Update passed parameters
                for parameter, value in parameters.items():
                    param_re = re.compile(r"^{0} = .*$".format(parameter), re.MULTILINE)
                    if not clean and param_re.search(remote_conf):
                        remote_conf = param_re.sub("{0} = {1}".format(parameter, value),
                                                   remote_conf, count=1)
                    else:
                        remote_conf += "{0} = {1}\n".format(parameter, value)

                # Rewrite file with updated configuration
                remote_conf_file.write(remote_conf)
        except IOError:
            message = 'Error accessing "{0}" file on node with ID {1}'.format(
                file_name, ui_instance.switch.id)
            raise UIException(message)

    def wait_on_dcrpd_service(self, instance=None, services=None, timeout=45):
        """
        @brief  Wait for DCRP services are launched.
        @param  instance: UI instance to wait DCRP services on
        @type  instance: UI instance
        @param  services: List of services' names
        @type  services: list[str]
        @param  timeout: Timeout for waiting
        @type  timeout: int
        """
        if not instance:
            raise UIException("Failure: timeout on loading DCRP services, node id {}.".format(
                instance.switch.id))

        end_time = time.time() + timeout

        # Get delay (1/3 of timeout) for retrieving DCRP service's status once per it
        delay = timeout // 3

        while time.time() < end_time:
            if self.check_dcrpd_service(instance, services=services):
                # Make sure that started processes stay up and running
                time.sleep(1)
                if self.check_dcrpd_service(instance, services=services) is True:
                    return
            time.sleep(delay)
        raise UIException("Failure: timeout on loading DCRP services, node id {}.".format(
            instance.switch.id))

    @in_parallel
    def check_isis_nodes_discovery(self, instance=None):
        """
        @brief  Check whether all nodes discovered each other with ISIS
        @return  True if all nodes discovered each other and False if not
        @rtype  bool
        """
        if instance:
            # Create list of all nodes' MAC addresses
            nodes_macs = [node_conf.config.get('cpu_mac_address')
                          for node_conf in self.switch.node.values()]

            # Get information about discovered neighbors from isisd on each node
            discovered = None
            try:
                discovered = instance.cli_send_command('vtysh -c "show isis hostname"').stdout
            except UICmdException as ex:
                self.class_logger.error(ex)
                pytest.fail('Failed to get IS-IS discovery status, node id {}.'.format(
                    instance.switch.id))

            discovered_list = re.findall(r'([a-f0-9.]{14})', discovered, re.MULTILINE)
            discovered_list = [":".join(
                [mac.replace(".", "")[x:x+2] for x in range(0, 12, 2)]) for mac in discovered_list]

            if set(nodes_macs) == set(discovered_list):
                return True
            return False
        else:
            raise UIException("UI instance isn't specified.")

    @staticmethod
    def parse_isis_table_topology(topology_table):
        """
        @brief  Parse 'show isis topology' table
        @param  topology_table:  List of 'show isis topology' raw output
        @type  topology_table:  list[str] | iter()
        @return A dictionary containing the vertex, type, metric, next_hop, interface and
                parent values for each destination node
        @rtype:  iter()
        """
        for row in topology_table:
            match = re.search(
                r"(?P<vertex>\S+)?\s*(?P<type>\S+)?\s*(?P<metric>\S+)?\s*(?P<next_hop>\S+)?\s*(?P<interface>\S+)?\s*(?P<parent>\S+)?", row)
            if match:
                row = match.groupdict()
                if row['vertex']:
                    # Set vertex, connection_type, metric on the first line to use on next lines
                    vertex = row['vertex']
                    connection_type = row['type']
                    row['metric'] = int(row['metric'])
                    metric = row['metric']
                else:
                    if len(set(row.values())) == 2:
                        # Temporary skip last line since last parent value is outside of table
                        continue
                    else:
                        row['parent'] = row['next_hop']
                        row['interface'] = row['metric']
                        row['next_hop'] = row['type']
                        # This row doesn't have a vertex, connection_type,
                        # metric because it implicitly uses the previous
                        row['vertex'] = vertex
                        row['type'] = connection_type
                        row['metric'] = metric
                yield row

    @staticmethod
    def parse_isis_table_neighbor(neighbor_table):
        """
        @brief  Parse 'show isis neighbor' table
        @param  neighbor_table:  List of 'show isis neighbor' raw output
        @type  neighbor_table:  list[str] | iter()
        @return A dictionary containing the system_id, interface, level, state, hold_time, snpa
                of each neighbor.
        @rtype:  iter()
        """
        for row in neighbor_table:
            match = re.search(
                r"\s*(?P<system_id>\S+)?\s*(?P<interface>\S+)?\s*(?P<level>\S+)?\s*(?P<state>\S+)?\s*(?P<hold_time>\S+)?\s*(?P<snpa>\S+)?", row)
            if match:
                row = match.groupdict()
                row["level"] = int(row["level"])
                row["hold_time"] = int(row["hold_time"])
                yield row

    @in_parallel
    def get_isis_topology(self, instance=None):
        """
        @brief Get IS-IS topology table
        @return  List of dictionary with keys: vertex, type, metric, next_hop, interface, parent
        @rtype  list[dict]
        """
        if instance:
            try:
                topology_output = instance.cli_send_command('vtysh -c "show isis topology"').stdout
            except UICmdException as ex:
                self.class_logger.error(ex)
                pytest.fail('Failed to get IS-IS topology, node id {}.'.format(
                    instance.switch.id))
            table = list(self.parse_isis_table_topology(topology_output.strip().splitlines()[4:]))
            for record in table:
                record["interface"] = instance.name_to_portid_map.get(record["interface"])
            return table
        else:
            raise UIException("UI instance isn't specified.")

    @in_parallel
    def get_isis_neighbors(self, instance=None):
        """
        @brief Get IS-IS neighbor table
        @return  List of dictionary with keys: system_id, interface, level, state, hold_time, snpa
        @rtype  list[dict]
        """
        if instance:
            try:
                neighbor_output = instance.cli_send_command('vtysh -c "show isis neighbor"').stdout
            except UICmdException as ex:
                self.class_logger.error(ex)
                pytest.fail('Failed to get IS-IS neighbor, node id {}.'.format(
                    instance.switch.id))
            table = list(self.parse_isis_table_neighbor(neighbor_output.strip().splitlines()[2:]))
            return table
        else:
            raise UIException("UI instance isn't specified.")

    @in_parallel
    def get_node_hostname(self, instance=None):
        """
        @brief Get node's hostname
        @return  Hostname of node.
        @rtype  str
        """
        if instance:
            try:
                hostname_output = instance.cli_send_command('hostname').stdout
            except UICmdException as ex:
                self.class_logger.error(ex)
                pytest.fail('Failed to get hostname, node id {}.'.format(
                    instance.switch.id))
            return hostname_output.strip()
        else:
            raise UIException("UI instance isn't specified.")

    @staticmethod
    def get_tg_ports_of_node(env, node_id, links_count=1):
        """
        @brief Get tg ports connected to specified node
        @param  env:  Environment
        @type  env:  object
        @param  node_id:  Node id. E.g.: '4615'
        @type  node_id:  str
        @param links_count: Required links count for specific node
        @type links_count: int
        @return  TG instances and related tg/switch ports connected between each other. E.g.:
                {'tg': {1: <dev_obj1>, 2: <dev_obj1>}, 'tg_ports': {1: (1,6,5), 2:(1,6,6)}, 'sw_ports':  {1: 13, 2: 21}}
        @rtype  dict
        """
        ports = env.get_ports()
        res = {'tg_obj': {}, 'tg_ports': {}, 'sw_ports':{}}
        tg_id = 1
        for dev, links in ports.items():
            for key, nodes in links.items():
                if node_id in nodes:
                    res['tg_obj'][tg_id] = env.id2instance(tuple(set(dev) - set(('9999',)))[0])
                    res['sw_ports'][tg_id] = nodes.split()[1]
                    res['tg_ports'][tg_id] = ports[tuple(reversed(dev))][key]
                    tg_id += 1
        if len(res['tg_obj']) < links_count:
            pytest.skip("Node id {} doesn't have available TG links".format(node_id))

        return res

    @in_parallel
    def set_age_time_out(self, instance=None, age_time=3600):
        """
        @brief  Set age time out value on all nodes.
        """
        # Modify values
        instance.modify_bridge_info(agingTime=age_time)
        # instance.configure_arp(arp_len=self.MAX_DCRP_TABLE9_SIZE)

        # Return status
        return instance.get_table_bridge_info(param='agingTime', port=0) == age_time

    @in_parallel
    def get_macs(self, instance=None):
        """
        @brief  Set age time out value on all nodes.
        """
        # Get MAC addresses from HW rule#9
        out = instance.cli_send_command("match -f 5555 -p 30001 get_rules table 9").stdout
        return set(re.findall(r'ethernet.dst_mac\s=\s((?:[\w]{2}:){5}[\w]{2})', out, re.MULTILINE))
