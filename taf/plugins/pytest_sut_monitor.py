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

"""``pytest_sut_monitor.py``

`Collect monitoring info based on Colletcd RRDs`

Note:
    For correct functioning collectd should be properly configured:
      1) Collectd server should be configured in the lab
      2) Collectd client should be configured on device
      3) On device should be configured hostname equal to the 'name' value in JSON

"""

import errno
import json
import os
from shutil import rmtree
import time

import pytest

from . import loggers
from .pytest_onsenv import setup_scope
from testlib.custom_exceptions import UICmdException
from testlib import clissh
from testlib import rrdtool_graph
from testlib import multicall
from testlib.cli_template import CmdStatus


PATH_TO_RRD = '/var/lib/collectd/rrd'


INCLUDES = {'rr', 'linux_host', 'generic'}

SUPPORTED_GRAPHS = {
    'MEMORY': 'memory',
    'CPU': 'cpu',
    # 'INTERFACE': 'interface-',
    'INTERFACE_BYTES': 'interface-',
    'LOAD': 'load',
    'DISK': 'disk-'
}


RESULTS_DIR = '/tmp/sut_monitor'


def pytest_addoption(parser):
    """ Describe plugin specified options.

    """
    group = parser.getgroup("SUT monitoring", "plugin: SUT monitor")
    group.addoption("--monitor", action="store_true", default=False,
                    help="Gather collectd information about environment")


def pytest_configure(config):
    """Registering plugin.

    """
    if config.option.monitor:
        config.pluginmanager.register(SutMonitorPlugin(), "_sut_monitor")


def pytest_unconfigure(config):
    """Unregistering plugin.

    """
    sut_monitor = getattr(config, "_sut_monitor", None)
    if sut_monitor:
        del config._sut_monitor
        config.pluginmanager.unregister(sut_monitor)


class SutMonitor(object):
    """Main functionality for collectd client/server manipulation.

    """
    class_logger = loggers.ClassLogger()

    def __init__(self, env):
        """Initialize SutMonitor object instance.

        Args:
            env(testlib.common3.Environment): TAF environment instance

        """
        super().__init__()
        self.env = env
        # Initialize start and stop time values
        self.start_time = time.time()
        self.end_time = time.time()
        # Initialize test name value
        self.test = 'Undefined'
        # Store collectd folders in dict
        self.devices = {}
        # Store created graphs in list
        self.test_files = []
        # Get Collectd server host instance from environment
        self.server = next(iter(dev for dev in list(getattr(self.env, "settings", {}).values())
                                if dev.type == 'collectd_settings'),
                           None)
        # Create folder to store graphs
        self.create_dir(RESULTS_DIR, clear=False)
        # Filter environment device for gathering collectd info
        # get device with proper type and related Collectd server host
        self.devices = {dev.name: {} for dev in self.env.id_map.values()
                        if dev.type in INCLUDES and self.server.id in dev.related_obj}

    def create_dir(self, dir_name, clear=True):
        """Create folder on TAF host.

        Args:
            dir_name(str): folder path
            clear(bool): flag to delete folder if exists

        """
        if clear:
            try:
                rmtree(dir_name)
            except OSError as e:
                if e.errno == errno.ENOENT:
                    pass
                else:
                    raise

        if not os.path.exists(dir_name):
            self.class_logger.debug("Create directory {}:".format(dir_name))
            os.makedirs(dir_name)

    def configure_server(self):
        """Create SSH connection to Collectd server host.

        """
        self.class_logger.debug("Connect to the Collectd server")
        ssh = clissh.CLISSH(self.server.config['ip_host'],
                            self.server.config['ip_port'],
                            self.server.config['username'],
                            self.server.config['password'])

        self.server.ssh = ssh
        self.server.ssh.login()
        self.server.ssh.open_shell()

    def start_on_nodes(self):
        """Start Collectd service on devices.

        """
        for dev in self.env.id_map.values():
            if dev.type in INCLUDES and dev.name in self.devices:
                try:
                    dev.ui.collectd.start()
                except UICmdException as err:
                    self.class_logger.debug("Error on Collectd restart"
                                            " on device {0}: {1}".format(dev.name, err))

    def exec_command(self, command):
        """Execute shell command on Collectd server host.

        Args:
            command(str):  command to execute

        Returns:
            str:  command execution output

        """
        cmd_status = self.server.ssh.exec_command(command)
        if cmd_status.stderr:
            self.class_logger.debug("Command {0} returns error: {1}".format(command,
                                                                            cmd_status.stderr))
        if int(cmd_status.rc) != 0:
            self.class_logger.debug("Return code is {0}, expected '0' "
                                    "on command '{1}'.".format(cmd_status.rc, command))

        return cmd_status.stdout

    def multicall(self, commands):
        """Execute a list of commands on Collectd server host.

        Args:
            commands(list[str]): list of commands to be executed

        Returns:
            list[str]:list of commands results

        """
        results = []
        # cmds are full strings, so we have to split in remote_multicall_template
        for cmd in multicall.generate_calls(commands):
            cmd_status = self.server.ssh.exec_command(cmd)
            # convert to CmdStatus objects
            if cmd_status.stdout:
                results.extend(
                    (result[0], CmdStatus(*result[1:]))
                    for result in json.loads(cmd_status.stdout))
        return [x[1].stdout for x in results]

    def copy_file(self, remote_file, local_file):
        """Copy file from Collect server host to TAF host.

        Args:
            remote_file(str): path to file on remote Collectd server host
            local_file(str):  path to file on local TAF host

        """
        self.class_logger.debug("Copy file {0} to the local file {1}".format(remote_file,
                                                                             local_file))
        self.server.ssh.get_file(remote_file, local_file)

    def configure(self):
        """ Configure monitoring tool.

        """
        if self.server:
            # Connect to Collectd server host
            self.configure_server()

    def list_rrd_folders(self):
        """List device's RRD folders on Collectd server host.

        """
        for dev_name in self.devices:
            collectd_folder = os.path.join(PATH_TO_RRD, dev_name)
            # List all RRD folder related to specific device
            folders = self.exec_command(
                'find {}/*' ' -maxdepth 1 -type d -print0'.format(collectd_folder)).split('\0')
            # Filter folder by supported graphs
            # Store results in dict {graph_type: list_of_folders}
            folder_dict = {
                _key: [x for x in folders if x.split(os.path.sep)[-1].startswith(_value)]
                for _key, _value in list(SUPPORTED_GRAPHS.items())
            }
            # Update device info
            self.devices[dev_name]['folders'] = folder_dict

    def item_teardown(self):
        """Create RRD graphs on test teardown.

        """
        self.class_logger.info("Generating graphs...")
        self.class_logger.debug("PROFILING: SutMonitor start time %d", time.time())
        # Store rrdtool commands in list
        commands = []
        # Store graphs names in list
        file_names = []
        # Create folder to store results (new folder for each test case)
        item_folder = os.path.join(RESULTS_DIR, self.test)
        self.create_dir(item_folder)
        # Clear list of generated graphs for previous test
        del self.test_files[:]
        # Get time of test's ending
        self.end_time = time.time()
        # Get RRD folders
        self.list_rrd_folders()
        # Loop over supported devices
        for name, values in self.devices.items():
            # Loop over graph type
            for gtype, folders in values['folders'].items():
                # Loop over folders
                for folder in folders:
                    # Get real path to RRD folder for specific device
                    # Note: device's name should be equal FQDN
                    rrd_folder = os.path.join(PATH_TO_RRD, name, folder)
                    # Exclude empty graphs
                    if self.is_not_empty(rrd_folder,
                                         int(self.start_time),
                                         int(self.end_time),
                                         gtype):
                        # Generate graph name as deviceName_RRDFolderName
                        file_name = "{0}_{1}.png".format(name, folder.split(os.path.sep)[-1])
                        file_names.append(file_name)
                        # Generate command for graph creation and append to commands list
                        # Store graph on Collectd server host in /tmp/ directory
                        commands.append(rrdtool_graph.get_graph_command(
                            rrd_folder,
                            int(self.start_time),
                            int(self.end_time),
                            gtype=gtype,
                            destination=os.path.join('/tmp', file_name)))
        # Create graphs on Collectd server host
        results = self.multicall(commands)
        # Copy generated file
        removes = []
        for res, _file in zip(results, file_names):
            if res:
                self.copy_file(os.path.join('/tmp', _file), os.path.join(item_folder, _file))
                self.test_files.append(os.path.join(item_folder, _file))
                removes.append('rm -f {}'.format(os.path.join('/tmp', _file)))
        # Remove the original file
        self.multicall(removes)
        # Reinit the next test's start time
        self.start_time = self.end_time
        self.class_logger.debug("PROFILING: SutMonitor end time {0}, "
                                "duration {1}".format(time.time(), time.time() - self.end_time))

    def is_not_empty(self, folder, start, end, gtype):
        """Check if RRD folder contains non-empty data.

        Args:
            folder(str): RRD folder to check for
            start(str): time period start value
            end(int): time period end value
            gtype(str): RRD folder CF

        Returns:
            bool: True if folder contains non-empty data

        """
        if gtype == 'LOAD':
            return True
        # Generate rrdtool fetch command to get data for specific perion
        fetch = rrdtool_graph.get_fetch_commands(folder, start, end, gtype)
        results = self.multicall(fetch)
        # rrdtool fetch output example
        # 1456330420: -nan -nan
        # 1456330430: 1.154e+9 0.0001e-9
        # where the first value is timestamp, all others are data values
        #
        # Convert all values to int
        # values = []
        # for res in results:
        #    for val in res.splitlines():
        #        values.extend(list(map(self.convert, val.split()[1:])))

        def convert(value):
            try:
                return int(float(value))
            except ValueError:
                return 0
        values = [convert(x)
                  for res in results for val in res.splitlines() for x in val.split()[1:]]
        # Check for non-zero values
        if any(values):
            return True
        return False

    def teardown(self):
        """Close SSH connection to the Collectd server host.

        """
        if self.server and self.server.ssh:
            self.server.ssh.close()


class SutMonitorPlugin(object):
    """SutMonitorPlugin implementation.

    """

    def __init__(self):
        super().__init__()
        self.sut_monitor = None

    @pytest.fixture(autouse=True, scope='session')
    def monitor_init(self, env_init):
        """Initialize SutMonitor on session start.

        Args:
            env_init(testlib.common3.Environment): 'env_init' pytest fixture from pytest_onsenv.py

        """
        self.sut_monitor = SutMonitor(env_init)
        return self.sut_monitor

    @pytest.fixture(scope=setup_scope(), autouse=True)
    def monitor(self, request, env_main, monitor_init):  # pylint: disable=W0613
        """Start Collectd service on devices.

        """
        request.addfinalizer(monitor_init.teardown)
        monitor_init.configure()
        monitor_init.start_on_nodes()
        return monitor_init

    @pytest.fixture(autouse=True)
    def test_monitor(self, request, env, monitor):  # pylint: disable=W0613
        """Gather collectd info for certain test case.

        Args:
            request(pytest.request): pytest request object
            env(testlib.common3.Environment): env fixture
            monitor_start(SutMonitor): monitor_start fixture

        """
        monitor.test = request.node.name
        request.addfinalizer(monitor.item_teardown)

    @pytest.hookimpl(tryfirst=True, hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):   # pylint: disable=W0613
        """Add generated graphs to the pytest report in order to access from reporting plugin.

        """
        outcome = yield
        report = outcome.get_result()

        if call.when == 'teardown' and self.sut_monitor.test_files:
            report.monitor = self.sut_monitor.test_files
