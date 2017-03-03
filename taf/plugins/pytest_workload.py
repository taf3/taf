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

"""``pytest_workload.py``

`Add workload on SUTs using stress tool`

"""

from collections import namedtuple
import time
from multiprocessing import Pool as ThreadPool
from multiprocessing import Event, Manager

import pytest

from . import loggers
from .pytest_onsenv import setup_scope
from testlib.custom_exceptions import TAFCoreException, UICmdException, ToolException


ARGS = namedtuple('ARGS', ('class_name', 'config', 'opts', 'shared', 'workers'))
STOP_REQUEST = Event()
WORKLOAD_TIME = 60
WORKERS = ['cpu', 'vm', 'vm_bytes', 'io', 'disk', 'time']


def device_workload(args):
    """Start workload on device.

    """
    # Create duplicate instance of device in order to use new ssh connection
    dev = args.class_name(args.config, args.opts)
    dev.ui.connect()

    try:
        while not STOP_REQUEST.is_set():
            try:
                dev.ui.start_workload(**args.workers)
                time.sleep(int(args.workers['time']))
                results = dev.ui.get_workload_results(mode='delete')
                # try/except statement is defined to handle case
                # when stress tool is stopped according to own timeout
                try:
                    dev.ui.stop_workload()
                except UICmdException:
                    pass
                if any(x.loglevel == 'FAIL' for x in results):
                    args.shared.append('Failed')
                else:
                    args.shared.append('Success')
            except (UICmdException, ToolException):
                args.shared.append('Failed')

    except Exception as err:
        print(err)
        dev.ui.disconnect()


def pytest_addoption(parser):
    """Describe plugin specified options.

    """
    group = parser.getgroup("Workload", "plugin: stress workload")
    group.addoption("--workload", action="store_true", default=False,
                    help="Add workload on SUT using stress tool")
    group.addoption("--workload_type", action="store", default="continuous",
                     choices=["continuous", "interrupted"],
                     help="Workload type.")
    group.addoption("--workload_workers", action="store", default=None,
                     help="Number of workload workers in format "
                     "[cpu_workers, vm_workers, vm_bytes, io_workers, hdd_workers, time].")


def pytest_configure(config):
    """Registering plugin.

    """
    if config.option.workload:
        config.pluginmanager.register(WorkloadPlugin(config.option.workload_type,
                                                     config.option.workload_workers), "_workload")


def pytest_unconfigure(config):
    """Unregistering plugin.

    """
    workload = getattr(config, "_workload", None)
    if workload:
        del config._workload
        config.pluginmanager.unregister(workload)


def get_workers(line):
    if line:
        s_workers = line[1:-1].split(',')
        workers = dict(list(zip(WORKERS, s_workers)))
        return workers
    return {}


class WorkloadContinuous(object):
    """Main functionality for workload manipulation.

    """
    class_logger = loggers.ClassLogger()

    def __init__(self, env, workers):
        """Initialize WorkloadContinuous object instance.

        Args:
            env(testlib.common3.Environment): TAF environment instance

        """
        self.env = env

        # Filter environment device for workload
        # get device with hw.stress_tool_attributes
        self.devices = [dev for dev in self.env.id_map.values()
                        if hasattr(dev, 'hw') and hasattr(dev.hw, 'stress_tool_attributes')]
        self.workers = get_workers(workers)
        if self.workers:
            self.workers['time'] = None

    def start_on_nodes(self):
        """Start workload on devices.

        """
        for dev in self.devices:
            try:
                dev.ui.start_workload(**self.workers)
            except (UICmdException, ToolException) as err:
                self.class_logger.debug("Error on workload start"
                                        " on device {0}: {1}".format(dev.name, err))
                raise

    def item_setup(self):
        """Start the workload if no active.

        """
        for dev in self.devices:
            if not dev.ui.get_active_workloads():
                dev.ui.start_workload()

    def item_teardown(self):
        """Stop the workload and get the results.

        """
        for dev in self.devices:
            try:
                results = dev.ui.get_workload_results()
                if dev.type == "dcrp_domain":
                    if any(x.loglevel == 'FAIL' for res in results.values() for x in res):
                        raise TAFCoreException("Workload was failed on device {}".format(dev.name))
                else:
                    if any(x.loglevel == 'FAIL' for x in results):
                        raise TAFCoreException("Workload was failed on device {}".format(dev.name))
            except (UICmdException, ToolException) as err:
                self.class_logger.debug("Error on workload item teardown"
                                        " on device {0}: {1}".format(dev.name, err))
                raise

    def teardown(self):
        """Stop the workload.

        """
        for dev in self.devices:
            try:
                dev.ui.stop_workload()
            except (UICmdException, ToolException) as err:
                self.class_logger.debug("Error on workload teardown"
                                        " on device {0}: {1}".format(dev.name, err))
                raise


class WorkloadInterrupted(object):
    """Main functionality for workload manipulation.

    """
    class_logger = loggers.ClassLogger()

    def __init__(self, env, workers):
        """Initialize WorkloadInterrupted object instance.

        Args:
            env(testlib.common3.Environment): TAF environment instance

        """
        self.env = env

        # Filter environment device for workload
        # get device with hw.stress_tool_attributes
        self.devices = [dev for dev in self.env.id_map.values()
                        if hasattr(dev, 'hw') and hasattr(dev.hw, 'stress_tool_attributes')]
        manager = Manager()
        self.workload_results = {}
        for dev in self.devices:
            self.workload_results[dev.id] = manager.list([])  # pylint: disable=no-member
        self.pool = ThreadPool(len(self.devices))
        self.workers = get_workers(workers)
        if not self.workers:
            self.workers = {'time': WORKLOAD_TIME}
        else:
            if not int(self.workers.get('time', 0)):
                self.workers['time'] = WORKLOAD_TIME

    def start_on_nodes(self):
        """Start workload on devices.

        """
        try:
            self.pool.map_async(device_workload,
                            [ARGS(type(dev),
                                  dev.config,
                                  dev.opts,
                                  self.workload_results[dev.id],
                                  self.workers)
                             for dev in self.devices])
        except Exception as err:
            self.class_logger.debug("Workload error: {0}".format(err))
            raise

    def item_setup(self):
        """Start the workload if no active.

        """
        pass

    def item_teardown(self):
        """Stop the workload and get the results.

        """
        failed_results = []
        for dev in self.devices:
            dev_results = self.workload_results[dev.id]
            if any(x == 'Failed' for x in dev_results):
                failed_results.append(dev.id)
            del self.workload_results[dev.id][:]
        if failed_results:
            raise TAFCoreException("Workload was failed"
                                   " on devices {}".format(" ".join(failed_results)))

    def teardown(self):
        """Stop the workload.

        """
        self.class_logger.debug("Workload teardown")
        STOP_REQUEST.set()
        self.pool.close()
        try:
            self.pool.join()
        except AttributeError:
            # Using pytest-cov plugin pool.join raises an error
            pass


WORKLOADS = {
    'continuous': WorkloadContinuous,
    'interrupted': WorkloadInterrupted
}


class WorkloadPlugin(object):
    """WorkloadPlugin implementation.

    """
    def __init__(self, workload_type, workers):
        self.workload_type = workload_type
        self.workers = workers

    @pytest.fixture(autouse=True, scope='session')
    def workload_init(self, env_init):
        """Initialize WorkloadPlugin on session start.

        Args:
            env_init(testlib.common3.Environment): 'env_init' pytest fixture from pytest_onsenv.py

        """
        self._workload = WORKLOADS[self.workload_type](env_init, self.workers)
        return self._workload

    @pytest.fixture(scope=setup_scope(), autouse=True)
    def workload(self, request, env_main, workload_init):
        """Start stress tool on devices.

        """
        request.addfinalizer(workload_init.teardown)
        workload_init.start_on_nodes()
        return workload_init

    @pytest.fixture(autouse=True)
    def test_workload(self, request, env, workload):
        """Gather collectd info for certain test case.

        Args:
            request(pytest.request):  pytest request object
            env(testlib.common3.Environment):  env fixture
            monitor_start(SutMonitor):  monitor_start fixture

        """
        request.addfinalizer(workload.item_teardown)
        workload.item_setup()
