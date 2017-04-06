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

"""``fixtures.py``

`Useful fixture functions/patterns for TAF`

"""
import functools
import os
import copy
import operator
from collections import namedtuple

import pytest

from .helpers import grouper
from . import loggers
from .dev_linux_host import GenericLinuxHost


def sshlog(request, env_name=None, env_obj=None, instance_class=GenericLinuxHost):
    """Register additional file handler for linux_host ssh loggers per test case.

    Args:
        request(pytest.request):  fixture request object.
        env_name(str):  Name of Environment class instance [optional].
        env_obj(Environment):  Environment instance [optional].
        instance_class(object):  SSH logger has to be crated only for environment attributes which are instances of this class [optional].

    Examples:

    Define your fixture based on this function::

        # My Environment fixture
        @pytest.fixture
        def my_env(request):
            env = Environment(...)
            request.addfinalizer(env.shutdown)
            env.initialize()
            return env

        @pytest.fixture(autouse=True)
        def ssh_logger(request):
            fixtures.sshlog(request, "my_env")

        def test_something(my_env):
            my_env.lhost[1].ssh.exec_command("command_to_be_executed")

    After that you have to see additional files in defined with \--logdir option folder.\n

    Also you can use it like function to modify existing env fixture::

        @pytest.fixture(autouse=True)
        def env_new(request, env):
            fixtures.sshlog(request, env_obj=env)
            return env

    """
    # Skip fixture if logdir isn't set.
    if not loggers.LOG_DIR:
        return

    def add_handler(log_adapter, log_file):
        """Register new file handler.

        """
        log_file_handler = loggers.logging.FileHandler(log_file)
        # Set the same formatter
        if log_adapter.logger.handlers and log_adapter.logger.handlers[0].formatter:
            log_file_handler.setFormatter(log_adapter.logger.handlers[0].formatter)
        log_adapter.logger.addHandler(log_file_handler)
        return log_file_handler

    def remove_handlers(env, log_handlers):
        """Remove all created and saved in log_handlers list additional file handlers.

        """
        for obj in list(env.id_map.values()):
            if obj.id in log_handlers:
                log_handlers[obj.id].flush()
                log_handlers[obj.id].close()
                obj.ssh.class_logger.logger.removeHandler(log_handlers[obj.id])
                log_handlers.pop(obj.id)

    # log_file_handlers to remove
    log_handlers = {}

    # Check if env is used in TC and file logging is enabled
    if env_obj is None and (env_name not in request.fixturenames or loggers.LOG_DIR is None):
        return
    if env_obj is None and env_name:
        env_obj = request.getfuncargvalue(env_name)

    request.addfinalizer(lambda: remove_handlers(env_obj, log_handlers))
    file_prefix = os.path.join(loggers.LOG_DIR, "{0}_{1}_".format(request.function.__name__, os.getpid()))

    # Search for LinuxHost objects
    for obj in list(env_obj.id_map.values()):
        if isinstance(obj, instance_class):
            log_file = "{0}_id_{1}_type_{2}.log".format(file_prefix, obj.id, obj.type)
            log_handlers[obj.id] = add_handler(obj.ssh.class_logger, log_file)


def autolog(request, logger_name="suite_logger"):
    """Inject logger object to test class.

    Args:
        request(pytest.request):  py.test request object.
        logger_name(str):  name of logger class attribute to create

    Notes:
        This fixture has to have scope level "class".
        You do not need to pass this fixture to test function in case you set autouse.

    Examples::

        @pytest.fixture(scope="class", autouse=True)
        def autolog(request):
            return fixtures.autolog(request, "wishful_logger_instance_name")

    """
    def remove_logger(cls):
        """Explicit close log handlers.

        """
        while getattr(cls, logger_name).logger.handlers:
            getattr(cls, logger_name).logger.handlers[0].flush()
            getattr(cls, logger_name).logger.handlers[0].close()
            getattr(cls, logger_name).logger.removeHandler(getattr(cls, logger_name).logger.handlers[0])
        delattr(cls, logger_name)

    taf_logger = loggers.module_logger(request.cls.__module__, request.cls.__name__)
    request.addfinalizer(lambda: remove_logger(request.cls))
    setattr(request.cls, logger_name, taf_logger)
    getattr(request.cls, logger_name).debug("Starting %s test suite." % (request.cls.__name__, ))
    del taf_logger


Device_Tuple = namedtuple('Device_Tuple', ['device_ids', 'lag_id'])

Ports_Tuple = namedtuple('Port_Tuple', ['ports', 'ports_list'])


class LagIdGenerator(object):

    INITIAL_LAG = 3800

    def __init__(self):
        super(LagIdGenerator, self).__init__()
        self.free_lags = {}

    @classmethod
    def id_to_key(cls, lag_id):
        """Get LAG key by LAG ID.

        Args:
            lag_id(int):  LAG ID

        Returns:
            int:  LAG key

        """
        return lag_id - cls.INITIAL_LAG

    def _default_set(self, max_lags):
        # create set since we will be intersecting
        # since we allocate after intersecting, initial order doesn't matter
        # we have to sort anyway
        return set(range(self.INITIAL_LAG, self.INITIAL_LAG + max_lags - 1))

    def generate_lag(self, *args):
        """Get lag ID for specific device.

        Args:
            args(list[SwitchGeneral]): list of devices to generate lag ids for

        Raises:
            StopIteration:  if cross part contains more than 2 devices

        Returns:
            int|None:  LAG ID

        """
        non_empty = [_f for _f in args if _f]
        if not non_empty:
            # in case device is not in cross connection
            return None
        lag_sets = [self.free_lags.setdefault(dev.id, self._default_set(dev.hw.max_lags)) for
                    dev in non_empty]
        # intersect all the sets using reduce
        # operator.and_ is & is intersection
        intersection = functools.reduce(operator.and_, lag_sets)
        # intersection of sets shouldn't have an ordering so we always have to sort
        # next will raise StopIteration if it can't allocate
        lag = next(iter(sorted(intersection)))
        for lag_set in lag_sets:
            # use discard so we don't raise an error in case we were passed
            # in the same device twice
            lag_set.discard(lag)
        return lag


class LagPortEnv(object):
    """Class for fixture that replaces ports with LAGs.

    """

    def __init__(self, request, env):
        super(LagPortEnv, self).__init__()
        self.cross_part_copy = copy.deepcopy(env.setup['cross'])
        self.ports_dict = {}
        self.request = request
        self.env = env
        self.lag_generator = LagIdGenerator()
        self.lags_to_create = {}
        self.cleanups = {}
        self.creates = {}

    def get_cross_part_lag(self, cross_part):
        """Get LAG ID for cross connection.

        Args:
            cross_part(list):  connection from setup file, e.g. ["03", 1, "1", 1]

        Raises:
            StopIteration:  if port is already in LAG

        Returns:
            tuple(dict{device_id: link_id}, LAG_ID):  dictionary of device_id: port_id and LAG ID

        """
        device_dict = {}  # store device.id: link_id pairs
        get_lag_args = []  # store  device objects
        # iterator over _id, _port_id pairs in cross_part
        for _id, _port_id in grouper(cross_part, 2):
            device = self.env.id_map[self.env.get_device_id(_id)]
            max_lags = getattr(getattr(device, 'hw', None), "max_lags", 0)
            # check if device supports LAG
            if max_lags:
                device_dict.update({device.id: _port_id})
                dev = device
                get_lag_args.append(dev)

        for dev_id, port_id in device_dict.items():
            device = self.env.id_map[self.env.get_device_id(dev_id)]
            real_port_id = self.env.get_real_port_name(dev_id, port_id)
            # check if port is not a LAG member
            ports_lags_table = device.ui.get_table_ports2lag()
            if any(r for r in ports_lags_table if r['portId'] == real_port_id):
                raise StopIteration("Port is already in LAG")

        lag = self.lag_generator.generate_lag(*get_lag_args)

        return Device_Tuple(device_dict, lag)

    def setup(self):
        for cross in self.env.setup['cross'].values():
            for cross_part in cross:
                for _id, _port_id in grouper(cross_part, 2):
                    device = self.env.id_map[self.env.get_device_id(_id)]
                    max_lags = getattr(getattr(device, 'hw', None), "max_lags", 0)
                    # check if device supports LAG
                    if max_lags:
                        # Wrap original clearconfig in order to recreate LAGs
                        if device.id not in self.cleanups:
                            self.cleanups[device.id] = device.clearconfig
                            device.clearconfig = self.add_lags(device, device.clearconfig)
                            self.creates[device.id] = device.start
                            device.start = self.add_lags(device, device.start)

    def setup_lags(self):
        """Define LAGs that will be created.

        Notes:
            This method changes initial device's attributes (ports and port_list).
            Initial configuration should be restored after test execution

        """
        for cross in self.env.setup["cross"].values():
            for cross_part in cross:
                # get LAG ID for specific cross connection
                try:
                    lag_env = self.get_cross_part_lag(cross_part)
                except StopIteration:
                    # Restore initial configuration in case of error
                    self.teardown()
                    # Skip test execution
                    pytest.skip("Test case could not be executed on LAGs: Port is already in LAG")
                if lag_env.lag_id:
                    for dev_id, port_id in lag_env.device_ids.items():
                        device = self.env.id_map[dev_id]
                        real_port_id = self.env.get_real_port_name(dev_id, port_id)
                        # backup ports and ports_list
                        self.ports_dict.setdefault(device.id,
                                                   Ports_Tuple(copy.deepcopy(device.ports),
                                                               copy.deepcopy(device.port_list)))
                        # Add LAGs to be created on device
                        self.lags_to_create.setdefault(device.id, []).append((lag_env.lag_id,
                                                                              real_port_id))
                        # Add changes in setup
                        # Add LAG ID in ports or port_list
                        # Change link ID in cross connection
                        if getattr(device, "port_list", None):
                            speed = self.env.get_port_speed(dev_id, port_id)
                            device.port_list.append([lag_env.lag_id, speed])
                            device.ports.append(lag_env.lag_id)
                            cross_part[cross_part.index(dev_id) + 1] = len(device.port_list)
                        elif getattr(device, "ports", None):
                            device.ports.append(lag_env.lag_id)
                            cross_part[cross_part.index(dev_id) + 1] = len(device.ports)

    def teardown(self):
        """Restore initial configuration.

        """
        # Restore setup JSON file
        for cross_id in self.env.setup["cross"]:
            del self.env.setup['cross'][cross_id][:]
            self.env.setup['cross'][cross_id].extend(self.cross_part_copy[cross_id])
        # Restore device's attributes ports and ports_list
        for dev_id in self.ports_dict:
            device = self.env.id_map[dev_id]
            device.ports = self.ports_dict[dev_id].ports
            device.port_list = self.ports_dict[dev_id].ports_list
        # Restore original clearconfig
        for dev_id in self.cleanups:
            device = self.env.id_map[dev_id]
            device.clearconfig = self.cleanups[dev_id]
            device.start = self.creates[dev_id]

    def add_lags(self, device, func):
        """Wrap original device's method e.g. clearconfig or restart.

        """
        def wrapper(*args, **kwargs):
            func(*args, **kwargs)
            if not self.lags_to_create:
                self.setup_lags()
            for lag_id, port_id in self.lags_to_create[device.id]:
                device.ui.create_lag(lag=lag_id,
                                     key=self.lag_generator.id_to_key(lag_id),
                                     lag_type="Static", hash_mode="None")
                device.ui.create_lag_ports(ports=[port_id, ],
                                           lag=lag_id,
                                           key=self.lag_generator.id_to_key(lag_id))
        return wrapper


def env_lag(request, env):
    """Replace physical ports in setup file with LAGs.

    Args:
        request(pytest.Request):  pytest request fixture
        env(Environment):  env fixture

    Notes:
        For correct functioning new fixture for test cases should be created.

    Examples::

        # Code in conftest file or test module
        from testlib.fixtures import env_lag

        @pytest.fixture(scope='module', autouse=True)
        def env_replace_lag(request, env_init):
            env_lag(request, env_init)

    """
    lag_env = LagPortEnv(request, env)
    request.addfinalizer(lag_env.teardown)
    lag_env.setup()


def lhost_to_switch(request, env_init):
    """Add Linux Hosts as Switch devices into environment.

    Notes:
        For correct functioning new fixture for test cases should be created.

    Examples::

        # Code in conftest file or test module
        from testlib.fixtures import lhost_to_switch

        @pytest.fixture(scope='module', autouse=True)
        def env_switch_lhost(request, env_init):
            lhost_to_switch(request, env_init)

    """
    # Get initial version of Environment object
    added_switches = []
    init_dut_map = copy.deepcopy(env_init.dut_map)

    def setup():
        # Add lhost instances into env.switch dictionary
        for _lhost in getattr(env_init, 'lhost', {}).values():
            switches = getattr(env_init, 'switch', {})
            eid = len(switches) + 1
            env_init.dut_map["sw{}".format(eid)] = _lhost.id
            if not hasattr(env_init, 'switch'):
                setattr(env_init, 'switch', {})
            env_init.switch[eid] = _lhost
            added_switches.append(eid)

    def teardown():
        # Rollback all changes
        env_init.dut_map = init_dut_map
        for _key in added_switches:
            env_init.switch.pop(_key)

    request.addfinalizer(teardown)
    setup()


def chef_prep(request, env_main, cll):
    """Do steps required by configuration management system tests.

    Notes:
        For correct functioning new fixture for test cases should be created.

    Examples::

        # Code in conftest file or test module
        from testlib.fixtures import chef_prep

        @pytest.fixture(scope='class', autouse=True)
        def suite_prep(request, env_main):
            chef_prep(request, env_main)

    """
    def _remove_chef_client():
        """Uninstall chef client and do cleanup of chef dir.

        """
        assert env_main.switch[1].ui.cli_send_command('yum erase -y chef*')[-1] == 0
        assert env_main.switch[1].ui.cli_send_command('rm -rf /etc/chef/')[-1] == 0
        env_main.chef[1].delete_node(cll.fqdn_hostname)

    def _remove_local_role_files():
        for x in os.listdir(cll.configs_path):
            os.remove(os.path.join(cll.configs_path, x))
        os.rmdir(cll.configs_path)

    def _teardown():
        # _remove_chef_client()
        env_main.chef[1].remove_role()
        _remove_local_role_files()

    cll.fqdn_hostname = env_main.switch[1].ui.cli_send_command('hostname -f')[0].strip()
    cll.configs_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'chef_roles')
    if not os.path.exists(cll.configs_path):
        os.makedirs(cll.configs_path)
    # Perform teardown sequence
    request.addfinalizer(_teardown)
