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

"""``common3.py``

`Testlib common functionality version 3.x`

"""

# Python built-in imports
import sys
import json
import os
import itertools
import traceback
from threading import Thread

import pytest

# Testlib imports
from .custom_exceptions import TAFCoreException
from . import entry_template
from . import environment
from . import loggers


VERSION = "3.0"

# Accessible from other modules list of loaded classes from dev_ files.
custom_classes = {}


# Add soft exit with environment sanitizing before exit.
def softexit(message, env=None):
    """Sanitizing environment and exit py.test execution.

    Args:
        message(str):  Exit message
        env(Environment):  Environment instance

    """
    if env is not None:
        env.sanitize()
    pytest.exit(message)


pytest.softexit = softexit


# Environment is inherited from dict to provide backward compatibility with TAFv1 suites
class Environment(dict):
    """Main class of all test environment.

    Notes:
        This class has to be used as base fixture in all test cases.
        It provides number of common methods to initialize, shutdown,
        cleanup environment functions which basically call appropriate methods of particular device classes.

    """

    class_logger = loggers.ClassLogger()

    def __init__(self, opts=None, **kwargs):
        """Read configuration files and create device objects.

        Args:
            opts(OptionParser):  py.test config.option object which contains all py.test cli options.

        Raises:
            TAFCoreException:  unexpected entry_type

        """
        super(Environment, self).__init__(**kwargs)
        self.opts = opts
        self._dict = {}
        self.config = self._get_conf(self.opts.env)
        self.setup = {}
        if self.opts.setup:
            self.setup = self._get_setup(self.opts.setup)
        # Map acroname to conf id
        self.dut_map = {}
        # Map config Id to instance index
        self.id_map = {}
        # Environment properties
        self.env_prop = {}
        # Device classes
        self.__dev = {}
        # Map autoname to conf Id
        self.autoname_map = {}
        # Get device classes
        device_module_names = self._find_dev_modules()
        self._import_device_modules(device_module_names)
        # Make loaded classes from dev_ file accessible for other modules
        for key, value in self.__dev.items():
            custom_classes[key] = value

        # Create env config according to setup
        new_config = [self.create_conf_entry(setup_entry) for setup_entry in self.setup['env']]
        # create a set from related ids lists
        related_ids = set(itertools.chain.from_iterable(
            conf_entry.get('related_id', []) for conf_entry in new_config))

        # Add related config entries from environment config if they are not already in new_config
        new_config_ids = set(_x['id'] for _x in new_config)
        # find the unadded related_ids.
        new_related_ids = related_ids - new_config_ids
        related_configs = [
            next(_e for _e in self.config if _e['id'] == rid) for rid in new_related_ids]
        new_config.extend(related_configs)

        # Save updated config
        self.config = new_config

        self.class_logger.info("Preparing environment objects.")
        # reading and appending config and creating instances
        for entry in self.config:
            self.class_logger.info(
                "Creating {0}:{1}:{2}".format(entry['entry_type'], entry['instance_type'],
                                              entry['id']))

            # Append related configs
            if "related_id" in entry:
                entry['related_conf'] = self._append_related_confs(entry['related_id'])

            # Creating setup entries instances
            try:
                ename = self.__dev[entry['entry_type']]['NAME']
            except KeyError:
                message = ("Unexpected value for entry_type: '%s' specified with id: '%s' " +
                           "added in config.") % (entry['entry_type'], entry['id'])
                raise TAFCoreException(message)

            # always create a switch objects so that
            # all the switch related plugins that expect a switch attribute
            # fail gracefully
            if not hasattr(self, "switch"):
                setattr(self, "switch", {})
            if not hasattr(self, ename):
                setattr(self, ename, {})
            eid = len(getattr(self, ename)) + 1
            # Append ID maps
            self.dut_map["%s%s" % (self.__dev[entry['entry_type']]['LINK_NAME'], eid)] = entry['id']
            # Create entry instance
            getattr(self, ename)[eid] = self.__dev[entry['entry_type']][entry['instance_type']](
                entry, self.opts)
            getattr(self, ename)[eid].env = self
            self.id_map[entry['id']] = getattr(self, ename)[eid]
            # In case entry contains autoname Environment object will contain d_<autoname>
            # attribute.
            if entry.get('autoname', False):
                # Append autoname and Id
                setattr(self, "d_{0}".format(entry['autoname']), getattr(self, ename)[eid])
                self.autoname_map[entry['autoname']] = entry['id']

        # Pass required by entries related objects:
        for entry in self.config:
            if "related_id" in entry:
                self.id_map[entry['id']].related_obj = dict(
                    [(_id, self.id_map[_id]) for _id in entry['related_id']])

        # To support heterogeneous setup we need to support multiple Cross connection types,
        # but allow user to be independent from this.
        # Cross object automatically detects connection owner and forward it to proper cross instance.
        self.cross = Cross(self.setup, self)
        # Append connections lists for cross entries.
        if "cross" in self.setup:
            for c_id in self.setup['cross']:
                self.id_map[c_id].connections = self.setup['cross'][c_id]
        # TODO: Add transparent support of multiple TG instances in one.

    def _import_device_modules(self, device_module_names):
        for mod_name in device_module_names:
            self.class_logger.debug("Loading %s module...", mod_name)
            try:
                new_module = __import__("testlib." + mod_name, fromlist=[mod_name])
            except ImportError:
                self.class_logger.warning("failed to import %s", mod_name, exc_info=True)
                # ignore modules that can't load, e.g. dependency problems such as tempest
                # instead failed when we try to instantiate the class
                continue
            # insert into global namespace
            globals()[mod_name] = new_module
            if new_module.ENTRY_TYPE and new_module.ENTRY_TYPE not in self.__dev:
                self.__dev[new_module.ENTRY_TYPE] = {
                    "NAME": new_module.NAME,
                    "LINK_NAME": getattr(new_module, 'LINK_NAME', new_module.NAME)
                }
            for instance_name, entry_class in new_module.INSTANCES.items():
                if issubclass(entry_class, entry_template.GenericEntry):
                    self.class_logger.debug(
                        "Found entry_type {0}, instance_type {1}.".format(new_module.ENTRY_TYPE,
                                                                          instance_name))
                    self.__dev[new_module.ENTRY_TYPE][instance_name] = entry_class

    def create_conf_entry(self, setup_entry):
        # Search for id in environment config
        # Add environment entry in setup if it's found, or leave setup entry as is.
        conf_entry = next(
            (cfg_e for cfg_e in self.config if cfg_e['id'] == setup_entry['id']),
            setup_entry)
        # Updating env keys according to setup
        conf_entry.update(setup_entry)
        return conf_entry

    def _find_dev_modules(self):
        # extract this so we can override in unittests
        devices = []
        testlib_path = os.path.dirname(__file__)
        for root, dirname, filenames in os.walk(testlib_path):
            for m in filenames:
                if m.startswith("dev_") and m.endswith(".py"):
                    rel_path = os.path.relpath(os.path.join(root, m), testlib_path)
                    # create module name relative to testlib
                    # foo/dev_bar.py -> foo.dev_bar
                    devices.append(os.path.splitext(rel_path)[0].replace(os.sep, '.'))
        return devices

    def _get_conf(self, file_name=None):
        """Load environment config from file.

        Args:
            file_name(str):  Name of a json file with a test environment configuration.

        Raises:
            TAFCoreException:  configuration file is not found
            IOError:  error on reading configuration file

        Returns:
            dict:  dict of the selected configuration.

        Notes:
            This method shouldn't be used outside this class. Use "config" attribute to access environment configuration.

        """
        if not file_name:
            self.class_logger.info("Environment file isn't set. All configurations will be taken from setup file.")
            # Return empty dict
            return dict()
        path_to_config = environment.get_conf_file(conf_name=file_name, conf_type="env")
        if not path_to_config:
            message = "Specified configuration file %s not found." % (file_name, )
            raise TAFCoreException(message)
        try:
            config = json.loads(open(path_to_config).read(), encoding="latin-1")
        except:
            message = "Cannot read specified configuration: %s" % (path_to_config, )
            self.class_logger.error(message)
            raise IOError(message)
        return config

    def _get_setup(self, file_name):
        """Reads setup file based on provided name.

        Args:
            file_name(str):  Name of a json file with setup.

        Raises:
            TAFCoreException:  setup file is not found
            IOError:  error on reading setup file

        Returns:
            list[dict]:  setup json content.

        """
        if not file_name:
            message = "Setup name must be specified."
            raise TAFCoreException(message)
        path_to_config = environment.get_conf_file(conf_name=file_name, conf_type="setup")
        if not path_to_config:
            message = "Cannot find given setup %s" % (file_name, )
            raise TAFCoreException(message)
        try:
            setup = json.loads(open(path_to_config).read(), encoding='ascii')
        except:
            message = "Cannot read specified setup configuration: %s" % (path_to_config, )
            self.class_logger.error(message)
            raise IOError(message)
        return setup

    def _get_device_conf(self, device_id):
        """Return config entry by given Id if one, else return None.

        Args:
            device_id(str):  Entry ID.

        Returns:
            dict:  Entry config.

        """
        return next((entry for entry in self.config if entry['id'] == device_id), None)

    def id2instance(self, device_id):
        """Returns entry instance by device id.

        Args:
            device_id(str):  Could be one of: device LINK_NAME, 'autoname' or 'id' from config.

        Returns:
            GenericEntry: Entry instance

        Examples::

            # by LINK_NAME
            env.id2instance("sw1")
            # by "autoname"
            env.get_device_id("DEV2")
            # by ID
            env.get_device_id("9")

        """
        dev_id = self.get_device_id(device_id)
        entry = [e for e in self.config if e['id'] == dev_id][0]
        instance = None
        for _i in list(getattr(self, self.__dev[entry['entry_type']]['NAME']).values()):
            if _i.id == dev_id:
                instance = _i
                break
        return instance

    def _append_related_confs(self, conf_ids):
        """Create dictionary with related device configurations.

        Args:
            conf_ids(list[str]):  List of related config IDs.

        Raises:
            Exception:  configuration is not found for specific device ID

        Returns:
            dict:  Dictionary with related device configurations

        """
        related_confs = {}
        for device_id in conf_ids:
            conf = self._get_device_conf(device_id)
            if conf:
                related_confs[device_id] = conf
            else:
                raise Exception("Configuration for device with id: %s not found." % device_id)
        return related_confs

    def safe_executor(self, obj, method, *args, **kwargs):
        """Invokes obj.method(*args, **kwargs) in try block and return error message with traceback.

        Args:
            obj(GenericEntry):  Entry instance
            method(str):  method name that has to be executed

        Returns:
            str:  Error message with traceback

        Warning:
            - Don't use in case obj.method has to return something.
            - Don't use in case an exception has to be handled by py.test.

        """
        try:
            self.class_logger.debug("Perform %s(*%s, **%s) on entry_type=%s, id=%s" %
                                    (method, args, kwargs, obj.type, obj.id))
            getattr(obj, method)(*args, **kwargs)
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback_message = traceback.format_exception(exc_type, exc_value, exc_traceback)
            message = ("Error while call %s of entry_type=%s id=%s:\n%s" %
                       (method, obj.type, obj.id, "".join(traceback_message)))
            self.class_logger.error(message)
            return message

    def parallelize(self, objects, method, safe=False):
        """Run objects method in multiple threads.

        Args:
            objects(list[GenericEntry]):  list of device objects.
            method(str):  method name that has to be executed.
            safe(bool):  Hide exception raisings, but print log message.

        Returns:
            None

        Examples::

            objects = [env.lhost[1], env.lhost[2]]
            env.parallelize(objects, "cleanup", False)

        """
        threads = []

        def executor(o, m):
            return getattr(o, m)()
        for obj in objects:
            func = self.safe_executor if safe else executor
            thread = Thread(target=func, args=(obj, method))
            threads.append(thread)
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    def ordered_action(self, action, prio, entry_types):
        """Perform action on entries with type in entry_types and ordered by prio.

        Args:
            action(str):  method name to execute.
            prio(str):  priority name to sort objects by.
            entry_types(list[str]):  entry types to apply action (apply action to all entry types if None).

        Returns:
            None

        """
        # Select all types in case list isn't set.
        if not entry_types:
            entry_types = list(self.__dev.keys())

        # Sort by start priorities
        prio_dict = self._get_prio_dict(prio)
        s_list = sorted(prio_dict.keys())

        # Leave only selected entry types in prio_dict
        for prio in prio_dict:
            for item in prio_dict[prio][:]:
                if self._get_device_conf(item.id)['entry_type'] not in entry_types:
                    prio_dict[prio].remove(item)

        for _s in s_list:
            if len(prio_dict[_s]) > 1 and self.opts.use_parallel_init:
                self.parallelize(prio_dict[_s], action)
            else:
                for obj in prio_dict[_s]:
                    self.class_logger.debug("Perform %s() on entry_type=%s, id=%s" %
                                            (action, obj.type, obj.id))
                    getattr(obj, action)()

    def _get_prio_dict(self, prio):
        """Return dict of entries by prio.

        Args:
            prio(str):  Priority name to order dict by .

        Returns:
            dict:  dict of lists where key = priority, value = list of device objects.

        """
        prio_dict = {}
        for _e in self.config:
            # Set default prio value (0) in case it's not set.
            _prio = _e[prio] if prio in _e else 0
            # Create/append list od device objects with the same priority.
            if _prio not in prio_dict:
                prio_dict[_prio] = []
            prio_dict[_prio].append(self.id_map[_e['id']])
        return prio_dict

    def initialize(self, entry_types=None):
        """Initialize test environment.

        Args:
            entry_types(list[str]):  List of entry types

        """
        self.class_logger.info("Initialize environment...")
        self.ordered_action("create", "sprio", entry_types)

    def cleanup(self, entry_types=None):
        """Cleaning environment.

        Args:
            entry_types(list[str]):  List of entry types

        """
        self.class_logger.info("Cleanup environment...")
        self.ordered_action("cleanup", "cprio", entry_types)

    def sanitize(self, entry_types=None):
        """Sanitizing environment.

        Args:
            entry_types(list[str]):  List of entry types

        """
        self.class_logger.info("Sanitizing environment...")
        self.ordered_action("sanitize", "kprio", entry_types)

    def check(self, entry_types=None):
        """Checking environment.

        Args:
            entry_types(list[str]):  List of entry types

        """
        self.class_logger.info("Check environment...")
        self.ordered_action("check", "tprio", entry_types)

    def shutdown(self, entry_types=None):
        """Stopping/Disconnecting environment.

        Args:
            entry_types(list[str]):  List of entry types

        Note:
            This method cares to release all environment even an exception is raised during destroy process.

        """
        # Keep all error messages and print them at the end.
        # This object won't be append in case parallelize execution.
        error_messages = []

        # Sort by start priorities
        prio_dict = self._get_prio_dict("kprio")
        s_list = sorted(prio_dict.keys())

        # In further method calling we set safe flag or use safe_executor
        # to log and pass exceptions on destroy.
        for _s in s_list:
            if len(prio_dict[_s]) > 1 and self.opts.use_parallel_init:
                self.parallelize(prio_dict[_s], "destroy", True)
            else:
                for obj in prio_dict[_s]:
                    err_msg = self.safe_executor(obj, "destroy")
                    if err_msg:
                        error_messages.append(err_msg)

        if error_messages:
            message = "The following errors encountered on environment shutdown:\n%s" % ("".join(error_messages), )
            self.class_logger.error(message)
            # if stdout logging is disabled print error messages anyway
            if not loggers.LOG_STREAM:
                sys.stderr.write("ERROR:\n%s" % (message, ))
                sys.stderr.flush()

    def get_device_id(self, dut):
        """Search device in config object by device name.

        Args:
            dut(str):  Could be one of: device LINK_NAME, 'autoname' or 'id' from config.

        Raises:
            TAFCoreException:  unknown device type

        Returns:
            str, int:  Device id which configured.

        Examples (Config object like)::

            {
                "env": [
                        {"id": 5, "port_list": [["port1", 10000], ["port2", 40000]},
                        {"id": 9, "autoname": "DEV2", "port_list": [["port1", 10000], ["port2", 40000]}
                       ]
                "cross": {"ID": [[5, 1, 9, 2], [5, 2, 9, 1]]}
            }

        Result is::

            # by LINK_NAME
            env.get_device_id("sw1") == 5
            # by "autoname"
            env.get_device_id("DEV2") == 9
            # by ID
            env.get_device_id(9) == 9

        """
        # Find dut in dut_map if it is ID device
        if dut in list(self.dut_map.values()):
            return dut
        # Find dut acronym in dut_map
        elif dut in self.dut_map:
            # If acronym in dut_map
            dev_id = self.dut_map[dut]
            return dev_id
        # Find dut acronym in autoname_map
        elif dut in self.autoname_map:
            # If acronym in autoname_map
            dev_id = self.autoname_map[dut]
            return dev_id
        # Raise an exception if invalid device type
        else:
            message = "This device type not found. This method supports only %s or %s device types." % (list(self.dut_map.keys()), list(self.autoname_map.keys()))
            raise TAFCoreException(message)

    def get_real_port_name(self, dut, port_id):
        """Search real port number/name by device name and port Id in config object.

        Args:
            dut(str):  Could be one of: device LINK_NAME, 'autoname' or 'id' from config.
            port_id(int):  Port Id from config object (ids starts from 1).

        Raises:
            TAFCoreException:  port_id is not found in configuration; device doesn't have ports or port_list attributes

        Returns:
            int, str:  Real port number/name or exception if there is no port with given Id in config.

        Examples (Config object like)::

            {
                "env": [
                        {"id": 99, "autoname": "DEV1", "port_list": [["port1", 10000], ["port2", 10000]},
                        {"id": 100, "ports": ["port10", 11]}
                       ]
                "cross": {"ID": [[99, 1, 100, 2], [99, 2, 100, 1]]}
            }

        Result is::

            # by LINK_MAME
            env.get_real_port_name("sw2", 2) == 11
            # by "autoname"
            env.get_real_port_name("DEV1", 1) == "port1"

        """
        # find device ID by acronym
        dev_id = self.get_device_id(dut)
        # find device object
        dev_obj = self.id_map[dev_id]
        # find port_id in port_list
        # WARNING: We HAVE to check ports and port_list in objects instead of configs,
        # because some device classes modify port names.
        # E.g.: json doesn't support tuples, but ports have to be hashable type.
        if hasattr(dev_obj, "port_list") and dev_obj.port_list:
            try:
                return dev_obj.port_list[port_id - 1][0]
            except IndexError:
                message = "Port ID %s is not found in 'port_list' of %s(%s)." % (port_id, dev_id, dut)
                raise TAFCoreException(message)
        # find port_id in ports
        elif hasattr(dev_obj, "ports") and dev_obj.ports:
            try:
                return dev_obj.ports[port_id - 1]
            except IndexError:
                message = "Port ID %s is not found in 'ports' of %s(%s)." % (port_id, dev_id, dut)
                raise TAFCoreException(message)
        else:
            message = "Device %s(%s) doesn't have 'ports' or 'port_list' attributes." % (dev_id, dut)
            raise TAFCoreException(message)

    def get_port_speed(self, dut, port_id):
        """Search speed port in config object namely in 'port_list' by device name and port Id.

        Args:
            dut(str):  Could be one of: device LINK_NAME, 'autoname' or 'id' from config.
            port_id(int):  Port Id from config object (ids starts from 1)

        Raises:
            TAFCoreException:  port is not present in configuration's 'port_list'

        Returns:
            int:  Port speed or exception if there is no port with given Id in config.

        Examples (Config object like)::

            {
                "env": [
                        {"id": 5, "autoname": "DEV1", "port_list": [["port1", 10000], ["port2", 40000]},
                        {"id": 9, "ports": ["port10", 11]}
                       ]
                "cross": {"ID": [[5, 1, 9, 2], [5, 2, 9, 1]]}
            }

        Result is::

            env.get_port_speed("sw1", 2) == 40000
            env.get_port_speed("DEV1", 1) == 10000

        """
        # find device id by acronym
        dev_id = self.get_device_id(dut)
        # find device id in config
        for dev_config in self.config:
            if dev_config['id'] == dev_id:
                # find port_id and speed in port_list
                if 'port_list' in dev_config:
                    try:
                        return dev_config['port_list'][port_id - 1][1]
                    # raise exception if no speed for port
                    except IndexError:
                        message = "Port id %s is not configured on device %s." % (port_id, dut)
                        raise TAFCoreException(message)
                # raise exception if not configured port_list
                else:
                    message = "List of ports speed is not configured on device %s." % dut
                    raise TAFCoreException(message)

    def get_ports(self, links=None):
        """Returns dictionary of ports based on links between devices.

        Args:
            links(list[list]):  List of devices in format [['dev1', 'dev2', number_of_links, port_speed], ] (list of lists).
                                Where: \a number_of_links - optional parameter(int or enum - "ALL"); \a port_speed - optional parameter.

        Raises:
            TAFCoreException:  wrong link format

        Returns:
            dict:  ports

        Examples (Config object like)::

            {
                "env": [
                        {"id": 99, "autoname": "DEV1", "port_list": [["port1", 10000], ["port2", 40000], ["port3", 10000]},
                        {"id": 100, "port_list": [["port10", 40000], [11, 10000], ["port12", 40000]}
                       ]
                "cross": {"ID": [[99, 1, 100, 2], [99, 2, 100, 1]]}
            }

        Result is::

            ports = env.get_ports([['sw1', 'sw2', 1], ])
            assert ports == {('sw2', 'sw1'): {1: "port10"}, ('sw1', 'sw2'): {1: "port1"}}

            ports = env.get_ports([['DEV1', 'sw2', 2], ])
            assert ports == {('sw2', 'sw1'): {1: "port10", 2: 11}, ('sw1', 'sw2'): {1: "port1", 2: "port2"}}

            # with optional parameter "port_speed"
            ports = env.get_ports([['sw1', 'sw2', 1, 10000], ])
            assert ports == {('sw1', 'sw2'): {1: "port1"}, ('sw2', 'sw1'): {1: "11"}}

            # Method returns all links between devices if no any optional parameters
            ports = env.get_ports([['sw1', 'sw2', ], ])
            assert ports == {('sw1', 'sw2'): {1: "port1", 2: "port2"}, ('sw2', 'sw1'): {1: "port10", 2: 11}}

            # The same with enum "ALL"
            ports = env.get_ports([['sw1', 'sw2', "ALL"], ])
            assert ports == {('sw1', 'sw2'): {1: "port1", 2: "port2"}, ('sw2', 'sw1'): {1: "port10", 2: 11}}

            # With optional parameters "port_speed" and "ALL"
            ports = env.get_ports([['sw1', 'sw2', "ALL", 40000], ])
            assert ports == {('sw1', 'sw2'): {1: "port2"}, ('sw2', 'sw1'): {1: "port10"}}

            # Method returns all links between devices if no parameter
            ports = env.get_ports()
            assert ports == {('sw1', 'sw2'): {1: "port1", 2: "port2"}, ('sw2', 'sw1'): {1: "port10", 2: 11}}

        """

        if links:
            # Create empty prototype for ports dictionary
            ports = {}
            for link in links:
                # if not specified all devices
                if len(link) < 2:
                    message = "At list is not specified devices."
                    raise TAFCoreException(message)
                ports[(link[0], link[1])] = {}
                ports[(link[1], link[0])] = {}

            # Process each link in links
            for link in links:
                # link Ids counter
                link_id = 0
                # if not specified number of links return all links between devices
                if len(link) == 2:
                    link.append("ALL")
                # if number of links specified zero then raise exception
                if link[2] == 0:
                    message = "Number of links cannot equal zero."
                    raise TAFCoreException(message)
                # the flag indicates that was set parameter port_speed
                port_speed_flag = False
                if len(link) == 4:
                    port_speed_flag = True
                    port_speed = link[3]
                # ports Ids counter
                ports_count = link[2]
                if link[2] == "ALL":
                    ports_count = 1
                # Process setups for each cross
                for cross_id in self.setup['cross']:
                    # Each link in setup
                    for setup_link in self.setup['cross'][cross_id]:
                        # This list will contain port Ids from setup
                        port_ids = []
                        try:
                            # Search for link in setup. Compare links by devices ID
                            if [setup_link[0], setup_link[2]] == [self.get_device_id(link[0]), self.get_device_id(link[1])]:
                                port_ids = [setup_link[1], setup_link[3]]
                            elif [setup_link[2], setup_link[0]] == [self.get_device_id(link[0]), self.get_device_id(link[1])]:
                                port_ids = [setup_link[3], setup_link[1]]
                        except TAFCoreException as err:
                            message = "Insufficient devices count required for test"
                            pytest.skip(message)
                        # Append ports
                        if port_ids:

                            if port_speed_flag:
                                if link_id < ports_count:
                                    if self.get_port_speed(link[0], port_ids[0]) == self.get_port_speed(link[1], port_ids[1]) == port_speed:
                                        link_id += 1
                                        ports[(link[0], link[1])][link_id] = self.get_real_port_name(link[0], port_ids[0])
                                        ports[(link[1], link[0])][link_id] = self.get_real_port_name(link[1], port_ids[1])
                            else:
                                if link_id < ports_count:
                                    link_id += 1
                                    ports[(link[0], link[1])][link_id] = self.get_real_port_name(link[0], port_ids[0])
                                    ports[(link[1], link[0])][link_id] = self.get_real_port_name(link[1], port_ids[1])
                            if link[2] == "ALL":
                                ports_count += 1
                            # If all links are collected
                            if link_id == ports_count:
                                break

                if link[2] == "ALL":
                    ports_count = link_id
                # Verify that ports dictionary full filed
                if (len(ports[(link[0], link[1])]) < ports_count or
                        len(ports[(link[1], link[0])]) < ports_count or
                        not ports[(link[0], link[1])] or
                        not ports[(link[1], link[0])]):
                    if port_speed_flag:
                        message = "No links with required speed {0}".format(port_speed)
                    else:
                        message = "Insufficient links count required for test"
                    pytest.skip(message)

            self.class_logger.debug("Got the following ports: %s." % (ports, ))
            return ports

        else:
            ports = {}
            # create tuples of existing device connection pairs
            for cross_id in self.setup['cross']:
                for setup_link in self.setup['cross'][cross_id]:
                    ports[setup_link[0], setup_link[2]] = {}
                    ports[setup_link[2], setup_link[0]] = {}
            # Process each tuple in ports
            for key in ports:
                # link Ids counter
                link_id = 0
                # Process setups for each cross
                for cross_id in self.setup['cross']:
                    # Each link in setup
                    for setup_link in self.setup['cross'][cross_id]:
                        # Search for link in setup. Compare links by devices ID
                        if [setup_link[0], setup_link[2]] == [self.get_device_id(key[0]), self.get_device_id(key[1])]:
                            link_id += 1
                            # Append ports
                            ports[(key[0], key[1])][link_id] = self.get_real_port_name(key[0], setup_link[1])
                        elif [setup_link[2], setup_link[0]] == [self.get_device_id(key[0]), self.get_device_id(key[1])]:
                            link_id += 1
                            ports[(key[0], key[1])][link_id] = self.get_real_port_name(key[0], setup_link[3])
            self.class_logger.debug("Got the following ports: %s." % (ports, ))
            return ports


class Cross(dict):
    """New interface to cross object without device id.

    """

    def __init__(self, setup, env):
        """Initialize Cross class.

        """
        super(Cross, self).__init__()
        self.setup = setup
        self.env = env
        if hasattr(env, "cross"):
            for key, value in list(env.cross.items()):
                self[key] = value

    def get_device_id(self, connection):
        """Search device in setup object by given connection.

        Args:
            connection(list):  Connection info in format [sw1, port1, sw2, port2]

        Raises:
            Exception:  no device in connection

        Returns:
            int:  device id which own connection

        """
        connection_reverse = connection[2:] + connection[:2]
        try:
            match = next(cross_id for cross_id, crosses in self.setup['cross'].items()
                         if connection in crosses or connection_reverse in crosses)
            # keys() is not guaranteed to be stable, why does this work?
            return list(self.setup['cross'].keys()).index(match) + 1
        except StopIteration:
            raise Exception("Can not find device with such connection: %s in config" % connection)

    def xconnect(self, connection):
        """Wrapper for xconnect method defined in xconnect.py module.

        Args:
            connection(list):  Connection info in format [sw1, port1, sw2, port2]

        """
        id_real_device = self.get_device_id(connection)
        return self[id_real_device].xconnect(connection)

    def xdisconnect(self, connection):
        """Wrapper for xdisconnect method defined in xconnect.py module.

        Args:
            connection(list):  in format [sw1, port1, sw2, port2]

        """
        id_real_device = self.get_device_id(connection)
        return self[id_real_device].xdisconnect(connection)

    def cross_connect(self, conn_list):
        """Wrapper for cross_connect method defined in xconnect.py module.

        Args:
            conn_list(list[list]):  List of connections

        Raises:
            Exception:  conn_list is empty

        """
        if conn_list:
            connection = conn_list[0]
            id_real_device = self.get_device_id(connection)
            return self[id_real_device].cross_connect([connection])
        else:
            raise Exception("conn_list is empty")

    def cross_disconnect(self, disconn_list):
        """Wrapper for cross_disconnect method defined in xconnect.py module.

        Args:
            disconn_list(list[list]):  List of connections

        Raises:
            Exception:  disconn_list is empty

        """
        if disconn_list:
            connection = disconn_list[0]
            id_real_device = self.get_device_id(connection)
            return self[id_real_device].cross_disconnect(disconn_list)
        else:
            raise Exception("disconn_list is empty")

    def get_connection(self, dev_id, port_no):
        """Get connection for device port.

        Args:
            dev_id(str):  Device ID/autoname/linkname ('tg1')
            port_no(int):  Device port number.

        Raises:
            Exception:  no connection for current port

        Returns:
            list:  Connection info

        """
        # Get device
        device_id = self.env.get_device_id(dev_id)
        dev_obj = self.env.id_map[device_id]

        # Get port_id from port_no
        port_id = dev_obj.ports.index(port_no)

        # Check for connection in setup
        connection = None
        for device in self.setup['cross']:
            for conn in self.setup['cross'][device]:
                if (device_id == conn[0] and port_id == conn[1] - 1) or (device_id == conn[2] and port_id == conn[3] - 1):
                    connection = conn
                    break
        if connection is None:
            raise Exception("Port {0} on device {1} is not used in current setup.".format(port_no, dev_id))

        # dev_id has to be source
        if connection[0] != device_id:
            connection = connection[2:] + connection[:2]

        return connection

    def device_port_disconnect(self, dev_id, port_no):
        """Connect/Disconnect device port.

        Args:
            dev_id(str):  Device ID/autoname/linkname ('tg1')
            port_no(int):  Device port number.

        """
        # Get connection
        connection = self.get_connection(dev_id, port_no)

        # Emulate port disconnection
        self.cross_disconnect([connection, ])

    def device_port_connect(self, dev_id, port_no):
        """Connect/Disconnect device port.

        Args:
            dev_id(str):  Device ID/autoname/linkname ('tg1')
            port_no(int):  Device port number.

        """
        # Get connection
        connection = self.get_connection(dev_id, port_no)

        # Emulate port connection
        self.cross_connect([connection, ])
