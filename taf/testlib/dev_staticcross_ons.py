#! /usr/bin/env python
"""
@copyright Copyright (c) 2011 - 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  dev_staticcross_ons.py

@summary staticcross_ons-specific functionality.
"""

from . import loggers
from . import dev_basecross
from .custom_exceptions import CrossException


class StaticCrossONS(dev_basecross.GenericXConnectMixin):
    """
    @brief  Stub for cross object in environment
    """

    class_logger = loggers.ClassLogger()

    def __init__(self, config, opts):
        """
        @brief Initialize StaticCrossONS class
        @param  config:  Configuration information.
        @type  config:  dict
        @param  opts:  py.test config.option object which contains all py.test cli options.
        @type  opts:  OptionParser
        """
        self.id = config['id']
        self.type = config['instance_type']
        self.opts = opts
        self.autoconnect = config['autoconnect'] if "autoconnect" in config else True

        # Store configuration of related devices
        self.related_conf = {}
        if "related_conf" in list(config.keys()):
            self.related_conf = config['related_conf']

    def _get_device(self, device_id):
        """
        @brief  Return device object by device id.
        @param  device_id:  Device ID
        @type  device_id:  str
        @raise  Exception:  device is not present in related configurations
        @rtype:  GenericEntry
        @return:  Device object
        """
        for dev in self.related_conf:
            if dev == device_id:
                return self.related_obj[dev]
        raise Exception("Device ID={0} not found in related configurations.".format(device_id))

    def xconnect(self, conn=None):
        """
        @brief  We have to connect only dest port as far as it is only emmulation.
        @param  conn:  Connection info in format [sw1, port1, sw2, port2]
        @type  conn:  list
        """
        # Get info about first device
        dest = self._get_device(conn[2])
        dest_port = dest.ports[conn[3] - 1]
        # Perform connect
        dest.connect_port(dest_port)

    def xdisconnect(self, conn=None):
        """
        @brief  We have to disconnect only dest port as far as it is only emmulation.
        @param  conn:  Connection info in format [sw1, port1, sw2, port2]
        @type  conn:  list
        """
        # Get info about first device
        dest = self._get_device(conn[2])
        dest_port = dest.ports[conn[3] - 1]
        # Perform disconnect
        dest.disconnect_port(dest_port)

    def cross_connect(self, conn_list=None):
        """
        @brief  Configure Cross connect.
        @param  conn_list:  List of connections
        @type  conn_list:  list[list]
        @raise  CrossException:  devices from conn_list are not in related configurations
        """
        # verification id of devices in related config
        if self.related_conf:
            list_id = []
            for conn in conn_list:
                list_id.append(conn[0])
                list_id.append(conn[2])
            if set(self.related_conf.keys()) != set(list_id):
                message = ("Set of cross connected devices %s is not appropriate related config %s."
                           % (list(set(list_id)), list(set(self.related_conf.keys()))))
                self.class_logger.error(message)
                raise CrossException(message)

        for conn in conn_list:
            self.xconnect(conn=conn)

    def cross_disconnect(self, disconn_list=None):
        """
        @brief  Configure Cross disconnect.
        @param  disconn_list:  List of connections
        @type  disconn_list:  list[list]
        """
        for conn in disconn_list:
            self.xdisconnect(conn=conn)

    def cross_clear(self):
        """
        @brief  Mandatory method for environment specific switch classes.
        """
        pass

    def start(self):
        """
        @brief  Mandatory method for environment specific switch classes.
        """
        pass

    def stop(self):
        """
        @brief  Mandatory method for environment specific switch classes.
        """
        pass

    def check(self):
        """
        @brief  Mandatory method for environment specific switch classes.
        """
        pass


ENTRY_TYPE = "cross"
INSTANCES = {"static_ons": StaticCrossONS}
NAME = "cross"
