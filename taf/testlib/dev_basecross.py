#!/usr/bin/env python
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

@file  dev_basecross.py

@summary  Cross connect specific functionality.
"""

from . import entry_template


class GenericXConnectMixin(entry_template.GenericEntry):
    """
    @description  General Cross object functionality.

    @par Configuration examples:
    @code{.json}
    {
     "name": "Zero Cross",
     "entry_type": "cross",
     "instance_type": "zero",
     "id": 31
    }
    @endcode
    @par Where:
    \b entry_type and \b instance_type are mandatory values and cannot be changed for current device type.
    \n\b id - int or str uniq device ID (mandatory)
    \n\b name - User defined device name (optional)
    """

    def create(self):
        """
        @brief  Create Cross connections.
        """
        if not self.opts.get_only:
            self.start()
            if self.autoconnect:
                self.cross_connect(self.connections)

    def destroy(self):
        """
        @brief  Destroy Cross connections.
        """
        if not self.opts.leave_on and not self.opts.get_only:
            if self.autoconnect:
                self.cross_disconnect(self.connections)
            self.stop()

    def check(self):
        """
        @brief  Mandatory method for environment specific switch classes.
        """
        pass

    def sanitize(self):
        """
        @brief  Mandatory method for environment specific switch classes.
        """
        pass

    def cleanup(self):
        """
        @brief  Mandatory method for environment specific switch classes.
        """
        pass


class ZeroCross(GenericXConnectMixin):
    """
    @description  Stub for cross object in environment. It should be used for static connected environment.
    """

    def __init__(self, config, opts):
        """
        @brief  Initialize ZeroCross class
        """
        self.id = config['id']
        self.type = config['instance_type']
        self.opts = opts
        self.autoconnect = True

    def xconnect(self, connection=None):
        """
        @brief  Mandatory method for environment specific switch classes.
        @param  connection:  Connection info in format [sw1, port1, sw2, port2]
        @type  connection:  list
        """
        pass

    def xdisconnect(self, connection=None):
        """
        @brief  Mandatory method for environment specific switch classes.
        @param  connection:  Connection info in format [sw1, port1, sw2, port2]
        @type  connection:  list
        """
        pass

    def cross_connect(self, conn_list=None):
        """
        @brief  Mandatory method for environment specific switch classes.
        @param  conn_list:  List of connections
        @type  conn_list:  list[list]
        """
        pass

    def cross_disconnect(self, disconn_list=None):
        """
        @brief  Mandatory method for environment specific switch classes.
        @param  disconn_list:  List of connections
        @type  disconn_list:  list[list]
        """
        pass

    def cross_clear(self):
        """
        @brief  Mandatory method for environment specific switch classes.
        """
        pass

    def _get_device_from_environment(self, device_id):
        """
        @brief  Mandatory method for environment specific switch classes.
        @param  device_id:  Device ID/autoname/linkname ('tg1')
        @type  device_id:  str
        """
        pass


ENTRY_TYPE = "cross"
INSTANCES = {"zero": ZeroCross}
NAME = "cross"
