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


"""``dev_basecross.py``

`Cross connect specific functionality`

"""

from . import entry_template


class GenericXConnectMixin(entry_template.GenericEntry):
    """General Cross object functionality.

    Configuration examples::

        {
         "name": "Zero Cross",
         "entry_type": "cross",
         "instance_type": "zero",
         "id": 31
        }

    Where:
        - \b entry_type and \b instance_type are mandatory values and cannot be changed for current device type.
        - \n\b id - int or str uniq device ID (mandatory)
        - \n\b name - User defined device name (optional)

    """

    def create(self):
        """Create Cross connections.

        """
        if not self.opts.get_only:
            self.start()
            if self.autoconnect:
                self.cross_connect(self.connections)

    def destroy(self):
        """Destroy Cross connections.

        """
        if not self.opts.leave_on and not self.opts.get_only:
            if self.autoconnect:
                self.cross_disconnect(self.connections)
            self.stop()

    def check(self):
        """Mandatory method for environment specific switch classes.

        """
        pass

    def sanitize(self):
        """Mandatory method for environment specific switch classes.

        """
        pass

    def cleanup(self):
        """Mandatory method for environment specific switch classes.

        """
        pass


class ZeroCross(GenericXConnectMixin):
    """Stub for cross object in environment. It should be used for static connected environment.

    """

    def __init__(self, config, opts):
        """Initialize ZeroCross class

        """
        self.id = config['id']
        self.type = config['instance_type']
        self.opts = opts
        self.autoconnect = True

    def xconnect(self, connection=None):
        """Mandatory method for environment specific switch classes.

        Args:
            connection(list):  Connection info in format [sw1, port1, sw2, port2]

        """
        pass

    def xdisconnect(self, connection=None):
        """Mandatory method for environment specific switch classes.

        Args:
            connection(list):  Connection info in format [sw1, port1, sw2, port2]

        """
        pass

    def cross_connect(self, conn_list=None):
        """Mandatory method for environment specific switch classes.

        Args:
            conn_list(list[list]):  List of connections

        """
        pass

    def cross_disconnect(self, disconn_list=None):
        """Mandatory method for environment specific switch classes.

        Args:
            disconn_list(list[list]):  List of connections

        """
        pass

    def cross_clear(self):
        """Mandatory method for environment specific switch classes.

        """
        pass

    def _get_device_from_environment(self, device_id):
        """Mandatory method for environment specific switch classes.

        Args:
            device_id(str):  Device ID/autoname/linkname ('tg1')

        """
        pass


ENTRY_TYPE = "cross"
INSTANCES = {"zero": ZeroCross}
NAME = "cross"
