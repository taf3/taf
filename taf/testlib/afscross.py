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

"""``afscross.py``

`xconnect-specific functionality`

"""

import argparse

from . import afs
from . import loggers
from .custom_exceptions import CrossException
from .dev_basecross import GenericXConnectMixin


class AFS(GenericXConnectMixin):
    """Basic interact with ASF.

    """

    class_logger = loggers.ClassLogger()

    def __init__(self, config, opts, env):
        """Reading/updating config, initialize afs object instance.

        Args:
            config(dict):  Configuration
            opts(OptionParser):  Options
            env(Environment):  Environment object

        """
        self.class_logger.debug("Create AFS object.")
        self.opts = opts

        # Correcting AFS port map
        if "mapcorrector" in config:
            for dev_id in config['mapcorrector']:
                # list of necessary portmap items
                valid_list = [int(key) for key in list(config['mapcorrector'][dev_id].keys())]
                # remove unnecessary items
                for item in config['portmap'][:]:
                    if item[0] == int(dev_id):
                        if not item[1] in valid_list:
                            config['portmap'].remove(item)
                # correct port IDs for necessary items
                for i in range(len(config['portmap'])):
                    if config['portmap'][i][0] == int(dev_id):
                        config['portmap'][i][1] = int(config['mapcorrector'][dev_id][str(config['portmap'][i][1])])

        self.config = {'id': config['id'], 'instance_type': config['instance_type'],
                       'ip_host': config['ip_host'], 'user': config['user'],
                       'password': config['password'], 'portmap': config['portmap']}

        self.id = config['id']
        self.type = config['instance_type']

        self.afs = afs.AFS(self.config)

    def cross_connect(self, conn_list):
        """Make connections between switches.

        Args:
            conn_list(list[list[int]]):  List of connections in format: [[sw1, port1, sw2, port2], ... ]

        Examples::

            cross_connect([[0, 1, 1, 1], [0, 2, 1, 2]])

        """
        for connection in conn_list:
            self.afs.xconnect(connection)
        self.afs.clear_connection_pool()

    def cross_disconnect(self, disconn_list):
        """Destroy connections between switches.

        Args:
            disconn_list(list[list[int]]):  List of connections in format: [[sw1, port1, sw2, port2], ... ]

        Examples::

            cross_disconnect([[0, 1, 1, 1], [0, 2, 1, 2]])

        """
        for connection in disconn_list:
            self.afs.xdisconnect(connection)
        self.afs.clear_connection_pool()

    def cross_clear(self):
        """Clear all connections between switches. (Not supporter for AFS environment).

        Raises:
            CrossException:  not supported method

        """
        message = "cross_clear method is supported only on virtual environment"
        self.class_logger.error(message)
        raise CrossException(message)

    def start(self):
        """Obligatory class for entry_type = cross.

        """
        # Run check() to verify that connection to AFS is OK.
        self.check()
        self.afs.clear_connection_pool()

    def stop(self):
        """Obligatory class for entry_type = cross.

        """
        # self.class_logger.debug("Destroy AFS object.")
        # self.connection_pool.disconnect_all()
        self.afs.__del__()

    def check(self):
        """Obligatory class for entry_type = cross.

        """
        # Get system information to verify that connection to AFS is OK.
        self.afs.get_sys_info()
        self.afs.clear_connection_pool()


# Do setup without running test cases
if __name__ == "__main__":

    from .common3 import Environment

    def parse_options():
        """Parsing env and cross options.

        Raises:
            CrossException:  setup option is obligatory

        """
        parser = argparse.ArgumentParser()
        parser.add_argument("--env", action="store", default=None, dest="env",
                          help="Testing environment. None by default.")
        parser.add_argument("--setup_file", action="store", default=None, dest="setup",
                          help="Environment cross configuration. None by default.")
        parser.add_argument("--loglevel", action="store", default="INFO", dest="loglevel",
                          help="Logging level, 'INFO' by default.")
        parser.add_argument("--leave_on", action="store_true", default=True,
                          help="Do not shutdown environment after the end of tests (affect only virtual environment). False by default.")
        parser.add_argument("--get_only", action="store_true", default=False,
                          help="Do not start cross device, connect to exists one (affect only virtual environment). False by default.")
        options = parser.parse_args()
        if options.setup is None:
            raise CrossException("Option --setup_file is obligatory!")
        return options

    def main():
        """Main work of standalone connections.

        """
        options = parse_options()
        env = Environment(options)
        for cross_id in env.cross:
            env.cross[cross_id].create()
            env.cross[cross_id].xconnect()

    main()
