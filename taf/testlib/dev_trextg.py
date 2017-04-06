# Copyright (c) 2016 - 2017, Intel Corporation.
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

"""``dev_trextg.py``

`TRex traffic generators specific functionality`

Notes:
    To install TRex client api package:
      1. Download package from http://trex-tgn.cisco.com/trex/release/
      2. Unpack main package 'v2.00.tar.gz' and then client package 'trex_client_v2.00.tar.gz'
      3. Add path to the trex client stateless lib for PYTHONPATH environment variable: env PYTHONPATH=<your path>/trex_client/stl

"""

from . import loggers
from .TRex.Trex import TrexMixin
from .tg_template import GenericTG
from .TRex.TrexHLT import TrexHLTMixin
from .packet_processor import PacketProcessor


class Trex(TrexMixin, TrexHLTMixin, PacketProcessor, GenericTG):
    """TRex interaction base class.

    Configuration examples:

    TRex server Example::

        {
         "name": "TRex"
         "entry_type": "tg",
         "instance_type": "trex",
         "id": "TG1",
         "ports": [0, 1],
         "ipaddr": "1.1.1.1",
         "ssh_user": "user",
         "ssh_pass": "PassworD",
        }

    Where::

        \b entry_type and \b instance_type are mandatory values and cannot be changed
        \n\b id - int or str uniq device ID (mandatory)
        \n\b name - User defined device name (optional)
        \n\b ports or \b port_list - short or long ports configuration (Only one of them has to be used)
        \n\b ipaddr - remote host IP address (mandatory)
        \n\b ssh_user - remote host login user (mandatory)
        \n\b ssh_pass - remote host login password (mandatory)

    Notes:
        You can safely add additional custom attributes.

    """

    class_logger = loggers.ClassLogger()

    def __init__(self, config, opts):
        """Initializes connection to TRex.

        Args:
            config(dict):  Configuration information.
            opts(OptionParser):  py.test config.option object which contains all py.test cli options.

        """
        self.config = config
        self.opts = opts
        # Indicates if TG object supports high level protocol emulation (can emulate dialogs)
        self.is_protocol_emulation_present = self.config.get("trex_hltapi", False)
        self.host = self.config["ipaddr"]
        super(Trex, self).__init__(self.config, self.opts)
        self.ports, self.port_list = self._get_speed_ports()

    def _get_speed_ports(self):
        """Get ports with speed from config.

        Returns:
            tuple(list[tuple], list[tuple, int]):  Tuple with list of ports used in real config and list of port/speed values

        Notes:
            This function check if port has speed in config file.

        """
        ports = []
        ports_list = []
        if 'ports' in self.config:
            ports = [int(x) for x in self.config["ports"]]
        if "port_list" in self.config:
            ports = [int(x[0]) for x in self.config["port_list"]]
            ports_list = [[int(x[0]), int(x[1])] for x in self.config["port_list"]]

        return ports, ports_list

    def start(self, wait_on=True):
        """Start Trex TG.

        Args:
            wait_on(bool):  Wait for device is loaded

        """
        pass

    def stop(self):
        """Shutdown TRex TG device.

        """
        pass

    def check(self):
        """Checking connection to TRex.

        Returns:
            None

        """
        if self.is_protocol_emulation_present:
            TrexHLTMixin.check(self)
        TrexMixin.check(self)

    def create(self):
        """Obligatory class for entry_type = tg.

        """
        if self.is_protocol_emulation_present:
            TrexHLTMixin.create(self)
        TrexMixin.create(self)

    def destroy(self):
        """Obligatory class for entry_type = tg.

        """
        self.class_logger.info("Destroying TRex object...")
        self.cleanup(mode="fast")
        self.class_logger.info("TRex Cleanup finished.")

        self.class_logger.info("Disconnecting TRex...")
        TrexMixin.destroy(self)
        if self.is_protocol_emulation_present:
            self.class_logger.info("Disconnecting TRexHLT...")
            TrexHLTMixin.destroy(self)

    def cleanup(self, mode="complete"):
        """This method should do TRex ports cleanup (remove streams etc.)

        Args:
            mode(str): "fast" or "complete". If mode == "fast", method does not clear streams on the port (string)

        """
        TrexMixin.cleanup(self, mode)
        if self.is_protocol_emulation_present:
            TrexHLTMixin.create(self)

    def sanitize(self):
        """Clear ownership before exit.

        """
        self.destroy()

    def get_os_mtu(self, iface=None):
        """Get MTU value in host OS.

        Args:
            iface(str):  Interface for getting MTU in host OS

        Returns:
            int: Original MTU value

        Examples::

            env.tg[1].get_os_mtu(iface=ports[('tg1', 'sw1')][1])

        """
        pass

    def set_os_mtu(self, iface=None, mtu=None):
        """Set MTU value in host OS.

        Args:
            iface(str):  Interface for changing MTU in host OS
            mtu(int):  New MTU value

        Returns:
            int:  Original MTU value

        Examples::

            env.tg[1].set_os_mtu(iface=ports[('tg1', 'sw1')][1], mtu=1650)

        """
        pass


ENTRY_TYPE = "tg"
INSTANCES = {"trex": Trex,
             }
NAME = "tg"
