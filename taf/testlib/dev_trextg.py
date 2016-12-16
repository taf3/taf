"""
@copyright Copyright (c) 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  dev_trextg.py

@summary  TRex traffic generators specific functionality.

@note  To install TRex client api package:
        1. Download package from http://trex-tgn.cisco.com/trex/release/
        2. Unpack main package 'v2.00.tar.gz' and then client package 'trex_client_v2.00.tar.gz'
        3. Add path to the trex client stateless lib for PYTHONPATH environment variable:
           env PYTHONPATH=<your path>/trex_client/stl
"""

from . import loggers
from .TRex.Trex import TrexMixin
from .tg_template import GenericTG
from .TRex.TrexHLT import TrexHLTMixin
from .packet_processor import PacketProcessor


class Trex(TrexMixin, TrexHLTMixin, PacketProcessor, GenericTG):
    """
    @description  TRex interaction base class.

    @par  Configuration examples:

    @par  TRex server Example:
    @code{.json}
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
    @endcode
    @par  Where:
    \b entry_type and \b instance_type are mandatory values and cannot be changed
    \n\b id - int or str uniq device ID (mandatory)
    \n\b name - User defined device name (optional)
    \n\b ports or \b port_list - short or long ports configuration (Only one of them has to be used)
    \n\b ipaddr - remote host IP address (mandatory)
    \n\b ssh_user - remote host login user (mandatory)
    \n\b ssh_pass - remote host login password (mandatory)

    @note  You can safely add additional custom attributes.
    """

    class_logger = loggers.ClassLogger()

    def __init__(self, config, opts):
        """
        @brief  Initializes connection to TRex.
        @param  config:  Configuration information.
        @type  config:  dict
        @param  opts:  py.test config.option object which contains all py.test cli options.
        @type  opts:  OptionParser
        """
        self.config = config
        self.opts = opts
        # Indicates if TG object supports high level protocol emulation (can emulate dialogs)
        self.is_protocol_emulation_present = self.config.get("trex_hltapi", False)
        self.host = self.config["ipaddr"]
        super(Trex, self).__init__(self.config, self.opts)
        self.ports, self.port_list = self._get_speed_ports()

    def _get_speed_ports(self):
        """
        @brief  Get ports with speed from config.
        @rtype:  tuple(list[tuple], list[tuple, int])
        @return:  Tuple with list of ports used in real config and list of port/speed values
        @note  This function check if port has speed in config file.
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
        """
        @brief  Start Trex TG.
        @param  wait_on:  Wait for device is loaded
        @type  wait_on:  bool
        """
        pass

    def stop(self):
        """
        @brief  Shutdown TRex TG device.
        """
        pass

    def check(self):
        """
        @brief  Checking connection to TRex.
        @return:  None
        """
        if self.is_protocol_emulation_present:
            TrexHLTMixin.check(self)
        TrexMixin.check(self)

    def create(self):
        """
        @brief  Obligatory class for entry_type = tg
        """
        if self.is_protocol_emulation_present:
            TrexHLTMixin.create(self)
        TrexMixin.create(self)

    def destroy(self):
        """
        @brief  Obligatory class for entry_type = tg
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
        """
        @brief  This method should do TRex ports cleanup (remove streams etc.)
        @param  mode: "fast" or "complete". If mode == "fast", method does not clear streams on the port (string)
        @type  mode:  str
        """
        TrexMixin.cleanup(self, mode)
        if self.is_protocol_emulation_present:
            TrexHLTMixin.create(self)

    def sanitize(self):
        """
        @brief  Clear ownership before exit.
        """
        self.destroy()

    def get_os_mtu(self, iface=None):
        """
        @copydoc  testlib::tg_template::GenericTG::get_os_mtu()
        """
        pass

    def set_os_mtu(self, iface=None, mtu=None):
        """
        @copydoc  testlib::tg_template::GenericTG::set_os_mtu()
        """
        pass


ENTRY_TYPE = "tg"
INSTANCES = {"trex": Trex,
             }
NAME = "tg"
