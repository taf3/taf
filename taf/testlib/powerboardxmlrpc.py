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

@file  powerboardxmlrpc.py

@summary  Functionality for power control of devices via XML-RPC connected via RaspberryPi.
"""

import xmlrpc.client
from . import loggers


mod_logger = loggers.module_logger(name=__name__)


class PowerBoardXmlRpc(object):
    """
    @description  Power control of devices via XML-RPC connected via RaspberryPi.
    """

    def __init__(self, config):
        """
        @brief  Initialize PowerBoardXmlRpc class
        @param  config:  Configuration information.
        @type  config:  dict
        """
        self.ip = config["pwboard_host"]
        self.port = config["pwboard_port"][0]
        self.system_id = config["pwboard_system_id"]

        self.device_name = config['name'] if "name" in config else "noname"

        self.commands = {"Reset": 3, "On": 1, "Off": 2, "Unknown": None}

        self.pi = xmlrpc.client.ServerProxy("http://" + self.ip + ":%d" % self.port + "/RPC2")

    def power_status(self):
        """
        @brief  Get Power Board status.
        """
        self.log("Get Status")
        for val in self.system_id:
            self.pi.resetGet(val)
        # fixme:
        # status of PK powered via Rpi is always On
        return "On"

    def power_reset(self):
        """
        @brief  Reset Power Board.
        """
        self.log("reset")
        for val in self.system_id:
            self.pi.reset(val)

    def power_off(self):
        """
        @brief  Switch off Power Board.
        """
        # PK does supports only reset option, thus resetHoled currently just performs reset
        self.log("Power Off")
        for val in self.system_id:
            self.pi.resetHold(val)

    def power_on(self):
        """
        @brief  Switch on Power Board.
        """
        self.log("Power On")
        for val in self.system_id:
            self.pi.resetRelease(val)

    def log(self, action):
        """
        @brief  Function for logging actions.
        """
        mod_logger.log(loggers.levels['INFO'], "Performing '%s' action for '%s' device..." % (action, self.device_name))

    #
    # backwards compatibility functions
    #
    def get_status(self, *args):
        """
        @brief  Get Power Board status.
        """
        return self.power_status()

    def do_action(self, pwboard, pwport, command):
        """
        @brief  Perform specific action.
        """
        if command == 3:
            return self.power_reset()
        if command == 2:
            return self.power_off()
        if command == 1:
            return self.power_on()
