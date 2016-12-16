#!/usr/bin/env python
"""
@copyright Copyright (c) 2015 - 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file dcrpd.py

@summary Class to abstract dcrpd operations
"""

from testlib.custom_exceptions import UICmdException
from testlib.linux import service_lib
from testlib.ui_onpss_shell.switch_driver import SwitchDriver


class Dcrpd(object):

    SERVICE = 'dcrpd'
    CONFIG_PATH = "/usr/lib/systemd/system/"
    MANIFEST_FILE = CONFIG_PATH + "dcrpd.service"

    def __init__(self, run_command, switch):
        """
        @param run_command: function that runs the actual commands
        @type run_command: function
        """
        super(Dcrpd, self).__init__()
        self.run_command = run_command
        self.switch = switch
        self.switch_driver = SwitchDriver(self, switch)
        self.service_manager = service_lib.specific_service_manager_factory(
            self.SERVICE, self.run_command)

    def start(self):
        """
        @brief  Start dcrpd process
        @raise  UICmdException: On non-zero return code
        """
        self.switch.ui.modify_ports(ports=[self.switch.ui.cpu_port], adminMode='Up')
        self.service_manager.start()

    def stop(self):
        """
        @brief  Stop dcrpd process
        @raise  UICmdException: On non-zero return code
        """
        self.service_manager.stop()
        self.switch.ui.modify_ports(ports=[self.switch.ui.cpu_port], adminMode='Down')

    def restart(self):
        """
        @brief  Restarting dcrpd process
        @raise  UICmdException: On non-zero return code
        """
        self.service_manager.restart()

    def force_reload(self):
        """
        @brief  Restarting the switch driver and then the dcrpd process
        @raise  UICmdException: On non-zero return code
        """
        self.switch_driver.force_reload()
        self.switch.ui.modify_ports(ports=[self.switch.ui.cpu_port], adminMode='Up')
        self.restart()

    def enable(self):
        """
        @brief  Enabling dcrpd service on start
        @raise  UICmdException: On non-zero return code
        """
        self.service_manager.enable()

    def disable(self):
        """
        @brief  Disabling dcrpd service on start
        @raise  UICmdException: On non-zero return code
        """
        self.service_manager.disable()

    def get_status(self):
        """
        @brief  Get dcrpd process status
        @raise  UICmdException: On non-zero or non-three return code
        @rtype:  str
        """
        try:
            result = self.service_manager.status()
        except UICmdException as err:
            if err.rc == 3:
                # If service is not active
                return err.stdout
            else:
                raise

        return result.stdout
