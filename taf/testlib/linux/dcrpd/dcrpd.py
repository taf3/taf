# Copyright (c) 2015 - 2017, Intel Corporation.
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

"""``dcrpd.py``

`Class to abstract dcrpd operations`

"""

from testlib.custom_exceptions import UICmdException
from testlib.linux import service_lib
from testlib.ui_onpss_shell.switch_driver import SwitchDriver


class Dcrpd(object):

    SERVICE = 'dcrpd'
    CONFIG_PATH = "/usr/lib/systemd/system/"
    MANIFEST_FILE = CONFIG_PATH + "dcrpd.service"

    def __init__(self, run_command, switch):
        """Initialize Dcrpd class.

        Args:
            run_command(function): function that runs the actual commands

        """
        super(Dcrpd, self).__init__()
        self.run_command = run_command
        self.switch = switch
        self.switch_driver = SwitchDriver(self, switch)
        self.service_manager = service_lib.SpecificServiceManager(self.SERVICE, self.run_command)

    def start(self):
        """Start dcrpd process.

        Raises:
            UICmdException: On non-zero return code

        """
        self.switch.ui.modify_ports(ports=[self.switch.ui.cpu_port], adminMode='Up')
        self.service_manager.start()

    def stop(self):
        """Stop dcrpd process.

        Raises:
            UICmdException: On non-zero return code

        """
        self.service_manager.stop()
        self.switch.ui.modify_ports(ports=[self.switch.ui.cpu_port], adminMode='Down')

    def restart(self):
        """Restarting dcrpd process.

        Raises:
            UICmdException: On non-zero return code

        """
        self.service_manager.restart()

    def force_reload(self):
        """Restarting the switch driver and then the dcrpd process.

        Raises:
            UICmdException: On non-zero return code

        """
        self.switch_driver.force_reload()
        self.switch.ui.modify_ports(ports=[self.switch.ui.cpu_port], adminMode='Up')
        self.restart()

    def enable(self):
        """Enabling dcrpd service on start.

        Raises:
            UICmdException: On non-zero return code

        """
        self.service_manager.enable()

    def disable(self):
        """Disabling dcrpd service on start.

        Raises:
            UICmdException: On non-zero return code

        """
        self.service_manager.disable()

    def get_status(self):
        """Get dcrpd process status.

        Raises:
            UICmdException: On non-zero or non-three return code

        Returns:
            str

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
