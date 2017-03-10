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

"""``switch_userver.py``

`uServer-specific functionality`

"""

import time

from .switch_ons import SwitchONS


class SwitchUServer(SwitchONS):
    """uServer devices class.

    """

    def __init__(self, config, opts):
        """Initialize SwitchUServer class.

        Args:
            config(dict):  Configuration information.
            opts(OptionParser):  py.test config.option object which contains all py.test cli options.

        """
        super(SwitchUServer, self).__init__(config, opts)
        self.default_restart_type = "ui"
        self.origin_restart_type = "ui"
        if "ipmi" in self.config:
            self._fill_ipmi(self.config["ipmi"])
            self.default_restart_type = "ipmi"

    def _fill_ipmi(self, config):
        """Configure IPMI.

        Args:
            config(dict):  Configuration information.

        """
        self.ipmi = {}
        for key in list(config.keys()):
            self.ipmi[key] = config[key]

    def get_chassis_config(self):
        """Get chassis configuration.

        """
        if "ipmi" in self.config:
            chassis_info = self.getprop_table('ChassisConfig')[0]
            self.ipmi["ipmi_host"] = self.ipmi[chassis_info['activePhysicalMgmtPort']]
            self.ipmi["ipmi_slot"] = int(chassis_info['switchSlotId']) + 1

    def _ipmi_restart(self):
        """Restart IPMI.

        """
        import os

        self.class_logger.info("Performing restart via IPMI")

        return os.system("ipmitool -H %s -U %s -P %s raw %s" % (self.ipmi["ipmi_host"],
                                                                self.ipmi["ipmi_user"],
                                                                self.ipmi["ipmi_pass"],
                                                                self.ipmi["ipmi_reset_cmd"].format(slot_id=self.ipmi["ipmi_slot"])))

    def _ipmi_poweroff(self):
        """Performing Power Off via IPMI.

        """
        import os
        self.class_logger.info("Performing PowerOFF via IPMI")

        return os.system("ipmitool -H %s -U %s -P %s raw %s" % (self.ipmi["ipmi_host"],
                                                                self.ipmi["ipmi_user"],
                                                                self.ipmi["ipmi_pass"],
                                                                self.ipmi["ipmi_off_cmd"].format(slot_id=self.ipmi["ipmi_slot"])))

    def _ipmi_poweron(self):
        """Performing Power On via IPMI.

        """
        import os
        self.class_logger.info("Performing PowerON via IPMI")

        return os.system("ipmitool -H %s -U %s -P %s raw %s" % (self.ipmi["ipmi_host"],
                                                                self.ipmi["ipmi_user"],
                                                                self.ipmi["ipmi_pass"],
                                                                self.ipmi["ipmi_on_cmd"].format(slot_id=self.ipmi["ipmi_slot"])))

    def restart(self, wait_on=True, mode="powercycle"):
        """Power Off IPMI.

        Args:
            wait_on(bool):  Indicates if wait for device status
            mode(str):  Restart mode. powercycle|ui|ipmi

        """
        if mode == "ipmi":
            if "ipmi" in self.config:
                if self._ipmi_poweroff() == 0:
                    self.status = False
                    self.waitoff(timeout=60)
                    if self._ipmi_poweron() == 0:
                        time.sleep(25)
                        # workaround ends
                        self.waiton(300)
                        self.status = True
                        # Set initial ports speed
                        self.speed_preconfig()
                        return
            return False
        return super(SwitchUServer, self).restart(wait_on, mode)

    def get(self, init_start=False, retry_count=7):
        """Get or start switch instance. Get chassis configuration.

        Args:
            init_start(bool):  Perform switch start operation or not
            retry_count(int):  Number of retries to start(restart) switch

        """
        super(SwitchUServer, self).get(init_start, retry_count)
        # Make sure that ChassisConfig is already updated
        time.sleep(10)
        self.get_chassis_config()
