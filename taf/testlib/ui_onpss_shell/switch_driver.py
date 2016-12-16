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

@file  switch_driver.py

@summary  Switch Driver abstraction
"""

import os
from collections import namedtuple, OrderedDict

from ..custom_exceptions import UIException

SwitchDriverEntry = namedtuple("SwitchDriver", "name kernel_module script")


class SwitchDriver(object):
    # ordered because we want to search for fm10kd first
    SWITCH_DRIVERS = OrderedDict([
        ("fm10kd", SwitchDriverEntry("fm10kd", "fm10ks", "fm10kdr")),
        # focalpoint module was renamed to switch?
        ("switchd", SwitchDriverEntry("switchd", "switch", "switchdr")),
    ])
    MODPROBE_COMMAND = "modprobe"

    def __init__(self, ui_instance, switch_instance):
        """

        @param ui_instance: ui_onpss_shell instance
        @type ui_instance: UiOnpssShell
        @param switch_instance: specific switch instance
        @type switch_instance: SwitchGeneral
        """
        super(SwitchDriver, self).__init__()
        self.ui = ui_instance
        self.switch = switch_instance

    @staticmethod
    def _gen_which_command(prog):
        """

        @param prog: command to search for in the patch
        @type prog: str
        @return: path of program
        @rtype: str
        """
        return "which {} 2>/dev/null".format(prog)

    def autodetect(self):
        """
        Search for switch drivers and set the name, kernel_module and script
        accordingly

        @raise UIException: when switch driver not found
        """
        if not getattr(self, "path", None):
            # search for the daemons and assume everything else exists
            autodetect_command = " || ".join(
                [self._gen_which_command(s.name) for s in self.SWITCH_DRIVERS.values()])
            path = self.ui.cli_send_command(autodetect_command).stdout.strip()
            if path:
                name = os.path.basename(path)
                try:
                    drv = self.SWITCH_DRIVERS[name]
                except KeyError:
                    raise UIException("Cannot detect switch driver")
                else:
                    self.name = drv.name  # pylint: disable=attribute-defined-outside-init
                    self.kernel_module = drv.kernel_module  # pylint: disable=attribute-defined-outside-init
                    self.script = drv.script  # pylint: disable=attribute-defined-outside-init
                    self.path = path  # pylint: disable=attribute-defined-outside-init

            else:
                raise UIException("Cannot detect switch driver")
            self.switch.class_logger.debug((self.name, self.kernel_module, self.script))

    def force_reload(self):
        """
        Reload the switch driver using the manual reload script

        """
        self.ui.cli_send_command("{0.script} -r".format(self))

    def is_active(self):
        """
        Check is switch driver service is running

        @return: True if switch driver service is running
        @rtype: bool
        """
        command = "systemctl is-active {0}".format(self.name)
        # rc = 3, stdout = 'failed\n'
        out, err, rc = self.ui.cli_send_command(command, expected_rcs={0, 3})
        # use exact compare, not in
        # possible values are 'active' or 'unknown' or failed with rc 3.
        # only return true if we get 'active'
        return out.strip() == "active"

    def stop_and_unload(self):
        """
        Stop the switch driver using the script

        Normally we would just stop the services, this is for hose manual cases
        """
        self.ui.cli_send_command("{0.script} -s".format(self))

    def kill(self):
        """
        Kill the switch driver process.

        Normally we would just stop the service, this is for those manual cases

        """
        self.ui.cli_send_command("pkill {0.name}".format(self))

    def process_exists(self):
        """
        Check if the switch driver process itself is running

        @return: True is switch driver process is running
        @rtype: bool
        """
        output = self.ui.cli_send_command("pgrep -x {0}".format(self.name), expected_rcs={
            0, 1}).rc
        return output == 0

    def modprobe(self):
        """
        modprobe the switch driver kernel module

        """
        self.ui.switch.cli_send_command("{0} {1}".format(
            self.MODPROBE_COMMAND, self.kernel_module))
