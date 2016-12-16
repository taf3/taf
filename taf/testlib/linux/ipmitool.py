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

@file ipmitool.py

@summary Class to abstract ipmitool operations
"""
from testlib.custom_exceptions import SwitchException


class IpmiTool(object):

    SERVICE = 'ipmitool'

    def __init__(self, run_command, ipmi_config, tray=""):
        """
        @brief Initialize IpmiTool class.
        """
        super(IpmiTool, self).__init__()
        self.run_command = run_command
        self.ipmi_host = ipmi_config['ipmi_host']
        self.ipmi_user = ipmi_config['ipmi_user']
        self.ipmi_pass = ipmi_config['ipmi_pass']
        self.ipmi_reset_string = ipmi_config['ipmi_reset']
        self.ipmi_status_string = ipmi_config['ipmi_status']
        self.tray = tray

    def reset(self):
        """
        @brief:  Uses ipmi to issue the reset command.
        """
        command = '{0} -H {1} -U {2} -P {3} -b {4} -t {5}'.format(
            self.SERVICE, self.ipmi_host, self.ipmi_user,
            self.ipmi_pass, self.tray, self.ipmi_reset_string)
        result = self.run_command(command=command)

        if result.stderr:
            raise SwitchException("Error during IPMI power cycle: {0}".format(result.stderr))

    def status(self):
        """
        @brief:  Uses ipmi to issue get status command.
        @raise:  SwitchException
        @return:  Returns the result.stdout
        @rtype:  str
        """
        command = '{0} -H {1} -U {2} -P {3} -b {4} -t {5}'.format(
            self.SERVICE, self.ipmi_host, self.ipmi_user,
            self.ipmi_pass, self.tray, self.ipmi_status_string)
        result = self.run_command(command=command)

        if result.stderr:
            raise SwitchException("Error during IPMI get status: {0}".format(result.stderr))

        return result.stdout
