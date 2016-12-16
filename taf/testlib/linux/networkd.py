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

@file networkd.py

@summary Class to abstract networkd operations
"""
from testlib.linux import service_lib


class NetworkD(object):
    SERVICE = "systemd-networkd"
    CONFIG_PATH = "/etc/systemd/network/"

    def __init__(self, run_command, mgmt_ports):
        """

        @param run_command: function that runs the actual commands
        @type run_command: function
        @param mgmt_ports: list of mgmt ports to treat specially
        @type mgmt_ports: iter
        """
        super(NetworkD, self).__init__()
        self.run_command = run_command
        self.mgmt_ports = mgmt_ports
        self.service_manager = service_lib.specific_service_manager_factory(
            self.SERVICE, self.run_command)

    def restart(self):
        """
        @brief  Restarting systemd-networkd process
        @rtype:  bool
        @return:  True if result is none otherwise false
        """
        result = self.service_manager.restart()
        return result.stdout

    def stop(self):
        return self.service_manager.stop()

    def start(self):
        return self.service_manager.start()

    def clear_settings(self, exclude_ports=None):
        """
        Clear networkd settings for all ports except those excluded.

        @param exclude_ports: list of extra ports to exclude from clear settings, is appended to
        mgmt_ports
        @type exclude_ports: iter()
        """
        if exclude_ports is None:
            exclude_iter = self.mgmt_ports
        else:
            exclude_iter = self.mgmt_ports + exclude_ports
        suffixes = [".network", ".netdev", ".link", ".swport"]
        mgmt_ports = ["-name '{0}{1}'".format(port, suffix) for port in exclude_iter for suffix in suffixes]
        # Exclude mgmt ports
        exclude_str = r'-not \( {} \)'.format(" -or ".join(mgmt_ports))
        # we have to remove config file to clear the config
        # ignore failure if dir doesn't exist
        self.run_command(
            r"find {0} -mindepth 1 {1} -delete".format(self.CONFIG_PATH, exclude_str),
            expected_rcs={0, 1})
