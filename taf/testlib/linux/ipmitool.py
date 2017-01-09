#!/usr/bin/env python
"""
@copyright Copyright (c) 2015 - 2017, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  ipmitool.py

@summary  Class to abstract ipmitool operations
"""
import re

import pytest


class IpmiTool(object):

    SERVICE = 'ipmitool'

    def __init__(self, run_command):
        """
        @brief Initialize IpmiTool class.
        """
        super(IpmiTool, self).__init__()
        self.run_command = run_command

    def get_sdr_list(self):
        """
        @brief  Get all available Sensor Data Repository entries
        @return:  Returns list of sdr
        @rtype:  list
        """
        sdr = self.run_command('"{}" sdr list'.format(self.SERVICE)).stdout
        return re.findall(r'^(.*?)\s+\|', sdr, re.MULTILINE)

    def get_sensors_states(self, sensor, expected_rcs=frozenset({0, 1})):
        """
        @brief  Get all available sensor states for sensor
        @param  sensor:  name of sensor
        @type  sensor:  str
        @param  expected_rcs: if sensor is not available in HW rc=1, but events for sensor could be generated
        @type  expected_rcs:  set
        @return:  Returns list of sensor states
        @rtype:  list
        """
        sensor_states_list = self.run_command("{0} event '{1}'".format(self.SERVICE, sensor),
                                              expected_rcs=expected_rcs).stdout
        return re.findall(r'\s{3}(.+)', sensor_states_list, re.MULTILINE)

    def generate_event(self, sensor, sensor_state):
        """
        @brief  Method for generating event for sensor with sensor state
        @param  sensor:  name of sensor
        @type  sensor:  str
        @param  sensor_state:  name of sensor state
        @type  sensor_state:  str
        """
        self.run_command('"{0}" event "{1}" "{2}"'.format(self.SERVICE, sensor, sensor_state.strip()))

    def clear_sel(self):
        """
        @brief  Method for clear System Event Log
        """
        self.run_command('"{0}" sel clear'.format(self.SERVICE))

    def is_ipmi_supported_by_system(self):
        """
        @brief  Method for check if ipmi is supported by device
        """
        if 'IPMI' not in self.run_command('dmidecode -t38').stdout:
            pytest.skip('ipmi does not supported on current machine')
