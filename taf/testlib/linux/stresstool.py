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

@file  stresstool.py

@summary  Run stress tool on the remote host and parse output
"""
import re
from collections import namedtuple

from testlib.linux import tool_general


Line = namedtuple('Line', 'loglevel, worker, message')


STRESS_LINE_RE = re.compile(r'stress: (?P<loglevel>\w*): \[(?P<worker>\d*)\] (?P<message>.*)')


class StressParser(object):
    """
    @description  Class for parsing stress output
    """

    def __init__(self):
        """
        @brief  Initialize StressParser class
        """
        super(StressParser, self).__init__()

    @staticmethod
    def parse(output):
        """
        @brief  Parse output from stress execution
        @param output: stress output
        @type  output: str
        @rtype:  list
        @return:  list of parsed stress results
        """
        return [Line(*m.group('loglevel', 'worker', 'message'))
                for m in STRESS_LINE_RE.finditer(output)]


class StressTool(tool_general.GenericTool):
    """
    @description  Class for Stress tool functionality
    """

    def __init__(self, run_command):
        """
        @brief  Initialize StressTool class
        @param run_command: function that runs the actual commands
        @type run_command: function
        """
        super(StressTool, self).__init__(run_command, 'stress')

    def start(self, cpu=None, vm=None, vm_bytes=None, io=None, disk=None, time=10, **kwargs):
        """
        @brief  Generate stress command, launch stress and store results in the file
        @param cpu:  number of CPU workers
        @type  cpu:  int
        @param vm:  number of memory workers
        @type  vm:  int
        @param vm_bytes: amount of used memory
        @type  vm_bytes:  str
        @param io:  number of IO workers
        @type  io:  int
        @param disk: number of disk workers
        @type  disk:  str
        @param time: time of execution
        @type  time:  int
        @rtype:  int
        @return:  tool instance ID
        """
        c_options = ['stress',
                     '--verbose',
                     '--cpu {}'.format(cpu) if cpu and int(cpu) else '',
                     '--vm {}'.format(vm) if vm and int(vm) else '',
                     '--vm-bytes {}'.format(vm_bytes) if vm_bytes else '',
                     '--io {}'.format(io) if io and int(io) else '',
                     '--hdd {}'.format(disk) if disk and int(disk) else '',
                     '--timeout {}s'.format(time) if time and int(time) else '']

        command = ' '.join((x for x in c_options if x))
        # Execute command
        return super(StressTool, self).start(command, timeout=10)

    def parse(self, output):
        """
        @brief  Parse the stress output
        @param output:  stress origin output
        @type  output: str
        @rtype:  list
        @return:  list of parsed stress results
        """
        return StressParser.parse(output)
