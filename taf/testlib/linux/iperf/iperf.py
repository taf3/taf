# Copyright (c) 2016 - 2017, Intel Corporation.
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

"""``iperf.py``

`Run iperf on the remote host and parse output`

"""

import os
import sys
from collections import namedtuple

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))
from utils.iperflexer import sumparser  # pylint: disable=no-name-in-module
from utils.iperflexer import iperfexpressions  # pylint: disable=no-name-in-module
from utils.iperflexer.main import UNITS  # pylint: disable=no-name-in-module
from testlib.linux import tool_general
from testlib.linux.iperf import iperf_cmd

Line = namedtuple('Line', 'interval, transfer, t_units, bandwidth, b_units')

IPERF_UNITS = {
    'm': 'mbits',
    'k': 'kbits',
    'M': 'mbytes',
    'K': 'kbytes',
    'a': 'mbytes',
    'g': 'gbits',
    'G': 'gbytes',
}


class IPerfParser(sumparser.SumParser):
    """Class for parsing Iperf output.

    """

    def __init__(self, *args, **kwargs):
        """Initialize IPerfParser class.

        """
        if kwargs.get('units', None):
            kwargs['units'] = UNITS[kwargs['units']]
        super(IPerfParser, self).__init__(*args, **kwargs)
        self.format = iperfexpressions.ParserKeys.human

    def parse(self, output):
        """Parse output from iperf execution.

        Args:
            output(str): iperf output

        Returns:
            list:  list of parsed iperf results

        """
        results = []
        for line in output.splitlines():
            match = self.search(line)
            if match:
                start = float(match[iperfexpressions.ParserKeys.start])
                end = float(match[iperfexpressions.ParserKeys.end])
                bandwidth = self.bandwidth(match)
                transfer = self.transfer(match)
                results.append(Line((start, end),
                                    transfer,
                                    self._transfer_units,
                                    bandwidth,
                                    self.units))
        return results


class Iperf(tool_general.GenericTool):
    """Class for Iperf functionality.

    """

    def __init__(self, run_command):
        """Initialize Iperf class.

        Args:
            run_command(function): function that runs the actual commands

        """
        super(Iperf, self).__init__(run_command, 'iperf')

    def start(self, prefix=None, options=None, command=None, **kwargs):
        """Generate Iperf command, launch iperf and store results in the file.

        Args:
            prefix(str): command prefix
            options(list of str): intermediate iperf options list
            command(Command): intermediate iperf command object

        Returns:
            dict:  iperf instance process info

        """
        # intermediate operands in 'command' and 'options', if any,  prevail in this
        # respective order and overrule the (both default and set) method arguments
        cmd = iperf_cmd.CmdIperf(**kwargs)
        if options:
            _opts_cmd = iperf_cmd.CmdIperf(options)
            cmd.update(_opts_cmd)

        if command:
            cmd.update(command)

        cmd.check_args()
        args_list = cmd.to_args_list()

        # TODO: do we need timeout with systemd?
        cmd_time = cmd.get('time', 10)
        timeout = int(cmd_time) + 30 if cmd_time else 60

        cmd_list = [self.tool]
        if prefix:
            cmd_list = [prefix, self.tool]

        if args_list:
            cmd_list.extend(args_list)

        cmd_str = ' '.join(map(str, cmd_list))
        instance_id = super(Iperf, self).start(cmd_str, timeout=timeout)
        self.instances[instance_id]['iperf_cmd'] = cmd
        return instance_id

    def parse(self, output, parser=None, threads=1, units='m'):
        """Parse the Iperf output.

        Args:
            output(str):  Iperf origin output
            parser(IPerfParser): parser object
            threads(int): num iperf threads
            units(str): iperf units

        Returns:
            list:  list of parsed iperf results

        """
        if not parser:
            parser = IPerfParser(threads=threads, units=IPERF_UNITS[units])

        return parser.parse(output)
