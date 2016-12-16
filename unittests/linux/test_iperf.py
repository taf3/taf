#!/usr/bin/env python
"""
@copyright Copyright (c) 2015-2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  test_iperf.py

@summary  IPerfRunner Unittests
"""
from unittest.mock import MagicMock

import pytest

from testlib.custom_exceptions import UnknownArguments, ArgumentsCollision

from testlib.linux.iperf import iperf_cmd

from testlib.linux.iperf import Iperf, IPerfParser, Line
from testlib.cli_template import CmdStatus

CLIENT_SINGLETHREAD = """
------------------------------------------------------------
Client connecting to 127.0.0.1, TCP port 5001
TCP window size:  169 KByte (default)
------------------------------------------------------------
[  3] local 127.0.0.1 port 42306 connected with 127.0.0.1 port 5001
[ ID] Interval       Transfer     Bandwidth
[  3]  0.0- 1.0 sec  3.95 GBytes  34.0 Gbits/sec
[  3]  1.0- 2.0 sec  3.97 GBytes  34.1 Gbits/sec
[  3]  2.0- 3.0 sec  3.75 GBytes  32.2 Gbits/sec
[  3]  3.0- 4.0 sec  3.91 GBytes  33.6 Gbits/sec
[  3]  4.0- 5.0 sec  3.92 GBytes  33.7 Gbits/sec
[  3]  5.0- 6.0 sec  3.94 GBytes  33.9 Gbits/sec
[  3]  6.0- 7.0 sec  3.95 GBytes  33.9 Gbits/sec
[  3]  7.0- 8.0 sec  3.85 GBytes  33.1 Gbits/sec
[  3]  8.0- 9.0 sec  3.86 GBytes  33.1 Gbits/sec
[  3]  9.0-10.0 sec  3.85 GBytes  33.1 Gbits/sec
[  3]  0.0-10.0 sec  39.0 GBytes  33.5 Gbits/sec
"""

SERVER_SINGLETHREAD = """
------------------------------------------------------------
Server listening on TCP port 5001
TCP window size: 85.3 KByte (default)
------------------------------------------------------------
[  4] local 127.0.0.1 port 5001 connected with 127.0.0.1 port 42306
[ ID] Interval       Transfer     Bandwidth
[  4]  0.0- 1.0 sec  3.95 GBytes  34.0 Gbits/sec
[  4]  1.0- 2.0 sec  3.97 GBytes  34.1 Gbits/sec
[  4]  2.0- 3.0 sec  3.75 GBytes  32.2 Gbits/sec
[  4]  3.0- 4.0 sec  3.91 GBytes  33.6 Gbits/sec
[  4]  4.0- 5.0 sec  3.92 GBytes  33.7 Gbits/sec
[  4]  5.0- 6.0 sec  3.94 GBytes  33.9 Gbits/sec
[  4]  6.0- 7.0 sec  3.95 GBytes  33.9 Gbits/sec
[  4]  7.0- 8.0 sec  3.85 GBytes  33.1 Gbits/sec
[  4]  8.0- 9.0 sec  3.86 GBytes  33.1 Gbits/sec
[  4]  9.0-10.0 sec  3.85 GBytes  33.1 Gbits/sec
[  4]  0.0-10.0 sec  39.0 GBytes  33.4 Gbits/sec
"""

CLIENT_MULTITHREAD = """
------------------------------------------------------------
Client connecting to 127.0.0.1, TCP port 5001
TCP window size: 0.00 GByte (default)
------------------------------------------------------------
[  4] local 127.0.0.1 port 42326 connected with 127.0.0.1 port 5001
[  3] local 127.0.0.1 port 42327 connected with 127.0.0.1 port 5001
[  5] local 127.0.0.1 port 42328 connected with 127.0.0.1 port 5001
[ ID] Interval       Transfer     Bandwidth
[  4]  0.0- 1.0 sec  3.02 GBytes  25.9 Gbits/sec
[  3]  0.0- 1.0 sec  2.48 GBytes  21.3 Gbits/sec
[  5]  0.0- 1.0 sec  2.31 GBytes  19.8 Gbits/sec
[SUM]  0.0- 1.0 sec  7.80 GBytes  67.0 Gbits/sec
[  4]  1.0- 2.0 sec  2.86 GBytes  24.6 Gbits/sec
[  3]  1.0- 2.0 sec  2.31 GBytes  19.8 Gbits/sec
[  5]  1.0- 2.0 sec  3.03 GBytes  26.0 Gbits/sec
[SUM]  1.0- 2.0 sec  8.20 GBytes  70.5 Gbits/sec
[  4]  2.0- 3.0 sec  3.66 GBytes  31.4 Gbits/sec
[  5]  2.0- 3.0 sec  2.21 GBytes  19.0 Gbits/sec
[  3]  2.0- 3.0 sec  2.15 GBytes  18.5 Gbits/sec
[SUM]  2.0- 3.0 sec  8.02 GBytes  68.9 Gbits/sec
[  4]  3.0- 4.0 sec  1.90 GBytes  16.3 Gbits/sec
[  3]  3.0- 4.0 sec  3.83 GBytes  32.9 Gbits/sec
[  5]  3.0- 4.0 sec  1.90 GBytes  16.3 Gbits/sec
[SUM]  3.0- 4.0 sec  7.64 GBytes  65.6 Gbits/sec
[  4]  4.0- 5.0 sec  2.19 GBytes  18.9 Gbits/sec
[  3]  4.0- 5.0 sec  3.06 GBytes  26.3 Gbits/sec
[  5]  4.0- 5.0 sec  2.82 GBytes  24.2 Gbits/sec
[SUM]  4.0- 5.0 sec  8.07 GBytes  69.3 Gbits/sec
[  4]  5.0- 6.0 sec  2.17 GBytes  18.6 Gbits/sec
[  3]  5.0- 6.0 sec  2.62 GBytes  22.5 Gbits/sec
[  5]  5.0- 6.0 sec  3.01 GBytes  25.9 Gbits/sec
[SUM]  5.0- 6.0 sec  7.80 GBytes  67.0 Gbits/sec
[  4]  6.0- 7.0 sec  3.69 GBytes  31.7 Gbits/sec
[  3]  6.0- 7.0 sec  2.03 GBytes  17.4 Gbits/sec
[  5]  6.0- 7.0 sec  2.00 GBytes  17.2 Gbits/sec
[SUM]  6.0- 7.0 sec  7.72 GBytes  66.3 Gbits/sec
[  4]  7.0- 8.0 sec  3.12 GBytes  26.8 Gbits/sec
[  3]  7.0- 8.0 sec  2.87 GBytes  24.6 Gbits/sec
[  5]  7.0- 8.0 sec  2.47 GBytes  21.3 Gbits/sec
[SUM]  7.0- 8.0 sec  8.46 GBytes  72.7 Gbits/sec
[  4]  8.0- 9.0 sec  3.37 GBytes  28.9 Gbits/sec
[  3]  8.0- 9.0 sec  2.40 GBytes  20.6 Gbits/sec
[  5]  8.0- 9.0 sec  2.34 GBytes  20.1 Gbits/sec
[SUM]  8.0- 9.0 sec  8.11 GBytes  69.6 Gbits/sec
[  3]  0.0-10.0 sec  26.3 GBytes  22.6 Gbits/sec
[  5]  0.0-10.0 sec  24.9 GBytes  21.4 Gbits/sec
[  4]  9.0-10.0 sec  2.64 GBytes  22.6 Gbits/sec
[  4]  0.0-10.0 sec  28.6 GBytes  24.6 Gbits/sec
[SUM]  0.0-10.0 sec  79.8 GBytes  68.5 Gbits/sec
"""

SERVER_MULTITHREAD = """
------------------------------------------------------------
Server listening on TCP port 5001
TCP window size: 0.00 GByte (default)
------------------------------------------------------------
[  4] local 127.0.0.1 port 5001 connected with 127.0.0.1 port 42326
[  6] local 127.0.0.1 port 5001 connected with 127.0.0.1 port 42328
[  5] local 127.0.0.1 port 5001 connected with 127.0.0.1 port 42327
[ ID] Interval       Transfer     Bandwidth
[  6]  0.0- 1.0 sec  2.31 GBytes  19.8 Gbits/sec
[  5]  0.0- 1.0 sec  2.48 GBytes  21.3 Gbits/sec
[  4]  0.0- 1.0 sec  3.02 GBytes  25.9 Gbits/sec
[SUM]  0.0- 1.0 sec  7.80 GBytes  67.0 Gbits/sec
[  4]  1.0- 2.0 sec  2.86 GBytes  24.6 Gbits/sec
[  6]  1.0- 2.0 sec  3.03 GBytes  26.0 Gbits/sec
[  5]  1.0- 2.0 sec  2.31 GBytes  19.8 Gbits/sec
[SUM]  1.0- 2.0 sec  8.20 GBytes  70.5 Gbits/sec
[  4]  2.0- 3.0 sec  3.66 GBytes  31.4 Gbits/sec
[  6]  2.0- 3.0 sec  2.21 GBytes  19.0 Gbits/sec
[  5]  2.0- 3.0 sec  2.15 GBytes  18.5 Gbits/sec
[SUM]  2.0- 3.0 sec  8.02 GBytes  68.9 Gbits/sec
[  4]  3.0- 4.0 sec  1.90 GBytes  16.3 Gbits/sec
[  5]  3.0- 4.0 sec  3.83 GBytes  32.9 Gbits/sec
[  6]  3.0- 4.0 sec  1.90 GBytes  16.3 Gbits/sec
[SUM]  3.0- 4.0 sec  7.64 GBytes  65.6 Gbits/sec
[  4]  4.0- 5.0 sec  2.19 GBytes  18.9 Gbits/sec
[  5]  4.0- 5.0 sec  3.06 GBytes  26.3 Gbits/sec
[  6]  4.0- 5.0 sec  2.82 GBytes  24.2 Gbits/sec
[SUM]  4.0- 5.0 sec  8.07 GBytes  69.3 Gbits/sec
[  4]  5.0- 6.0 sec  2.17 GBytes  18.6 Gbits/sec
[  6]  5.0- 6.0 sec  3.02 GBytes  25.9 Gbits/sec
[  5]  5.0- 6.0 sec  2.62 GBytes  22.5 Gbits/sec
[SUM]  5.0- 6.0 sec  7.80 GBytes  67.0 Gbits/sec
[  4]  6.0- 7.0 sec  3.69 GBytes  31.7 Gbits/sec
[  6]  6.0- 7.0 sec  2.00 GBytes  17.2 Gbits/sec
[  5]  6.0- 7.0 sec  2.03 GBytes  17.4 Gbits/sec
[SUM]  6.0- 7.0 sec  7.72 GBytes  66.3 Gbits/sec
[  4]  7.0- 8.0 sec  3.12 GBytes  26.8 Gbits/sec
[  6]  7.0- 8.0 sec  2.47 GBytes  21.3 Gbits/sec
[  5]  7.0- 8.0 sec  2.87 GBytes  24.6 Gbits/sec
[SUM]  7.0- 8.0 sec  8.46 GBytes  72.7 Gbits/sec
[  4]  8.0- 9.0 sec  3.37 GBytes  28.9 Gbits/sec
[  6]  8.0- 9.0 sec  2.34 GBytes  20.1 Gbits/sec
[  5]  8.0- 9.0 sec  2.40 GBytes  20.6 Gbits/sec
[SUM]  8.0- 9.0 sec  8.11 GBytes  69.6 Gbits/sec
[  4]  9.0-10.0 sec  2.64 GBytes  22.6 Gbits/sec
[  6]  9.0-10.0 sec  2.82 GBytes  24.2 Gbits/sec
[  6]  0.0-10.0 sec  24.9 GBytes  21.4 Gbits/sec
[  5]  9.0-10.0 sec  2.54 GBytes  21.9 Gbits/sec
[SUM]  9.0-10.0 sec  8.00 GBytes  68.7 Gbits/sec
[  5]  0.0-10.0 sec  26.3 GBytes  22.6 Gbits/sec
[  4]  0.0-10.0 sec  28.6 GBytes  24.5 Gbits/sec
[SUM]  0.0-10.0 sec  79.8 GBytes  68.5 Gbits/sec
"""


class TestIPerfParser(object):

    def test_single_thread_client_output(self):
        parser = IPerfParser(threads=1)
        results = parser.parse(CLIENT_SINGLETHREAD)
        assert results == [Line((0.0, 1.0), 3.95 * 1024, 'MBytes', 34.0 * 1000, 'Mbits'),
                           Line((1.0, 2.0), 3.97 * 1024, 'MBytes', 34.1 * 1000, 'Mbits'),
                           Line((2.0, 3.0), 3.75 * 1024, 'MBytes', 32.2 * 1000, 'Mbits'),
                           Line((3.0, 4.0), 3.91 * 1024, 'MBytes', 33.6 * 1000, 'Mbits'),
                           Line((4.0, 5.0), 3.92 * 1024, 'MBytes', 33.7 * 1000, 'Mbits'),
                           Line((5.0, 6.0), 3.94 * 1024, 'MBytes', 33.9 * 1000, 'Mbits'),
                           Line((6.0, 7.0), 3.95 * 1024, 'MBytes', 33.9 * 1000, 'Mbits'),
                           Line((7.0, 8.0), 3.85 * 1024, 'MBytes', 33.1 * 1000, 'Mbits'),
                           Line((8.0, 9.0), 3.86 * 1024, 'MBytes', 33.1 * 1000, 'Mbits'),
                           Line((9.0, 10.0), 3.85 * 1024, 'MBytes', 33.1 * 1000, 'Mbits'),
                           Line((0.0, 10.0), 39.0 * 1024, 'MBytes', 33.5 * 1000, 'Mbits')]

    def test_single_thread_client_output_gbytes_format(self):
        parser = IPerfParser(threads=1, units='gbytes')
        results = parser.parse(CLIENT_SINGLETHREAD)
        assert results == [Line((0.0, 1.0), 3.95, 'GBytes', 34.0 / 8, 'GBytes'),
                           Line((1.0, 2.0), 3.97, 'GBytes', 34.1 / 8, 'GBytes'),
                           Line((2.0, 3.0), 3.75, 'GBytes', 32.2 / 8, 'GBytes'),
                           Line((3.0, 4.0), 3.91, 'GBytes', 33.6 / 8, 'GBytes'),
                           Line((4.0, 5.0), 3.92, 'GBytes', 33.7 / 8, 'GBytes'),
                           Line((5.0, 6.0), 3.94, 'GBytes', 33.9 / 8, 'GBytes'),
                           Line((6.0, 7.0), 3.95, 'GBytes', 33.9 / 8, 'GBytes'),
                           Line((7.0, 8.0), 3.85, 'GBytes', 33.1 / 8, 'GBytes'),
                           Line((8.0, 9.0), 3.86, 'GBytes', 33.1 / 8, 'GBytes'),
                           Line((9.0, 10.0), 3.85, 'GBytes', 33.1 / 8, 'GBytes'),
                           Line((0.0, 10.0), 39.0, 'GBytes', 33.5 / 8, 'GBytes')]

    def test_single_thread_server_output(self):
        parser = IPerfParser(threads=1)
        results = parser.parse(SERVER_SINGLETHREAD)
        assert results == [Line((0.0, 1.0), 3.95 * 1024, 'MBytes', 34.0 * 1000, 'Mbits'),
                           Line((1.0, 2.0), 3.97 * 1024, 'MBytes', 34.1 * 1000, 'Mbits'),
                           Line((2.0, 3.0), 3.75 * 1024, 'MBytes', 32.2 * 1000, 'Mbits'),
                           Line((3.0, 4.0), 3.91 * 1024, 'MBytes', 33.6 * 1000, 'Mbits'),
                           Line((4.0, 5.0), 3.92 * 1024, 'MBytes', 33.7 * 1000, 'Mbits'),
                           Line((5.0, 6.0), 3.94 * 1024, 'MBytes', 33.9 * 1000, 'Mbits'),
                           Line((6.0, 7.0), 3.95 * 1024, 'MBytes', 33.9 * 1000, 'Mbits'),
                           Line((7.0, 8.0), 3.85 * 1024, 'MBytes', 33.1 * 1000, 'Mbits'),
                           Line((8.0, 9.0), 3.86 * 1024, 'MBytes', 33.1 * 1000, 'Mbits'),
                           Line((9.0, 10.0), 3.85 * 1024, 'MBytes', 33.1 * 1000, 'Mbits'),
                           Line((0.0, 10.0), 39.0 * 1024, 'MBytes', 33.4 * 1000, 'Mbits')]

    def test_single_thread_server_output_gbits_format(self):
        parser = IPerfParser(threads=1, units='gbits')
        results = parser.parse(CLIENT_SINGLETHREAD)
        assert results == [Line((0.0, 1.0), 3.95, 'GBytes', 34.0, 'Gbits'),
                           Line((1.0, 2.0), 3.97, 'GBytes', 34.1, 'Gbits'),
                           Line((2.0, 3.0), 3.75, 'GBytes', 32.2, 'Gbits'),
                           Line((3.0, 4.0), 3.91, 'GBytes', 33.6, 'Gbits'),
                           Line((4.0, 5.0), 3.92, 'GBytes', 33.7, 'Gbits'),
                           Line((5.0, 6.0), 3.94, 'GBytes', 33.9, 'Gbits'),
                           Line((6.0, 7.0), 3.95, 'GBytes', 33.9, 'Gbits'),
                           Line((7.0, 8.0), 3.85, 'GBytes', 33.1, 'Gbits'),
                           Line((8.0, 9.0), 3.86, 'GBytes', 33.1, 'Gbits'),
                           Line((9.0, 10.0), 3.85, 'GBytes', 33.1, 'Gbits'),
                           Line((0.0, 10.0), 39.0, 'GBytes', 33.5, 'Gbits')]

    def test_multi_thread_client_output(self):
        parser = IPerfParser(threads=3)
        results = parser.parse(CLIENT_MULTITHREAD)
        assert results == [Line((0.0, 1.0), 7.8 * 1024, 'MBytes', 67.0 * 1000, 'Mbits'),
                           Line((1.0, 2.0), 8.2 * 1024, 'MBytes', 70.5 * 1000, 'Mbits'),
                           Line((2.0, 3.0), 8.02 * 1024, 'MBytes', 68.9 * 1000, 'Mbits'),
                           Line((3.0, 4.0), 7.64 * 1024, 'MBytes', 65.6 * 1000, 'Mbits'),
                           Line((4.0, 5.0), 8.07 * 1024, 'MBytes', 69.3 * 1000, 'Mbits'),
                           Line((5.0, 6.0), 7.8 * 1024, 'MBytes', 67.0 * 1000, 'Mbits'),
                           Line((6.0, 7.0), 7.72 * 1024, 'MBytes', 66.3 * 1000, 'Mbits'),
                           Line((7.0, 8.0), 8.46 * 1024, 'MBytes', 72.7 * 1000, 'Mbits'),
                           Line((8.0, 9.0), 8.11 * 1024, 'MBytes', 69.6 * 1000, 'Mbits'),
                           Line((0.0, 10.0), 79.8 * 1024, 'MBytes', 68.5 * 1000, 'Mbits')]

    def test_multi_thread_server_output(self):
        parser = IPerfParser(threads=3)
        results = parser.parse(SERVER_MULTITHREAD)
        assert results == [Line((0.0, 1.0), 7.8 * 1024, 'MBytes', 67.0 * 1000, 'Mbits'),
                           Line((1.0, 2.0), 8.2 * 1024, 'MBytes', 70.5 * 1000, 'Mbits'),
                           Line((2.0, 3.0), 8.02 * 1024, 'MBytes', 68.9 * 1000, 'Mbits'),
                           Line((3.0, 4.0), 7.64 * 1024, 'MBytes', 65.6 * 1000, 'Mbits'),
                           Line((4.0, 5.0), 8.07 * 1024, 'MBytes', 69.3 * 1000, 'Mbits'),
                           Line((5.0, 6.0), 7.8 * 1024, 'MBytes', 67.0 * 1000, 'Mbits'),
                           Line((6.0, 7.0), 7.72 * 1024, 'MBytes', 66.3 * 1000, 'Mbits'),
                           Line((7.0, 8.0), 8.46 * 1024, 'MBytes', 72.7 * 1000, 'Mbits'),
                           Line((8.0, 9.0), 8.11 * 1024, 'MBytes', 69.6 * 1000, 'Mbits'),
                           Line((9.0, 10.0), 8.0 * 1024, 'MBytes', 68.7 * 1000, 'Mbits'),
                           Line((0.0, 10.0), 79.8 * 1024, 'MBytes', 68.5 * 1000, 'Mbits')]


class TestIperf(object):

    host = '127.0.0.1'
    user = 'admin'
    password = 'admin'

    @classmethod
    def _side_effect(cls, *args, **kwargs):
        if 'journalct' in args[0]:
            return CmdStatus(CLIENT_SINGLETHREAD, "", 0)
        return CmdStatus("", "", 0)

    @pytest.fixture
    def runner(self):
        runner = Iperf(MagicMock(side_effect=self._side_effect))
        return runner

    @classmethod
    def _build_args_list(cls, out_list, out_dict, out_map):
        _marker = object()

        cmd_list = []
        for arg_k in out_list:
            arg_v = out_dict.get(arg_k, _marker)
            if arg_v != _marker:
                assert arg_k in out_map
                out_k = out_map[arg_k]

                if arg_v is None:
                    cmd_list.append(str(out_k))
                else:
                    cmd_list.extend(map(str, [out_k, arg_v]))

        return cmd_list

    @classmethod
    def _parse_linux_cmd(cls, cmd_str, name=None):
        """
        Extract the command arguments from a linux command line string
        """
        # TODO employ regexp parsing instead of the str operations
        # remove first 4 words
        cmds = cmd_str.split()[4:]
        if cmds[0] == name:
            cmds.pop(0)
        return cmds

    def _run_and_parse(self, runner, **kwargs):
        runner.start(**kwargs)

        # Verify command sequence for client launch
        commands = [x[0][0] for x in runner.run_command.call_args_list]
        return self._parse_linux_cmd(commands[0], name='iperf')

    def test_iperf_runner_start_empty(self, runner):
        with pytest.raises(ArgumentsCollision):
            runner.start()

    def test_iperf_runner_start_unknown(self, runner):
        with pytest.raises(UnknownArguments):
            runner.start(unknown_argument=object())

    def test_iperf_runner_start_server_and_client(self, runner):
        with pytest.raises(ArgumentsCollision):
            runner.start(server=True, client='localhost')

    def test_iperf_runner_start_server_empty(self, runner):
        iperf_kwargs = {
            'server': True
        }
        runner_kwargs = dict(iperf_kwargs)

        _expected_cmd_list = ['--server']
        _cmd_list = self._run_and_parse(runner, **runner_kwargs)
        assert _cmd_list == _expected_cmd_list

    def test_iperf_runner_start_server_kwargs(self, runner):
        iperf_kwargs = {
            'server': True,
            'bind': '192.168.1.10',
            'format': 'g',
            'interval': 1,
            'udp': True
        }
        runner_kwargs = dict(iperf_kwargs)

        output_list = ['server', 'bind', 'format', 'interval', 'udp']
        output_dict = {
            'server': None,
            'bind': '192.168.1.10',
            'format': 'g',
            'interval': 1,
            'udp': None
        }
        output_map = {
            'server': '--server',
            'bind': '--bind',
            'format': '--format',
            'interval': '--interval',
            'udp': '--udp'
        }

        _expected_args_list = self._build_args_list(output_list, output_dict, output_map)
        _args_list = self._run_and_parse(runner, **runner_kwargs)
        assert _args_list == _expected_args_list

    def test_iperf_runner_start_server_with_options(self, runner):
        iperf_kwargs = dict(
            {
                'server': True,
                # 'bind': '192.168.1.10',
                'format': 'g',
                'interval': 1,
                'udp': True
            },
            options=['--bind', '192.168.1.10']
        )
        runner_kwargs = dict(iperf_kwargs)

        output_list = ['server', 'bind', 'format', 'interval', 'udp']
        output_dict = {
            'server': None,
            'bind': '192.168.1.10',
            'format': 'g',
            'interval': 1,
            'udp': None
        }
        output_map = {
            'server': '--server',
            'bind': '--bind',
            'format': '--format',
            'interval': '--interval',
            'udp': '--udp'
        }

        _expected_args_list = self._build_args_list(output_list, output_dict, output_map)
        _args_list = self._run_and_parse(runner, **runner_kwargs)
        assert _args_list == _expected_args_list

    def test_iperf_runner_start_server_command(self, runner):
        iperf_cmd_kwargs = {
            'server': True,
            'bind': '192.168.1.10',
            'format': 'g',
            'interval': 1,
            'udp': True
        }
        runner_kwargs = dict(command=iperf_cmd.CmdIperf(**iperf_cmd_kwargs))

        output_list = ['server', 'bind', 'format', 'interval', 'udp']
        output_dict = {
            'server': None,
            'bind': '192.168.1.10',
            'format': 'g',
            'interval': 1,
            'udp': None
        }
        output_map = {
            'server': '--server',
            'bind': '--bind',
            'format': '--format',
            'interval': '--interval',
            'udp': '--udp'
        }

        _expected_args_list = self._build_args_list(output_list, output_dict, output_map)
        _args_list = self._run_and_parse(runner, **runner_kwargs)
        assert _args_list == _expected_args_list

    def test_iperf_runner_start_server_command_kwargs(self, runner):
        iperf_cmd_kwargs = {
            'server': True,
            'bind': '192.168.2.20',
            'format': 'g',
            'interval': 10,
            'udp': True
        }
        iperf_kwargs = dict(
            iperf_cmd_kwargs,
            options=['--format', 'k',
                     '--interval', '100'],
            command=iperf_cmd.CmdIperf(server=True,
                                       interval=1000,
                                       bind='192.168.2.2')
        )
        runner_kwargs = dict(iperf_kwargs)

        output_list = ['server', 'bind', 'format', 'interval', 'udp']
        output_dict = {
            'server': None,
            'bind': '192.168.2.2',
            'format': 'k',
            'interval': 1000,
            'udp': None
        }
        output_map = {
            'server': '--server',
            'bind': '--bind',
            'format': '--format',
            'interval': '--interval',
            'udp': '--udp'
        }

        _expected_args_list = self._build_args_list(output_list, output_dict, output_map)
        _args_list = self._run_and_parse(runner, **runner_kwargs)
        assert _args_list == _expected_args_list

    def test_iperf_runner_start_client_empty(self, runner):
        iperf_kwargs = {
            'client': '192.168.1.11'
        }
        runner_kwargs = dict(iperf_kwargs)

        _expected_cmd_list = ['--client', '192.168.1.11']
        _cmd_list = self._run_and_parse(runner, **runner_kwargs)
        assert _cmd_list == _expected_cmd_list

    def test_iperf_runner_start_client_kwargs(self, runner):
        iperf_kwargs = {
            'client': '192.168.1.11',
            'parallel': 2,
            'bind': '192.168.1.10',
            'format': 'k',
            'interval': 1,
            'udp': True
        }
        runner_kwargs = dict(iperf_kwargs)

        output_list = ['client', 'parallel', 'bind', 'format', 'interval', 'udp']
        output_dict = {
            'client': '192.168.1.11',
            'parallel': 2,
            'bind': '192.168.1.10',
            'format': 'k',
            'interval': 1,
            'udp': None
        }
        output_map = {
            'client': '--client',
            'parallel': '--parallel',
            'bind': '--bind',
            'format': '--format',
            'interval': '--interval',
            'udp': '--udp'
        }

        _expected_args_list = self._build_args_list(output_list, output_dict, output_map)
        _args_list = self._run_and_parse(runner, **runner_kwargs)
        assert _args_list == _expected_args_list

    def test_iperf_runner_start_client_with_options(self, runner):
        iperf_cmd_kwargs = {
            'client': '192.168.1.11',
        }
        iperf_kwargs = dict(
            iperf_cmd_kwargs,
            options=['--udp',
                     '--format', 'k',
                     '--bind', '192.168.1.10']
        )
        runner_kwargs = dict(iperf_kwargs)

        output_list = ['client', 'bind', 'format', 'udp']
        output_dict = {
            'client': '192.168.1.11',
            'bind': '192.168.1.10',
            'format': 'k',
            'udp': None
        }
        output_map = {
            'client': '--client',
            'parallel': '--parallel',
            'bind': '--bind',
            'format': '--format',
            'interval': '--interval',
            'udp': '--udp'
        }

        _expected_args_list = self._build_args_list(output_list, output_dict, output_map)
        _args_list = self._run_and_parse(runner, **runner_kwargs)
        assert _args_list == _expected_args_list

    def test_iperf_runner_start_client_command(self, runner):
        iperf_cmd_kwargs = {
            'client': '192.168.1.11',
            'parallel': 2,
            'time': 10,
            'bind': '192.168.1.10',
            'format': 'g',
            'interval': 1,
            'udp': True
        }
        runner_kwargs = dict(
            command=iperf_cmd.CmdIperf(**iperf_cmd_kwargs)
        )

        output_list = ['client', 'parallel', 'time', 'bind', 'format', 'interval', 'udp']
        output_dict = {
            'client': '192.168.1.11',
            'parallel': 2,
            'time': 10,
            'bind': '192.168.1.10',
            'format': 'g',
            'interval': 1,
            'udp': None
        }
        output_map = {
            'client': '--client',
            'parallel': '--parallel',
            'time': '--time',
            'bind': '--bind',
            'format': '--format',
            'interval': '--interval',
            'udp': '--udp'
        }

        _expected_args_list = self._build_args_list(output_list, output_dict, output_map)
        _args_list = self._run_and_parse(runner, **runner_kwargs)
        assert _args_list == _expected_args_list

    def test_iperf_runner_get_results(self, runner):
        service_name = 'unittest'
        runner.instances[1] = {'service_name': service_name}
        output = runner.get_results(1)

        # Verify command sequence
        commands = [x[0][0] for x in runner.run_command.call_args_list]
        assert commands == ['journalctl --no-pager -o cat -u {}'.format(service_name)]

        # Verify output
        assert output == CLIENT_SINGLETHREAD

    def test_iperf_runner_parse(self, runner):
        iperf_kwargs = {
            'server': True
        }
        runner_kwargs = dict(iperf_kwargs)
        iperf_instance = runner.start(**runner_kwargs)
        assert iperf_instance

        cmd = runner.instances[iperf_instance]['iperf_cmd']
        _format = cmd.get('format', 'M')
        parallel = cmd.get('parallel', 1)
        output = runner.parse(CLIENT_SINGLETHREAD, units=_format, threads=parallel)
        assert output == [Line((0.0, 1.0), 3.95 * 1024, 'MBytes', 34.0 * 1000 / 8, 'MBytes'),
                          Line((1.0, 2.0), 3.97 * 1024, 'MBytes', 34.1 * 1000 / 8, 'MBytes'),
                          Line((2.0, 3.0), 3.75 * 1024, 'MBytes', 32.2 * 1000 / 8, 'MBytes'),
                          Line((3.0, 4.0), 3.91 * 1024, 'MBytes', 33.6 * 1000 / 8, 'MBytes'),
                          Line((4.0, 5.0), 3.92 * 1024, 'MBytes', 33.7 * 1000 / 8, 'MBytes'),
                          Line((5.0, 6.0), 3.94 * 1024, 'MBytes', 33.9 * 1000 / 8, 'MBytes'),
                          Line((6.0, 7.0), 3.95 * 1024, 'MBytes', 33.9 * 1000 / 8, 'MBytes'),
                          Line((7.0, 8.0), 3.85 * 1024, 'MBytes', 33.1 * 1000 / 8, 'MBytes'),
                          Line((8.0, 9.0), 3.86 * 1024, 'MBytes', 33.1 * 1000 / 8, 'MBytes'),
                          Line((9.0, 10.0), 3.85 * 1024, 'MBytes', 33.1 * 1000 / 8, 'MBytes'),
                          Line((0.0, 10.0), 39.0 * 1024, 'MBytes', 33.5 * 1000 / 8, 'MBytes')]

    def test_iperf_runner_parse_gbytes_format(self, runner):
        iperf_kwargs = {
            'server': True,
            'format': 'G'
        }
        runner_kwargs = dict(iperf_kwargs)
        iperf_instance = runner.start(**runner_kwargs)
        assert iperf_instance

        cmd = runner.instances[iperf_instance]['iperf_cmd']
        _format = cmd.get('format', 'M')
        output = runner.parse(CLIENT_SINGLETHREAD, units=_format)
        assert output == [Line((0.0, 1.0), 3.95, 'GBytes', 34.0 / 8, 'GBytes'),
                          Line((1.0, 2.0), 3.97, 'GBytes', 34.1 / 8, 'GBytes'),
                          Line((2.0, 3.0), 3.75, 'GBytes', 32.2 / 8, 'GBytes'),
                          Line((3.0, 4.0), 3.91, 'GBytes', 33.6 / 8, 'GBytes'),
                          Line((4.0, 5.0), 3.92, 'GBytes', 33.7 / 8, 'GBytes'),
                          Line((5.0, 6.0), 3.94, 'GBytes', 33.9 / 8, 'GBytes'),
                          Line((6.0, 7.0), 3.95, 'GBytes', 33.9 / 8, 'GBytes'),
                          Line((7.0, 8.0), 3.85, 'GBytes', 33.1 / 8, 'GBytes'),
                          Line((8.0, 9.0), 3.86, 'GBytes', 33.1 / 8, 'GBytes'),
                          Line((9.0, 10.0), 3.85, 'GBytes', 33.1 / 8, 'GBytes'),
                          Line((0.0, 10.0), 39.0, 'GBytes', 33.5 / 8, 'GBytes')]
