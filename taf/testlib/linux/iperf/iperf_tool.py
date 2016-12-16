#!/usr/bin/env python
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

@file  iperf_tool.py

@summary  Standalone script for Iperf manipulation
"""

import argparse
import os
import time

from .iperf import Iperf
from testlib import loggers
from testlib import clissh
from testlib.custom_exceptions import TAFCoreException


mod_logger = loggers.module_logger(__name__)


class IPerfRunner(object):
    """
    @description Run Iperf on the remote host
    """

    def __init__(self, host, user, password):
        """
        @brief  Initialize IPerfRunner class
        """
        super(IPerfRunner, self).__init__()
        self.host = host
        self.user = user
        self.password = password
        self.ssh = clissh.CLISSH(host, 22, user, password, sudo_prompt="Password:")

    def execute_command(self, command, timeout=10, expected_rcs=frozenset({0})):
        """
        @brief  Execute command on the remote host
        @param command: command to execute
        @type  command:  str
        @param timeout: timeout for command execution
        @type  timeout: int
        @param expected_rcs: expected return code values
        @type  expected_rcs:  set
        @raise TAFCoreException: unexpected return code or sdterr
        @rtype:  tuple(stdout, sdterr, rc)
        @return:  command execution result
        """
        cmd_status = self.ssh.exec_command(command, timeout=timeout)
        if int(cmd_status.rc) not in expected_rcs:
            raise TAFCoreException(
                "Return code is {0}, expected {1} on command '{2}'.".format(
                    cmd_status.rc, expected_rcs, command))
        if cmd_status.stderr:
            raise TAFCoreException(
                "Command returns error: stdout {0}, stderr {1}, rc {2} on command '{3}'.".format(
                    cmd_status.stdout, cmd_status.stderr, cmd_status.rc, command))
        return cmd_status

    def run(self, **kwargs):
        """
        @brief  Connect to the remote host, run iperf and parse output
        @param server: iperf server IP address
        @type  server:  str
        @param threads: iperf connections count
        @type  threads:  int
        @param interval: iperf interval time
        @type  interval:  int
        @param time: time of iperf execution
        @type  time:  int
        @param bind: host IP address for bind to
        @type  bind:  str
        @param udp_mode: flag for launch iperf in UDP mode
        @type  udp_mode:  bool
        @param port: iperf L4 port
        @type  port:  int
        @param units: iperf bandwidth format
        @type  units:  str
        @param iperf_file: file to store iperf origin output
        @type  iperf_file:  str
        @rtype:  list(tuple)
        @return:  list of parsed iperf results
        """
        try:
            self.ssh.login()
            self.ssh.open_shell()
            iperf = Iperf(self.execute_command)
            iperf_id = iperf.start(**kwargs)
            time.sleep(int(kwargs['time']) + 2)
            iperf.stop(iperf_id)
            return iperf.parse(iperf.get_results(iperf_id), iperf_id)
        finally:
            if self.ssh:
                self.ssh.close()


def create_argparser():
    arg_parser = argparse.ArgumentParser(
        description="Execute iperf on remote host and parse output")

    arg_parser.add_argument(
        '--host',
        required=True,
        help='remote host info',
    )

    arg_parser.add_argument(
        '--user',
        required=True,
        help='remote host user',
    )

    arg_parser.add_argument(
        '--password',
        required=True,
        help='remote host user password',
    )

    arg_parser.add_argument(
        '-c', '--server',
        required=False,
        help='iperf server info',
        default=None,
        action="store"
    )

    arg_parser.add_argument(
        '-t', '--timeout',
        required=False,
        help='iperf timeout',
        default=10,
        action="store"
    )

    arg_parser.add_argument(
        '-i', '--interval',
        required=False,
        help='iperf interval',
        default=0,
        action="store"
    )

    arg_parser.add_argument(
        '-B', '--bind',
        required=False,
        help='iperf bind value',
        default=None,
        action="store"
    )

    arg_parser.add_argument(
        '-u', '--udp_mode',
        required=False,
        help='iperf traffic mode udp',
        default=False,
        action="store_true"
    )

    arg_parser.add_argument(
        '-b', '--bandwidth',
        required=False,
        help='iperf bandwidth value',
        default=None,
        action="store"
    )

    arg_parser.add_argument(
        '-P', '--threads',
        required=False,
        help='iperf threads info',
        default=1,
        action="store"
    )

    arg_parser.add_argument(
        '-p', '--port',
        required=False,
        help='iperf TCP port',
        default=None,
        action="store"
    )

    arg_parser.add_argument(
        '-f', '--units',
        required=False,
        help='iperf units info',
        default='a',
        action="store"
    )

    arg_parser.add_argument(
        '--loglevel',
        help='Set log_level, default: %(default)s',
        choices=[x for x in loggers.levels],
        action="store",
        default='INFO'
    )

    return arg_parser


def main(args):
    """ Execute iperf on the remote host """
    host = IPerfRunner(args.host, args.user, args.password)
    res = host.run(server=args.server, threads=args.threads, interval=args.interval,
                   time=args.timeout, bind=args.bind, udp_mode=args.udp_mode,
                   port=args.port, units=args.units, bandwidth=args.bandwidth)
    for line in res:
        mod_logger.info(line)


if __name__ == '__main__':

    _arg_parser = create_argparser()
    _args = _arg_parser.parse_args()

    raise SystemExit(main(_args))
