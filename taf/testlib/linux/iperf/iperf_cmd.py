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

"""``iperf_cmd.py``

`iperf command parsing and building support`

"""

import itertools

from collections import OrderedDict
from argparse import ArgumentParser

from testlib.linux.commands.cmd_helper import Command, CommandHelper, ArgumentBuilder
from testlib.custom_exceptions import UnknownArguments, ArgumentsCollision

chain_it = itertools.chain.from_iterable


IPERF_GENERAL_OPTS = {
    'format': {
        'names': {'short': '-f', 'long': '--format'},
        'help': '[kmKM]   format to report: Kbits, Mbits, KBytes, MBytes',
        'choices': 'kmKM',
    },
    'help': {
        'names': {'short': '-h', 'long': '--help'},
        'help': 'print a help synopsis',
        'action': 'store_true',
    },
    'interval': {
        'names': {'short': '-i', 'long': '--interval'},
        'help': 'pause N seconds between periodic bandwidth reports',
        # 'default': 10,
        'type': int,
    },
    'len': {
        'names': {'short': '-l', 'long': '--len'},
        'help': '\\d+[KM] set length read/write buffer to N (default 8 KB)',
        'default': '8K',
    },
    'print_mss': {
        'names': {'short': '-m', 'long': '--print_mss'},
        'help': 'print TCP maximum segment size (MTU - TCP/IP header)',
        'action': 'store_true',
    },
    'output': {
        'names': {'short': '-o', 'long': '--output'},
        'help': 'output the report or error message to this specified file',
    },
    'port': {
        'names': {'short': '-p', 'long': '--port'},
        'help': 'set server port to listen on/connect to N (default 5001)',
        'default': '5001',
        'type': int,
    },
    'udp': {
        'names': {'short': '-u', 'long': '--udp'},
        'help': 'use UDP rather than TCP',
        'action': 'store_true',
    },
    'window': {
        'names': {'short': '-w', 'long': '--window'},
        'help': '\\d+[KM] TCP window size (socket buffer size)',
    },
    'bind': {
        'names': {'short': '-B', 'long': '--bind'},
        'help': 'bind to <host>, an interface or multicast address',
    },
    'compatibility': {
        'names': {'short': '-C', 'long': '--compatibility'},
        'help': 'for use with older versions does not send extra messages',
        'action': 'store_true',
    },
    'mss': {
        'names': {'short': '-M', 'long': '--mss'},
        'help': '\\d+ set TCP maximum segment size (MTU - 40 bytes)',
        'default': 40,
        'type': int,
    },
    'nodelay': {
        'names': {'short': '-N', 'long': '--nodelay'},
        'help': "set TCP no delay, disabling Nagle's Algorithm",
        'action': 'store_true',
    },
    'version': {
        'names': {'short': '-v', 'long': '--version'},
        'help': 'print version information and quit',
        'action': 'store_true',
    },
    'IPv6Version': {
        'names': {'short': '-V', 'long': '--IPv6Version'},
        'help': 'set the domain to IPv6',
        'action': 'store_true',
    },
    'reportexclude': {
        'names': {'short': '-X', 'long': '--reportexclude'},
        'help': '[CDMSV] exclude C(connection) D(data) M(multicast) S(settings) V(server) reports',
        'choices': 'CDMSV',
    },
    'reportstyle': {
        'names': {'short': '-m', 'long': '--print_mss'},
        'help': 'C|c if set to C or c report results as CSV',
        'choices': 'Cc',
    },
}
IPERF_SERVER_OPTS = {
    'server': {
        'names': {'short': '-s', 'long': '--server'},
        'help': 'run in server mode',
        'action': 'store_true',
    },
    'single_udp': {
        'names': {'short': '-U', 'long': '--single_udp'},
        'help': 'run in single threaded UDP mode',
        'action': 'store_true',
    },
    'daemon': {
        'names': {'short': '-D', 'long': '--daemon'},
        'help': 'run the server as a daemon',
        'action': 'store_true',
    },
}
IPERF_CLIENT_OPTS = {
    'bandwidth': {
        'names': {'short': '-b', 'long': '--bandwidth'},
        'help': '\\d+[KM] set target bandwidth to N bits/sec (default 1 Mbit.sec)\
                This setting requires UDP (-u)'
    },
    'client': {
        'names': {'short': '-c', 'long': '--client'},
        'help': 'run in client mode, connecting to <host>',
    },
    'dualtest': {
        'names': {'short': '-d', 'long': '--dualtest'},
        'help': 'do a bidirectional test simultaneously',
        'action': 'store_true',
    },
    'num': {
        'names': {'short': '-n', 'long': '--num'},
        'help': '\d[KM] number of bytes to transmit (instead of -t)',
    },
    'tradeoff': {
        'names': {'short': '-r', 'long': '--tradeoff'},
        'help': 'do a bidirectional test individually',
        'action': 'store_true',
    },
    'time': {
        'names': {'short': '-t', 'long': '--time'},
        'help': 'time in seconds to transmit for (default 10 secs)',
        'type': int,
    },
    'fileinput': {
        'names': {'short': '-F', 'long': '--fileinput'},
        'help': 'input the data to be transmitted from a file',
    },
    'stdin': {
        'names': {'short': '-I', 'long': '--stdin'},
        'help': 'input the data to be transmitted from stdin',
        'action': 'store_true',
    },
    'listenport': {
        'names': {'short': '-L', 'long': '--listenport'},
        'help': 'port to receive bidirectional tests back on',
        'type': int,
    },
    'parallel': {
        'names': {'short': '-P', 'long': '--parallel'},
        'help': 'number of parallel client threads to run',
        'type': int,
    },
    'ttl': {
        'names': {'short': '-T', 'long': '--ttl'},
        'help': 'time-to-live, for multicast (default 1)',
        'type': int,
    },
    'linux-congestion': {
        'names': {'short': '-Z', 'long': '--linux-congestion'},
        'help': 'set TCP congestino control algorithm (Linux only)',
    },
}

# specify the order of the output arguments when buildinig up a command
_IPERF_ARGS_ORDERED = OrderedDict.fromkeys(
    itertools.chain(['server', 'client'],
                    sorted(IPERF_SERVER_OPTS),
                    sorted(IPERF_CLIENT_OPTS),
                    sorted(IPERF_GENERAL_OPTS)))


class IperfArgumentBuilder(ArgumentBuilder):
    """
    """
    ARGS_ORDERED = list(_IPERF_ARGS_ORDERED.keys())

    @classmethod
    def get_formatter(cls):
        _formatter = {
            'optional': cls.FORMATTER_BY_VALUE_MAP(
                {
                    cls.__TRUE__: cls.FORMAT_KEY_BY_TAG('long'),
                    cls.__FALSE__: cls.FORMAT_NONE,
                    None: cls.FORMAT_NONE
                },
                default=cls.FORMATTER_JOIN_KEY_VAL(
                    key=cls.FORMAT_KEY_BY_TAG('long'),
                    joiner=cls.FORMAT_ARG_APPEND_LIST,
                    val=cls.FORMAT_VAL_TRANSFORM(str),
                )
            ),
            'positional': cls.FORMAT_VAL_TRANSFORM(str)
        }
        return _formatter

    def __init__(self):
        super(IperfArgumentBuilder, self).__init__(args_order=self.ARGS_ORDERED,
                                                   args_formatter=self.get_formatter())


class CmdIperfHelper(CommandHelper):
    """
    """
    @classmethod
    def check_args(cls, **kwargs):
        """Input command arguments checking API

        """
        __kwargs = cls._encode_args(**kwargs)
        return cls._check_args(**__kwargs)

    @classmethod
    def _check_args(cls, **__kwargs):
        kwargs = cls._decode_args(**__kwargs)
        is_server = kwargs.get('server', None)
        is_client = kwargs.get('client', None)
        if (is_server and is_client) or (not is_server and not is_client):
            raise ArgumentsCollision(server=is_server, client=is_client)

        if is_server:
            return cls._check_server_args(**__kwargs)

        return cls._check_client_args(**__kwargs)

    # TODO maybe put these outside the class to avoid name mangling?
    @classmethod
    def _check_server_args(cls, __server=False, __single_udp=None, __daemon=None, **__kwargs):
        assert __server
        return cls._check_general_args(**__kwargs)

    @classmethod
    def _check_client_args(cls, __client=None, __bandwidth=None, __dualtest=None, __num=None,
                           __stdin=None, __tradeoff=None, __time=None, __fileinput=None,
                           __listenport=None, __parallel=None, __ttl=None, __linux_congestion=None,
                           **__kwargs):
        assert __client
        return cls._check_general_args(**__kwargs)

    @classmethod
    def _check_general_args(cls, __format='m', __help=False, __interval=10, __len='8K',
                            __print_mss=False, __output=None, __port=5001, __udp=False,
                            __window=None, __bind=None, __compatibility=False, __mss=40,
                            __nodelay=False, __version=False, __IPv6Version=False,
                            __reportexclude=None, __reportstyle=None, **__kwargs):
        if __kwargs:
            raise UnknownArguments(**cls._decode_args(**__kwargs))

        return True


IPERF_PARSER = ArgumentParser(prog='iperf', conflict_handler='resolve')
IPERF_BUILDER = IperfArgumentBuilder()

_params_dict = dict(dict(IPERF_GENERAL_OPTS, **IPERF_SERVER_OPTS), **IPERF_CLIENT_OPTS)
iperf_cmd_kwargs = {
    'arg_parser':  IPERF_PARSER,
    'params':      _params_dict,
    'arg_builder': IPERF_BUILDER,
    'default_list': []
}
IPERF_CMD_HELPER = CmdIperfHelper(**iperf_cmd_kwargs)


class CmdIperf(Command):
    CMD_HELPER = IPERF_CMD_HELPER
