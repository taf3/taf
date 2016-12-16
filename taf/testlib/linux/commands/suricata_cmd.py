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

@file  suricata_cmd.py

@summary  suricata command parsing and building support
"""

import itertools

from collections import OrderedDict
from argparse import ArgumentParser

from testlib.linux.commands.cmd_helper import Command, CommandHelper, ArgumentBuilder
from testlib.custom_exceptions import UnknownArguments


SURICATA_OPTS = {
    'test_config': {
        'names': {'short': '-T'},
        'help': 'test configuration file (use with -c)',
    },
    'daemon': {
        'names': {'short': '-D'},
        'help': 'run as daemon',
    },
    'version': {
        'names': {'short': '-V'},
        'help': 'display Suricata version',
    },
    'verbosity': {
        'names': {'short': '-v'},  # , 'long': '-vv'},
        'help': 'increase default Suricata verbosity',
    },
    'list_app_layer_prots': {
        'names': {'long': '--list-app-layer-protos'},
        'help': 'list supported app layer protocols',
    },
    'list_runmodes': {
        'names': {'long': '--list-runmodes'},
        'help': 'list supported runmodes',
    },
    'engine_analysis': {
        'names': {'long': '--engine-analysis'},
        'help': 'print reports on analysis of different sections in the engine and exit. \
                Please have a look at the conf parameter engine-analysis on what reports \
                can be printed',
    },
    'init_errors_fatal': {
        'names': {'long': '--init-errors-fatal'},
        'help': 'enable fatal failure on signature init error',
    },
    'disable_detection': {
        'names': {'long': '--disable-detection'},
        'help': 'disable detection engine',
    },
    'dump_config': {
        'names': {'long': '--dump-config'},
        'help': 'show the running configuration',
    },
    'build_info': {
        'names': {'long': '--build-info'},
        'help': 'display build information',
    }
}


SURICATA_KEYWORDS = {
    'config': {
        'names': {'short': '-c'},
        'help': '<path>: path to configuration file'
    },
    'pcap_live_mode': {
        'names': {'short': '-i'},
        'help': '<dev or ip>: run in pcap live mode'
    },
    'bpf_filter': {
        'names': {'short': '-F'},
        'help': '<bpf filter file>: bpf filter file'
    },
    'pcap_offline_mode': {
        'names': {'short': '-r'},
        'help': '<path>: run in pcap file/offline mode'
    },
    'inline_nfqueue_mode': {
        'names': {'short': '-q'},
        'help': '<qid>: run in inline nfqueue mode'
    },
    'sig_file': {
        'names': {'short': '-s'},
        'help':  '<path>: path to signature file loaded in addition to suricata.yaml \
                 settings (optional)'
    },
    'sig_exc_file': {
        'names': {'short': '-S'},
        'help': '<path>: path to signature file loaded exclusively (optional)'
    },
    'log_dir': {
        'names': {'short': '-l'},
        'help': '<dir>: default log directory'
    },
    'checksum_check': {
        'names': {'short': '-k'},
        'help': '[all|none]: force checksum check (all) or disabled it (none)',
        'choices': ['all', 'none']
    },
    'runmode': {
        'names': {'long': '--runmode'},
        'help': '<unmode_id>: specific runmode modification the engine should run.  The argument \
                              supplied should be the id for the runmode obtained by running \
                              --list-runmodes'
    },
    'pid_file': {
        'names': {'long': '--pidfile'},
        'help': '<file>: write pid to this file'
    },
    'pcap_buf_size': {
        'names': {'long': '--pcap-buffer-size'},
        'help': '<size>: size of the pcap buffer value from 0 - 2147483647',
        'type': int
    },
    'user': {
        'names': {'long': '--user'},
        'help': '<user>: run suricata as this user after init'
    },
    'group': {
        'names': {'long': '--group'},
        'help': '<group>: run suricata as this group after init'
    },
    'erf_in': {
        'names': {'long': '--erf-in'},
        'help': '<path>: process an ERF file'
    },
    'set': {
        'names': {'long': '--set'},
        'help': 'name=value: set a configuration value'
    }
}


SURICATA_OPT_KEYWORDS = {
    'list_keywords': {
        'names': {'long': '--list-keywords'},
        'help': '[=all|csv|<kword>]: list keywords implemented by the engine',
    },
    'pcap_mode': {
        'names': {'long': '--pcap'},
        'help': '[=<dev>]: run in pcap mode, no value select interfaces from suricata.yaml',
    },
    'af_packet': {
        'names': {'long': '--af-packet'},
        'help': '[=<dev>]: run in af-packet mode, no value select interfaces from suricata.yaml',
    },
    'unix_socket': {
        'names': {'long': '--unix-socket'},
        'help': '[=<file>]: use unix socket to control suricata work',
    },
}


# fine-tune options by class accordingly
for v in SURICATA_OPTS.values():
    v.update(action='store_true')


__NO_OPTKW_VAL__ = object()
__NO_OPTKW_VAL_KWARGS = {
    'nargs': '?',
    'const': __NO_OPTKW_VAL__,
    'default': __NO_OPTKW_VAL__
}
for v in SURICATA_OPT_KEYWORDS.values():
    v.update(__NO_OPTKW_VAL_KWARGS)


# specify the order of the output arguments when buildinig up a command
_SURICATA_ARGS_ORDERED = OrderedDict(
    itertools.chain(sorted(SURICATA_OPTS.items()),
                    sorted(SURICATA_KEYWORDS.items()),
                    sorted(SURICATA_OPT_KEYWORDS.items())))


class SuricataArgumentBuilder(ArgumentBuilder):
    """
    """
    ARGS_ORDERED = _SURICATA_ARGS_ORDERED
    ARGS_FORMATTER = {}  # init after class definition
    __NOT_FOUND = object()

    @classmethod
    def get_args_formatter(cls, redo=False):
        if redo or not cls.ARGS_FORMATTER:
            cls.ARGS_FORMATTER = {
                'optional': cls.FORMATTER_BY_VALUE_MAP(
                    {
                        None: cls.FORMAT_NONE,
                        cls.__FALSE__: cls.FORMAT_NONE,
                        __NO_OPTKW_VAL__: cls.FORMAT_KEY_FIRST,
                        cls.__TRUE__: cls.FORMAT_KEY_FIRST,
                    },
                    default=cls.FORMATTER_JOIN_KEY_VAL(
                        key=cls.FORMAT_KEY_FIRST,
                        joiner=cls.FORMAT_ARG_JOIN_BY_KEY_CLASS,
                        val=cls.FORMAT_VAL_TRANSFORM(str),
                    )
                ),
                'positional': cls.FORMAT_VAL_TRANSFORM(str)
            }
        return cls.ARGS_FORMATTER

    @classmethod
    def FORMAT_ARG_JOIN_BY_KEY_CLASS(cls, params, arg_name=None,
                                     key_fmtd=None, val_fmtd=None, **kwargs):
        if SURICATA_OPTS.get(arg_name, cls.__NOT_FOUND) != cls.__NOT_FOUND:
            return key_fmtd
        if SURICATA_KEYWORDS.get(arg_name, cls.__NOT_FOUND) != cls.__NOT_FOUND:
            return [key_fmtd, val_fmtd]
        if SURICATA_OPT_KEYWORDS.get(arg_name, cls.__NOT_FOUND) != cls.__NOT_FOUND:
            return key_fmtd

    def __init__(self):
        super(SuricataArgumentBuilder, self).__init__(args_order=self.ARGS_ORDERED,
                                                      args_formatter=self.get_args_formatter())


SuricataArgumentBuilder.get_args_formatter()


class CmdSuricataHelper(CommandHelper):
    """
    """
    @classmethod
    def check_args(cls, *args, **kwargs):
        __kwargs = cls._encode_args(**kwargs)
        return cls._check_args(**__kwargs)

    @classmethod
    def check_opts(cls,
                   __test_config=False, __daemon=False, __version=False, __verbosity=False,
                   __list_app_layer_prots=False, __list_runmodes=False, __engine_analysis=False,
                   __init_errors_fatal=False, __disable_detection=False, __dump_config=False,
                   __build_info=False,
                   **__kwargs):
        return __kwargs

    @classmethod
    def check_keywords(cls,
                       __config=None, __pcap_live_mode=None, __bpf_filter=None,
                       __pcap_offline_mode=None, __inline_nfqueue_mode=None, __sig_file=None,
                       __sig_exc_file=None, __log_dir=None, __checksum_check=None, __runmode=None,
                       __pid_file=None, __pcap_buf_size=None, __user=None, __group=None,
                       __erf_in=None, __set=None,
                       **__kwargs):
        return __kwargs

    @classmethod
    def check_opt_keywords(cls,
                           __list_keywords=None, __pcap_mode=None, __af_packet=None,
                           __unix_socket=None,
                           **__kwargs):
        return __kwargs

    @classmethod
    def _check_args(cls, **__kwargs):
        __kwargs = cls.check_opts(**__kwargs)
        __kwargs = cls.check_keywords(**__kwargs)
        __kwargs = cls.check_opt_keywords(**__kwargs)

        if __kwargs:
            raise UnknownArguments(**cls._decode_args(**__kwargs))

        return True


SURICATA_PARSER = ArgumentParser(prog='suricata', conflict_handler='resolve')
SURICATA_BUILDER = SuricataArgumentBuilder()

suricata_cmd_kwargs = {
    'arg_parser':    SURICATA_PARSER,
    'params':        _SURICATA_ARGS_ORDERED,
    'arg_builder':   SURICATA_BUILDER,
    'default_list': []
}
SURICATA_CMD_HELPER = CmdSuricataHelper(**suricata_cmd_kwargs)


class CmdSuricata(Command):
    CMD_HELPER = SURICATA_CMD_HELPER
