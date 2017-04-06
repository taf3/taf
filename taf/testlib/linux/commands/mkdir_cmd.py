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

"""''iperf_cmd.py''

'iperf command parsing and building support'

"""

from argparse import ArgumentParser

from testlib.linux.commands.cmd_helper import Command, CommandHelper, ArgumentBuilder
from testlib.custom_exceptions import UnknownArguments, ArgumentsCollision


MKDIR_OPTS = {
    'mode': {
        'names': {
            'short': '-m',
            'long': '--mode',
        },
        'help': 'set file mode (as in chmod), not a=rwx - umask',
    },
    'parents': {
        'names': {
            'short': '-p',
            'long': '--parents',
        },
        'help': 'no error if existing, make parent directories as needed',
        'action': 'store_true',
    },
    'verbose': {
        'names': {
            'short': '-v',
            'long': '--verbose',
        },
        'help': 'print a message for each created directory',
        'action': 'store_true',
    },
    'context': {
        'names': {
            'short': '-Z',
            'long': '--context',
        },
        'help': 'set the SELinux security context of each created directory to CTX',
    },
    'help': {
        'names': {
            'long': '--help',
        },
        'help': 'display this help and exit',
        'action': 'store_true',
    },
    'version': {
        'names': {
            'long': '--version',
        },
        'help': 'output version information and exit',
        'action': 'store_true',
    },
    'name': {
        # 'required': True,
        'help': 'the name of the directory to be created',
    },
}

# specify the order of the output arguments when buildinig up a command
_MKDIR_ARGS_ORDERED = ['mode', 'parents', 'verbose', 'context', 'help', 'version', 'name']


class MkdirArgumentBuilder(ArgumentBuilder):
    """
    """
    ARGS_ORDERED = _MKDIR_ARGS_ORDERED

    @classmethod
    def GET_KEY_TAG_SHORT_IF_EXIST_ELSE_LONG(cls, params, arg_name=None, **kwargs):
        _par_names = params[arg_name]['names']
        if _par_names:
            _short = _par_names.get('short', None)
            if _short:
                return _short

            return _par_names.get('long', None)

    @classmethod
    def get_formatter(cls):
        _formatter = {
            'optional': cls.FORMATTER_BY_VALUE_MAP(
                {
                    None: cls.FORMAT_NONE,
                    cls.__FALSE__: cls.FORMAT_NONE,
                    cls.__TRUE__: cls.GET_KEY_TAG_SHORT_IF_EXIST_ELSE_LONG,
                },
                default=cls.FORMATTER_JOIN_KEY_VAL(
                    key=cls.GET_KEY_TAG_SHORT_IF_EXIST_ELSE_LONG,
                    joiner=cls.FORMAT_ARG_JOIN_STR('='),
                    val=cls.FORMAT_VAL_TRANSFORM(str),
                ),
            ),
            'positional': cls.FORMAT_VAL_TRANSFORM(str),
        }
        return _formatter

    def __init__(self):
        super(MkdirArgumentBuilder, self).__init__(args_order=self.ARGS_ORDERED,
                                                   args_formatter=self.get_formatter())


class CmdMkdirHelper(CommandHelper):
    """
    """
    @classmethod
    def check_args(cls, *args, **kwargs):
        __kwargs = cls._encode_args(**kwargs)
        return cls._check_args(**__kwargs)

    @classmethod
    def _check_args(cls, __mode=None, __parents=False, __verbose=False, __context=None,
                    __help=False, __version=False, __name=None, **__kwargs):
        if not __name:
            raise ArgumentsCollision(name=__name)

        if __kwargs:
            raise UnknownArguments(**cls._decode_args(**__kwargs))

        return True


MKDIR_PARSER = ArgumentParser(prog='mkdir', conflict_handler='resolve')
MKDIR_BUILDER = MkdirArgumentBuilder()

__name_default = None
MKDIR_CMD_HELPER = CmdMkdirHelper(arg_parser=MKDIR_PARSER, params=MKDIR_OPTS,
                                  arg_builder=MKDIR_BUILDER, default_list=[__name_default])


class CmdMkdir(Command):
    CMD_HELPER = MKDIR_CMD_HELPER
