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

@file  test_commands.py

@summary  Command helpers Unittests
"""
from collections import OrderedDict

import pytest

from testlib.custom_exceptions import UnknownArguments, ArgumentsCollision
from testlib.linux.commands import mkdir_cmd
from testlib.linux.commands.cmd_helper import Command, CommandHelper


def pytest_raises(exc_iter):
    def decorator(f):
        def wrapper(*args, **kwargs):
            with pytest.raises(exc_iter):
                f(*args, **kwargs)
        return wrapper
    return decorator


class TestCmdHelperBasic(object):

    Command.CMD_HELPER = CommandHelper(params=OrderedDict.fromkeys('abcde', {}))

    @pytest_raises(SystemExit)
    def test_empty_argparse_raises_exception(self):
        # create a Command with the default empty CommandHelper
        Command(list(''))

    def test_inits(self):
        l = Command(list('abcde'))
        s = Command('a b c d e')
        d = Command({k: k for k in 'abcde'})
        c = Command(l)
        n = Command(l._ns)
        assert l == s == d == c == n

    def test_copy(self):
        l = Command(list('abcde'))
        d = Command.copy(l)
        assert l == d

    def test_validate_dict(self):
        l = Command(list('abcde'))
        l._validate_dict(**{k: k for k in 'abcde'})

    def test_get(self):
        l = Command(list('abcde'))
        assert l.get('a') == 'a'

    def test_iter(self):
        l = Command(list('abcde'))
        for a in l:
            assert a in 'abcde'

    def test_update(self):
        l = Command(list('abcde'))
        o = Command(list('abcde'[::-1]))
        l.update(dict(list(zip('abcde', 'abcde'[::-1]))))
        assert l == o


class TestCommandHelper(object):

    @classmethod
    def _build_args_list(cls, out_list, out_dict):
        _marker = object()

        cmd_list = []
        for arg_k in out_list:
            arg_v = out_dict.get(arg_k, _marker)
            if arg_v != _marker:
                if arg_v:
                    if isinstance(arg_v, list):
                        cmd_list.extend(arg_v)
                    elif isinstance(arg_v, int):
                        cmd_list.append(str(arg_v))
                    elif isinstance(arg_v, str):
                        cmd_list.append(arg_v)

        return cmd_list

    def test_cmd_helper_start_empty(self):
        with pytest.raises(ArgumentsCollision):
            mkdir_cmd.CmdMkdir().check_args()

    def test_cmd_helper_start_unknown(self):
        with pytest.raises(UnknownArguments):
            mkdir_cmd.CmdMkdir(unknown_argument=object()).check_args()

    def test_cmd_helper_start_ok(self):
        mkdir_cmd.CmdMkdir(name=object()).check_args()

    def test_cmd_helper_mkdir_kwargs_set(self):
        mkdir_kwargs = {
            'mode': 'a+x',
            'parents': False,
            'verbose': True,
            'context': 'CTX',
            'help': True,
            'version': True,
            'name': 'some/dir/name'
        }
        cmd = mkdir_cmd.CmdMkdir(**mkdir_kwargs)
        cmd.check_args()

        output_list = mkdir_cmd.MkdirArgumentBuilder.ARGS_ORDERED
        output_dict = {
            'mode': '-m=a+x',
            'parents': None,
            'verbose': '-v',
            'context': '-Z=CTX',
            'help': '--help',
            'version': '--version',
            'name': ['some/dir/name']
        }
        _args_list = self._build_args_list(output_list, output_dict)

        assert 'name' in cmd
        assert 'parents' not in cmd
        assert mkdir_kwargs['name'] == cmd['name']
        assert _args_list == cmd.to_args_list()

    def test_cmd_helper_mkdir_kwargs_update(self):
        mkdir_kwargs = {
            'mode': 'a+x',
            'parents': False,
            'verbose': True,
            'context': 'CTX',
            'help': True,
            'version': True,
            'name': 'some/dir/name'
        }
        cmd = mkdir_cmd.CmdMkdir(**mkdir_kwargs)
        cmd.check_args()

        cmd.update(parents=True, version=False)
        cmd.check_args()

        output_list = mkdir_cmd.MkdirArgumentBuilder.ARGS_ORDERED
        output_dict = {
            'mode': '-m=a+x',
            'parents': '-p',
            'verbose': '-v',
            'context': '-Z=CTX',
            'help': '--help',
            'version': None,
            'name': ['some/dir/name']
        }
        _args_list = self._build_args_list(output_list, output_dict)

        assert 'name' in cmd
        assert 'parents' in cmd
        assert mkdir_kwargs['name'] == cmd['name']
        assert _args_list == cmd.to_args_list()

    def test_cmd_helper_mkdir_kwargs_extend(self):
        mkdir_kwargs = {
            'mode': 'a+x',
            'parents': False,
            'verbose': True,
            'context': 'CTX',
            'help': True,
            'version': True,
            'name': 'some/dir/name'
        }
        cmd = mkdir_cmd.CmdMkdir(**mkdir_kwargs)
        cmd.check_args()

        cmd.extend(parents=True, version=False)
        cmd.check_args()

        output_list = mkdir_cmd.MkdirArgumentBuilder.ARGS_ORDERED
        output_dict = {
            'mode': '-m=a+x',
            'parents': '-p',
            'verbose': '-v',
            'context': '-Z=CTX',
            'help': '--help',
            'version': '--version',
            'name': ['some/dir/name']
        }
        _args_list = self._build_args_list(output_list, output_dict)

        assert 'name' in cmd
        assert 'parents' in cmd
        assert mkdir_kwargs['name'] == cmd['name']
        assert _args_list == cmd.to_args_list()

    def test_cmd_helper_mkdir_kwarg_unset(self):
        mkdir_kwargs = {
            'mode': 'a+x',
            'parents': False,
            'verbose': True,
            'context': 'CTX',
            'help': True,
            'version': True,
            'name': 'some/dir/name'
        }
        cmd = mkdir_cmd.CmdMkdir(**mkdir_kwargs)
        cmd.check_args()

        cmd.unset(mode='', parents='', verbose='', context='', version='', **{'help': ''})
        cmd.check_args()

        output_list = mkdir_cmd.MkdirArgumentBuilder.ARGS_ORDERED
        output_dict = {
            'name': 'some/dir/name'
        }
        _args_list = self._build_args_list(output_list, output_dict)

        assert 'name' in cmd
        assert 'parents' not in cmd
        assert mkdir_kwargs['name'] == cmd['name']
        assert _args_list == cmd.to_args_list()

    def test_cmd_helper_mkdir_merge(self):
        mkdir_kwargs_lhs = {
            'mode': 'a+x',
            'parents': False,
            'verbose': True,
            'context': 'CTX',
            'help': True,
            'version': True,
            'name': 'lhs'
        }
        cmd_lhs = mkdir_cmd.CmdMkdir(**mkdir_kwargs_lhs)
        cmd_lhs.check_args()

        mkdir_kwargs_rhs = {
            'mode': 'a+x',
            'parents': True,
            'verbose': False,
            'context': 'CTX',
            'help': False,
            'version': False,
            'name': 'rhs'
        }
        cmd_rhs = mkdir_cmd.CmdMkdir(**mkdir_kwargs_rhs)
        cmd_rhs.check_args()

        cmd = mkdir_cmd.CmdMkdir.merge(cmd_lhs, cmd_rhs)
        cmd.check_args()

        assert cmd['name'] == 'rhs'
        assert cmd['parents']
        assert not cmd['verbose']
        assert cmd._to_dict(cmd) == mkdir_kwargs_rhs
