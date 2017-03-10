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

"""``cmd_helper.py``

`Flexible command representation with parsing and building support`

"""

import copy
import operator
import argparse

from collections import Mapping, OrderedDict

from testlib.custom_exceptions import CmdArgsException, UnknownArguments


class ArgumentBuilder(object):
    """
    """
    ARGS_ORDER = []

    def __init__(self, args_order=None, args_formatter=None):
        self.args_order = args_order
        self.args_formatter = args_formatter

    # SECTION optional args' key formatter
    @classmethod
    def FORMAT_KEY_FIRST(cls, params, arg_name=None, **kwargs):
        keys = list(params[arg_name]['names'].values())
        return operator.itemgetter(0)(keys)

    @classmethod
    def FORMAT_KEY_LAST(cls, params, arg_name=None, **kwargs):
        keys = list(params[arg_name]['names'].values())
        return operator.itemgetter(-1)(keys)

    @classmethod
    def FORMAT_KEY_LONGEST(cls, params, arg_name=None, **kwargs):
        keys = list(params[arg_name]['names'].values())
        return max(keys, key=len)

    @classmethod
    def FORMAT_KEY_SHORTEST(cls, params, arg_name=None, **kwargs):
        keys = list(params[arg_name]['names'].values())
        return min(keys, key=len)

    @classmethod
    def FORMAT_NONE(cls, *args, **kwargs):
        pass

    @classmethod
    def FORMAT_KEY_BY_TAG(cls, tag):
        _tag_getter = operator.itemgetter(tag)

        def wrapper(params, arg_name=None, **kwargs):
            return _tag_getter(params[arg_name]['names'])
        return wrapper

    @classmethod
    def FORMAT_VAL_TRANSFORM(cls, trans_f):
        def wrapper(params, arg_val=None, **kwargs):
            return trans_f(arg_val)
        return wrapper

    @classmethod
    def FORMAT_ARG_APPEND_LIST(cls, params, key_fmtd=None, val_fmtd=None, **kwargs):
        return [key_fmtd, val_fmtd]

    @classmethod
    def FORMAT_ARG_JOIN_STR(cls, join_char=None):
        def wrapper(params, key_fmtd=None, val_fmtd=None, **kwargs):
            return '{}{}{}'.format(key_fmtd, join_char, val_fmtd)
        return wrapper

    @classmethod
    def FORMATTER_JOIN_KEY_VAL(cls, key=None, val=None, joiner=None):
        def wrapper(params, arg_name=None, arg_val=None, **kwargs):
            _key_out = _val_out = _out = None
            arg_kwargs = {
                'arg_name': arg_name,
                'arg_val': arg_val
            }
            if key:
                _key_out = key(params, **arg_kwargs)
            if val:
                _val_out = val(params, **arg_kwargs)
            if joiner:
                _out = joiner(params, **dict(arg_kwargs, key_fmtd=_key_out, val_fmtd=_val_out))
            return _out
        return wrapper

    # a little hack to allow for booleans to simulate unique objects behavior.
    # As opposed to ints 0/1 for keywords False/True respectively.
    __FALSE__ = object()
    __TRUE__ = object()
    __BOOL_MAP__ = {}

    @classmethod
    def FORMATTER_BY_VALUE_MAP(cls, val_map, default=None):
        def wrapper(params, arg_name=None, arg_val=None, **kwargs):
            if isinstance(arg_val, bool):
                __arg_val = cls.__BOOL_MAP__[arg_val]
                arg_formatter = val_map.get(__arg_val, default)
            else:
                arg_formatter = val_map.get(arg_val, default)

            if arg_formatter:
                return arg_formatter(params, arg_name=arg_name, arg_val=arg_val)
        return wrapper

    # SECTION builder
    def build_args(self, opts_map, pos_map, args, order=None, formatter=None):
        """
        """
        if not order:
            if self.args_order:
                order = self.args_order
            else:
                order = sorted(args)

        if not formatter:
            if self.args_formatter:
                formatter = self.args_formatter
            else:
                formatter = self.__DEFAULT_FORMATTER

        args_list = []
        for arg_name in order:
            if arg_name in args:
                arg_val = args[arg_name]

                if arg_name in opts_map:
                    assert 'names' in opts_map[arg_name]
                    _fmt = formatter['optional']
                    _fmt_args = [opts_map]

                elif arg_name in pos_map:
                    assert 'pos' in pos_map[arg_name]
                    _fmt = formatter['positional']
                    _fmt_args = [pos_map]

                else:
                    raise Exception('Unknown argument: %s=%s', arg_name, arg_val)

                _fmt_kwargs = {
                    'arg_name': arg_name,
                    'arg_val': arg_val
                }
                _out = _fmt(*_fmt_args, **_fmt_kwargs)
                if _out:
                    if isinstance(_out, list):
                        args_list.extend(_out)
                    elif isinstance(_out, str):
                        args_list.append(_out)

        return args_list

    @classmethod
    def get_formatter(cls):
        _formatter = {
            'optional': cls.FORMATTER_BY_VALUE_MAP(
                {
                    cls.__TRUE__: cls.FORMAT_KEY_FIRST,
                    cls.__FALSE__: cls.FORMAT_NONE,
                    None: cls.FORMAT_NONE
                },
                default=cls.FORMATTER_JOIN_KEY_VAL(
                    key=cls.FORMAT_KEY_FIRST,
                    joiner=cls.FORMAT_ARG_APPEND_LIST,
                    val=cls.FORMAT_VAL_TRANSFORM(str),
                )
            ),
            'positional': cls.FORMAT_VAL_TRANSFORM(str)
        }
        return _formatter

    __DEFAULT_FORMATTER = {}


ArgumentBuilder.__BOOL_MAP__ = {
    False: ArgumentBuilder.__FALSE__,
    True: ArgumentBuilder.__TRUE__
}

ArgumentBuilder.__DEFAULT_FORMATTER = ArgumentBuilder.get_formatter()


class CommandHelper(object):
    """
    """
    MANGLED_CLS_PREFIX = None

    @classmethod
    def _get_cls_prefix(cls):
        if not cls.MANGLED_CLS_PREFIX:
            cls.MANGLED_CLS_PREFIX = '_{}'.format(cls.__name__)
        return cls.MANGLED_CLS_PREFIX

    @classmethod
    def _encode_args(cls, **kwargs):
        return {'{}__{}'.format(cls._get_cls_prefix(), k): v for k, v in kwargs.items()}

    @classmethod
    def _decode_args(cls, **__kwargs):
        return {k[len(cls._get_cls_prefix()) + 2:]: v for k, v in __kwargs.items()}

    @classmethod
    def check_args(cls, **kwargs):
        """Input command arguments checking API.

        Todo:
            abstract

        """
        pass

    def __init__(self, prog=None, arg_parser=None, conflict_handler=None, params=None,
                 arg_builder=None, default_list=None):
        """
        """
        self.posarg_list = []
        self.posarg_map = {}
        self.optarg_list = []
        self.optarg_map = {}
        self.default_image = None

        if not conflict_handler:
            conflict_handler = 'resolve'
        if not arg_parser:
            arg_parser = argparse.ArgumentParser(prog=prog, conflict_handler=conflict_handler)
        self.arg_parser = arg_parser

        if not arg_builder:
            arg_builder = ArgumentBuilder()
        self.arg_builder = arg_builder

        if params:
            self._init_params(params, default_list=default_list)

    def _init_params(self, params, default_list=None):
        self.params = params
        for param_name, param_desc in params.items():
            _par = copy.deepcopy(param_desc)
            if 'names' in param_desc:  # optional arg
                self.optarg_map[param_name] = _par
                names = _par.pop('names')
                self.arg_parser.add_argument(*list(names.values()), dest=param_name, **_par)
                _par['names'] = names
                _par['pos'] = len(self.optarg_list)
            else:  # positional arg
                self.posarg_map[param_name] = _par
                self.arg_parser.add_argument(param_name)
                _par['pos'] = len(self.posarg_list)
                self.posarg_list.append(param_name)

        if default_list is None:
            default_list = [None] * len(self.posarg_map)
        self.default_image = self.arg_parser.parse_args(default_list)
        assert self.default_image

    def parse_args(self, args_list):
        return self.arg_parser.parse_args(args_list)

    def get_set_args(self, args_in, args_out=None, args_order=None):
        """A command builder helper function.

        Strips the dict off the unset (default) arguments.
        Learns which fields in 'args_in' (dict or argparse.Namespace instance), possibly
        parsed earlier, had been set before the parsing took place.
        If an intermediate dict is provided in 'args_out', mutate in place and overwrite it on collision.

        """
        if args_out is None:
            args_out = OrderedDict()

        assert args_in is not None
        if isinstance(args_in, Command):
            args_in = args_in._ns
        if isinstance(args_in, argparse.Namespace):
            args_in = args_in.__dict__

        if isinstance(args_in, dict):
            pass
        else:
            raise Exception('get_set_args(): Argument error: Expected dict, got %s', type(args_in))

        if self.default_image.__dict__ == args_in:
            return args_out

        if not args_order:
            if self.arg_builder.args_order:
                args_order = self.arg_builder.args_order
            else:
                args_order = sorted(args_in)

        _marker = object()
        for k in args_order:
            if args_in.get(k, _marker) != self.default_image.__dict__.get(k, _marker):
                args_out[k] = args_in[k]

        return args_out

    def build_cmd_list(self, **kwargs):
        """A command builder helper function.

        Reverse parse_args() functionality.
        Converts the input sequence of command arguments(key[:value] pairs) to a command options list.

        """
        return self.arg_builder.build_args(self.optarg_map, self.posarg_map, kwargs)


_DEFAULT_CMD_HELPER = CommandHelper()


class Command(Mapping):
    """Command holder object flexible representation.

    """
    CMD_HELPER = _DEFAULT_CMD_HELPER

    @classmethod
    def copy(cls, cmd):
        return cls(cmd)

    @classmethod
    def from_kwargs(cls, **kwargs):
        return cls(kwargs)

    @classmethod
    def _validate_dict(cls, **kwargs):
        unknown = {}
        for k in kwargs:
            if not hasattr(cls.CMD_HELPER.default_image, k):
                unknown[k] = kwargs[k]

        if unknown:
            raise UnknownArguments(**unknown)

    def _update_kwargs(self, **kwargs):
        self._validate_dict(**kwargs)
        self._ns.__init__(**kwargs)

    def _extend_kwargs(self, **kwargs):
        self._validate_dict(**kwargs)
        set_self = self.get_set_args()
        to_update = {k: kwargs[k] for k in kwargs if k not in set_self}
        self._ns.__init__(**to_update)

    def _unset_kwargs(self, **kwargs):
        self._validate_dict(**kwargs)
        to_update = {k: getattr(self.CMD_HELPER.default_image, k) for k in kwargs}
        self._ns.__init__(**to_update)

    def __init__(self, *args, **kwargs):
        # technically Mapping has no __init__, but we keep this to be proper for MI
        super(Command, self).__init__()  # pylint: disable=no-member

        self._ns = None
        for cmd in args:
            self._init_cmd(cmd)

        if self._ns is None:
            self._ns = copy.copy(self.CMD_HELPER.default_image)

        if kwargs:
            self._update_kwargs(**kwargs)

        assert self._ns

    def _init_cmd(self, cmd_rep):
        if isinstance(cmd_rep, Command):
            self._ns = copy.deepcopy(cmd_rep._ns)
        elif isinstance(cmd_rep, argparse.Namespace):
            self._ns = copy.deepcopy(cmd_rep)
        elif isinstance(cmd_rep, dict):
            self._ns = copy.deepcopy(self.CMD_HELPER.default_image)
            self._update_kwargs(**cmd_rep)
        elif isinstance(cmd_rep, list):
            self._ns = self._list_2_ns(cmd_rep)
        elif isinstance(cmd_rep, str):
            self._ns = self._str_2_ns(cmd_rep)

    # Conversion/parsing methods
    @classmethod
    def _list_2_ns(cls, cmd_list):
        cmd_ns = cls.CMD_HELPER.parse_args(cmd_list)
        return cmd_ns

    @classmethod
    def list_2_cmd(cls, cmd_list):
        return cls(cls._list_2_ns(cmd_list))

    @classmethod
    def _str_2_ns(cls, cmd_str):
        _cmd_list = cmd_str.split()
        cmd_ns = cls.CMD_HELPER.parse_args(_cmd_list)
        return cmd_ns

    @classmethod
    def str_2_cmd(cls, cmd_str):
        return cls(cls._str_2_ns(cmd_str))

    # Conversion/building methods
    @classmethod
    def _ns_2_list(cls, cmd_ns):
        cmd_list = None
        try:
            cmd_args = cls.CMD_HELPER.get_set_args(cmd_ns)
            cmd_list = cls.CMD_HELPER.build_cmd_list(**cmd_args)
        except CmdArgsException:
            pass
        return cmd_list

    @classmethod
    def cmd_2_list(cls, cmd):
        return cls._ns_2_list(cmd._ns)

    @classmethod
    def _ns_2_str(cls, cmd_ns):
        cmd_list = cls._ns_2_list(cmd_ns)
        return ' '.join(cmd_list)

    @classmethod
    def cmd_2_str(cls, cmd):
        return cls._ns_2_str(cmd._ns)

    def to_args_list(self):
        return self._ns_2_list(self._ns)

    @classmethod
    def _to_dict(cls, cmd_rep):
        _cmd_dict = None
        if isinstance(cmd_rep, Command):
            _cmd_dict = cmd_rep._ns.__dict__
        elif isinstance(cmd_rep, argparse.Namespace):
            _cmd_dict = cmd_rep.__dict__
        elif isinstance(cmd_rep, dict):
            _cmd_dict = cmd_rep
        elif isinstance(cmd_rep, list):
            _cmd_dict = cls._list_2_ns(cmd_rep).__dict__
        elif isinstance(cmd_rep, str):
            _cmd_dict = cls._str_2_ns(cmd_rep).__dict__

        return _cmd_dict

    # Auxilliary
    def __str__(self):
        return self._ns_2_str(self._ns)

    def __repr__(self):
        return "%s:%r" % (type(self), self._ns)

    def __bool__(self):
        return self._ns != self.CMD_HELPER.default_image

    # def __bool__(self):
    #     return self.__nonzero__()

    # Container methods
    def __iter__(self):
        return self.get_set_args().__iter__()

    def __len__(self):
        return self.get_set_args().__len__()

    def __contains__(self, item):
        _marker = object()
        return self.CMD_HELPER.default_image.__dict__.get(item, _marker) \
            != self._ns.__dict__.get(item, _marker)

    def __getitem__(self, item):
        return getattr(self._ns, item)

    def __setitem__(self, item, value):
        return setattr(self._ns, item, value)

    def get(self, item, *args):
        return self.get_set_args().get(item, *args)

    def clear(self):
        self._ns = self.CMD_HELPER.default_image

    def keys(self):
        return self.get_set_args().keys()

    def values(self):
        return self.get_set_args().values()

    def items(self):
        return self.get_set_args().items()

    # def iterkeys(self):
    #     return self.get_set_args().iterkeys()
    #
    # def itervalues(self):
    #     return self.get_set_args().values()
    #
    # def iteritems(self):
    #     return self.get_set_args().items()

    # Command arithmetics
    @classmethod
    def merge(cls, cmd_lhs, cmd_rhs):
        # we have to merge dicts before we check defaults with get_set_args()
        _cmd_dict = cls._to_dict(cmd_lhs)
        _cmd_dict.update(cls._to_dict(cmd_rhs))
        cmd = cls(**cls.CMD_HELPER.get_set_args(_cmd_dict))
        return cmd

    def update(self, *args, **kwargs):
        """Add new stuff and update existing

        cmd{a: 1, b: 2, c:3} + (cmd{b: 'b', c: 'c', d: 'd'}) => cmd{a: 1, b: 'b', c: 'c', d: 'd'}

        """
        for cmd in args:
            self._update_cmd(cmd)

        if kwargs:
            self._update_kwargs(**kwargs)

        return self

    def _update_cmd(self, cmd_rep):
        _cmd_dict = self._to_dict(cmd_rep)
        assert _cmd_dict is not None
        self._update_kwargs(**self.CMD_HELPER.get_set_args(_cmd_dict))

    def extend(self, *args, **kwargs):
        """Add new stuff only

        cmd{a: 1, b: 2, c:3} + (cmd{b: 'b', c: 'c', d: 'd'}) => cmd{a: 1, b: 2, c: 3, d: 'd'}

        """
        for cmd in args:
            self._extend_cmd(cmd)

        if kwargs:
            self._extend_kwargs(**kwargs)

        return self

    def _extend_cmd(self, cmd_rep):
        _cmd_dict = self._to_dict(cmd_rep)
        assert _cmd_dict is not None
        self._extend_kwargs(**self.CMD_HELPER.get_set_args(_cmd_dict))

    def unset(self, *args, **kwargs):
        """Remove stuff

        cmd{a: 1, b: 2, c: 3} - {cmd{b: 'b', c: 'c', d: 'd'} => cmd{a: 1}

        """
        for cmd in args:
            self._unset_cmd(cmd)

        if kwargs:
            self._unset_kwargs(**kwargs)

        return self

    def _unset_cmd(self, cmd_rep):
        _cmd_dict = self._to_dict(cmd_rep)
        assert _cmd_dict is not None
        self._unset_kwargs(**self.CMD_HELPER.get_set_args(_cmd_dict))

    def __eq__(self, other):
        if isinstance(other, Command):
            return self._ns == other._ns
        elif isinstance(other, argparse.Namespace):
            return self._ns == other
        elif isinstance(other, dict):
            return self.get_set_args() == other
        elif isinstance(other, list):
            return self._ns == self._list_2_ns(other)
        elif isinstance(other, str):
            return self._ns == self._str_2_ns(other)

        return False

    # Command utilities
    def get_set_args(self, **kwargs):
        if kwargs:
            return self.CMD_HELPER.get_set_args(kwargs)

        return self.CMD_HELPER.get_set_args(self._ns)

    def check_args(self, **kwargs):
        if not kwargs:
            kwargs = self.CMD_HELPER.get_set_args(self)

        return self.CMD_HELPER.check_args(**kwargs)
