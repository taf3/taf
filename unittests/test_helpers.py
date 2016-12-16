"""
@copyright Copyright (c) 2011 - 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file test_helpers.py

@summary Unittests for helpers functions.
"""
from collections import namedtuple
from collections import OrderedDict

import pytest

from testlib import helpers


class Config(object):

    def __init__(self, env):
        self.env = env
        self.option = Options()


class Options(object):

    def __init__(self):
        self.ui = "ons_xmlrpc"


class Device(object):

    def __init__(self, stype):
        self.type = stype


class Env(object):

    def __init__(self, switches, tgs):
        self.switch = {i: Device(y) for i, y in enumerate(switches)}
        self.tg = {i: Device(y) for i, y in enumerate(tgs)}


def test_simswitch_only_marker():
    config = Config(Env(["lxc", ], ["ixiahl", ]))
    assert not eval(helpers.simswitch_only().args[0]), "simswitch_only marker returns True"

    config.env.switch[0].type = "rr"
    assert eval(helpers.simswitch_only().args[0]), "simswitch_only marker returns False"
    del config

    config = Config(Env(["rr", "lxc"], ["ixiahl", ]))
    assert eval(helpers.simswitch_only().args[0]), "simswitch_only marker returns False"
    del config


def test_realswitch_only_marker():
    config = Config(Env(["lxc", ], ["ixiahl", ]))
    assert eval(helpers.realswitch_only().args[0]), "realswitch_only marker returns False"

    config.env.switch[0].type = "rr"
    assert not eval(helpers.realswitch_only().args[0]), "realswitch_only marker returns True"
    del config

    config = Config(Env(["rr", "lxc"], ["ixiahl", ]))
    assert eval(helpers.realswitch_only().args[0]), "realswitch_only marker returns False"
    del config


def test_skip_on_platforms_marker():
    config = Config(Env(["lxc", ], ["ixiahl", ]))
    assert eval(helpers.skip_on_platforms(["lxc", "rr"]).args[0]), "skip_on_platforms marker returns False"

    config.env.switch[0].type = "rr"
    assert eval(helpers.skip_on_platforms(["lxc", "rr"]).args[0]), "skip_on_platforms marker returns False"

    assert not eval(helpers.skip_on_platforms(["lxc"]).args[0]), "skip_on_platforms marker returns True"
    del config

    config = Config(Env(["rr", "seacliff"], ["ixiahl", ]))
    assert eval(helpers.skip_on_platforms(["lxc", "seacliff"]).args[0]), "skip_on_platforms marker returns False"
    del config

    config = Config(Env(["rr"], ["ixiahl", ]))
    assert not eval(helpers.skip_on_platforms(["lxc"]).args[0]), "skip_on_platforms marker returns True"

    assert not eval(helpers.skip_on_platforms(["lxc", "seacliff"]).args[0]), "skip_on_platforms marker returns True"
    del config


def test_run_on_platforms_marker():
    config = Config(Env(["lxc", ], ["ixiahl", ]))
    assert not eval(helpers.run_on_platforms(["lxc", "iz1"]).args[0]), "run_on_platforms marker returns True"

    config.env.switch[0].type = "rr"
    assert not eval(helpers.run_on_platforms(["lxc", "rr"]).args[0]), "run_on_platforms marker returns True"

    assert eval(helpers.run_on_platforms(["lxc"]).args[0]), "run_on_platforms marker returns False"
    del config

    config = Config(Env(["rr", "seacliff"], ["ixiahl", ]))
    assert not eval(helpers.run_on_platforms(["rr", "seacliff"]).args[0]), "run_on_platforms marker returns True"

    assert eval(helpers.run_on_platforms(["lxc", "seacliff"]).args[0]), "run_on_platforms marker returns False"

    assert eval(helpers.run_on_platforms(["lxc"]).args[0]), "run_on_platforms marker returns False"

    assert eval(helpers.run_on_platforms(["lxc", "rr"]).args[0]), "run_on_platforms marker returns False"

    assert not eval(helpers.run_on_platforms(["seacliff", "seacliff", "rr"]).args[0]), "run_on_platforms marker returns True"
    del config

    config = Config(Env(["rr", "seacliff", "lxc"], ["ixiahl", ]))
    assert eval(helpers.run_on_platforms(["seacliff", "lxc"]).args[0]), "run_on_platforms marker returns False"
    del config


def test_skip_on_ui_marker():
    config = Config(Env(["lxc", ], ["ixiahl", ]))
    assert not eval(helpers.skip_on_ui(["ons_cli", "web"]).args[0]), "skip_on_ui marker returns True"

    config.option.ui = "ons_cli"
    assert eval(helpers.skip_on_ui(["ons_cli", "web"]).args[0]), "skip_on_ui marker returns False"


def test_run_on_ui_marker():
    config = Config(Env(["lxc", ], ["ixiahl", ]))
    assert eval(helpers.run_on_ui(["ons_cli", "web"]).args[0]), "run_on_ui marker returns False"

    config.option.ui = "ons_cli"
    assert not eval(helpers.run_on_ui(["ons_cli", "web"]).args[0]), "run_on_ui marker returns True"


def test_skip_on_tg_marker():
    config = Config(Env(["lxc", ], ["ixiahl", ]))
    assert eval(helpers.skip_on_tg(["ixiahl", "trex"]).args[0]), "skip_on_tg marker returns False"

    config.env.tg[0].type = "trex"
    assert eval(helpers.skip_on_tg(["ixiahl", "trex"]).args[0]), "skip_on_tg marker returns False"

    config.env.tg[0].type = "ixiahl"
    assert not eval(helpers.skip_on_tg(["trex"]).args[0]), "skip_on_tg marker returns True"

    config.env.tg[0].type = "riperf"
    assert not eval(helpers.skip_on_tg(["trex", "ixiahl"]).args[0]), "skip_on_tg marker returns True"
    del config

    config = Config(Env(["rr", "seacliff"], ["ixiahl", "trex"]))
    assert eval(helpers.skip_on_tg(["riperf", "trex"]).args[0]), "skip_on_tg marker returns False"
    del config

    config = Config(Env(["rr", "seacliff"], ["ixiahl", "trex"]))
    assert not eval(helpers.skip_on_tg(["riperf", "tg"]).args[0]), "skip_on_tg marker returns True"
    del config


def test_run_on_tg_marker():
    config = Config(Env(["lxc", ], ["ixiahl", ]))
    assert not eval(helpers.run_on_tg(["ixiahl", "trex"]).args[0]), "run_on_tg marker returns True"

    assert eval(helpers.run_on_tg(["trex"]).args[0]), "run_on_tg marker returns False"

    config.env.tg[0].type = "trex"
    assert not eval(helpers.run_on_tg(["ixiahl", "trex"]).args[0]), "run_on_tg marker returns True"
    del config

    config = Config(Env(["lxc", ], ["ixiahl", "trex"]))
    assert not eval(helpers.run_on_tg(["trex", "ixiahl"]).args[0]), "run_on_tg marker returns True"

    assert not eval(helpers.run_on_tg(["ixiahl", "trex", "riperf"]).args[0]), "run_on_tg marker returns True"

    assert eval(helpers.run_on_tg(["ixiahl"]).args[0]), "run_on_tg marker returns False"

    assert eval(helpers.run_on_tg(["ixiahl", "tg"]).args[0]), "run_on_tg marker returns False"
    del config

    config = Config(Env(["rr", "seacliff"], ["ixiahl", "trex", "riperf"]))
    assert eval(helpers.run_on_tg(["ixiahl", "trex"]).args[0]), "run_on_tg marker returns False"
    del config


class TestGetAttribute(object):

    def test_namedtuple_is_decorator(self):
        arg = namedtuple("Param", "a b c")
        m = helpers.MarkDecorator("sanity", [arg(1, 2, 3)])
        attr = helpers.get_attribute_from_argvalue(m, "a")
        assert attr == 1

    def test_unnamedtuple_is_decorator(self):
        arg = ('a', 'b', 'c')
        m = helpers.MarkDecorator("sanity", [arg])
        attr = helpers.get_attribute_from_argvalue(m, 1)
        assert attr == 'b'

    def test_is_namedtuple(self):
        arg = namedtuple("Param", "a b c")
        attr = helpers.get_attribute_from_argvalue(arg(1, 2, 3), "a")
        assert attr == 1

    def test_unnamedtuple(self):
        arg = ('a', 'b', 'c')
        attr = helpers.get_attribute_from_argvalue(arg, 1)
        assert attr == 'b'

    def test_is_not_found_with_decorator(self):
        m = helpers.MarkDecorator("sanity")
        with pytest.raises(IndexError):
            helpers.get_attribute_from_argvalue(m, "a")

    def test_is_not_found(self):
        arg = namedtuple("Param", "a b c")
        with pytest.raises(AttributeError):
            helpers.get_attribute_from_argvalue(arg(1, 2, 3), "d")

        arg = ('a', 'b', 'c')
        with pytest.raises(IndexError):
            helpers.get_attribute_from_argvalue(arg, 4)


class TestGetSteppedValue(object):

    def test_get_stepped_value_ordereddict(self):
        step_ordereddict = OrderedDict([(89567522, 21856), (179135044, 43712),
                                        (358270089, 87424), (715827712, 174848)])

        step_value = helpers.get_stepped_value(
            value=50000, step=step_ordereddict, step_type='Down')
        assert step_value == 50000 // 21856 * 21856

        step_value = helpers.get_stepped_value(
            value=50000, step=step_ordereddict, step_type='Up')
        assert step_value == 50000 // 21856 * 21856 + 21856

        step_value = helpers.get_stepped_value(
            value=50000, step=step_ordereddict, step_type='Round')
        assert step_value == 50000 // 21856 * 21856

        step_value = helpers.get_stepped_value(
            value=89567522, step=step_ordereddict, step_type='Down')
        assert step_value == 89567522 // 21856 * 21856

        step_value = helpers.get_stepped_value(
            value=179115040, step=step_ordereddict, step_type='Down')
        assert step_value == 179115040 // 43712 * 43712

        step_value = helpers.get_stepped_value(
            value=179115040, step=step_ordereddict, step_type='Up')
        assert step_value == 179115040 // 43712 * 43712 + 43712

        step_value = helpers.get_stepped_value(
            value=179115040, step=step_ordereddict, step_type='Round')
        assert step_value == 179115040 // 43712 * 43712 + 43712

        step_value = helpers.get_stepped_value(
            value=715827713, step=step_ordereddict, step_type='Up')
        assert step_value == 715827712 // 174848 * 174848 + 174848

    def test_get_stepped_value_int(self):
        step_value = helpers.get_stepped_value(
            value=50000, step=21856, step_type='Down')
        assert step_value == 50000 // 21856 * 21856

        step_value = helpers.get_stepped_value(
            value=50000, step=21856, step_type='Up')
        assert step_value == 50000 // 21856 * 21856 + 21856

        step_value = helpers.get_stepped_value(
            value=50000, step=21856, step_type='Round')
        assert step_value == 50000 // 21856 * 21856

        step_value = helpers.get_stepped_value(
            value=40000, step=21856, step_type='Round')
        assert step_value == 40000 // 21856 * 21856 + 21856

    def test_get_stepped_value_invalid(self):

        with pytest.raises(KeyError):
            helpers.get_stepped_value(
                value=40000, step='foo', step_type='Round')

        dict_step = {0: 'a', 1: 'b'}
        with pytest.raises(KeyError):
            helpers.get_stepped_value(
                value=40000, step=dict_step, step_type='Round')

        ordereddict_step = OrderedDict([(89567522, 'a'), (179135044, 'b')])
        with pytest.raises(KeyError):
            helpers.get_stepped_value(
                value=40000, step=ordereddict_step, step_type='Round')


class TestGrouper(object):

    def test_grouper_3(self):
        assert list(helpers.grouper('ABCDEFG', 3)) == [('A', 'B', 'C'), ('D', 'E', 'F'), ('G',)]

    def test_grouper_1(self):
        assert list(helpers.grouper('ABCDEFG', 1)) == [('A',), ('B',), ('C',), ('D',), ('E',), ('F',), ('G',)]

    def test_grouper_negative(self):
        with pytest.raises(ValueError):
            list(helpers.grouper('ABCDEFG', -1)) == []

    def test_grouper_empty(self):
        assert list(helpers.grouper('', 3)) == []

    def test_grouper_bigger(self):
        assert list(helpers.grouper('ABCDEFG', 200)) == [('A', 'B', 'C', 'D', 'E', 'F', 'G')]
