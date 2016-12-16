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

@file test_fixtures.py

@summary Unittests for TAF fixtures.
"""
import copy
import os
import xmlrpc.client
from unittest.mock import patch, MagicMock, Mock

import pytest

from .common import FakeXMLRPCServer
from testlib import fixtures
from testlib import common3


# config of environment
ENV = [
    {"name": "Zero Cross", "entry_type": "cross", "instance_type": "static_ons", "id": "5",
     "kprio": 10, "sprio": 300, "cprio": 300, "tprio": 300},

    {"name": "IXIA-103", "entry_type": "tg", "instance_type": "ixiahl", "id": "03",
     "ip_host": "192.168.0.250", "kprio": 200, "sprio": 200, "cprio": 200, "tprio": 200,
     "ports": [[1, 1, 1], [1, 1, 2]]},

    {"name": "sct01or", "entry_type": "switch", "instance_type": "seacliff", "id": "1",
     "kprio": 100, "ip_host": "192.168.0.11", "ip_port": "8081",
     "use_sshtun": 1, "sshtun_user": "admin", "sshtun_pass": "admin",
     "sshtun_port": 22, "default_gw": "192.168.0.1", "net_mask": "255.255.255.0",
     "ports_count": 52, "pwboard_host": "10.10.10.10", "pwboard_port": "23", "halt": 0,
     "use_serial": False,
     "portserv_host": "10.10.10.11", "portserv_user": "admin",
     "portserv_pass": "password", "portserv_tty": 6, "portserv_port": 2501,
     "telnet_loginprompt": "localhost login:", "telnet_passprompt": "Password:",
     "telnet_user": "admin", "telnet_pass": "admin",
     "telnet_prompt": "[admin@localhost ~]$",
     "cli_user": "admin", "cli_user_passw": "admin", "cli_user_prompt": "Switch ",
     "ports": [],
     "related_id": []},

    {"name": "sct02or", "entry_type": "switch", "instance_type": "seacliff", "id": "2",
     "kprio": 100, "ip_host": "192.168.0.12", "ip_port": "8081",
     "use_sshtun": 1, "sshtun_user": "admin", "sshtun_pass": "admin",
     "sshtun_port": 22, "default_gw": "192.168.0.1", "net_mask": "255.255.255.0",
     "ports_count": 52, "pwboard_host": "10.10.10.12", "pwboard_port": "22", "halt": 0,
     "use_serial": False,
     "portserv_host": "10.10.10.13", "portserv_user": "admin",
     "portserv_pass": "password", "portserv_tty": 6, "portserv_port": 2502,
     "telnet_loginprompt": "localhost login:", "telnet_passprompt": "Password:",
     "telnet_user": "admin", "telnet_pass": "admin",
     "telnet_prompt": "[admin@localhost ~]$",
     "cli_user": "admin", "cli_user_passw": "admin", "cli_user_prompt": "Switch ",
     "ports": [],
     "related_id": []}
]

# simplified setup
SETUP_SIMPLIFIED = {
    "env": [
        {"id": "03", "ports": [[1, 1, 1], [1, 1, 2], [1, 1, 3], [1, 1, 4], [1, 1, 5]]},
        {"id": "1", "ports": [5, 4, 3, 2, 1]},
        {"id": "5", "related_id": ["03", "1"]}
    ],
    "cross":
        {"5":
            [
                ["03", 1, "1", 1],
                ["03", 2, "1", 2],
                ["03", 3, "1", 3],
                ["03", 4, "1", 4],
                ["03", 5, "1", 5]
        ]
    }
}

# simplified setup with port_list
SETUP_SIMPLIFIED_LIST = {
    "env": [
        {"id": "03", "ports": [[1, 1, 1], [1, 1, 2], [1, 1, 3], [1, 1, 4], [1, 1, 5]]},
        {"id": "1", "port_list": [[5, 10000],
                                  [4, 10000],
                                  [3, 10000],
                                  [2, 10000],
                                  [1, 40000]]},
        {"id": "5", "related_id": ["03", "1"]}
    ],
    "cross":
        {"5":
            [
                ["03", 1, "1", 1],
                ["03", 2, "1", 2],
                ["03", 3, "1", 3],
                ["03", 4, "1", 4],
                ["03", 5, "1", 5]
        ]
    }
}

# complex setup
SETUP_COMPLEX = {
    "env": [
        {"id": "03", "ports": [[1, 1, 1], [1, 1, 2], [1, 1, 3], [1, 1, 4], [1, 1, 5]]},
        {"id": "1", "ports": [1, 2, 3, 6, 7]},
        {"id": "2", "ports": [3, 4, 8, 9]},
        {"id": "5", "related_id": ["03", "1", "2"]}
    ],
    "cross":
        {"5":
            [
                ["03", 1, "1", 1],
                ["03", 2, "1", 2],
                ["03", 3, "1", 3],
                ["03", 3, "2", 1],
                ["03", 4, "2", 2],
                ["1", 4, "2", 3],
                ["1", 5, "2", 4]
        ]
    }
}


class EnvTest(object):

    def __init__(self, setup, env):
        self.setup_dict = setup
        self.env = env

    def start(self, request, monkeypatch, xmlrpcs):
        for serv in xmlrpcs:
            serv.lags = []
            serv.ports_to_lags = []
        _env_list = self.env
        _setup_dict = self.setup_dict

        # first method for monkeypatching
        def _setup(self, x):
            _s = copy.deepcopy(_setup_dict)
            return _s

        # second method for monkeypatching
        def _conf(self, x):
            _e = copy.deepcopy(_env_list)
            return _e

        def clearconfig(*args, **kwargs):
            pass

        # monkeypatching methods _get_conf and _get_setup
        monkeypatch.setattr(common3.Environment, "_get_conf", _conf)
        monkeypatch.setattr(common3.Environment, "_get_setup", _setup)

        # define environment with fake class
        # mock Tkinter so we don't need Ixia installed
        # I only know how to do this with mock, if monkeypatch can do this we should use that
        with patch.dict('sys.modules', {'Tkinter': MagicMock()}):
            env = common3.Environment(FakeOpts())

        # Create fake XMLRPC server
        for switch, serv in zip(iter(env.switch.values()), xmlrpcs):  # pylint: disable=no-member
            # use the actual port of the server from the BaseServer superclass attribute
            prox = xmlrpc.client.ServerProxy('http://{0[0]}:{0[1]}'.format(serv.server.server_address))
            switch.xmlproxy = prox  # pylint: disable=no-member
            switch.hw.max_lags = 256  # pylint: disable=no-member
            switch.clearconfig = clearconfig

        return env


# fake class for options
class FakeOpts(object):
    # fake json file
    setup = "setup.json"
    # fake json file
    env = ""
    get_only = True
    build_path = ''
    ui = 'ons_xmlrpc'


@pytest.fixture(scope="module")
def fake_xmlrpc(request):
    servers = set()
    for port in {9001, 9002}:
        # make unique ports per PID so we don't have errno 98 Address already in use races.
        xml = FakeXMLRPCServer(port + os.getpid())
        xml.start()
        servers.add(xml)

    def _stop():
        for serv in servers:
            serv.stop()

    request.addfinalizer(_stop)

    return servers


@pytest.fixture()
def env(request, monkeypatch, fake_xmlrpc):
    "Fixture of environment with LXC for unittests of methods get_ports and get_speed."
    env = EnvTest(SETUP_SIMPLIFIED, ENV)
    return env.start(request, monkeypatch, fake_xmlrpc)


@pytest.fixture()
def env_list(request, monkeypatch, fake_xmlrpc):
    "Fixture of environment with LXC for unittests of methods get_ports and get_speed."

    env = EnvTest(SETUP_SIMPLIFIED_LIST, ENV)
    return env.start(request, monkeypatch, fake_xmlrpc)


@pytest.fixture()
def env_complex(request, monkeypatch, fake_xmlrpc):
    "Fixture of environment with LXC for unittests of methods get_ports and get_speed."
    env = EnvTest(SETUP_COMPLEX, ENV)
    return env.start(request, monkeypatch, fake_xmlrpc)


# Tests for env_lag fixture
def test_env_lag_1(request, env):
    """
    @brief  Verify env_lag fixture adds LAGs into ports list
    """
    fixtures.env_lag(request, env)
    for _switch in env.switch.values():
        _switch.clearconfig()
    assert env.switch[1].ports == [5, 4, 3, 2, 1, 3800, 3801, 3802, 3803, 3804]
    assert env.switch[1].port_list == []


def test_env_lag_2(request, env):
    """
    @brief  Verify env_lag fixture adds LAGs into LagsAdmin table
    """
    fixtures.env_lag(request, env)
    for _switch in env.switch.values():
        _switch.clearconfig()
    lags = set(x['lagId'] for x in env.switch[1].ui.get_table_lags())
    assert lags == {3800, 3801, 3802, 3803, 3804}


def test_env_lag_3(request, env):
    """
    @brief  Verify env_lag fixture adds ports to LAGs
    """
    fixtures.env_lag(request, env)
    for _switch in env.switch.values():
        _switch.clearconfig()
    ports_lags = {x['portId']: x['lagId']
                  for x in env.switch[1].ui.get_table_ports2lag()}
    assert ports_lags == {5: 3800, 4: 3801, 3: 3802, 2: 3803, 1: 3804}


def test_env_lag_4(request, env_list):
    """
    @brief  Verify env_lag fixture adds LAGs into port_list
    """
    fixtures.env_lag(request, env_list)
    for _switch in env_list.switch.values():
        _switch.clearconfig()
    assert env_list.switch[1].ports == [5, 4, 3, 2, 1, 3800, 3801, 3802, 3803, 3804]
    assert env_list.switch[1].port_list == [[5, 10000],
                                            [4, 10000],
                                            [3, 10000],
                                            [2, 10000],
                                            [1, 40000],
                                            [3800, 10000],
                                            [3801, 10000],
                                            [3802, 10000],
                                            [3803, 10000],
                                            [3804, 40000]]


def test_env_lag_5(request, env_list):
    """
    @brief  Verify env_lag fixture adds LAGs into LagsAdmin table
    """
    fixtures.env_lag(request, env_list)
    for _switch in env_list.switch.values():
        _switch.clearconfig()
    lags = set(x['lagId'] for x in env_list.switch[1].ui.get_table_lags())
    assert lags == {3800, 3801, 3802, 3803, 3804}


def test_env_lag_6(request, env_list):
    """
    @brief  Verify env_lag fixture adds ports to LAGs
    """
    fixtures.env_lag(request, env_list)
    for _switch in env_list.switch.values():
        _switch.clearconfig()
    ports_lags = {x['portId']: x['lagId']
                  for x in env_list.switch[1].ui.get_table_ports2lag()}
    assert ports_lags == {5: 3800, 4: 3801, 3: 3802, 2: 3803, 1: 3804}


def test_env_lag_7(request, env):
    """
    @brief  Verify env_lag fixture changes links in setup file
    """
    fixtures.env_lag(request, env)
    for _switch in env.switch.values():
        _switch.clearconfig()
    assert env.setup["cross"]['5'] == [['03', 1, '1', 6],
                                       ['03', 2, '1', 7],
                                       ['03', 3, '1', 8],
                                       ['03', 4, '1', 9],
                                       ['03', 5, '1', 10]]


def test_env_lag_8(request, env_list):
    """
    @brief  Verify env_lag fixture changes links in setup file
    """
    fixtures.env_lag(request, env_list)
    for _switch in env_list.switch.values():
        _switch.clearconfig()
    assert env_list.setup["cross"]['5'] == [['03', 1, '1', 6],
                                       ['03', 2, '1', 7],
                                       ['03', 3, '1', 8],
                                       ['03', 4, '1', 9],
                                       ['03', 5, '1', 10]]


def test_env_lag_9(request, env):
    """
    @brief  Verify env_lag fixture doesn't add LAGs into ports list in case max_lags
            is less than links count
    """
    env.switch[1].hw.max_lags = 4
    fixtures.env_lag(request, env)
    with pytest.raises(pytest.skip.Exception):
        for _switch in env.switch.values():
            _switch.clearconfig()
    assert env.switch[1].ports == [5, 4, 3, 2, 1]
    assert env.switch[1].port_list == []


def test_env_lag_10(request, env_list):
    """
    @brief  Verify env_lag fixture doesn't add LAGs into ports list in case max_lags
            is less than links count
    """
    env_list.switch[1].hw.max_lags = 4
    fixtures.env_lag(request, env_list)
    with pytest.raises(pytest.skip.Exception):
        for _switch in env_list.switch.values():
            _switch.clearconfig()
    assert env_list.switch[1].ports == [5, 4, 3, 2, 1]
    assert env_list.switch[1].port_list == [[5, 10000],
                                            [4, 10000],
                                            [3, 10000],
                                            [2, 10000],
                                            [1, 40000]]


def test_env_lag_11(request, env):
    """
    @brief  Verify env_lag fixture doesn't add LAGs into ports list in case
            port is already in LAG
    """
    env.switch[1].ui.create_lag(3900, 100, "Static", "None")
    env.switch[1].ui.create_lag_ports([1, ], 3900, 100)
    fixtures.env_lag(request, env)
    with pytest.raises(pytest.skip.Exception):
        for _switch in env.switch.values():
            _switch.clearconfig()
    assert env.switch[1].ports == [5, 4, 3, 2, 1]
    assert env.switch[1].port_list == []


def test_env_lag_12(request, env_list):
    """
    @brief  Verify env_lag fixture doesn't add LAGs into ports list in case
            port is already in LAG
    """
    env_list.switch[1].ui.create_lag(3900, 100, "Static", "None")
    env_list.switch[1].ui.create_lag_ports([1, ], 3900, 100)
    fixtures.env_lag(request, env_list)
    with pytest.raises(pytest.skip.Exception):
        for _switch in env_list.switch.values():
            _switch.clearconfig()
    assert env_list.switch[1].ports == [5, 4, 3, 2, 1]
    assert env_list.switch[1].port_list == [[5, 10000],
                                            [4, 10000],
                                            [3, 10000],
                                            [2, 10000],
                                            [1, 40000]]


def test_env_lag_13(request, env_complex):
    """
    @brief  Verify env_lag fixture adds LAGs into ports list in complex setup
    """
    fixtures.env_lag(request, env_complex)
    for _switch in env_complex.switch.values():
        _switch.clearconfig()
    assert env_complex.switch[1].ports == [1, 2, 3, 6, 7, 3800, 3801, 3802, 3803, 3804]
    assert env_complex.switch[1].port_list == []
    assert env_complex.switch[2].ports == [3, 4, 8, 9, 3800, 3801, 3803, 3804]
    assert env_complex.switch[2].port_list == []


def test_env_lag_14(request, env_complex):
    """
    @brief  Verify env_lag fixture adds LAGs into LagsAdmin table in complex setup
    """
    fixtures.env_lag(request, env_complex)
    for _switch in env_complex.switch.values():
        _switch.clearconfig()
    lags = set(x['lagId'] for x in env_complex.switch[1].ui.get_table_lags())
    assert lags == {3800, 3801, 3802, 3803, 3804}
    lags = set(x['lagId'] for x in env_complex.switch[2].ui.get_table_lags())
    assert lags == {3800, 3801, 3803, 3804}


def test_env_lag_15(request, env_complex):
    """
    @brief  Verify env_lag fixture adds ports to LAGs in complex setup
    """
    fixtures.env_lag(request, env_complex)
    for _switch in env_complex.switch.values():
        _switch.clearconfig()
    ports_lags = {x['portId']: x['lagId']
                  for x in env_complex.switch[1].ui.get_table_ports2lag()}
    assert ports_lags == {1: 3800, 2: 3801, 3: 3802, 6: 3803, 7: 3804}
    ports_lags = {x['portId']: x['lagId']
                  for x in env_complex.switch[2].ui.get_table_ports2lag()}
    assert ports_lags == {3: 3800, 4: 3801, 8: 3803, 9: 3804}


class TestLagIdGenerator(object):

    def test_none_if_no_args(self):
        g = fixtures.LagIdGenerator()
        assert g.generate_lag() is None

    def test_ignore_none(self):
        g = fixtures.LagIdGenerator()
        d1 = Mock()
        d1.id = 1
        d1.hw.max_lags = 200
        assert g.generate_lag(d1, None) == g.INITIAL_LAG
        assert g.INITIAL_LAG not in g.free_lags[d1.id]

    def test_intersection(self):
        g = fixtures.LagIdGenerator()
        d1 = Mock()
        d1.id = 1
        d1.hw.max_lags = 200
        d2 = Mock()
        d2.id = 2
        d2.hw.max_lags = 200
        d1_allocated = [g.generate_lag(d1, None) for r in range(5)]
        assert g.generate_lag(d1, d2) not in d1_allocated

    def test_stop_iteration_when_no_intersection(self):
        g = fixtures.LagIdGenerator()
        d1 = Mock()
        d1.id = 1
        d1.hw.max_lags = 200
        d2 = Mock()
        d2.id = 2
        d2.hw.max_lags = 3
        d1_allocated = [g.generate_lag(d1, None) for r in range(5)]
        with pytest.raises(StopIteration) as excinfo:
            assert g.generate_lag(d1, d2) not in d1_allocated
        assert excinfo.type == StopIteration

    def test_handle_same_device_twice(self):
        g = fixtures.LagIdGenerator()
        d1 = Mock()
        d1.id = 1
        d1.hw.max_lags = 200
        assert g.generate_lag(d1, d1) == g.INITIAL_LAG
        assert g.INITIAL_LAG not in g.free_lags[d1.id]
