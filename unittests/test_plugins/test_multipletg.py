"""
@copyright Copyright (c) 2015 - 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file test_multipletg.py

@summary Unittests for pytest_multipletg plugin.
"""
import copy
from unittest.mock import patch, MagicMock

import pytest

from testlib import multiple_tg
from testlib import common3
from plugins.pytest_multipletg import MultipleTGClass


# config of environment
ENV = [
    {"name": "Zero Cross", "entry_type": "cross", "instance_type": "static_ons", "id": "5",
     "kprio": 10, "sprio": 300, "cprio": 300, "tprio": 300},

    {"name": "IXIA-1", "entry_type": "tg", "instance_type": "ixiahl", "id": "01",
     "ip_host": "192.168.0.1",
     "ports": [[1, 1, 1], [1, 1, 2]]},

    {"name": "IXIA-2", "entry_type": "tg", "instance_type": "ixiahl", "id": "02",
     "ip_host": "192.168.0.2",
     "ports": [[1, 1, 1], [1, 1, 2]]},

    {"name": "sct01or", "entry_type": "switch", "instance_type": "seacliff", "id": "03",
     "kprio": 100, "ip_host": "192.168.0.3", "ip_port": "8081",
     "use_sshtun": 1, "sshtun_user": "admin", "sshtun_pass": "admin",
     "sshtun_port": 22, "default_gw": "192.167.0.1", "net_mask": "255.255.254.0",
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

    {"name": "sct02or", "entry_type": "switch", "instance_type": "seacliff", "id": "04",
     "kprio": 100, "ip_host": "192.168.0.4", "ip_port": "8081",
     "use_sshtun": 1, "sshtun_user": "admin", "sshtun_pass": "admin",
     "sshtun_port": 22, "default_gw": "192.167.0.1", "net_mask": "255.255.254.0",
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

# setup with two IXIAs
SETUP = {
    "env": [
        {"id": "01", "ports": [[1, 1, 1], [1, 1, 2]]},
        {"id": "02", "ports": [[1, 2, 1], [1, 2, 2]]},
        {"id": "03", "ports": [4, 3, 2, 1]},
        {"id": "5", "related_id": ["01", "02", "03"]}
    ],
    "cross":
        {"5":
            [
                ["03", 1, "01", 1],
                ["03", 2, "01", 2],
                ["03", 3, "02", 1],
                ["03", 4, "02", 2]
        ]
    }
}

# setup with two IXIAs and port_list
SETUP_LIST = {
    "env": [
        {"id": "01", "port_list": [[[1, 1, 1], 10000], [[1, 1, 2], 10000]]},
        {"id": "02", "ports": [[1, 2, 1], [1, 2, 2]]},
        {"id": "03", "ports": [4, 3, 2, 1]},
        {"id": "5", "related_id": ["01", "02", "03"]}
    ],
    "cross":
        {"5":
            [
                ["03", 1, "01", 1],
                ["03", 2, "01", 2],
                ["03", 3, "02", 1],
                ["03", 4, "02", 2]
        ]
    }
}

# complex setup with two IXIAs
SETUP_COMPLEX = {
    "env": [
        {"id": "01", "ports": [[1, 1, 1], [1, 1, 2]]},
        {"id": "02", "ports": [[1, 2, 1], [1, 2, 2]]},
        {"id": "03", "ports": [1, 2, 3]},
        {"id": "04", "ports": [3, 4, 8]},
        {"id": "5", "related_id": ["01", "02", "03", "04"]}
    ],
    "cross":
        {"5":
            [
                ["01", 1, "03", 1],
                ["01", 2, "03", 2],
                ["02", 1, "04", 1],
                ["02", 2, "04", 2],
                ["03", 3, "04", 3]
        ]
    }
}


class EnvTest(object):

    def __init__(self, setup, env):
        self.setup_dict = setup
        self.env = env

    def start(self, request, monkeypatch):
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

        # monkeypatching methods _get_conf and _get_setup
        monkeypatch.setattr(common3.Environment, "_get_conf", _conf)
        monkeypatch.setattr(common3.Environment, "_get_setup", _setup)

        # define environment with fake class
        # mock Tkinter so we don't need Ixia installed
        # I only know how to do this with mock, if monkeypatch can do this we should use that
        with patch.dict('sys.modules', {'Tkinter': MagicMock()}):
            env = common3.Environment(FakeOpts())

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


@pytest.fixture()
def env(request, monkeypatch):
    "Fixture of environment with LXC for unittests of methods get_ports and get_speed."
    env = EnvTest(SETUP, ENV)
    return env.start(request, monkeypatch)


@pytest.fixture()
def env_list(request, monkeypatch):
    "Fixture of environment with LXC for unittests of methods get_ports and get_speed."

    env = EnvTest(SETUP_LIST, ENV)
    return env.start(request, monkeypatch)


@pytest.fixture()
def env_complex(request, monkeypatch):
    "Fixture of environment with LXC for unittests of methods get_ports and get_speed."
    env = EnvTest(SETUP_COMPLEX, ENV)
    return env.start(request, monkeypatch)


# Tests for pytest_multipletg plugin
def test_multipletg_1(request, env):
    """
    @brief  Verify pytest_multipletg plugin creates MultipleTG instance and modifies env.tg dict
    """
    # Verify env.tg before
    assert list(env.tg.keys()) == [1, 2]
    tg = MultipleTGClass(env)
    tg.setup()
    # Verify env.tg after setup
    assert list(env.tg.keys()) == [1]
    assert isinstance(env.tg[1], multiple_tg.MultipleTG)
    assert env.tg[1].id == "0102"
    assert env.tg[1].type == "ixiahl"
    assert not env.tg[1].port_list  # port_list should be empty
    assert sorted(env.tg[1].ports) == [
        multiple_tg.Port("01", (1, 1, 1)),
        multiple_tg.Port("01", (1, 1, 2)),
        multiple_tg.Port("02", (1, 2, 1)),
        multiple_tg.Port("02", (1, 2, 2))]


def test_multipletg_2(request, env):
    """
    @brief  Verify pytest_multipletg plugin modifies cross section
    """
    assert env.cross[1].connections == [
        ["03", 1, "01", 1],
        ["03", 2, "01", 2],
        ["03", 3, "02", 1],
        ["03", 4, "02", 2]
    ]
    tg = MultipleTGClass(env)
    tg.setup()
    index_1 = env.tg[1].ports.index(multiple_tg.Port("01", (1, 1, 1))) + 1
    index_2 = env.tg[1].ports.index(multiple_tg.Port("01", (1, 1, 2))) + 1
    index_3 = env.tg[1].ports.index(multiple_tg.Port("02", (1, 2, 1))) + 1
    index_4 = env.tg[1].ports.index(multiple_tg.Port("02", (1, 2, 2))) + 1
    assert set([index_1, index_2, index_3, index_4]) == {1, 2, 3, 4}
    assert env.cross[1].connections == [
        ["03", 1, "0102", index_1],
        ["03", 2, "0102", index_2],
        ["03", 3, "0102", index_3],
        ["03", 4, "0102", index_4]
    ]


def test_multipletg_3(request, env):
    """
    @brief  Verify pytest_multipletg plugin restores env.tg dict on teardown
    """
    tg = MultipleTGClass(env)
    tg.setup()
    tg.teardown()
    # Verify env.tg after teardown
    assert list(env.tg.keys()) == [1, 2]
    assert env.tg[1].ports == [(1, 1, 1), (1, 1, 2)]
    assert env.tg[2].ports == [(1, 2, 1), (1, 2, 2)]


def test_multipletg_4(request, env):
    """
    @brief  Verify pytest_multipletg plugin restores cross section on teardown
    """
    tg = MultipleTGClass(env)
    tg.setup()
    tg.teardown()
    assert env.cross[1].connections == [
        ["03", 1, "01", 1],
        ["03", 2, "01", 2],
        ["03", 3, "02", 1],
        ["03", 4, "02", 2]
    ]


def test_multipletg_5(request, env_list):
    """
    @brief  Verify pytest_multipletg plugin creates port_list if it is in setup
    """
    tg = MultipleTGClass(env_list)
    tg.setup()
    assert sorted(env_list.tg[1].ports) == [
        multiple_tg.Port("01", (1, 1, 1)),
        multiple_tg.Port("01", (1, 1, 2)),
        multiple_tg.Port("02", (1, 2, 1)),
        multiple_tg.Port("02", (1, 2, 2))
        ]


def test_multipletg_6(request, env_complex):
    """
    @brief  Verify pytest_multipletg plugin modifies cross section in complex setup
    """
    assert env_complex.cross[1].connections == [
        ["01", 1, "03", 1],
        ["01", 2, "03", 2],
        ["02", 1, "04", 1],
        ["02", 2, "04", 2],
        ["03", 3, "04", 3]
    ]
    tg = MultipleTGClass(env_complex)
    tg.setup()
    index_1 = env_complex.tg[1].ports.index(multiple_tg.Port("01", (1, 1, 1))) + 1
    index_2 = env_complex.tg[1].ports.index(multiple_tg.Port("01", (1, 1, 2))) + 1
    index_3 = env_complex.tg[1].ports.index(multiple_tg.Port("02", (1, 2, 1))) + 1
    index_4 = env_complex.tg[1].ports.index(multiple_tg.Port("02", (1, 2, 2))) + 1
    assert set([index_1, index_2, index_3, index_4]) == {1, 2, 3, 4}
    assert env_complex.cross[1].connections == [
        ["0102", index_1, "03", 1],
        ["0102", index_2, "03", 2],
        ["0102", index_3, "04", 1],
        ["0102", index_4, "04", 2],
        ["03", 3, "04", 3]
    ]
