# Copyright (c) 2011 - 2017, Intel Corporation.
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

"""``test_getports.py``

`Unittests for getting ports functions`

"""

import pytest

from testlib import common3


# simplified setup
SETUP_SIMPLE = {"env": [{"id": 0, "ports": [[1, 5, 1], [1, 5, 2], [1, 5, 3], [1, 5, 4], [1, 5, 5]]},
                        {"id": 415},
                        {"id": "31"}],
                "cross": {"31": [[0, 1, 415, 1], [0, 2, 415, 2], [0, 3, 415, 3], [0, 4, 415, 4], [0, 5, 415, 5]]}}

# golden setup
SETUP_GOLDEN = {"env": [{"id": 0, "ports": [[1, 1, 1], [1, 1, 2], [1, 1, 3], [1, 1, 4], [1, 1, 5], [1, 1, 6], [1, 1, 7], [1, 1, 8],
                                            [1, 1, 9], [1, 1, 10], [1, 1, 11], [1, 1, 12]]},
                        {"id": 415},
                        {"id": 413},
                        {"id": 412},
                        {"id": "31"}],
                "cross": {"31": [[0, 1, 415, 1], [0, 2, 415, 2], [0, 3, 415, 3], [0, 4, 415, 4], [0, 5, 415, 5],
                                 [415, 16, 413, 16], [415, 17, 413, 17], [415, 18, 413, 18], [415, 19, 413, 19],
                                 [415, 20, 413, 20], [415, 21, 413, 21], [415, 22, 413, 22], [415, 23, 413, 23], [415, 24, 413, 24],
                                 [415, 11, 412, 11], [415, 12, 412, 12], [415, 13, 412, 13], [415, 14, 412, 14],
                                 [0, 10, 412, 1], [0, 11, 412, 2], [0, 12, 412, 3],
                                 [413, 11, 412, 5], [413, 12, 412, 6], [413, 13, 412, 7], [413, 14, 412, 8],
                                 [0, 6, 413, 1], [0, 7, 413, 2], [0, 8, 413, 3], [0, 9, 413, 4]]}}

# config of environment
ENV = [{"name": "tg1", "entry_type": "tg", "instance_type": "riperf", "id": 0, "ip_host": "127.0.0.1"},
       {"name": "Zero Cross", "entry_type": "cross", "instance_type": "zero", "id": "31"},
       {"name": "seacliff15", "entry_type": "switch", "instance_type": "seacliff", "id": 415,
        "ip_host": "127.0.1.146", "ip_port": "8081",
        "use_sshtun": 1, "sshtun_user": "admin", "sshtun_pass": "admin", "sshtun_port": 22,
        "default_gw": "127.0.1.1", "net_mask": "255.255.255.0",
        "ports_count": "52", "pwboard_host": "127.0.1.94", "pwboard_port": "15", "halt": 0,
        "portserv_host": "127.0.1.93", "portserv_user": "root", "portserv_pass": "dbps", "portserv_tty": 15, "portserv_port": 2015,
        "telnet_loginprompt": "seacliff15 login:", "telnet_passprompt": "Password:",
        "telnet_user": "admin", "telnet_pass": "admin", "telnet_prompt": "[admin@seacliff15 ~]$",
        "cli_user": "admin", "cli_user_passw": "admin", "cli_user_prompt": "Switch",
        "ports": [24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50],
        "related_id": ["31"]},
       {"name": "seacliff13", "entry_type": "switch", "instance_type": "seacliff", "id": 413,
        "ip_host": "127.0.1.137", "ip_port": "8081",
        "use_sshtun": 1, "sshtun_user": "admin", "sshtun_pass": "admin", "sshtun_port": 22,
        "default_gw": "127.0.1.1", "net_mask": "255.255.255.0",
        "ports_count": "52", "pwboard_host": "127.0.1.94", "pwboard_port": "13", "halt": 0,
        "portserv_host": "127.0.1.93", "portserv_user": "root", "portserv_pass": "dbps", "portserv_tty": 13, "portserv_port": 2013,
        "telnet_loginprompt": "seacliff13 login:", "telnet_passprompt": "Password:",
        "telnet_user": "admin", "telnet_pass": "admin", "telnet_prompt": "[admin@seacliff13 ~]$",
        "cli_user": "admin", "cli_user_passw": "admin", "cli_user_prompt": "Switch",
        "ports": [24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50],
        "related_id": ["31"]},
       {"name": "seacliff12", "entry_type": "switch", "instance_type": "seacliff", "id": 412,
        "ip_host": "127.0.1.145", "ip_port": "8081",
        "use_sshtun": 1, "sshtun_user": "admin", "sshtun_pass": "admin", "sshtun_port": 22,
        "default_gw": "127.0.1.1", "net_mask": "255.255.255.0",
        "ports_count": "52", "pwboard_host": "127.0.1.94", "pwboard_port": "12", "halt": 0,
        "portserv_host": "127.0.1.93", "portserv_user": "root", "portserv_pass": "dbps", "portserv_tty": 12, "portserv_port": 2012,
        "telnet_loginprompt": "seacliff12 login:", "telnet_passprompt": "Password:",
        "telnet_user": "admin", "telnet_pass": "admin", "telnet_prompt": "[admin@seacliff12 ~]$",
        "cli_user": "admin", "cli_user_passw": "admin", "cli_user_prompt": "Switch",
        "ports": [24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50],
        "related_id": ["31"]}]


# fake class for options
class FakeOpts(object):
    """FakeOpts class.

    """
    # fake json file
    setup = "setup.json"
    # fake json file
    env = "setup.json"
    get_only = False
    build_path = ''
    ui = 'ons_xmlrpc'


@pytest.fixture()
def env_golden(request, monkeypatch):
    """Fixture of environment for unittests of methods get_ports and get_speed.

    """
    # first method for monkeypatching

    def _setup(self, x):
        return SETUP_GOLDEN
    # second method for monkeypatching

    def _conf(self, x):
        return ENV
    # third method for monkeypatching

    def _init(self):
        pass

    # monkeypatching methods _get_conf and _get_setup
    monkeypatch.setattr(common3.Environment, "_get_conf", _conf)
    monkeypatch.setattr(common3.Environment, "_get_setup", _setup)
    # define environment with fake class
    env = common3.Environment(FakeOpts())
    return env


@pytest.fixture()
def env_simple(request, monkeypatch):
    """Fixture of environment for unittests of methods get_ports and get_speed.

    """
    # first method for monkeypatching
    def _setup(self, x):
        return SETUP_SIMPLE
    # second method for monkeypatching

    def _conf(self, x):
        return ENV
    # third method for monkeypatching

    def _init(self):
        pass

    # monkeypatching methods _get_conf and _get_setup
    monkeypatch.setattr(common3.Environment, "_get_conf", _conf)
    monkeypatch.setattr(common3.Environment, "_get_setup", _setup)
    # define environment with fake class
    env = common3.Environment(FakeOpts())
    return env


def test_getports01(env_golden):
    # expected result
    ports = env_golden.get_ports([['sw1', 'sw2', 1], ['sw1', 'sw3', 1], ['sw2', 'sw3', 1], ['tg1', 'sw1', 1], ['tg1', 'sw2', 1], ['tg1', 'sw3', 1]])
    # verify expected result
    assert ports[('sw1', 'sw2')] == {1: 39}
    assert ports[('sw2', 'sw1')] == {1: 39}


def test_getports02(env_simple):
    # expected result
    ports = env_simple.get_ports([['tg1', 'sw1', 3], ])
    # verify expected result
    assert ports[('sw1', 'tg1')][1] == 24
    assert ports[('sw1', 'tg1')][2] == 25
    assert ports[('sw1', 'tg1')][3] == 26


def test_getports03(env_golden):
    # expected result
    ports = env_golden.get_ports([['sw1', 'tg1', 3], ])
    # verify expected result
    assert ports[('sw1', 'tg1')][1] == 24
    assert ports[('sw1', 'tg1')][2] == 25
    assert ports[('sw1', 'tg1')][3] == 26
