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

@file test_common3.py

@summary Unittests for common3 functions.

@note
    - get_ports()
    - get_port_speed()
    - get_device_id
"""

import pytest

from testlib import common3
from testlib.dev_ixia import Ixia
from testlib.dev_switch_lxc import SwitchLXC
from testlib.custom_exceptions import TAFCoreException

# setup for LXC
SETUP_LXC = {"env": [{"id": "33", "related_id": ["16", "17", "18"]},
                     {"id": "16", "autoname": "LXC1", "port_list": [["xe1", 2500], ["xe2", 10000], ["xe3", 10000], ["xe4", 10000]]},
                     {"id": "17", "autoname": "LXC2", "port_list": [["xe1", 10000], ["xe2", 2500], ["xe3", 10000]]},
                     {"id": "18"},
                     {"id": "19"}],
             "cross": {"33": [
                 ["16", 1, "17", 2],
                 ["17", 1, "16", 2],
                 ["16", 3, "17", 3],
                 ["16", 4, "19", 1]
             ]}}

# golden setup with TG
SETUP_TG = {"env": [{"id": "0", "ports": [[1, 1, 1], [1, 1, 2], [1, 1, 3], [1, 1, 4], [1, 1, 5], [1, 1, 6], [1, 1, 7], [1, 1, 8],
                                          [1, 1, 9], [1, 1, 10], [1, 1, 11], [1, 1, 12]]},
                    {"id": "415"},
                    {"id": "413"},
                    {"id": "412"},
                    {"id": "31"}],
            "cross": {"31": [["0", 1, "415", 1], ["0", 2, "415", 2], ["0", 3, "415", 3], ["0", 4, "415", 4], ["0", 5, "415", 5],
                             ["415", 16, "413", 16], ["415", 17, "413", 17], ["415", 18, "413", 18], ["415", 19, "413", 19],
                             ["415", 20, "413", 20], ["415", 21, "413", 21], ["415", 22, "413", 22], ["415", 23, "413", 23], ["415", 24, "413", 24],
                             ["415", 11, "412", 11], ["415", 12, "412", 12], ["415", 13, "412", 13], ["415", 14, "412", 14],
                             ["0", 10, "412", 1], ["0", 11, "412", 2], ["0", 12, "412", 3],
                             ["413", 11, "412", 5], ["413", 12, "412", 6], ["413", 13, "412", 7], ["413", 14, "412", 8],
                             ["0", 6, "413", 1], ["0", 7, "413", 2], ["0", 8, "413", 3], ["0", 9, "413", 4]]}}

# config of environment
ENV = [{"entry_type": "cross", "instance_type": "vlab", "id": "33", "ip_host": "10.0.5.100", "ip_port": "8050", "ip_iface": "br0",
        "ports": ["vlab0", "vlab1", "vlab2", "vlab3", "vlab4", "vlab5", "vlab6", "vlab7", "vlab8", "vlab9", "vlab10", "vlab11"],
        "tgmap": ["22"], "related_id": ["16", "17", "18", "19"]},
       {"name": "ss1_lxc", "entry_type": "switch", "instance_type": "lxc", "id": "18",
        "ip_host": "127.0.0.18", "ip_port": "8083", "ports_count": "32",
        "cli_user": "lxc_admin", "cli_user_passw": "lxc_admin", "cli_user_prompt": "Switch", "cli_img_path": "usr/lib/cli_img",
        "related_id": ["33"]},
       {"name": "ss2_lxc", "entry_type": "switch", "instance_type": "lxc", "id": "17",
        "ip_host": "127.0.0.17", "ip_port": "8081", "ports_count": "32",
        "cli_user": "lxc_admin", "cli_user_passw": "lxc_admin", "cli_user_prompt": "Switch", "cli_img_path": "usr/lib/cli_img",
        "ports": ["xe1", "xe2", 3],
        "related_id": ["33"]},
       {"name": "ss1_lxc", "entry_type": "switch", "instance_type": "lxc", "id": "16",
        "ip_host": "127.0.0.16", "ip_port": "8082", "ports_count": "32",
        "cli_user": "lxc_admin", "cli_user_passw": "lxc_admin", "cli_user_prompt": "Switch", "cli_img_path": "usr/lib/cli_img",
        "ports": ["xe1", "xe2", 3, "xe4"],
        "related_id": ["33"]},
       {"name": "ss1_lxc", "entry_type": "switch", "instance_type": "lxc", "id": "19",
        "ip_host": "127.0.0.19", "ip_port": "8084", "ports_count": "32", "autoname": "LXC4",
        "cli_user": "lxc_admin", "cli_user_passw": "lxc_admin", "cli_user_prompt": "Switch", "cli_img_path": "usr/lib/cli_img",
        "ports": [1],
        "related_id": ["33"]},
       {"name": "IXIA-103", "entry_type": "tg", "instance_type": "ixiahl", "id": "0", "ip_host": "127.0.1.103"},
       {"name": "Zero Cross", "entry_type": "cross", "instance_type": "zero", "id": "31"},
       {"name": "seacliff15", "entry_type": "switch", "instance_type": "seacliff", "id": "415",
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
       {"name": "seacliff13", "entry_type": "switch", "instance_type": "seacliff", "id": "413",
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
       {"name": "seacliff12", "entry_type": "switch", "instance_type": "seacliff", "id": "412",
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
    # fake json file
    setup = "setup.json"
    # fake json file
    env = ""
    get_only = False
    build_path = ''
    ui = 'ons_xmlrpc'


@pytest.fixture()
def test(request, monkeypatch):
    """Fixture of environment with LXC for unittests of methods get_ports and get_speed."""

    # first method for monkeypatching
    def _setup(self, x):
        return SETUP_LXC

    # second method for monkeypatching
    def _conf(self, x):
        return ENV

    # monkeypatching methods _get_conf and _get_setup
    monkeypatch.setattr(common3.Environment, "_get_conf", _conf)
    monkeypatch.setattr(common3.Environment, "_get_setup", _setup)

    # define environment with fake class
    env = common3.Environment(FakeOpts())
    return env


@pytest.fixture()
def test_tg(request, monkeypatch):
    """ Fixture of environment with TG for unittests of methods get_ports. """
    # first method for monkeypatching
    def _setup(self, x):
        return SETUP_TG

    # second method for monkeypatching
    def _conf(self, x):
        return ENV

    # third method for monkeypatching
    def _init(self):
        pass

    # monkeypatching methods _get_conf and _get_setup
    monkeypatch.setattr(common3.Environment, "_get_conf", _conf)
    monkeypatch.setattr(common3.Environment, "_get_setup", _setup)
    # monkeypatching method _init_tcl from class Ixia
    monkeypatch.setattr(Ixia, "_init_tcl", _init)
    # define environment with fake class
    env = common3.Environment(FakeOpts())
    return env


@pytest.fixture()
def test_cross(request, monkeypatch):
    """Fixture of environment with LXC for unittests of cross."""

    cross = common3.Cross(SETUP_LXC, ENV)
    return cross


def test_get_ports_1(test):
    """ Verify that method get_ports returns the correct value if input data of three links between devices."""
    # expected result
    result = {('sw2', 'sw1'): {1: "xe2", 2: "xe1", 3: "xe3"}, ('sw1', 'sw2'): {1: "xe1", 2: "xe2", 3: "xe3"}}
    # verify expected result
    assert test.get_ports([['sw1', 'sw2', 3], ]) == result


def test_get_ports_2(test):
    """ Verify that method get_ports returns the correct value if input data of two links between devices."""
    # expected result
    result = {('sw2', 'sw1'): {1: "xe2", 2: "xe1"}, ('sw1', 'sw2'): {1: "xe1", 2: "xe2"}}
    # verify expected result
    assert test.get_ports([['sw1', 'sw2', 2], ]) == result


def test_get_ports_3(test):
    """ Verify that method get_ports returns the correct value if input data of one links between devices."""
    # expected result
    result = {('sw4', 'sw1'): {1: 1}, ('sw1', 'sw4'): {1: "xe4"}}
    # verify expected result
    assert test.get_ports([['sw1', 'sw4', 1], ]) == result


def test_get_ports_4(test):
    """ Verify that method get_ports returns all links if no input data."""
    # expected result
    result = {(test.switch[2].id, test.switch[1].id): {1: "xe2", 2: "xe1", 3: "xe3"},
              (test.switch[1].id, test.switch[2].id): {1: "xe1", 2: "xe2", 3: "xe3"},
              (test.switch[1].id, test.switch[4].id): {1: "xe4"},
              (test.switch[4].id, test.switch[1].id): {1: 1}}
    # verify expected result
    assert test.get_ports() == result


def test_get_ports_5(test):
    """ Verify that method get_ports returns all links if number of links are not defined."""
    # expected result
    result = {('sw2', 'sw1'): {1: "xe2", 2: "xe1", 3: "xe3"}, ('sw1', 'sw2'): {1: "xe1", 2: "xe2", 3: "xe3"}}
    # verify expected result
    assert test.get_ports([['sw1', 'sw2'], ]) == result


def test_get_ports_6(test):
    """ Verify that method get_ports returns the correct value if input data of two links between devices and optional parameter port_speed."""
    # expected result
    result = {('sw2', 'sw1'): {1: "xe1", 2: "xe3"}, ('sw1', 'sw2'): {1: "xe2", 2: "xe3"}}
    # verify expected result
    assert test.get_ports([['sw1', 'sw2', 2, 10000], ]) == result


def test_get_ports_7(test):
    """ Verify that method get_ports returns the correct value if input data of one links between devices and optional parameter port_speed."""
    # expected result
    result = {('sw1', 'sw2'): {1: "xe2"}, ('sw2', 'sw1'): {1: "xe1"}}
    # verify expected result
    assert test.get_ports([['sw1', 'sw2', 1, 10000], ]) == result


def test_get_ports_8(test):
    """ Verify that that method get_ports returns the correct value if input data of one links between devices , autoname and optional parameter port_speed."""
    # expected result
    result = {('sw1', 'LXC2'): {1: "xe2"}, ('LXC2', 'sw1'): {1: "xe1"}}
    # verify expected result
    assert test.get_ports([['sw1', 'LXC2', 1, 10000], ]) == result


def test_get_ports_skip_1(test, monkeypatch):
    """ Verify that behavior of method get_ports is correct if device name or type is incorrect."""
    with pytest.raises(pytest.skip.Exception) as excinfo:
        res = test.get_ports([['sw1', 'TG', 1], ])
    # verify reason of skip
    assert str(excinfo.value) == "Insufficient devices count required for test"


def test_get_ports_skip_2(test, monkeypatch):
    """ Verify that behavior of method get_ports is correct if input data of links are incorrect between devices."""
    with pytest.raises(pytest.skip.Exception) as excinfo:
        test.get_ports([['sw1', 'sw2', 100], ])
    # verify reason of skip
    assert str(excinfo.value) == "Insufficient links count required for test"


def test_get_ports_skip_3(test, monkeypatch):
    """ Verify that behavior of method get_ports is correct if there is no connection between devices."""
    with pytest.raises(pytest.skip.Exception) as excinfo:
        test.get_ports([['sw1', 'sw3', 1], ])
    # verify reason of skip
    assert str(excinfo.value) == "Insufficient links count required for test"


def test_get_ports_skip_4(test, monkeypatch):
    """ Verify that behavior of method get_ports is correct if there is no connection between devices and links are not defined"""
    with pytest.raises(pytest.skip.Exception) as excinfo:
        test.get_ports([['sw1', 'sw3', ], ])
    # verify reason of skip
    assert str(excinfo.value) == "Insufficient links count required for test"


def test_get_ports_skip_5(test, monkeypatch):
    """ Verify that behavior of method get_ports is correct if port speed is incorrect"""
    port_speed = 20000
    with pytest.raises(pytest.skip.Exception) as excinfo:
        test.get_ports([['sw1', 'sw2', 2, port_speed], ])
    # verify reason of skip
    assert str(excinfo.value) == "No links with required speed {0}".format(port_speed)


def test_get_ports_error_1(test):
    """ Verify that method get_ports returns Error message if input data of zero links between devices."""
    # catch exception
    with pytest.raises(TAFCoreException) as excepinfo:
        test.get_ports([['sw1', 'sw2', 0], ])
    # expected result
    result = "Number of links cannot equal zero."
    # verify expected result
    assert excepinfo.value.parameter == result


def test_get_ports_error_2(test):
    """ Verify that method get_ports returns Error message if input data are incorrect."""
    # catch exception
    with pytest.raises(TAFCoreException) as excepinfo:
        test.get_ports([['sw1', ], ])
    # expected result
    result = "At list is not specified devices."
    # verify expected result
    assert excepinfo.value.parameter == result


def test_get_device_id_1(test):
    """ Verify that method get_device_id returns the correct value if input data of acronym."""
    # verify expected result
    assert test.get_device_id("sw1") == "16"


def test_get_device_id_2(test):
    """ Verify that method get_device_id returns the correct value if input data of autoname."""
    # verify expected result
    assert test.get_device_id("LXC2") == "17"


def test_get_device_id_3(test):
    """ Verify that method get_device_id returns Error message if input data incorrect."""
    # catch exception
    with pytest.raises(TAFCoreException) as excepinfo:
        test.get_device_id("sw")
    # verify expected result
    result = "This device type not found. This method supports only %s or %s device types." % (list(test.dut_map.keys()), list(test.autoname_map.keys()))
    assert excepinfo.value.parameter == result


def test_get_device_id_4(test):
    """ Verify that method get_device_id returns the correct value if input data of device's ID."""
    # verify expected result
    assert test.get_device_id("18") == "18"


def test_get_port_speed_1(test):
    """ Verify that method get_port_speed returns the correct value."""
    # verify expected result
    assert test.get_port_speed("sw1", 2) == 10000


def test_get_port_speed_2(test):
    """ Verify that method get_port_speed returns the correct value."""
    # verify expected result
    assert test.get_port_speed("LXC2", 3) == 10000


def test_get_port_speed_3(test):
    """ Verify that method get_port_speed returns Error message if input data incorrect."""
    # define arguments for method
    arg_1 = "LXC1"
    arg_2 = 5
    # catch exception
    with pytest.raises(TAFCoreException) as excepinfo:
        test.get_port_speed(arg_1, arg_2)
    # verify expected result
    result = "Port id %s is not configured on device %s." % (arg_2, arg_1)
    assert excepinfo.value.parameter == result


def test_get_port_speed_4(test):
    """ Verify that method get_port_speed returns Error message if input data incorrect."""
    # define arguments for method
    arg_1 = "sw3"
    arg_2 = 1
    # catch exception
    with pytest.raises(TAFCoreException) as excepinfo:
        test.get_port_speed(arg_1, arg_2)
    # verify expected result
    result = "List of ports speed is not configured on device %s." % arg_1
    assert excepinfo.value.parameter == result


def test_get_real_port_name_1(test):
    """ Verify that method get_real_port_name returns Error message if input data incorrect."""
    # define arguments for method
    arg_1 = "sw3"
    arg_2 = 10
    # catch exception
    with pytest.raises(TAFCoreException) as excepinfo:
        test.get_real_port_name(arg_1, arg_2)
    # verify expected result
    result = "Device %s(%s) doesn't have 'ports' or 'port_list' attributes." % (test.switch[3].id, arg_1)
    assert excepinfo.value.parameter == result


def test_get_real_port_name_2(test):
    """ Verify that method get_real_port_name returns Error message if input data incorrect."""
    # define arguments for method
    arg_1 = "sw1"
    arg_2 = 17
    # catch exception
    with pytest.raises(TAFCoreException) as excepinfo:
        test.get_real_port_name(arg_1, arg_2)
    # verify expected result
    result = "Port ID %s is not found in 'port_list' of %s(%s)." % (arg_2, test.switch[1].id, arg_1)
    assert excepinfo.value.parameter == result


def test_get_real_port_name_3(test):
    """ Verify that method get_real_port_name returns Error message if input data incorrect."""
    # define arguments for method
    arg_1 = "19"
    arg_2 = 30
    # catch exception
    with pytest.raises(TAFCoreException) as excepinfo:
        test.get_real_port_name(arg_1, arg_2)
    # verify expected result
    result = "Port ID %s is not found in 'ports' of %s(%s)." % (arg_2, test.switch[4].id, arg_1)
    assert excepinfo.value.parameter == result


def test_get_ports_12(test_tg):
    """ Verify that method get_ports returns the correct values for setup with TG."""
    # expected result
    ports = test_tg.get_ports()
    # verify expected result
    assert ports[("415", "0")][1] == 24
    assert ports[("415", "0")][2] == 25
    assert ports[("0", "415")][1] == (1, 1, 1)
    assert ports[("0", "415")][2] == (1, 1, 2)
    assert ports[("415", "412")] == {1: 34, 2: 35, 3: 36, 4: 37}
    assert ports[("412", "415")][3] == 36
    assert ports[("415", "413")][9] == 47
    assert ports[("413", "415")][1] == 39
    assert ports[("0", "412")][3] == (1, 1, 12)
    assert ports[("412", "0")][1] == 24
    assert ports[("413", "412")][1] == 34
    assert ports[("412", "413")] == {1: 28, 2: 29, 3: 30, 4: 31}
    assert ports[("0", "413")][3] == (1, 1, 8)
    assert ports[("413", "0")][4] == 27


def test_get_ports_13(test):
    """ Verify that method get_ports returns the correct value if input data without optional parameter 'number_of_links'."""
    # expected result
    result = {('sw1', 'sw2'): {1: 'xe1', 2: 'xe2', 3: 'xe3'}, ('sw2', 'sw1'): {1: 'xe2', 2: 'xe1', 3: 'xe3'}}
    # verify expected result
    assert test.get_ports([['sw1', 'sw2', ], ]) == result


def test_get_ports_14(test):
    """ Verify that method get_ports returns the correct value if input data with two optional parameters."""
    # expected result
    result = {('sw1', 'sw2'): {1: 'xe2', 2: 'xe3'}, ('sw2', 'sw1'): {1: 'xe1', 2: 'xe3'}}
    # verify expected result
    assert test.get_ports([['sw1', 'sw2', "ALL", 10000], ]) == result


def test_get_ports_15(test):
    """ Verify that method get_ports returns the correct value if input data with optional parameter 'number_of_links' - enum 'ALL'."""
    # expected result
    result = {('sw1', 'sw2'): {1: 'xe1', 2: 'xe2', 3: 'xe3'}, ('sw2', 'sw1'): {1: 'xe2', 2: 'xe1', 3: 'xe3'}}
    # verify expected result
    assert test.get_ports([['sw1', 'sw2', "ALL", ], ]) == result


def test_id2instance_1(test):
    """ Verify that method id2instance returns the correct object if input data id device as str."""
    instance = test.id2instance('16')
    assert isinstance(instance, SwitchLXC)


def test_id2instance_2(test_tg):
    """ Verify that method id2instance returns the correct object if input data id device as int."""
    instance = test_tg.id2instance("0")
    assert isinstance(instance, Ixia)


def test_id2instance_3(test):
    """ Verify that method id2instance returns the correct object if input data device LINK_NAME."""
    instance = test.id2instance('sw2')
    assert isinstance(instance, SwitchLXC)


class TestCross(object):

    @pytest.fixture(autouse=True)
    def create_ui(self, test_cross):
        self.cross = test_cross

    def test_get_device_id1(self):
        # assert self.cross.get_device_id(con) == 5
        for connections in self.cross.setup['cross'].values():
            for con in connections:
                assert self.cross.get_device_id(con) == 1
        for connections in self.cross.setup['cross'].values():
            for connection in connections:
                con = connection[2:] + connection[:2]
                assert self.cross.get_device_id(con) == 1

    def test_not_found_raises_exception(self):
        with pytest.raises(Exception) as excinfo:
            self.cross.get_device_id([])
        assert 'Can not find device with such connection' in str(excinfo.value)
