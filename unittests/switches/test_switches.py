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

"""``test_switches.py``

`Switch's unittests`

"""
import xmlrpc.client

import pytest

from ..common import FakeXMLRPCServer, TCP_PORT
from testlib import dev_switch_lxc
from testlib.custom_exceptions import SwitchException


SWITCH_CONFIG = {"name": "Test Switch", "entry_type": "switch", "instance_type": "lxc", "id": "1",
                 "ip_host": "192.168.0.10", "ip_port": "8081",
                 "use_sshtun": 1, "sshtun_user": "admin", "sshtun_pass": "admin", "sshtun_port": 22,
                 "default_gw": "192.168.0.1", "net_mask": "255.255.255.0",
                 "ports_count": "64", "pwboard_host": "192.167.0.5", "pwboard_port": "2", "halt": 0,
                 "use_serial": False,
                 "portserv_host": "192.168.1.5", "portserv_user": "root", "portserv_pass": "dbps", "portserv_tty": 14, "portserv_port": 2008,
                 "telnet_loginprompt": "localhost login:", "telnet_passprompt": "Password:",
                 "telnet_user": "admin", "telnet_pass": "admin", "telnet_prompt": "[admin@localhost ~]$",
                 "cli_user": "admin", "cli_user_passw": "admin", "cli_user_prompt": "Switch",
                 "ports": [],
                 "cli_img_path": "usr/lib/ons/cli_img/",
                 "related_conf": {}}


@pytest.fixture(scope="module")
def switch(request):
    sw = dev_switch_lxc.SwitchLXC(SWITCH_CONFIG, request.config.option)
    xml = FakeXMLRPCServer()
    sw.fake_server = xml
    sw.xmlproxy = xmlrpc.client.ServerProxy('http://localhost:{0}'.format(TCP_PORT))
    xml.start()

    def _stop():
        xml.stop()

    request.addfinalizer(_stop)
    return sw


def test_switch_init(switch):
    assert switch.id == SWITCH_CONFIG["id"]
    assert switch.type == SWITCH_CONFIG["instance_type"]
    assert switch.name == SWITCH_CONFIG["name"]
    assert switch.ipaddr == SWITCH_CONFIG["ip_host"]
    assert switch.port == SWITCH_CONFIG["ip_port"]
    assert switch.ports_count == SWITCH_CONFIG["ports_count"]
    assert switch.ports == []
    assert switch.port_list == []
    assert switch.mgmt_ports == []

    assert switch.default_restart_type == "powercycle"

    # Use serial console for real devices or not.
    assert switch._use_serial == SWITCH_CONFIG["use_serial"]
    # assert switch._use_sshtun is True
    # assert switch._sshtun_user == SWITCH_CONFIG["sshtun_user"]
    # assert switch._sshtun_pass == SWITCH_CONFIG["sshtun_pass"]
    assert switch._sshtun_port == SWITCH_CONFIG["sshtun_port"]
    assert switch.status is False
    assert switch.db_corruption is False


def test_get_speed_ports_1(switch):
    """Test _get_speed_ports function if 'ports' in config.

    """
    switch.config["ports"] = [1, 2, 3]
    ports, speed_ports, ports_map = switch._get_speed_ports()
    assert ports == [1, 2, 3]
    assert speed_ports == []
    assert ports_map == []


def test_get_speed_ports_2(switch):
    """Test _get_speed_ports function if 'port_list' in config.

    """
    switch.config["port_list"] = [[1, 10000], [2, 40000], [3, 2500]]
    ports, speed_ports, ports_map = switch._get_speed_ports()
    assert ports == [1, 2, 3]
    assert speed_ports == [[1, 10000], [2, 40000], [3, 2500]]
    assert ports_map == []


def test_get_speed_ports_3(switch):
    """Test _get_speed_ports function if 'ports' and 'port_list' in config.

    """
    switch.config["ports"] = [5, 6, 7]
    switch.config["port_list"] = [[1, 10000], [2, 40000], [3, 2500]]
    ports, speed_ports, ports_map = switch._get_speed_ports()
    assert ports == [1, 2, 3]
    assert speed_ports == [[1, 10000], [2, 40000], [3, 2500]]
    assert ports_map == []


def test_get_speed_ports_4(switch):
    """Test _get_speed_ports function if 'ports_map' in config.

    """
    switch.config["ports"] = [5, 6, 7]
    switch.config["port_list"] = [[1, 10000], [2, 40000], [3, 2500]]
    switch.config["ports_map"] = [[61, [61, 62, 63, 64]], [65, [65, 66, 67, 68]]]
    ports, speed_ports, ports_map = switch._get_speed_ports()
    assert ports == [1, 2, 3]
    assert speed_ports == [[1, 10000], [2, 40000], [3, 2500]]
    assert ports_map == [[61, [61, 62, 63, 64]], [65, [65, 66, 67, 68]]]


def test_set_app_log_level_1(switch):
    """Test set_app_log_level function.

    """
    sw = switch.xmlproxy.nb.Applications.getTable()
    for row in sw:
        assert row['logLevel'] == 'test level'
    switch.set_app_log_level()
    sw = switch.xmlproxy.nb.Applications.getTable()
    for row in sw:
        assert row['logLevel'] == 'Notice'
    switch.set_app_log_level(loglevel='test level')
    sw = switch.xmlproxy.nb.Applications.getTable()
    for row in sw:
        assert row['logLevel'] == 'test level'


def test_set_app_log_level_2(switch):
    """Test set_app_log_level function negative.

    """
    sw = switch.xmlproxy.nb.Applications.getTable()
    for row in sw:
        assert row['logLevel'] == 'test level'
    with pytest.raises(Exception):
        switch.set_app_log_level(loglevel='error')
    sw = switch.xmlproxy.nb.Applications.getTable()
    for row in sw:
        assert row['logLevel'] == 'test level'


def test_get_port_for_probe(switch):
    """Test _get_port_for_probe function.

    """
    use_tun = switch._use_sshtun
    ssh_port = switch._sshtun_port
    port = switch.port
    switch._use_sshtun = True
    _port = switch._get_port_for_probe()
    assert _port == int(ssh_port)
    switch._use_sshtun = False
    _port = switch._get_port_for_probe()
    assert _port == int(port)
    switch._use_sshtun = use_tun


def test_check_app_table_1(switch):
    """Test check_app_table function.

    """
    assert switch.check_app_table() is True


def test_check_app_table_2(switch):
    """Test check_app_table function negative.

    """
    apps = switch.fake_server.applications
    switch.fake_server.applications = [{'name': 'ONSApplicationServer', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 1, 'operationalState': 'Stop'},
                                       {'name': 'SimSwitchApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 2, 'operationalState': 'Run'},
                                       {'name': 'ONSCoreServer', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 3, 'operationalState': 'Run'},
                                       {'name': 'ONSNorthboundServer', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 4, 'operationalState': 'Run'},
                                       {'name': 'L3DhcpRelayControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 5, 'operationalState': 'Run'},
                                       {'name': 'L2MirrorControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 6, 'operationalState': 'Run'},
                                       {'name': 'L2QosControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 7, 'operationalState': 'Run'},
                                       {'name': 'L2StormControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 8, 'operationalState': 'Run'},
                                       {'name': 'L2StatsControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 9, 'operationalState': 'Run'},
                                       {'name': 'ONSOpenVSwitchApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 10, 'operationalState': 'Run'},
                                       {'name': 'L1SfpControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 11, 'operationalState': 'Run'},
                                       {'name': 'L2VlanControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 12, 'operationalState': 'Run'},
                                       {'name': 'L1PortControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 13, 'operationalState': 'Run'},
                                       {'name': 'L2QinqControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 14, 'operationalState': 'Run'},
                                       {'name': 'L2FdbControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 15, 'operationalState': 'Run'},
                                       {'name': 'L2AclControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 16, 'operationalState': 'Run'},
                                       {'name': 'L1SwitchControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 17, 'operationalState': 'Run'},
                                       {'name': 'L2MulticastControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 18, 'operationalState': 'Run'},
                                       {'name': 'L2LagControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 19, 'operationalState': 'Run'},
                                       {'name': 'L3ControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 20, 'operationalState': 'Run'},
                                       {'name': 'L2LldpControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 21, 'operationalState': 'Run'},
                                       {'name': 'L2StpControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 22, 'operationalState': 'Run'}]
    assert switch.check_app_table() is False
    switch.fake_server.applications = apps


def test_check_app_table_3(switch):
    """Test check_app_table function negative.

    """
    apps = switch.fake_server.applications
    switch.fake_server.applications = [{'name': 'SimSwitchApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 2, 'operationalState': 'Run'},
                                       {'name': 'ONSCoreServer', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 3, 'operationalState': 'Run'},
                                       {'name': 'ONSNorthboundServer', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 4, 'operationalState': 'Run'},
                                       {'name': 'L3DhcpRelayControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 5, 'operationalState': 'Run'},
                                       {'name': 'L2MirrorControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 6, 'operationalState': 'Run'},
                                       {'name': 'L2QosControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 7, 'operationalState': 'Run'},
                                       {'name': 'L2StormControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 8, 'operationalState': 'Run'},
                                       {'name': 'L2StatsControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 9, 'operationalState': 'Run'},
                                       {'name': 'ONSOpenVSwitchApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 10, 'operationalState': 'Run'},
                                       {'name': 'L1SfpControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 11, 'operationalState': 'Run'},
                                       {'name': 'L2VlanControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 12, 'operationalState': 'Run'},
                                       {'name': 'L1PortControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 13, 'operationalState': 'Run'},
                                       {'name': 'L2QinqControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 14, 'operationalState': 'Run'},
                                       {'name': 'L2FdbControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 15, 'operationalState': 'Run'},
                                       {'name': 'L2AclControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 16, 'operationalState': 'Run'},
                                       {'name': 'L1SwitchControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 17, 'operationalState': 'Run'},
                                       {'name': 'L2MulticastControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 18, 'operationalState': 'Run'},
                                       {'name': 'L2LagControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 19, 'operationalState': 'Run'},
                                       {'name': 'L3ControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 20, 'operationalState': 'Run'},
                                       {'name': 'L2LldpControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 21, 'operationalState': 'Run'},
                                       {'name': 'L2StpControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 22, 'operationalState': 'Run'}]
    assert switch.check_app_table() is False
    switch.fake_server.applications = apps


def test_probe_1(switch):
    """Test probe function negative.

    """
    switch.ipaddr = '127.0.0.1'
    switch.port = 22
    switch._use_sshtun = False
    res = switch.probe()
    assert res['isup'] is True
    assert res['type'] == 'unknown'
    assert res['prop'] == {}


def test_probe_2(switch):
    """Test probe function.

    """
    switch.fake_server.server.register_function(switch.fake_server.platform_get_table, 'nb.Platform.getTable')
    switch.fake_server.server.register_function(switch.fake_server.ports_gettable, 'nb.Ports.getTable')
    switch.ipaddr = '127.0.0.1'
    switch.port = 22
    switch._use_sshtun = False
    res = switch.probe()
    assert res['isup'] is True
    assert res['type'] == 'switchpp'
    assert res['prop'] == switch.fake_server.platform[0]


def test_waiton_1(switch):
    """Test waiton function.

    """
    switch.ipaddr = '127.0.0.1'
    switch.port = 22
    switch._use_sshtun = False
    res = switch.waiton()
    assert res['isup'] is True
    assert res['type'] == 'switchpp'
    assert res['prop'] == switch.fake_server.platform[0]


def test_waiton_2(switch):
    """Test waiton function negative.

    """
    apps = switch.fake_server.applications
    switch.fake_server.applications = [{'name': 'SimSwitchApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 2, 'operationalState': 'Run'},
                                       {'name': 'ONSCoreServer', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 3, 'operationalState': 'Run'},
                                       {'name': 'ONSNorthboundServer', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 4, 'operationalState': 'Run'},
                                       {'name': 'L3DhcpRelayControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 5, 'operationalState': 'Run'},
                                       {'name': 'L2MirrorControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 6, 'operationalState': 'Run'},
                                       {'name': 'L2QosControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 7, 'operationalState': 'Run'},
                                       {'name': 'L2StormControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 8, 'operationalState': 'Run'},
                                       {'name': 'L2StatsControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 9, 'operationalState': 'Run'},
                                       {'name': 'ONSOpenVSwitchApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 10, 'operationalState': 'Run'},
                                       {'name': 'L1SfpControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 11, 'operationalState': 'Run'},
                                       {'name': 'L2VlanControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 12, 'operationalState': 'Run'},
                                       {'name': 'L1PortControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 13, 'operationalState': 'Run'},
                                       {'name': 'L2QinqControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 14, 'operationalState': 'Run'},
                                       {'name': 'L2FdbControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 15, 'operationalState': 'Run'},
                                       {'name': 'L2AclControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 16, 'operationalState': 'Run'},
                                       {'name': 'L1SwitchControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 17, 'operationalState': 'Run'},
                                       {'name': 'L2MulticastControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 18, 'operationalState': 'Run'},
                                       {'name': 'L2LagControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 19, 'operationalState': 'Run'},
                                       {'name': 'L3ControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 20, 'operationalState': 'Run'},
                                       {'name': 'L2LldpControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 21, 'operationalState': 'Run'},
                                       {'name': 'L2StpControlApp', 'logLevel': 'test level', 'adminState': 'Run', 'appId': 22, 'operationalState': 'Run'}]
    switch.ipaddr = '127.0.0.1'
    switch.port = 22
    switch._use_sshtun = False
    with pytest.raises(SwitchException):
        switch.waiton()
    switch.fake_server.applications = apps


def test_waitoff_1(switch):
    """Test waitoff function.

    """
    switch.ipaddr = '8.8.8.8'
    switch.port = 22
    switch._use_sshtun = False
    res = switch.waitoff()
    assert res is True


def test_waitoff_2(switch):
    """Test waitoff function negative.

    """
    switch.ipaddr = '127.0.0.1'
    switch.port = 22
    switch._use_sshtun = False
    with pytest.raises(SwitchException):
        switch.waitoff()


def test_clearconfig_1(switch):
    """Test clearconfig function negative.

    """
    with pytest.raises(Exception):
        switch.clearconfig()


def test_clearconfig_2(switch):
    """Test clearconfig function.

    """
    switch.fake_server.server.register_function(switch.fake_server.clear_config, 'nb.clearConfig')
    switch.clearconfig()


def test_getprop(switch):
    """Test getprop function.

    """
    name = switch.getprop('Ports', 'name', 1)
    assert name == switch.fake_server.ports[0]['name']


def test_getprop_row(switch):
    """Test getprop_row function.

    """
    row = switch.getprop_row('Platform', 1)
    assert row == switch.fake_server.platform[0]


def test_getprop_table(switch):
    """Test getprop_table function.

    """
    table = switch.getprop_table('Ports')
    assert table == switch.fake_server.ports


def test_getprop_size(switch):
    """Test getprop_size function.

    """
    size = switch.getprop_size('Ports')
    assert size == len(switch.fake_server.ports)


def test_getprop_table_info(switch):
    """Test getprop_table_info function.

    """
    info = switch.getprop_table_info('Ports')
    assert info == switch.fake_server.ports_info


def test_getprop_field_info(switch):
    """Test getprop_field_info function.

    """
    info = switch.getprop_field_info('Ports', 'name')
    assert info == switch.fake_server.ports_name_info


def test_getprop_method_help_1(switch):
    """Test getprop_method_help function.

    """
    info = switch.getprop_method_help('nb.Ports.getRow')
    assert info == switch.fake_server.ports_get_row_help


def test_getprop_method_help_2(switch):
    """Test getprop_method_help function negative.

    """
    with pytest.raises(Exception):
        switch.getprop_method_help('nb.Ports.addRow')


def test_setprop(switch):
    """Test setprop function.

    """
    sw = switch.xmlproxy.nb.Applications.getTable()
    assert sw[0]['logLevel'] == 'test level'
    assert switch.setprop('Applications', 'logLevel', [1, 'Test']) == 0
    sw = switch.xmlproxy.nb.Applications.getTable()
    assert sw[0]['logLevel'] == 'Test'
    assert switch.setprop('Applications', 'logLevel', [1, 'test level']) == 0
    sw = switch.xmlproxy.nb.Applications.getTable()
    assert sw[0]['logLevel'] == 'test level'


def test_setprop_row(switch):
    """Test setprop_row function.

    """
    size = switch.getprop_size('Ports')
    assert switch.setprop_row('Ports', [11, 'Up', 1, 'Physical', 'Down', 10000, 'xe10']) == 0
    size1 = switch.getprop_size('Ports')
    assert size1 - size == 1


def test_delprop_row(switch):
    """Test delprop_row function.

    """
    size = switch.getprop_size('Ports')
    assert switch.delprop_row('Ports', 11) == 0
    size1 = switch.getprop_size('Ports')
    assert size - size1 == 1


def test_findprop(switch):
    """Test findprop function.

    """
    row = switch.findprop('Applications', [1, 1, 'L2StpControlApp'])
    assert row == 22


def test_existsprop(switch):
    """Test existsprop function.

    """
    row = switch.existsprop('Applications', [1, 1, 'L2StpControlApp'])
    assert row == 22


def test_multicall_1(switch):
    """Test multicall function.

    """
    calls = [{'methodName': 'nb.Vlans.addRow', 'params': [(10, 'Vlan_10'), (20, 'Vlan_20'), (30, 'Vlan_30'), (40, 'Vlan_40'), ]}, ]
    results = switch.multicall(calls)
    assert set([x['result'] for x in results]) == set('0')


def test_multicall_2(switch):
    """Test multicall function negative.

    """
    calls = [{'methodName1': 'nb.Vlans.addRow', 'params': [(10, 'Vlan_10'), (20, 'Vlan_20'), (30, 'Vlan_30'), (40, 'Vlan_40'), ]}, ]
    with pytest.raises(Exception):
        switch.multicall(calls)


def test_multicall_3(switch):
    """Test multicall function negative.

    """
    switch.fake_server.error_multicall = True
    _calls = [{'methodName': 'nb.Vlans.addRow', 'params': [(10, 'Vlan_10'), (20, 'Vlan_20'), (30, 'Vlan_30'), (40, 'Vlan_40'), ]}, ]
    with pytest.raises(AssertionError):
        switch.multicall(_calls)
