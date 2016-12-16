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

@file  test_dev_linux_host.py

@summary  Unittests for dev_linux_host.py
"""

import pytest

from testlib import dev_linux_host
from testlib.dev_linux_host import GenericLinuxHost
from testlib.dev_linux_host import IpNetworkNamespace
from testlib.cli_template import CmdStatus
from testlib.linux_host_bash import LinuxHostBash

LH_CFG = {"name": "HOST", "instance_type": "generic_linux_host", "id": 19, "ipaddr": "localhost",
          "ssh_user": "user", "ssh_pass": "pass", "ports": ["xe1"]}

STR_TABLR = [{'discardMode': 'None', 'macAddress': '94:DE:80:AB:01:53', 'pvpt': 0, 'portId': 1, 'description': 'xe1',
              'operationalStatus':'Down', 'loopback': 'None', 'duplex': 'Full', 'adminMode': 'Down',
              'autoNegotiate': 'Disabled', 'ingressFiltering': 'Disabled', 'maxFrameSize': 9216, 'pvid': 1,
              'type': 'Physical', 'macMode': 'Normal','flowControl': 'None', 'learnMode': 'Hardware',
              'appError': 'False', 'cutThrough': 'Disabled', 'speed': 10000, 'name': 'xe1'}]

class FakeOpts(object):
    # fake json file
    setup = "setup.json"
    # fake json file
    env = "setup.json"
    get_only = False
    lhost_ui = "linux_bash"


OPTS = FakeOpts()


class FakeCLISSH(object):
    login_status = True
    shell_read = None

    cmd_list = []

    def __init__(self, *args, **kwargs):
        pass

    def exec_command(self, command, time=0):
        self.cmd_list.append(command)
        return CmdStatus("", "", 0)

@pytest.fixture(autouse=True)
def patch_clissh(request, monkeypatch):
    if request.module.__name__ == "unittests.test_dev_linux_host":
        monkeypatch.setattr(dev_linux_host.clissh, 'CLISSH', FakeCLISSH)


@pytest.fixture
def lh(monkeypatch, patch_clissh):
    cmd_list = []

    def mockreturn(self, command):
        cmd_list.append(command)
        return "", ""

    def m_get_table_ports(self, ports=None, all_params=False, ip_addr=False):
        return STR_TABLR

    def m_generate_port_name(self,port):
        return port

    def m_cli_set(self, commands, timeout=None, split_lines=True, expected_rcs=frozenset({0}),
                multicall_treshold=0):
        for command in commands:
            cmd_list.append(command[0])
        return [[CmdStatus("", stderr="", rc=0)]]

    monkeypatch.setattr(GenericLinuxHost, 'exec_cmd', mockreturn)

    monkeypatch.setattr(LinuxHostBash, 'cli_set', m_cli_set)

    lh = GenericLinuxHost(LH_CFG, OPTS)
    lh.produced_cmd_list = cmd_list

    monkeypatch.setattr(LinuxHostBash, 'get_table_ports', m_get_table_ports)
    monkeypatch.setattr(LinuxHostBash, 'generate_port_name', m_generate_port_name)
    monkeypatch.setattr(lh.ssh, 'shell_read', lambda timeout=1, interval=1: "")
    return lh


def test_ifconfig_1(monkeypatch, lh):
    """
    @brief Verify that ifconfig command form correct set of commands when all parameters are used.
    """
    cmd_list_expected = ['ip addr add 1.1.1.1 dev xe1', 'ip addr add 2002:: dev xe1', 'ip link set xe1 up', 'ip link set dev xe1 address 00:12:13:15:45:78']
    lh.ifconfig("up", ["xe1"], ['1.1.1.1'], ['2002::'], ["00:12:13:15:45:78"])
    for comm, value in enumerate(cmd_list_expected):
        assert lh.produced_cmd_list[comm] == cmd_list_expected[comm]


def test_ifconfig_2():
    """
    @brief Verify that ifconfig command return exception when lengths of ipaddr, ip6addr, mac parameters is not correct.
    """
    lh = GenericLinuxHost(LH_CFG, OPTS)
    commands = [('up', ['xe1'], ['1.1.1.1', "2.2.2.2"], None, None, "ipaddr"), ('up', ['xe1'], None, ['2002::', '3000::'], None, "ip6addr"),
                ('up', ['xe1'], None, None, ["00:12:12:12:23:56", "12:23:45:05:12:10", "10:11:02:12:12:13"], "mac")]
    for mode, port, ip, ip6, mac, name in commands:
        with pytest.raises(Exception) as excepinfo:
            lh.ifconfig(mode, port, ip, ip6, mac)
            result = "The lengths of the %s and ports lists are not equal." % name
            assert str(excepinfo.value) == result


def test_ifconfig_4():
    """
    @brief Verify that ifconfig command return exception when stats parameter without ports is given.
    """
    lh = GenericLinuxHost(LH_CFG, OPTS)
    with pytest.raises(Exception) as excepinfo:
        lh.ifconfig("stats")
    expect_result = "Ports table is empty"
    assert str(excepinfo.value) == expect_result


def test_ifconfig_5():
    """
    @brief Verify that ifconfig command return exception when improper mode is set.
    """
    lh = GenericLinuxHost(LH_CFG, OPTS)
    mode = "upfg"
    with pytest.raises(Exception) as excepinfo:
        lh.ifconfig(mode)
    expect_result = "Unknown mode parameter value - %s" % (mode, )
    assert excepinfo.value.parameter == expect_result


def test_ifconfig_6(monkeypatch,lh):
    """
    @brief Verify that ifconfig function return proper dictionary when 'stat' parameter is used.
    """

    result_expected = {'xe1': {'RX-OK': '13', 'TX-OVR': '0', 'Iface': 'veth1', 'TX-OK': '13', 'MTU': '1500',
                       'Met': '0', 'RX-ERR': '0', 'TX-DRP': '0', 'TX-ERR': '0', 'RX-DRP': '0', 'RX-OVR': '0', 'Flg': 'BMRU'}}
    cmd_list = []

    def mockreturn(self, command):
        cmd_list.append(command)
        result = "Iface   MTU Met   RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg \n \
                  veth1     1500 0        13      0      0 0            13      0      0      0 BMRU \n"
        return CmdStatus(result, "", 0)

    monkeypatch.setattr(GenericLinuxHost, 'exec_cmd', mockreturn)
    result_received = lh.ifconfig("stats", ["xe1"])
    assert result_received == result_expected


def test_ifconfig_7(monkeypatch, lh):
    """
    @brief Verify that exec command works with root privileges.
    """
    cmd_list_expected = ['ip addr add 1.1.1.1 dev lo', 'ip addr add 2.2.2.2 dev xe1', 'ip link set lo up', 'ip link set xe1 up']

    lh.ifconfig("up", None, ['1.1.1.1', '2.2.2.2'])
    for comm, value in enumerate(cmd_list_expected):
        assert lh.produced_cmd_list[comm] == cmd_list_expected[comm]


def test_routes_1(monkeypatch, lh):
    """
    @brief Verify that routes forms correct set of commands when all parameters are used.
    """

    cmd_list_expected = ['ip link set dev xe1 up', 'ip -4 route add 10.10.10.10 via 20.20.20.20 dev xe1', 'ip -6 route add 1000:: via 2000:: dev xe1',
                         'ip -6 route add 50.50.50.50 via 127.0.0.1 dev sit1 metric 1']
    lh.routes("up", ['10.10.10.10'], ['1000::'], ["xe1"], ["20.20.20.20"], ["2000::"], "option", "metric", "50.50.50.50", "127.0.0.1")
    for comm, value in enumerate(cmd_list_expected):
        assert lh.produced_cmd_list[comm] == cmd_list_expected[comm]


def test_routes_2():
    """
    @brief Verify that routes command return exception when incorrect mode value is set.
    """
    lh = GenericLinuxHost(LH_CFG, OPTS)
    mode = "upf"
    with pytest.raises(Exception) as excepinfo:
        lh.routes(mode)
    result = "Unknown mode parameter value - %s" % mode
    assert str(excepinfo.value) == result


def test_routes_3():
    """
    @brief Verify that routes function return exception when length of nexthop and netwrk lists is not equal.
    """
    lh = GenericLinuxHost(LH_CFG, OPTS)
    with pytest.raises(Exception) as excepinfo:
        lh.routes("up", ['10.10.10.10'], None, ["xe1"], ["20.20.20.20", "30.30.36.2"], None)
    result = "The lengths of the lists nexthop and netwrk is not equal."
    assert result == str(excepinfo.value)


def test_routes_4():
    """
    @brief Verify that routes function return exception when length of nexthop and ports lists is not equal.
    """
    lh = GenericLinuxHost(LH_CFG, OPTS)
    with pytest.raises(Exception) as excepinfo:
        lh.routes("up", ['default'], None, ["xe1", "xe2"], ["1.1.1.1"], None)
    result = "The lengths of the lists nexthop and ports is not equal."
    assert result == str(excepinfo.value)


def test_routes_5(monkeypatch, lh):
    """
    @brief Verify that route function return correct set of commands when ports parameter is None.
    """
    cmd_list_expected = ['ip link set dev lo up', 'ip link set dev xe1 up', 'ip -4 route add 10.10.10.10 via 20.20.20.20 dev lo',
                         'ip -4 route add 30.30.30.30 via 40.40.40.40 dev xe1']
    lh.routes("up", ['10.10.10.10', "30.30.30.30"], None, None, ["20.20.20.20", "40.40.40.40"])
    for comm, value in enumerate(cmd_list_expected):
        assert lh.produced_cmd_list[comm] == cmd_list_expected[comm]


def test_routes_6(monkeypatch, lh):
    """
    @brief Verify that route function return correct set of commands.
    """
    cmd_list_expected = ['ip link set dev xe1 up', 'ip -4 default via 20.20.20.20 dev xe1']
    lh.routes("up", ["default"], None, ["xe1"], ["20.20.20.20"])
    for comm, value in enumerate(cmd_list_expected):
        assert lh.produced_cmd_list[comm] == cmd_list_expected[comm]


def test_routes_7(monkeypatch, lh):
    """
    @brief Verify that route function return correct set of commands.
    """
    cmd_list_expected = ['ip link set dev xe1 up', 'ip -6 route add default via 3003:: dev xe1']
    lh.routes("up", None, ["default"], ["xe1"], None, ["3003::"])
    for comm, value in enumerate(cmd_list_expected):
        assert lh.produced_cmd_list[comm] == cmd_list_expected[comm]


def test_routes_8(monkeypatch, lh):
    """
    @brief Verify that route function return correct set of commands.
    """
    cmd_list_expected = ['ip link set dev xe1 up', 'ip -6 route add default via 3003:: dev xe1']
    lh.routes("up", None, ["default"], ["xe1"], None, ["3003::"], "option")
    for comm, value in enumerate(cmd_list_expected):
        assert lh.produced_cmd_list[comm] == cmd_list_expected[comm]


def test_ipforwrd_1(monkeypatch, lh):
    """
    @brief Verify that ip_forward function return correct set of commands when correct parameters are used.
    """
    cmd_list_expected = ["sysctl -w net.ipv4.ip_forward=1", "sysctl -w net.ipv6.conf.all.forwarding=1"]
    ipfrw_param = ["-4", "-6"]
    for param in ipfrw_param:
        lh.ipforward([param, ])
    for comm, value in enumerate(cmd_list_expected):
        assert lh.produced_cmd_list[comm] == cmd_list_expected[comm]


def test_ipforward_2():
    """
    @brief Verify that ipforward command return exception when incorrect version value is set.
    """
    lh = GenericLinuxHost(LH_CFG, OPTS)
    inc_ver = "-8"
    with pytest.raises(Exception) as exepinfo:
        lh.ipforward(inc_ver)
    result = "Incorrect version value: %s. Allowed values is: ['-4', '-6']" % (inc_ver, )
    assert str(exepinfo.value) == result


def test_ipforward_3(monkeypatch, lh):
    """
    @brief Verify that ipforward command return correct set of commands when version is None.
    """
    cmd_list_expected = ["sysctl -w net.ipv4.ip_forward=1"]
    lh.ipforward(None)
    assert cmd_list_expected[0] == lh.produced_cmd_list[0]


def test_brctl_1(monkeypatch):
    """
    @brief Verify that brctl command return correct set of commands when add parameter with stp_cfg  is defined.
    """
    expected_commands = ["ifconfig -s -a | grep ^lhbr | awk '{print $1}'", 'sudo brctl addbr lhbr1', 'sudo brctl addif lhbr1 xe1',
                         'sudo brctl stp lhbr1 on', 'sudo brctl setbridgeprio lhbr1 1000', 'sudo ifconfig lhbr1 up']
    cmd_list = []

    def mockreturn(command):
        cmd_list.append(command)
        return CmdStatus("", "", 0)
    lh = GenericLinuxHost(LH_CFG, OPTS)
    monkeypatch.setattr(lh.ssh, 'exec_command', mockreturn)
    lh.brctl("add", ["xe1"], "br0", "on", {"bprio": 1000})
    for comm, value in enumerate(expected_commands):
        assert expected_commands[comm] == cmd_list[comm]


def test_brctl_2(monkeypatch):
    """
    @brief Verify that brctl command return correct set of commands when add command is used.
    """
    expected_brname = "lhbr1"
    expected_commands = ["ifconfig -s -a | grep ^lhbr | awk '{print $1}'", 'sudo brctl addbr lhbr1', 'sudo brctl addif lhbr1 xe1', 'sudo brctl stp lhbr1 on',
                         'sudo ifconfig lhbr1 up']
    cmd_list = []

    def mockreturn(command):
        cmd_list.append(command)
        return CmdStatus("", "", 0)
    lh = GenericLinuxHost(LH_CFG, OPTS)
    monkeypatch.setattr(lh.ssh, 'exec_command', mockreturn)
    brname = lh.brctl("add", ["xe1"], "br0", "on")
    assert brname == expected_brname
    for comm, value in enumerate(expected_commands):
        assert expected_commands[comm] == cmd_list[comm]


def test_brctl_3(monkeypatch, lh):
    """
    @brief Verify that brctl command return correct set of commands when cfg parameter is used.
    """
    cmd_list_expected = ['brctl stp br0 on', 'brctl addif br0 xe1', 'brctl setbridgeprio br0 1000', 'brctl setpathcost br0 xe1 1', 'brctl setmaxage br0 10',
                         'brctl setfd br0 7', 'brctl setportprio br0 xe2 15', 'brctl sethello br0 100']
    mode = "cfg"
    lh.brctl(mode, ["xe1"], "br0", "on", {"bprio": 1000, "pathcost": [("xe1", 1)], "hello": 100, "maxage": 10, "fwdelay": 7, "pprio": [("xe2", 15)]})
    assert set(lh.produced_cmd_list) == set(cmd_list_expected)


def test_brctl_4(monkeypatch):
    """
    @brief Verify cfg parameter in brctl return exception when bridge name is not given.
    """
    lh = GenericLinuxHost(LH_CFG, OPTS)
    mode = "cfg"
    with pytest.raises(Exception) as excepinfo:
        lh.brctl(mode)
    result = "Bridge name is not set."
    assert result == str(excepinfo.value)


def test_brctl_5():
    """
    @brief Verify brctl command return exception when bridge name is not given as parameter.
    """
    lh = GenericLinuxHost(LH_CFG, OPTS)
    mode = "delif"
    with pytest.raises(Exception) as excepinfo:
        lh.brctl(mode)
    result = "Bridge name or port is not set."
    assert result == str(excepinfo.value)


def test_brctl_6():
    """
    @brief Verify brctl command with delif parameter return exception when ports are not given
    """
    lh = GenericLinuxHost(LH_CFG, OPTS)
    mode = "delif"
    with pytest.raises(Exception) as excepinfo:
        lh.brctl(mode, None, "br0")
    result = "Bridge name or port is not set."
    assert result == str(excepinfo.value)


def test_brctl_7(monkeypatch, lh):
    """
    @brief Verify that brctl command with delif parameter return correct set of commands when all needed parameters are given.
    """
    cmd_list_expected = ["brctl delif br0 xe1"]
    lh.brctl("delif", ["xe1"], "br0")
    for comm, value in enumerate(cmd_list_expected):
        assert lh.produced_cmd_list[comm] == cmd_list_expected[comm]


def test_brctl_8(monkeypatch, lh):
    """
    @brief Verify that brctl command with del parameter return correct set of commands when all needed parameters are given.
    """
    cmd_list_expected = ["ifconfig br0 down", "brctl delbr br0"]
    mode = "del"
    lh.brctl(mode, None, "br0")
    for comm, value in enumerate(cmd_list_expected):
        assert lh.produced_cmd_list[comm] == cmd_list_expected[comm]


def test_brctl_9():
    """
    @brief Verify that brctl command return exception when br name is not set.
    """
    lh = GenericLinuxHost(LH_CFG, OPTS)
    mode = "del"
    with pytest.raises(Exception) as excepinfo:
        lh.brctl(mode)
    result = "Bridge name is not set."
    assert result == str(excepinfo.value)


def test_brctl_10():
    """
    @brief Verify brctl command return exception when incorrect mode is set.
    """
    lh = GenericLinuxHost(LH_CFG, OPTS)
    mode = "upfg"
    with pytest.raises(Exception) as excepinfo:
        lh.brctl(mode)
    result = "Unknown mode for brctl method."
    assert result == str(excepinfo.value)


def test_brctl_11(monkeypatch):
    """
    @brief Verify that brctl function return proper dictionary when 'stpstat' parameter is set.
    """
    result_expected = {'': {}, 'proxy1': {'designated root': '01f4.001b2189ac4c', 'state': 'forwarding', 'port id': '0000', 'path cost': '2',
                       'port number': '0'}, 'proxy0': {'port number': '2'}, 'lhbr2': {'max age': '20.00', 'designated root': '05dc.4aa38155aa0f',
                       'bridge max age': '4', 'max age 20.00': 'bridge max age', 'bridge id': '05dc.4aa38155aa0f', 'path cost': '4', 'root port': '1'}}
    cmd_list = []

    def mockreturn(self, command):
        cmd_list.append(command)
        result = "lhbr2 \nbridge id \t 05dc.4aa38155aa0f \ndesignated root \t 05dc.4aa38155aa0f \nroot port \t1 \t path cost \t4 \nmax age \t 20.00 \t \
                bridge max age \t 4 \n  max age 20.00 \t bridge max age \t 20.00 \n\nproxy0 (2) \n\n port id \t 0000 \t state \t forwarding \
                \ndesignated root \t 01f4.001b2189ac4c \t path cost \t 2 \n\nproxy1 (0) \n port id \t 0000 \t state \t forwarding \n designated root \
                \t 01f4.001b2189ac4c \t path cost \t 2 \n\n"
        return CmdStatus(result, "", 0)
    monkeypatch.setattr(GenericLinuxHost, 'exec_cmd', mockreturn)
    lh2 = GenericLinuxHost(LH_CFG, OPTS)
    result_received = lh2.brctl("stpstat", None, "br0")
    assert result_expected == result_received


def test_brctl_12(monkeypatch):
    """
    @brief Verify that brctl function return dictionary when "macs" parameter is set.
    """
    result_expected = {'1': [{'ageing timer': '119.25', 'no mac addr': '00:10:4b:b6:c6:e4', 'is local?': 'no'}],
                       '4': [{'ageing timer': '0.00', 'no mac addr': '08:00:09:fc:d2:11', 'is local?': 'yes'}]}
    cmd_list = []

    def mockreturn(self, command):
        cmd_list.append(command)
        result = "port \t no mac addr \t is local? \t ageing timer \n 1 \t 00:10:4b:b6:c6:e4 \t no \t 119.25 \n 4 \t 08:00:09:fc:d2:11 \t yes \t 0.00 \n"
        return CmdStatus(result, "", 0)
    monkeypatch.setattr(GenericLinuxHost, 'exec_cmd', mockreturn)
    lh2 = GenericLinuxHost(LH_CFG, OPTS)
    result_received = lh2.brctl("macs", None, "br0")
    assert result_received == result_expected


def test_brctl_13():
    """
    @brief Verify that brctl function with stpstat parameter return exception when bridge name is not set.
    """
    lh = GenericLinuxHost(LH_CFG, OPTS)
    with pytest.raises(Exception) as excepinfo:
        lh.brctl("stpstat", ["xe1"])
    result = "Bridge name is not set."
    assert result == str(excepinfo.value)


def test_brctl_14():
    """
    @brief Verify that brctl function with mac parameter return exception when bridge name is not set.
    """
    lh = GenericLinuxHost(LH_CFG, OPTS)
    with pytest.raises(Exception) as excepinfo:
        lh.brctl("macs", ["xe1"])
    result = "Bridge name is not set."
    assert result == str(excepinfo.value)


def test_getmac_1(monkeypatch):
    """
    @brief Verify that getmac function return interface mac address.
    """
    result_expected = "94:de:80:b0:25:f8"
    cmd_list = []

    def mockreturn(self, command):
        cmd_list.append(command)
        result = "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000 \n \
                  link/ether 94:de:80:b0:25:f8 brd ff:ff:ff:ff:ff:ff"
        return CmdStatus(result, "", 0)
    monkeypatch.setattr(GenericLinuxHost, 'exec_cmd', mockreturn)
    lh2 = GenericLinuxHost(LH_CFG, OPTS)
    result_received = lh2.getmac("xe1")
    assert result_expected == result_received


def test_ethtool_1():
    """
    @brief Verify ethtool function return exception when improper mode is set.
    """
    lh = GenericLinuxHost(LH_CFG, OPTS)
    inc_mode = "genericc"
    with pytest.raises(Exception) as exepinfo:
        lh.ethtool("xe1", inc_mode)
    result = "Incorrect mode=%s" % inc_mode
    assert str(exepinfo.value) == result


def test_ethtool_2(monkeypatch, lh):
    """
    @brief Verify ethtool function return correct set of commands when correct parameters are set.
    """
    cmd_list_expected = ["ethtool -s xe1 speed 40"]
    lh.ethtool("xe1", "generic", speed=40)
    for comm, value in enumerate(cmd_list_expected):
        assert lh.produced_cmd_list[comm] == cmd_list_expected[comm]
    print(lh.produced_cmd_list)
    print(cmd_list_expected)


def test_vconf_1(monkeypatch):
    """
    @brief Verify vconf function return correct command when rem parameter is set.
    """
    commands_expected = ['vconfig rem xe1.3']

    def mockreturn_8021q(self):
        pass
    monkeypatch.setattr(GenericLinuxHost, 'enable_8021q', mockreturn_8021q)

    cmd_list = []

    def mockreturn_exec_cmd(self, command):
        cmd_list.append(command)
        return "", ""
    monkeypatch.setattr(GenericLinuxHost, 'exec_cmd', mockreturn_exec_cmd)
    lh = GenericLinuxHost(LH_CFG, OPTS)
    lh.vlans = {'xe1': [3]}
    lh.vconfig("rem", "xe1", 3)
    assert cmd_list[0] == commands_expected[0]


def test_vconf_2(monkeypatch):
    """
    @brief Verify vconf function return correct command when add parameter is set.
    """
    commands_expected = ['vconfig add xe1 3']

    def mockreturn_8021q(self):
        pass
    monkeypatch.setattr(GenericLinuxHost, 'enable_8021q', mockreturn_8021q)

    cmd_list = []

    def mockreturn_exec_cmd(self, command):
        cmd_list.append(command)
        return "", ""
    monkeypatch.setattr(GenericLinuxHost, 'exec_cmd', mockreturn_exec_cmd)
    lh = GenericLinuxHost(LH_CFG, OPTS)
    lh.vconfig("add", "xe1", 3)
    assert cmd_list[0] == commands_expected[0]


def test_vconf_3(monkeypatch):
    """
    @brief Verify vconf function return exception after creating vlan which is already exist.
    """
    expected_result = "Port xe1 already in 3 vlan"

    def mockreturn_8021q(self):
        pass
    monkeypatch.setattr(GenericLinuxHost, 'enable_8021q', mockreturn_8021q)

    cmd_list = []

    def mockreturn_exec_cmd(self, command):
        cmd_list.append(command)
        return "", ""
    monkeypatch.setattr(GenericLinuxHost, 'exec_cmd', mockreturn_exec_cmd)
    lh = GenericLinuxHost(LH_CFG, OPTS)
    with pytest.raises(Exception) as excepinfo:
        lh.vlans = {'xe1': [3]}
        lh.vconfig("add", "xe1", 3)
    assert str(excepinfo.value) == expected_result


def test_vconf_4(monkeypatch):
    """
    @brief Verify that vconfig function return exception when mode is incorrect
    """
    def mockreturn_8021q(self):
        pass
    monkeypatch.setattr(GenericLinuxHost, 'enable_8021q', mockreturn_8021q)

    lh = GenericLinuxHost(LH_CFG, OPTS)
    mode = "upfg"
    with pytest.raises(Exception) as excepinfo:
        lh.vconfig(mode, "xe1", 3)
    result = "Incorrect mode=%s" % mode
    assert result == str(excepinfo.value)


def test_enable_8021q_1(monkeypatch):
    """
    @brief Verify that enable_802q_1 function return exception when 802.1q is not supported by current os.
    """
    def mockreturn(command):
        return CmdStatus("", "", 0)
    # monkeypatch.setattr(CLISSHNetNS, 'exec_command', mockreturn)
    lh = GenericLinuxHost(LH_CFG, OPTS)
    monkeypatch.setattr(lh.ssh, 'exec_command', mockreturn)
    with pytest.raises(Exception) as excepinfo:
        lh.enable_8021q()
    result = "Current OS doesn't support 802.1q."
    assert result == str(excepinfo.value)


def test_enable_8021q_2(monkeypatch):
    """
    @brief Verify that enable_802q_1 function return correct set of commands when 8021q is already loaded.
    """
    comm_expected = ['modprobe -l | grep 8021q', 'lsmod | grep ^8021q']
    cmd_list = []

    def mockreturn(command):
        cmd_list.append(command)
        so = "8021q"
        return CmdStatus(so, "", 0)
    lh = GenericLinuxHost(LH_CFG, OPTS)
    monkeypatch.setattr(lh.ssh, 'exec_command', mockreturn)
    lh.enable_8021q()
    for comm, value in enumerate(comm_expected):
        assert cmd_list[comm] == comm_expected[comm]


def test_enable_8021q_3(monkeypatch):
    """
    @brief Verify that enable_802q_1 function return exception if 8021q can not be loaded.
    """
    cmd_list = []

    def mockreturn(command):
        cmd_list.append(command)
        so = "8021q"
        if command == "lsmod | grep ^8021q":
            so = ""
        return CmdStatus(so, "", 0)
    lh = GenericLinuxHost(LH_CFG, OPTS)
    monkeypatch.setattr(lh.ssh, 'exec_command', mockreturn)
    with pytest.raises(Exception) as excepinfo:
        lh.enable_8021q()
    result = "Fail to load 8021q:\n8021q"
    assert str(excepinfo.value) == result


def test_cleanup_1(monkeypatch, lh):
    """
    @brief Verify that cleanup function clear route configurations.
    """
    def mockreturn(self, command):
        pass
    monkeypatch.setattr(GenericLinuxHost, 'exec_cmd', mockreturn)
    lh.route_list = ["route", "route 2"]
    lh.cleanup()
    assert len(lh.route_list) == 0


def test_cleanup_2(monkeypatch, lh):
    """
    @brief Verify that cleanup function clear ifconfig configurations.
    """
    def mockreturn(self, command):
        pass
    monkeypatch.setattr(GenericLinuxHost, 'exec_cmd', mockreturn)
    lh.ifconf_addrs = ["ifconfig", "ifconfig 2"]
    lh.cleanup()
    assert len(lh.ifconf_addrs) == 0


def test_cleanup_3(monkeypatch,lh):
    """
    @brief Verify that cleanup function clear vconfig configurations.
    """
    def mockreturn_8021q(self):
        pass
    monkeypatch.setattr(GenericLinuxHost, 'enable_8021q', mockreturn_8021q)

    def mockreturn_exec_cmd(self, command):
        return "", ""
    monkeypatch.setattr(GenericLinuxHost, 'exec_cmd', mockreturn_exec_cmd)
    lh.vlans = {'xe1': [3]}
    lh.cleanup()
    assert len(lh.vlans) == 0


def test_cleanup_4(monkeypatch, lh):
    """
    @brief Verify that cleanup function form correct set of commands to delete brctl bridges.
    """
    expected_result = ['ifconfig br0 down', 'brctl delbr br0']
    cmd_list = []

    def mockreturn(self, command):
        cmd_list.append(command)
        return "", ""
    monkeypatch.setattr(GenericLinuxHost, 'exec_cmd', mockreturn)
    lh.bridges = ["br0"]
    lh.cleanup()
    for comm, value in enumerate(expected_result):
        assert expected_result[comm] == cmd_list[comm]


def test_start_1(monkeypatch):
    """
    @brief Verify that start function return exception when namespace is already created
    """
    output_result = "Namespace is already created"

    def mockreturn(command):
        so = "HOST"
        return so, "", ""
    lh = IpNetworkNamespace(LH_CFG, OPTS)
    monkeypatch.setattr(lh.ssh, 'native_cmd', mockreturn)
    with pytest.raises(Exception) as excepinfo:
        lh.start()
    print(str(excepinfo.value))
    assert str(excepinfo.value) == output_result


def test_start_2(monkeypatch):
    """
    @brief Verify that start function exception when network namespace was not created.
    """
    result_output = "Cannot create network namespace. Return code = 5"

    def mockreturn(command):
        so = "HOST_2"
        print("dssd")
        print(command)
        if command == "ip netns add HOST":
            rc = "5"
        else:
            rc = ""
        return so, "", rc
    lh = IpNetworkNamespace(LH_CFG, OPTS)
    monkeypatch.setattr(lh.ssh, 'native_cmd', mockreturn)
    with pytest.raises(Exception) as excepinfo:
        lh.start()
    print(str(excepinfo.value))
    assert result_output == str(excepinfo.value)


def test_check_mgmt_bridge_1(monkeypatch):
    """
    @brief Verify that check_mgmt_bridge check that mgmt bridge is already created.
    """
    comm_expect = ['ifconfig mgmt111']
    cmd_list = []

    def mockreturn(command):
        cmd_list.append(command)
        so = "mgmt111 created"
        return so, "", ""
    lh = IpNetworkNamespace(LH_CFG, OPTS)
    lh.mgmt_br = "mgmt111"
    monkeypatch.setattr(lh.ssh, 'native_cmd', mockreturn)
    output_result = lh.check_mgmt_bridge()
    assert output_result
    assert comm_expect[0] == cmd_list[0]


def test_check_mgmt_bridge_2(monkeypatch):
    """
    @brief Verify that check_mgmt_bridge check that mgmt bridge is already created.
    """
    cmd_list = []

    def mockreturn(command):
        cmd_list.append(command)
        return "", "", ""
    lh = IpNetworkNamespace(LH_CFG, OPTS)
    lh.mgmt_br = "mgmt111"
    monkeypatch.setattr(lh.ssh, 'native_cmd', mockreturn)
    output_result = lh.check_mgmt_bridge()
    assert not output_result


def test_add_mgmt_bridge_1(monkeypatch):
    """
    @brief Verify that add_mgmt_bridge function generate correct set of commands to add mgmt bridge.
    """
    comm_expect = ['brctl addbr mbrlocalhos254', 'ifconfig mbrlocalhos254 localhos.254 up', "ifconfig mbrlocalhos254"]
    cmd_list = []

    def mockreturn_native_cmd(command):
        cmd_list.append(command)
        if comm_expect[0] in cmd_list:
            so, rc = True, "0"
            return so, "", rc
        else:
            rc = "0"
            return "", "", rc
    lh = IpNetworkNamespace(LH_CFG, OPTS)
    monkeypatch.setattr(lh.ssh, 'native_cmd', mockreturn_native_cmd)
    lh.add_mgmt_bridge()
    assert set(comm_expect) == set(cmd_list)


def test_add_mgmt_bridge_2(monkeypatch):
    """
    @brief Verify that add_mgmt_bridge function return exception when managment bridge can not be created.
    """
    output_result = "Failed to create management bridge for Network namespaces.\n" + "Stdout: , Stderr: Error"

    def mockreturn_mgmt_br(command):
        so = False
        return so

    def mockreturn_native_cmd(command):
        se = "Error"
        rc = "5"
        return "", se, rc
    lh = IpNetworkNamespace(LH_CFG, OPTS)
    monkeypatch.setattr(IpNetworkNamespace, 'check_mgmt_bridge', mockreturn_mgmt_br)
    monkeypatch.setattr(lh.ssh, 'native_cmd', mockreturn_native_cmd)
    with pytest.raises(Exception) as excepinfo:
        lh.add_mgmt_bridge()
    assert str(excepinfo.value) == output_result


def test_del_mgmt_bridge_1(monkeypatch):
    """
    @brief Verify that del_mgmt_bridge function return correct set of commands to delete mgmt bridge.
    """
    comm_expect = ['ifconfig mbrlocalhos254 down', 'brctl delbr mbrlocalhos254']
    cmd_list = []

    def mockreturn_mgmt_br(command):
        so = True
        return so

    def mockreturn_native_cmd(command):
        cmd_list.append(command)
        rc = "0"
        return "", "", rc
    lh = IpNetworkNamespace(LH_CFG, OPTS)
    monkeypatch.setattr(IpNetworkNamespace, 'check_mgmt_bridge', mockreturn_mgmt_br)
    monkeypatch.setattr(lh.ssh, 'native_cmd', mockreturn_native_cmd)
    lh.del_mgmt_bridge()
    print(cmd_list)
    assert comm_expect[0] == cmd_list[0]


def test_del_mgmt_bridge_2(monkeypatch):
    """
    @brief Verify that del_mgmt_bridge function return exception when management bridge can not be deleted.
    """
    output_result = "Failed to delete management bridge for Network namespaces.\n" + "Stdout: , Stderr: Error"
    cmd_list = []

    def mockreturn_mgmt_br(command):
        so = True
        return so

    def mockreturn_native_cmd(command):
        cmd_list.append(command)
        rc = "5"
        se = "Error"
        return "", se, rc
    lh = IpNetworkNamespace(LH_CFG, OPTS)
    monkeypatch.setattr(IpNetworkNamespace, 'check_mgmt_bridge', mockreturn_mgmt_br)
    monkeypatch.setattr(lh.ssh, 'native_cmd', mockreturn_native_cmd)
    with pytest.raises(Exception) as excepinfo:
        lh.del_mgmt_bridge()
    print(str(excepinfo.value))
    assert str(excepinfo.value) == output_result


def test_add_mgmt_iface_1(monkeypatch):
    """
    @brief Verify that mgmt interface return correct set of commands for adding mgmt interface
    """
    comm_expect = ['ip link add veth19 type veth peer name veth19 netns HOST', 'brctl addif mbrlocalhos254 veth19', 'ifconfig veth19 up',
                   'ifconfig veth19 localhost up']
    cmd_list = []

    def mockreturn_native_cmd(command):
        cmd_list.append(command)
        rc = "0"
        return "", "", rc

    def mockreturn_exec_cmd(command):
        cmd_list.append(command)
        return CmdStatus("", "", 0)
    lh = IpNetworkNamespace(LH_CFG, OPTS)
    monkeypatch.setattr(lh.ssh, 'native_cmd', mockreturn_native_cmd)
    monkeypatch.setattr(lh.ssh, 'exec_command', mockreturn_exec_cmd)
    lh.add_mgmt_iface()
    assert comm_expect == comm_expect


def test_add_mgmt_iface_2(monkeypatch):
    """
    @brief Verify that add_mgmt_iface function return exception when mgmt iface can't be deleted.
    """
    output_exept = "Failed to create management iface for HOST.\n"

    def mockreturn(command):
        return "", "", ""
    lh = IpNetworkNamespace(LH_CFG, OPTS)
    with pytest.raises(Exception) as excepinfo:
        lh.add_mgmt_iface()
    assert str(excepinfo.value) == output_exept


def test_del_mgmt_iface_1(monkeypatch):
    """
    @brief Verify that del_mgmt_iface function return correct set of commands and exceptions when mgmt interface can not be deleted.
    """
    comm_expect = ['ip link delete veth19']
    cmd_list = []

    def mockreturn(command):
        cmd_list.append(command)
        rc = "0"
        return "", "", rc
    lh = IpNetworkNamespace(LH_CFG, OPTS)
    monkeypatch.setattr(lh.ssh, 'native_cmd', mockreturn)
    lh.del_mgmt_iface()
    assert comm_expect[0] == cmd_list[0]


def test_del_mgmt_iface_2(monkeypatch):
    """
    @brief Verify that del_mgmt_iface function return correct set of commands and exceptions when mgmt interface can not be deleted.
    """
    comm_expect = ['ip link delete veth19']
    output_expect = "Failed to delete management iface for HOST.\n"
    cmd_list = []

    def mockreturn(command):
        cmd_list.append(command)
        rc = 5
        return "", "", rc
    lh = IpNetworkNamespace(LH_CFG, OPTS)
    monkeypatch.setattr(lh.ssh, 'native_cmd', mockreturn)
    with pytest.raises(Exception) as excepinfo:
        lh.del_mgmt_iface()
    assert comm_expect[0] == cmd_list[0]
    print(str(excepinfo.value))
    print(output_expect)
    assert output_expect == str(excepinfo.value)


def test_init(monkeypatch):
    # no auth parameters
    temp_cfg = dict(LH_CFG)
    temp_cfg["ssh_pass"] = None
    lh = GenericLinuxHost(temp_cfg, OPTS)
    assert not hasattr(lh, "ssh")

    # only pkey
    temp_cfg["ssh_pkey"] = "pkey"
    lh = GenericLinuxHost(temp_cfg, OPTS)
    assert hasattr(lh, "ssh")
    assert lh.ssh_pkey == temp_cfg["ssh_pkey"]

    # only pkey file
    temp_cfg["ssh_pkey"] = None
    temp_cfg["ssh_pkey_file"] = "pkey_file"
    lh = GenericLinuxHost(temp_cfg, OPTS)
    assert hasattr(lh, "ssh")
    assert lh.ssh_pkey_file == temp_cfg["ssh_pkey_file"]

    # default ssh_port
    assert hasattr(lh, "ssh_port")
    assert lh.ssh_port == 22

    # ssh_port from config
    temp_cfg["ssh_port"] = 8080
    lh = GenericLinuxHost(temp_cfg, OPTS)
    assert hasattr(lh, "ssh_port")
    assert lh.ssh_port == 8080
