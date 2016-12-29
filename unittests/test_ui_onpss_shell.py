# coding=utf-8

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

@file test_ui_onpss_shell.py

@summary Unittests for UI ONPSS Shell.
"""
from unittest.mock import MagicMock

import pytest

from testlib.cli_template import CmdStatus
from testlib import ui_onpss_shell
from testlib.si_fm10k import SiliconFM10K
from testlib.custom_exceptions import UICmdException, UIException, AccessError, BoundaryError


class OnpssRawOutput(object):

    # Do not remove the whitespace at the end of the line, it is in the original output
    RAW_IPLINK_OUTPUT = [
        '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default \n',
        '    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 \n',
        '2: em1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000\n',
        '    link/ether 08:9e:01:72:d4:d0 brd ff:ff:ff:ff:ff:ff \n',
        '3: sw0p1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000001 state DOWN mode DEFAULT group default qlen 1000\n',
        '    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff \n',
        '4: sw0p2: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000002 state DOWN mode DEFAULT group default qlen 1000\n',
        '    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff \n',
        '11: sw0p9: <BROADCAST,MULTICAST> mtu 1500 qdisc pfifo_fast portid 00000009 state DOWN mode DEFAULT group default qlen 1000\n',
        '    link/ether 56:8b:3e:5f:cb:99 brd ff:ff:ff:ff:ff:ff \n',
        '12: sw0p10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast master team1 portid 0000000a state UP mode DEFAULT group default qlen 1000\n',
        '    link/ether 56:8b:3e:5f:cb:99 brd ff:ff:ff:ff:ff:ff \n',
        '13: sw0p11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast master team1 portid 0000000b state UP mode DEFAULT group default qlen 1000\n',
        '    link/ether 56:8b:3e:5f:cb:99 brd ff:ff:ff:ff:ff:ff \n',
        '14: sw0p12: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast master team2 portid 0000000c state UP mode DEFAULT group default qlen 1000\n',
        '    link/ether 0a:e1:f0:b5:56:0a brd ff:ff:ff:ff:ff:ff \n',
        '15: sw0p13: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast master team2 portid 0000000d state DOWN mode DEFAULT group default qlen 1000\n',
        '    link/ether 0a:e1:f0:b5:56:0a brd ff:ff:ff:ff:ff:ff \n',
        '66: sw0p64: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000040 state DOWN mode DEFAULT group default qlen 1000\n',
        '    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff \n',
        '67: sw0p0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000000 state DOWN mode DEFAULT group default qlen 1000\n',
        '    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff \n',
        '69: team1@NONE: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default \n',
        '    link/ether 56:8b:3e:5f:cb:99 brd ff:ff:ff:ff:ff:ff \n',
        '70: teamempty@NONE: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default \n',
        '    link/ether 1e:2f:f0:ed:f1:a1 brd ff:ff:ff:ff:ff:ff \n',
        '71: team2@NONE: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default \n',
        '    link/ether 0a:e1:f0:b5:56:0a brd ff:ff:ff:ff:ff:ff \n'
    ]

    RAW_IPLINK_DETAIL_OUTPUT = (
        '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default \\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0 \n'
        '2: pep8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 15346 qdisc mq state UP mode DEFAULT group default qlen 1000\\    link/ether a0:36:9f:60:b4:14 brd ff:ff:ff:ff:ff:ff promiscuity 1 \n'
        '3: pep4: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether a0:36:9f:60:b4:10 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '4: enp0s20f0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether a0:36:9f:60:bd:d0 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '5: enp0s20f1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether a0:36:9f:60:bd:d1 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '6: enp0s20f2: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether a0:36:9f:60:bd:d2 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '7: enp0s20f3: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether a0:36:9f:60:bd:d3 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '8: p1p1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000\\    link/ether a0:36:9f:5c:ff:fe brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '9: sw0p1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast portid 00000001 state UP mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '10: sw0p2: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000002 state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '11: sw0p3: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000003 state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '12: sw0p4: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000004 state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '13: sw0p5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast master team1 portid 00000005 state UP mode DEFAULT group default qlen 1000\\    link/ether b2:7c:46:41:6e:3c brd ff:ff:ff:ff:ff:ff promiscuity 0 \\    team_slave \n'
        '14: sw0p6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast master team1 portid 00000006 state UP mode DEFAULT group default qlen 1000\\    link/ether b2:7c:46:41:6e:3c brd ff:ff:ff:ff:ff:ff promiscuity 0 \\    team_slave \n'
        '15: sw0p7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast master team2 portid 00000007 state UP mode DEFAULT group default qlen 1000\\    link/ether 9a:3d:f6:a2:ef:f6 brd ff:ff:ff:ff:ff:ff promiscuity 0 \\    team_slave \n'
        '16: sw0p8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast master 1234 portid 00000008 state UP mode DEFAULT group default qlen 1000\\    link/ether a2:76:22:ff:47:5d brd ff:ff:ff:ff:ff:ff promiscuity 0 \\    team_slave \n'
        '17: sw0p9: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000009 state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '18: sw0p10: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 0000000a state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '19: sw0p11: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 0000000b state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '20: sw0p12: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 0000000c state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '21: sw0p13: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 0000000d state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '22: sw0p14: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 0000000e state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '23: sw0p15: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 0000000f state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '24: sw0p16: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000010 state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '25: sw0p19: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000013 state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '26: sw0p20: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000014 state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '27: sw0p21: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000015 state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '28: sw0p22: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000016 state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '29: sw0p23: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000017 state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '30: sw0p24: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000018 state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '31: sw0p25: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000019 state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '32: sw0p0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000000 state DOWN mode DEFAULT group default qlen 1000\\    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff promiscuity 0 \n'
        '33: team1@NONE: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default \\    link/ether b2:7c:46:41:6e:3c brd ff:ff:ff:ff:ff:ff promiscuity 0 \\    team addrgenmode eui64 \n'
        '34: team2@NONE: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default \\    link/ether 9a:3d:f6:a2:ef:f6 brd ff:ff:ff:ff:ff:ff promiscuity 0 \\    team addrgenmode eui64 \n'
        '35: 1234: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default \\    link/ether a2:76:22:ff:47:5d brd ff:ff:ff:ff:ff:ff promiscuity 0 \\    team addrgenmode eui64 \n'
    )

    IP_SHOW_STATS_OUTPUT = """\
    2: em1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
        link/ether d4:c9:ef:52:7c:4d brd ff:ff:ff:ff:ff:ff
        RX: bytes  packets  errors  dropped overrun mcast
        2781945429 3202213  0       0       0       30131
        RX errors: length  crc     frame   fifo    missed
                   0        0       0       0       0
        TX: bytes  packets  errors  dropped carrier collsns
        646221183  2145799  0       0       0       0
        TX errors: aborted fifo    window  heartbeat
                   0        0       0       0
    """

    RAW_PING_OUTPUT = (
        'PATTERN: 0xff\n'
        'PING 192.168.10.2 (192.168.10.2) from 192.168.10.1 sw0p0: 56(84) bytes of data.\n'
        '64 bytes from 192.168.10.2: icmp_seq=1 ttl=64 time=0.647 ms\n'
        'TS:     3812901 absolute\n'
        '        64484186\n'
        '        0\n'
        '        -64484185\n'
        '\n'
        '64 bytes from 192.168.10.2: icmp_seq=1 ttl=64 time=0.542 ms\n'
        'TS:     3813902 absolute\n'
        '        64484185\n'
        '        0\n'
        '        -64484184\n'
        '\n'
        '64 bytes from 192.168.10.2: icmp_seq=1 ttl=64 time=0.544 ms\n'
        'TS:     3814902 absolute\n'
        '        64484185\n'
        '        0\n'
        '        -64484184\n'
        '\n'
        '--- 192.168.10.2 ping statistics ---\n'
        '3 packets transmitted, 3 received, 0% packet loss, time 4000ms\n'
        'rtt min/avg/max/mdev = 0.525/0.562/0.647/0.048 ms'
    )

    RAW_FDB_OUTPUT = (
        '33:33:00:00:00:01 dev pep8 self permanent\n'
        '01:00:5e:00:00:01 dev pep8 self permanent\n'
        '33:33:ff:60:b4:14 dev pep8 self permanent\n'
        '33:33:00:00:00:01 dev pep4 self permanent\n'
        '33:33:00:00:00:01 dev enp0s20f0 self permanent\n'
        '33:33:00:00:00:01 dev enp0s20f1 self permanent\n'
        '33:33:00:00:00:01 dev enp0s20f2 self permanent\n'
        '33:33:00:00:00:01 dev enp0s20f3 self permanent\n'
        '33:33:00:00:00:01 dev p1p1 self permanent\n'
        '01:00:5e:00:00:01 dev p1p1 self permanent\n'
        '33:33:ff:5c:ff:fe dev p1p1 self permanent\n'
        '00:11:22:33:44:55 dev sw0p5 vlan 2 self permanent\n'
        '00:11:22:33:44:55 dev sw0p5 vlan 22 self permanent\n'
        '00:11:22:33:44:55 dev sw0p5 vlan 222 self \n'
        '00:11:22:33:44:55 dev sw0p5 vlan 2222 self permanent\n'
        '55:44:33:22:11:00 dev sw0p6 vlan 3 self permanent\n'
        '55:44:33:22:11:00 dev sw0p6 vlan 33 self permanent\n'
        '55:44:33:22:11:00 dev sw0p6 vlan 333 self \n'
        '55:44:33:22:11:00 dev sw0p6 vlan 3333 self permanent\n'
    )

    NETWORKCTL_SAMPLE_1 = """\
    ●  6: enp0s29u1u7u1
            Type: ether
           State: degraded (configured)
            Path: pci-0000:00:1d.0-usb-0:1.7.1:1.0
          Driver: asix
          Vendor: ASIX Electronics Corp.
      HW Address: 0:60:63:43:78:95
             MTU: 1500
         Address: fe80::260:63ff:fe43:7895
    """

    NETWORKCTL_SAMPLE_2 = """\
    ● 8: p1p1
           Link File: /usr/lib/systemd/network/99-default.link
        Network File: n/a
                Type: ether
               State: n/a (n/a)
                Path: pci-0000:02:00.0
              Driver: igb
              Vendor: Intel Corporation
               Model: I210 Gigabit Network Connection (Ethernet Server Adapter I210-T1)
          HW Address: a0:36:9f:5c:ff:8e
                 MTU: 1500
             Address: 192.168.1.1
                      fe80::a236:9fff:fe5c:ff8e
    """

    RAW_VLAN_OUTPUT = (
        'port\tvlan ids\n'
        'sw0p1\tNone\n'
        'sw0p2\tNone\n'
        'sw0p3\tNone\n'
        'sw0p4\tNone\n'
        'sw0p5\t 2\n'
        '\t 3 Egress Untagged\n'
        '\t 33\n'
        '\t 222 PVID\n'
        '\t 2222\n'
        '\t 3333\n'
        '\n'
        'sw0p6\t 3\n'
        '\t 33\n'
        '\t 333 Egress Untagged\n'
        '\t 3333 PVID\n'
        '\n'
        'sw0p7\tNone\n'
        'sw0p8\tNone\n'
        'sw0p9\tNone\n'
        'sw0p10\tNone\n'
        'sw0p11\tNone\n'
        'sw0p12\t44 PVID Egress Untagged\n'
        'sw0p13\tNone\n'
        'sw0p14\tNone\n'
        'sw0p15\tNone\n'
        'sw0p16\tNone\n'
        'sw0p19\tNone\n'
        'sw0p20\tNone\n'
        'sw0p21\tNone\n'
        'sw0p22\tNone\n'
        'sw0p23\tNone\n'
        'sw0p24\tNone\n'
        'sw0p25\tNone\n'
        'sw0p0\tNone\n'
        'team25\t 4\n'
        '\t 44\n'
        '\t 444 Egress Untagged\n'
        '\t 4444 PVID\n'
        '\n'
    )

    SWITCH_ATTRIBUTES = \
        'autoneg\x00' \
        'bcast_capacity\x00' \
        'bcast_flooding\x00' \
        'bcast_pruning\x00' \
        'bcast_rate\x00' \
        'def_cfi\x00'

    RAW_ETHTHOOL_NO_LINK_OUTPUT = \
        'Settings for sw0p5:\n' \
        '\tSupported ports: [ FIBRE ]\n' \
        '\tSupported link modes:   Not reported\n' \
        '\tSupported pause frame use: No\n' \
        '\tSupports auto-negotiation: No\n' \
        '\tAdvertised link modes:  Not reported\n' \
        '\tAdvertised pause frame use: No\n' \
        '\tAdvertised auto-negotiation: No\n' \
        '\tSpeed: 40000Mb/s\n' \
        '\tDuplex: Full\n' \
        '\tPort: FIBRE\n' \
        '\tPHYAD: 0\n' \
        '\tTransceiver: internal\n' \
        '\tAuto-negotiation: off\n' \
        '\tLink detected: no\n'

    RAW_ARP_OUTPUT = (
        '10.20.30.40 dev sw0p5 lladdr 00:AA:AA:AA:AA:12 STALE\n'
        '192.168.10.60 dev sw0p6 lladdr 00:BB:BB:BB:BB:13 STALE\n'
        '192.168.10.65 dev sw0p5 lladdr 00:BB:BB:BB:BB:AA PERMANENT\n'
        '2001::2000 dev sw0p6 lladdr 00:12:12:12:12:12 STALE\n'
    )

@pytest.fixture
def ui():
    return ui_onpss_shell.UiOnpssShell(MagicMock(**{"hw": type("SiliconFM10K", (object,), {})()}))


class TestPortMapping(object):

    # This does in fact create a fresh UiOnpssShell for each test case
    @pytest.fixture(autouse=True)
    def create_ui(self, ui):
        self.ui = ui
        self.ui.switch.ssh.exec_command = MagicMock(return_value=CmdStatus("", "", 0))
        self.ports_table = [{'portId': p, 'name': "sw0p{}".format(p), 'type': 'Physical'} for p in range(4)]
        self.ui.get_table_ports = MagicMock(return_value=self.ports_table)
        self.ui.generate_port_name_mapping()
        self.ui.lag_map.update({v: "team{}".format(v) for v in range(3, 6)})
        self.ui.name_to_lagid_map.update({v: k for k, v in list(ui.lag_map.items())})

    @staticmethod
    def my_side_effect(*args, **kwargs):
        if 'find /sys/class/net/' in kwargs['command']:
            raise UICmdException("", "", "", "", rc=1)
        else:
            return CmdStatus("", "", 0)

    def test_portmap(self):
        # Check port_map
        for dev in self.ui.port_map:
            if dev < 4:
                assert self.ui.port_map[dev] == "sw0p{}".format(dev)
            else:
                assert self.ui.port_map[dev] == "team{}".format(dev)

        # Check switch_map
        for dev in self.ui.switch_map:
            assert self.ui.switch_map[dev] == "sw0p{}".format(dev)

        # Check lag_map
        for dev in self.ui.lag_map:
            assert self.ui.lag_map[dev] == "team{}".format(dev)

    def test_nametoportidmap(self):
        # Check name_to_portid_map
        for dev in self.ui.name_to_portid_map:
            assert self.ui.name_to_portid_map[dev] == int(dev[-1])

        # Check name_to_switchid_map
        for dev in self.ui.name_to_switchid_map:
            assert self.ui.name_to_switchid_map[dev] == int(dev[-1])

        # Check name_to_lagid_map
        for dev in self.ui.name_to_lagid_map:
            assert self.ui.name_to_lagid_map[dev] == int(dev[-1])

    def test_portmap_adding_new_active_lag(self):
        self.ui.create_lag(lag='newteam')
        assert 'newteam' in self.ui.lag_map
        assert 'newteam' in self.ui.port_map

    def test_nametoportidmap_adding_new_active_lag(self):
        self.ui.create_lag(lag='newteam')
        assert 'newteam' in self.ui.name_to_lagid_map
        assert 'newteam' in self.ui.name_to_portid_map

    def test_portmap_removing_active_lag(self):
        self.ui.create_lag(lag='newteam')
        self.ui.cli_send_command = MagicMock(side_effect=self.my_side_effect)
        self.ui.delete_lags(lags=['newteam'])
        assert 'newteam' not in self.ui.lag_map
        assert 'newteam' not in self.ui.port_map

    def test_nametoportidmap_removing_active_lag(self):
        self.ui.create_lag(lag='newteam')
        self.ui.cli_send_command = MagicMock(side_effect=self.my_side_effect)
        self.ui.delete_lags(lags=['newteam'])
        assert 'newteam' not in self.ui.name_to_lagid_map
        assert 'newteam' not in self.ui.name_to_portid_map


def ports_side_effect(*args, **kwargs):
    if 'max_frame_size' in args[0]:
        return CmdStatus("1536", "", 0)
    if 'ethtool' in args[0]:
        return CmdStatus(OnpssRawOutput.RAW_ETHTHOOL_NO_LINK_OUTPUT, "", 0)
    else:
        return CmdStatus(OnpssRawOutput.RAW_IPLINK_DETAIL_OUTPUT, "", 0)


def multicall_ports_side_effect(*args, **kwargs):
    if 'max_frame_size' in args[0][0]:
        return [[cmd, CmdStatus("1536", "", 0)] for cmd in args[0]]
    if 'ethtool' in args[0][0]:
        return [[cmd, CmdStatus(OnpssRawOutput.RAW_ETHTHOOL_NO_LINK_OUTPUT, "", 0)] for cmd in args[0]]
    else:
        return [args[0], CmdStatus(OnpssRawOutput.RAW_IPLINK_DETAIL_OUTPUT, "", 0)]


def test_get_table_lags(ui):

    ui.switch.ssh.exec_command = MagicMock(side_effect=ports_side_effect)
    ui.cli_multicall = MagicMock(side_effect=multicall_ports_side_effect)

    table = ui.get_table_lags()

    assert table == [
        {'lagControlType': 'Static', 'lagId': 'team1', 'hashMode': 'None', 'name': 'team1', 'actorAdminLagKey': 0},
        {'lagControlType': 'Static', 'lagId': 'team2', 'hashMode': 'None', 'name': 'team2', 'actorAdminLagKey': 0},
        {'lagControlType': 'Static', 'lagId': 1234, 'hashMode': 'None', 'name': 'lag1234', 'actorAdminLagKey': 0}
    ]


def test_get_table_ports2lag(ui):

    ui.switch.ssh.exec_command = MagicMock(side_effect=ports_side_effect)
    ui.cli_multicall = MagicMock(side_effect=multicall_ports_side_effect)

    table = ui.get_table_ports2lag()

    assert table == [
        {'actorPortPriority': 0, 'lagId': 'team1', 'portId': 5},
        {'actorPortPriority': 0, 'lagId': 'team1', 'portId': 6},
        {'actorPortPriority': 0, 'lagId': 'team2', 'portId': 7},
        {'actorPortPriority': 0, 'lagId': 1234, 'portId': 8}
    ]


class TestPortConfigSnapshot(object):

    @pytest.fixture(autouse=True)
    def create_ui(self, ui):
        self.ui = ui
        self.ui.switch.hw = SiliconFM10K()
        self.ports_table = [{'portId': p, 'name': "sw0p{}".format(p), 'type': 'Physical'} for p in range(4)]
        self.ui.get_table_ports = MagicMock(return_value=self.ports_table)
        self.ui.generate_port_name_mapping()
        self.ui.lag_map.update({v: "team{}".format(v) for v in range(3, 6)})
        self.ui.name_to_lagid_map.update({v: k for k, v in list(ui.lag_map.items())})

        self.ui.switch.ssh.exec_command = MagicMock(return_value=CmdStatus(
            OnpssRawOutput.SWITCH_ATTRIBUTES, "", 0))
        self.ui.get_port_configuration = MagicMock(return_value=0)


def test_cli_get_all(ui):

    ui.switch.ssh.exec_command = MagicMock(return_value=CmdStatus(
        "".join(OnpssRawOutput.RAW_IPLINK_OUTPUT), "", 0))

    table = ui.cli_get_all([['ip link show'], ])
    table2 = [ui.cli_set([['ip link show'], ])[0][0].stdout]
    expected_table = [[
        '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default ',
        '    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 ',
        '2: em1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000',
        '    link/ether 08:9e:01:72:d4:d0 brd ff:ff:ff:ff:ff:ff ',
        '3: sw0p1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000001 state DOWN mode DEFAULT group default qlen 1000',
        '    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff ',
        '4: sw0p2: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000002 state DOWN mode DEFAULT group default qlen 1000',
        '    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff ',
        '11: sw0p9: <BROADCAST,MULTICAST> mtu 1500 qdisc pfifo_fast portid 00000009 state DOWN mode DEFAULT group default qlen 1000',
        '    link/ether 56:8b:3e:5f:cb:99 brd ff:ff:ff:ff:ff:ff ',
        '12: sw0p10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast master team1 portid 0000000a state UP mode DEFAULT group default qlen 1000',
        '    link/ether 56:8b:3e:5f:cb:99 brd ff:ff:ff:ff:ff:ff ',
        '13: sw0p11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast master team1 portid 0000000b state UP mode DEFAULT group default qlen 1000',
        '    link/ether 56:8b:3e:5f:cb:99 brd ff:ff:ff:ff:ff:ff ',
        '14: sw0p12: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast master team2 portid 0000000c state UP mode DEFAULT group default qlen 1000',
        '    link/ether 0a:e1:f0:b5:56:0a brd ff:ff:ff:ff:ff:ff ',
        '15: sw0p13: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast master team2 portid 0000000d state DOWN mode DEFAULT group default qlen 1000',
        '    link/ether 0a:e1:f0:b5:56:0a brd ff:ff:ff:ff:ff:ff ',
        '66: sw0p64: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000040 state DOWN mode DEFAULT group default qlen 1000',
        '    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff ',
        '67: sw0p0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop portid 00000000 state DOWN mode DEFAULT group default qlen 1000',
        '    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff ',
        '69: team1@NONE: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default ',
        '    link/ether 56:8b:3e:5f:cb:99 brd ff:ff:ff:ff:ff:ff ',
        '70: teamempty@NONE: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default ',
        '    link/ether 1e:2f:f0:ed:f1:a1 brd ff:ff:ff:ff:ff:ff ',
        '71: team2@NONE: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default ',
        '    link/ether 0a:e1:f0:b5:56:0a brd ff:ff:ff:ff:ff:ff ']]

    assert table == expected_table
    assert table2 == expected_table


def test_get_table_fdb(ui):
    ui.name_to_portid_map = {"sw0p5": 5, "sw0p6": 6}
    ui.switch.ssh.exec_command = MagicMock(return_value=CmdStatus(
        OnpssRawOutput.RAW_FDB_OUTPUT, "", 0))

    table = ui.get_table_fdb()

    assert table == [
        {'macAddress': '00:11:22:33:44:55', 'portId': 5, 'vlanId': 2, 'type': 'Static'},
        {'macAddress': '00:11:22:33:44:55', 'portId': 5, 'vlanId': 22, 'type': 'Static'},
        {'macAddress': '00:11:22:33:44:55', 'portId': 5, 'vlanId': 222, 'type': 'Dynamic'},
        {'macAddress': '00:11:22:33:44:55', 'portId': 5, 'vlanId': 2222, 'type': 'Static'},
        {'macAddress': '55:44:33:22:11:00', 'portId': 6, 'vlanId': 3, 'type': 'Static'},
        {'macAddress': '55:44:33:22:11:00', 'portId': 6, 'vlanId': 33, 'type': 'Static'},
        {'macAddress': '55:44:33:22:11:00', 'portId': 6, 'vlanId': 333, 'type': 'Dynamic'},
        {'macAddress': '55:44:33:22:11:00', 'portId': 6, 'vlanId': 3333, 'type': 'Static'}
    ]

    table = ui.get_table_fdb('static')

    assert table == [
        {'macAddress': '00:11:22:33:44:55', 'portId': 5, 'vlanId': 2},
        {'macAddress': '00:11:22:33:44:55', 'portId': 5, 'vlanId': 22},
        {'macAddress': '00:11:22:33:44:55', 'portId': 5, 'vlanId': 2222},
        {'macAddress': '55:44:33:22:11:00', 'portId': 6, 'vlanId': 3},
        {'macAddress': '55:44:33:22:11:00', 'portId': 6, 'vlanId': 33},
        {'macAddress': '55:44:33:22:11:00', 'portId': 6, 'vlanId': 3333}
    ]

    table = ui.get_table_fdb('dynamic')

    assert table == [
        {'macAddress': '00:11:22:33:44:55', 'portId': 5, 'vlanId': 222, 'type': 'Dynamic'},
        {'macAddress': '55:44:33:22:11:00', 'portId': 6, 'vlanId': 333, 'type': 'Dynamic'}
    ]


def test_get_table_ports2vlans(ui):
    ui.name_to_portid_map = {"sw0p5": 5, "sw0p6": 6, "sw0p12": 12, "team25": "team25"}
    ui.switch.ssh.exec_command = MagicMock(return_value=CmdStatus(OnpssRawOutput.RAW_VLAN_OUTPUT, "", 0))

    table = ui.get_table_ports2vlans()

    assert table == [
        {'portId': 5, 'vlanId': 2, 'tagged': 'Tagged', 'pvid': False},
        {'portId': 5, 'vlanId': 3, 'tagged': 'Untagged', 'pvid': False},
        {'portId': 5, 'vlanId': 33, 'tagged': 'Tagged', 'pvid': False},
        {'portId': 5, 'vlanId': 222, 'tagged': 'Tagged', 'pvid': True},
        {'portId': 5, 'vlanId': 2222, 'tagged': 'Tagged', 'pvid': False},
        {'portId': 5, 'vlanId': 3333, 'tagged': 'Tagged', 'pvid': False},
        {'portId': 6, 'vlanId': 3, 'tagged': 'Tagged', 'pvid': False},
        {'portId': 6, 'vlanId': 33, 'tagged': 'Tagged', 'pvid': False},
        {'portId': 6, 'vlanId': 333, 'tagged': 'Untagged', 'pvid': False},
        {'portId': 6, 'vlanId': 3333, 'tagged': 'Tagged', 'pvid': True},
        {'portId': 12, 'vlanId': 44, 'tagged': 'Untagged', 'pvid': True},
        {'portId': "team25", 'vlanId': 4, 'tagged': 'Tagged', 'pvid': False},
        {'portId': "team25", 'vlanId': 44, 'tagged': 'Tagged', 'pvid': False},
        {'portId': "team25", 'vlanId': 444, 'tagged': 'Untagged', 'pvid': False},
        {'portId': "team25", 'vlanId': 4444, 'tagged': 'Tagged', 'pvid': True},
    ]


def test_parse_ip_show_stats():
    out = ui_onpss_shell.UiOnpssShell.parse_ip_show_stats(
        OnpssRawOutput.IP_SHOW_STATS_OUTPUT.splitlines())
    assert out == {
        'RX:bytes': '2781945429',
        'RX:dropped': '0',
        'RX:errors': '0',
        'RX:mcast': '30131',
        'RX:overrun': '0',
        'RX:packets': '3202213',
        'RX errors:length': '0',
        'RX errors:crc': '0',
        'RX errors:frame': '0',
        'RX errors:fifo': '0',
        'RX errors:missed': '0',
        'TX:bytes': '646221183',
        'TX:carrier': '0',
        'TX:collsns': '0',
        'TX:dropped': '0',
        'TX:errors': '0',
        'TX:packets': '2145799',
        'TX errors:aborted': '0',
        'TX errors:fifo': '0',
        'TX errors:window': '0',
        'TX errors:heartbeat': '0',
    }


def vlan_ports_side_effect(*args, **kwargs):
    if 'show' in args[0]:
        return CmdStatus(OnpssRawOutput.RAW_VLAN_OUTPUT, "", 0)
    else:
        return CmdStatus("", "", 0)


def test_modify_vlan_ports_pvid(ui):
    ui.name_to_portid_map = {"sw0p5": 5, "sw0p6": 6, "sw0p12": 12, "team25": "team25"}
    ui.port_map = {5: "sw0p5", 6: "sw0p6", 12: "sw0p12", "team25": "team25"}

    ui.switch.ssh.exec_command = MagicMock(side_effect=vlan_ports_side_effect)

    ui.modify_vlan_ports(ports=[5, 6, 12], vlans=[3], tagged='pvid')

    call_list = [arg[0][0] for arg in ui.switch.ssh.exec_command.call_args_list]
    assert set(call_list) == set(['bridge vlan show',  # Get Ports2Vlans table
                         'bridge vlan del vid 3 dev sw0p5 self ',  # Delete existing record for sw0p5
                         'bridge vlan del vid 3 dev sw0p6 self ',  # Delete existing record for sw0p5
                         'bridge vlan add vid 3 dev sw0p6 self pvid',  # Add new record for sw0p6 with old 'tagged' value
                         'bridge vlan add vid 3 dev sw0p5 self pvid untagged',  # Add new record for sw0p5 with old 'tagged' value
                         'bridge vlan add vid 3 dev sw0p12 self pvid'])  # Add new record for sw0p12


def test_modify_vlan_ports_tagged(ui):
    ui.name_to_portid_map = {"sw0p5": 5, "sw0p6": 6, "sw0p12": 12, "team25": "team25"}
    ui.port_map = {5: "sw0p5", 6: "sw0p6", 12: "sw0p12", "team25": "team25"}

    ui.switch.ssh.exec_command = MagicMock(side_effect=vlan_ports_side_effect)

    ui.modify_vlan_ports(ports=[5, 6, 12], vlans=[3333], tagged='Untagged')

    call_list = [arg[0][0] for arg in ui.switch.ssh.exec_command.call_args_list]
    assert set(call_list) == set(['bridge vlan show',  # Get Ports2Vlans table
                         'bridge vlan del vid 3333 dev sw0p5 self ',  # Delete existing record for sw0p5
                         'bridge vlan del vid 3333 dev sw0p6 self ',  # Delete existing record for sw0p5
                         'bridge vlan add vid 3333 dev sw0p5 self untagged',  # Add new record for sw0p5 with old 'pvid' value
                         'bridge vlan add vid 3333 dev sw0p6 self pvid untagged',  # Add new record for sw0p6 with old 'pvid' value
                         'bridge vlan add vid 3333 dev sw0p12 self untagged'])  # Add new record for sw0p12


class TestGenerateVlanCommand(object):

    @pytest.fixture(autouse=True)
    def create_ui(self, ui):
        self.ui = ui
        self.ui.port_map = {0: "p0", 1: "p1"}
        self.ports = [0, 1]
        self.port_names = [self.ui.port_map[p] for p in self.ports]

    # ui = ui()
    # ui.port_map = {0: "p0", 1: "p1"}
    # ports = [0, 1]
    # port_names = [ui.port_map[p] for p in ports]

    def test_generate_bridge_vlan_commands_add_multiport_singlevlan(self):

        result = self.ui._generate_bridge_vlan_commands("add", self.port_names, [0], 'Tagged')

        assert result == [
            "bridge vlan add vid 0 dev p0 self Tagged",
            "bridge vlan add vid 0 dev p1 self Tagged"
        ]

    def test_generate_bridge_vlan_commands_add_singleport_multiplevlan(self):

        result = self.ui._generate_bridge_vlan_commands("add", self.port_names[1:], [0, 1], 'Tagged')
        assert result == [
            "bridge vlan add vid 0 dev p1 self Tagged",
            "bridge vlan add vid 1 dev p1 self Tagged",
        ]

    def test_generate_bridge_vlan_commands_del_singleport_singlevlan(self):

        result = self.ui._generate_bridge_vlan_commands("del", self. port_names[1:], [0])
        assert result == [
            "bridge vlan del vid 0 dev p1 self "
        ]

    def test_generate_bridge_vlan_commands_del_multiport_multivlan(self):

        result = self.ui._generate_bridge_vlan_commands("del", self.port_names, [0, 1])
        assert result == [
            "bridge vlan del vid 0 dev p0 self ",
            "bridge vlan del vid 0 dev p1 self ",
            "bridge vlan del vid 1 dev p0 self ",
            "bridge vlan del vid 1 dev p1 self ",
        ]


def test_get_icmp_ping_result(ui):
    table = ui.parse_icmp_ping_result(OnpssRawOutput.RAW_PING_OUTPUT)
    assert table == {
        'ip_addr': '192.168.10.2',
        'source_ip': '192.168.10.1',
        'mgmt_interface': 'sw0p0',
        'bytes': 56,
        'transmitted': 3,
        'received': 3,
        'error': None,
        'lost': 0,
        'time': 4000,
        'time_stamp': '3812901',
        'pattern': '0xff'
    }


def test_get_table_arp(ui):
    ui.name_to_portid_map = {"sw0p5": 5, "sw0p6": 6}
    ui.port_map = {5: "sw0p5", 6: "sw0p6"}
    ui.switch.ssh.exec_command = MagicMock(return_value=CmdStatus(
        OnpssRawOutput.RAW_ARP_OUTPUT, "", 0))
    ui.get_available_switch_ports = MagicMock(return_value=[5, 6])

    table = ui.get_table_arp()

    assert table == [
        {'ifName': 5, 'phyAddress': '00:AA:AA:AA:AA:12', 'netAddress': '10.20.30.40', 'type': 'None'},
        {'ifName': 6, 'phyAddress': '00:BB:BB:BB:BB:13', 'netAddress': '192.168.10.60', 'type': 'None'},
        {'ifName': 5, 'phyAddress': '00:BB:BB:BB:BB:AA', 'netAddress': '192.168.10.65', 'type': 'Static'},
        {'ifName': 6, 'phyAddress': '00:12:12:12:12:12', 'netAddress': '2001::2000', 'type': 'None'}
    ]


class TestCliSendCommand(object):

    @pytest.fixture(autouse=True)
    def create_ui(self, ui):
        self.ui = ui
        print(id(ui))

    def test_cli_send_command_raises_exception_when_unexpected_rc_defaults(self):
        self.ui.switch.ssh.exec_command.return_value = CmdStatus("", "", 1234)
        with pytest.raises(UICmdException) as excinfo:
            self.ui.cli_send_command("")
        assert excinfo.value.rc == 1234

    def test_cli_send_command_raises_exception_when_unexpected_rc(self):
        self.ui.switch.ssh.exec_command.return_value = CmdStatus("", "", 1234)
        with pytest.raises(UICmdException) as excinfo:
            self.ui.cli_send_command("", expected_rcs=2)
        assert excinfo.value.rc == 1234

    def test_cli_send_command_passes_with_expected_rc_int(self):
        self.ui.switch.ssh.exec_command.return_value = CmdStatus("", "", 4)
        assert self.ui.cli_send_command("", expected_rcs=4)[-1] == 4

    def test_cli_send_command_passes_with_expected_rc_set(self):
        self.ui.switch.ssh.exec_command.return_value = CmdStatus("", "", 4)
        assert self.ui.cli_send_command("", expected_rcs=set(range(5)))[-1] == 4

    def test_cli_send_command_handles_ssh_no_exit_status(self):
        self.ui.switch.ssh.exec_command.return_value = CmdStatus("", "", self.ui.SSH_NO_EXIT_STATUS)
        assert self.ui.cli_send_command(
            "", expected_rcs={self.ui.SSH_NO_EXIT_STATUS})[-1] == self.ui.SSH_NO_EXIT_STATUS


class TestStaticMacs(object):

    ui = ui()
    ui.port_map = {0: "p0", 1: "p1"}
    ui.get_table_ports2lag = MagicMock(return_value=[{'lagId': 'team1', 'portId': 5}])

    def test_create_static_mac_raises_uiexcepion_if_not_in_device(self):
        with pytest.raises(UIException):
            self.ui.create_static_macs(2.0, 0, "00:11:22:33:44:55")

    def test_delete_static_mac_raises_uiexcepion_if_not_in_device(self):
        with pytest.raises(UIException):
            self.ui.delete_static_mac(3.0, 0, "00:11:22:33:44:55")


class TestGetTableBridgeInfo(object):

    # This does in fact create a fresh UiOnpssShell for each test case
    @pytest.fixture(autouse=True)
    def create_ui(self, ui):
        self.ui = ui

    def test_raises_exception_when_no_port_and_no_mgmt_ports(self):
        self.ui.switch.mgmt_iface = None
        with pytest.raises(UIException) as excinfo:
            self.ui.get_table_bridge_info()
        assert "Port should be provided".lower() in excinfo.exconly()

    def test_uses_mgmt_port_when_no_port_specified(self):
        mgmt_iface = "this_is_mgmt_iface"
        self.ui.switch.mgmt_iface = mgmt_iface
        self.ui.cli_send_command = MagicMock(return_value=CmdStatus("", "", 0))
        self.ui.get_table_bridge_info()
        assert mgmt_iface in self.ui.cli_send_command.call_args[0][0]

    def test_use_port_itself_when_string(self):
        port_arg = "this_is_port_arg"
        self.ui.cli_send_command = MagicMock(return_value=CmdStatus("", "", 0))
        self.ui.get_table_bridge_info(port=port_arg)
        assert port_arg in self.ui.cli_send_command.call_args[0][0]

    def test_lookup_port_when_int(self):
        port_arg = "this_is_port_arg"
        self.ui.port_map = {3: port_arg}
        self.ui.cli_send_command = MagicMock(return_value=CmdStatus("", "", 0))
        self.ui.get_table_bridge_info(port=3)
        assert port_arg in self.ui.cli_send_command.call_args[0][0]

    def test_param_is_not_none(self):
        port_arg = "this_is_port_arg"
        self.ui.port_map = {3: port_arg}
        self.ui.cli_send_command = MagicMock(return_value=CmdStatus("", "", 0))
        self.ui.get_table_bridge_info(param="duplex", port=3)
        assert port_arg in self.ui.cli_send_command.call_args[0][0]
        assert "duplex" in self.ui.cli_send_command.call_args[0][0]


class TestImportHWModule(object):

    def test_cpu_rate_limiting_fm10k(self):
        ui = ui_onpss_shell.UiOnpssShell(MagicMock(**{"hw": type("SiliconFM10K", (object,), {})()}))
        # self.ui.cli_send_command = MagicMock(side_effect=[CmdStatus("fm10kd\n", "", 0)])
        module = ui.hw
        assert module.gen_cpu_rate_limiting_command("a", "b") == "nohup a -c </dev/null &>b &"

    def test_cpu_rate_limiting_fm6k(self):
        ui = ui_onpss_shell.UiOnpssShell(MagicMock(**{"hw": type("SiliconFM6K", (object,), {})()}))
        # self.ui.cli_send_command = MagicMock(side_effect=[CmdStatus("fm10kd\n", "", 0)])
        module = ui.hw
        assert module.gen_cpu_rate_limiting_command("daemon", "log_file") == \
            "nohup env FM_API_ATTR_FILE=/etc/ies_api_attributes daemon -c </dev/null " \
            "&>log_file &"


class TestNetworkCtl(object):

    # This does in fact create a fresh UiOnpssShell for each test case
    @pytest.fixture(autouse=True)
    def create_ui(self, ui):
        self.ui = ui

    def test_get_ufd_networkctl_status_1(self):
        port_arg = "this_is_port_arg"
        port = 3
        self.ui.port_map = {port: port_arg}
        self.ui.cli_send_command = MagicMock(return_value=CmdStatus(
            OnpssRawOutput.NETWORKCTL_SAMPLE_1, '', 0))
        d = self.ui.get_ufd_networkctl_status([3])
        sample_1_good = {
            port: {
                '\u25cf  6': 'enp0s29u1u7u1', 'Address': 'fe80::260:63ff:fe43:7895', 'MTU': '1500',
                'Type': 'ether', 'State': 'degraded (configured)',
                'Path': 'pci-0000:00:1d.0-usb-0:1.7.1:1.0', 'Driver': 'asix',
                'Vendor': 'ASIX Electronics Corp.', 'HW Address': '0:60:63:43:78:95',
            }
        }
        assert d[port] == sample_1_good[port]

    def test_get_ufd_networkctl_status_2(self):
        port_arg = "this_is_port_arg"
        port = 3
        self.ui.port_map = {port: port_arg}
        self.ui.cli_send_command = MagicMock(return_value=CmdStatus(
            OnpssRawOutput.NETWORKCTL_SAMPLE_2, '', 0))
        d = self.ui.get_ufd_networkctl_status([3])
        sample_2_good = {
            port: {
                '\u25cf 8': 'p1p1',
                'Link File': '/usr/lib/systemd/network/99-default.link',
                'Network File': 'n/a',
                'Type': 'ether',
                'State': 'n/a (n/a)',
                'Path': 'pci-0000:02:00.0',
                'Driver': 'igb',
                'Vendor': 'Intel Corporation',
                'Model': 'I210 Gigabit Network Connection (Ethernet Server Adapter I210-T1)',
                'HW Address': 'a0:36:9f:5c:ff:8e',
                'MTU': '1500',
                'Address': '192.168.1.1 fe80::a236:9fff:fe5c:ff8e',
            }
        }
        assert d[port] == sample_2_good[port]


class TestInvalidPort(object):

    # This does in fact create a fresh UiOnpssShell for each test case
    @pytest.fixture(autouse=True)
    def create_ui(self, ui):
        self.ui = ui

    def test_list_of_ports(self):
        test_ports = [1, 2, 3, 4]
        self.ui.port_map = {}
        with self.ui.create_invalid_ports(ports=test_ports) as ports:
            assert ports == test_ports
            for test_ports in ports:
                assert self.ui.port_map[test_ports] == "sw0p{}".format(test_ports)

    def test_number_of_ports(self):
        self.ui.port_map = {}
        ports_len = 3
        num_ports = 5
        self.ui.get_table_ports = MagicMock(return_value=list(range(ports_len)))
        with self.ui.create_invalid_ports(num=num_ports) as ports:
            assert len(ports) == num_ports
            for p in ports:
                assert self.ui.port_map[p] == "sw0p{}".format(p)

    def test_no_clobber(self):
        orig = {1: "sw0p1", 2: "sw0p2"}
        self.ui.port_map = orig.copy()
        ports_len = 3
        num_ports = 5
        self.ui.get_table_ports = MagicMock(return_value=list(range(ports_len)))
        with self.ui.create_invalid_ports(num=num_ports) as ports:
            assert len(ports) == num_ports
            for p in ports:
                assert self.ui.port_map[p] == "sw0p{}".format(p)
            for k, v in orig.items():
                assert self.ui.port_map[k] == v


class TestAbstractError(object):

    def test_access_error(self):
        with pytest.raises(AccessError):
            raise AccessError("manadatory arg")

    def test_boundary_error(self):
        with pytest.raises(BoundaryError):
            raise BoundaryError("manadatory arg")


class TestCreateMatchApi(object):

    @pytest.fixture(autouse=True)
    def create_ui(self, ui):
        self.ui = ui

    def test_create_match_api_tcam_subtable(self):
        self.ui.switch.ssh.exec_command = MagicMock(return_value=CmdStatus("", "", 0))
        result = self.ui.create_match_api_tcam_subtable(source_id=1,
                                                        table_id=6, table_name="tcam1",
                                                        max_table_entries=10,
                                                        match_field_type_pairs=[(
                                                            'ethernet.dst_mac', 'exact')],
                                                        actions=['normal'])
        expected_create_table = None
        assert result == expected_create_table

    def test_create_match_api_rule(self):
        self.ui.switch.ssh.exec_command = MagicMock(return_value=CmdStatus("", "", 0))
        match = [("ethernet.dst_mac", "02:02:11:03:03:04", "0xffffffffffff"), ]
        result = self.ui.create_match_api_rule(prio_id=1, handle_id=1, table_id=6,
                                               match_field_value_mask_list=match,
                                               action="normal", action_value=None)
        expected_result = None
        assert result == expected_result

    def test_get_table_match_api(self):
        sample_get_table = """

            tcam:1 src 1 apply 1 size 4096
              matches:
                  field: ig_port_metadata [ingress_port ingress_lport]
                  field: ethernet [dst_mac src_mac ethertype]
              actions:
                  13: drop_packet (  )
                  14: permit (  )
              attributes:

        """
        self.ui.switch.ssh.exec_command = MagicMock(return_value=CmdStatus(
            sample_get_table, '', 0))
        result = self.ui.get_table_match_api()
        expected_result = [{'table_src': 1,
                            'matches': ['ig_port_metadata [ingress_port ingress_lport]',
                                        'ethernet [dst_mac src_mac ethertype]'],
                            'actions': {13: 'drop_packet (  )', 14: 'permit (  )'},
                            'table_name': 'tcam', 'table_apply': 1,
                            'attributes': {}, 'table_id': 1, 'table_size': 4096}]
        assert result == expected_result

    def test_get_rules_match_api(self):
        sample_get_flow = (
            'table : 6 uid : 1 prio : 1 bytes : 0 packets : 0'
            'ethernet.dst_mac = 00:50:56:89:00:01 (ff:ff:ff:ff:ff:ff)\n\t   '
            '1: set_egress_port ( u32 egress_port7 )\n'
        )
        self.ui.switch.ssh.exec_command = MagicMock(return_value=CmdStatus(sample_get_flow, '', 0))
        result = self.ui.get_rules_match_api(table_id=6, handle_id=1)
        expected_result = [{'bytes_count': 0, 'handle_id': 1, 'table_id': 6,
                            'packets_count': 0, 'pri_id': 1,
                            'values': ('ethernet.dst_mac = 00:50:56:89:00:01 '
                                       '(ff:ff:ff:ff:ff:ff)\n\t   '
                                       '1: set_egress_port ( u32 egress_port7 )\n')}]
        assert result == expected_result
