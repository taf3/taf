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
from testlib import linux_host_bash
from testlib.custom_exceptions import UICmdException, UIException, AccessError, BoundaryError


class OnpssRawOutput(object):

    # Do not remove the whitespace at the end of the line, it is in the original output

    RAW_IPLINK_DETAIL_OUTPUT_OLD = (
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

    RAW_IPLINK_DETAIL_OUTPUT = (
        '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default \    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0\n'
        '2: virtual: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\    link/ether 52:54:00:e6:fa:6f brd ff:ff:ff:ff:ff:ff promiscuity 0\n'
        '3: public: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel master ovs-system state UP mode DEFAULT group default qlen 1000\    link/ether 52:54:00:42:60:3b brd ff:ff:ff:ff:ff:ff promiscuity 1 \    openvswitch_slave\n'
        '4: mgmt: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\    link/ether 52:54:00:12:56:6a brd ff:ff:ff:ff:ff:ff promiscuity 0\n'
        '5: inter: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\    link/ether 52:54:00:cb:52:a3 brd ff:ff:ff:ff:ff:ff promiscuity 0\n'
        '6: virbr0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default \    link/ether 52:54:00:7a:59:81 brd ff:ff:ff:ff:ff:ff promiscuity 0 \    bridge\n'
        '7: virbr0-nic: <BROADCAST,MULTICAST> mtu 1500 qdisc fq_codel master virbr0 state DOWN mode DEFAULT group default qlen 500\    link/ether 52:54:00:7a:59:81 brd ff:ff:ff:ff:ff:ff promiscuity 1 \    tun \    bridge_slave\n'
        '8: ovs-system: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default \    link/ether a2:d0:01:41:43:7e brd ff:ff:ff:ff:ff:ff promiscuity 1 \    openvswitch\n'
        '9: br-ex: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default \    link/ether e2:c9:ec:dc:97:46 brd ff:ff:ff:ff:ff:ff promiscuity 1 \    openvswitch\n'
        '10: qg-37eee8e0-67: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default \    link/ether 9a:c3:8b:48:da:ca brd ff:ff:ff:ff:ff:ff promiscuity 1 \    openvswitch\n'
        '11: br-int: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default \    link/ether ba:78:34:19:4a:47 brd ff:ff:ff:ff:ff:ff promiscuity 1 \    openvswitch\n'
        '12: qr-96ef1966-8d: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default \    link/ether 1a:ed:21:17:bf:a1 brd ff:ff:ff:ff:ff:ff promiscuity 1 \    openvswitch\n'
        '13: qr-35aafe49-25: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default \    link/ether 52:cc:5c:d4:4f:29 brd ff:ff:ff:ff:ff:ff promiscuity 1 \    openvswitch\n'
        '15: br-virtual: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default \    link/ether 66:5c:b0:16:63:46 brd ff:ff:ff:ff:ff:ff promiscuity 1 \    openvswitch\n'

    )

    RAW_ETHTHOOL_NO_LINK_OUTPUT = """\
Settings for sw0p5:
\tSupported ports: [ FIBRE ]
\tSupported link modes:   Not reported
\tSupported pause frame use: No
\tSupports auto-negotiation: No
\tAdvertised link modes:  Not reported
\tAdvertised pause frame use: No
\tAdvertised auto-negotiation: No
\tSpeed: 40000Mb/s
\tDuplex: Full
\tPort: FIBRE
\tPHYAD: 0
\tTransceiver: internal
\tAuto-negotiation: off
\tLink detected: no
"""

    RAW_READLINK_OUTPUT = """\
../../devices/pci0000:00/0000:00:15.0/0000:03:00.0/net/eth0
"""


@pytest.fixture
def ui():
    return linux_host_bash.LinuxHostBash(MagicMock())


def make_ports_side_effect(iplink_out, ethtool_out, pci_out):
    def ports_side_effect(*args, **kwargs):
        if 'mtu' in args[0]:
            return CmdStatus("1536", "", 0)
        if 'ethtool' in args[0]:
            return CmdStatus(ethtool_out, "", 0)
        if 'readlink' in args[0]:
            return CmdStatus(pci_out, "", 0)
        else:
            return CmdStatus(iplink_out, "", 0)
    return ports_side_effect


def make_multicall_ports_side_effect(iplink_out, ethtool_out, pci_out):
    def multicall_ports_side_effect(*args, **kwargs):
        if 'mtu' in args[0][0]:
            return [[cmd, CmdStatus("1536", "", 0)] for cmd in args[0]]
        if 'ethtool' in args[0][0]:
            return [[cmd, CmdStatus(ethtool_out, "", 0)] for cmd in args[0]]
        if 'readlink' in args[0][0]:
            return [[cmd, CmdStatus(pci_out, "", 0)] for cmd in args[0]]
        else:
            return [args[0], CmdStatus(iplink_out, "", 0)]
    return multicall_ports_side_effect


def test_get_table_ports(ui):
    ui.host.ssh.exec_command = MagicMock(
        side_effect=make_ports_side_effect(OnpssRawOutput.RAW_IPLINK_DETAIL_OUTPUT,
                                           OnpssRawOutput.RAW_ETHTHOOL_NO_LINK_OUTPUT,
                                           OnpssRawOutput.RAW_READLINK_OUTPUT))
    ui.cli_multicall = MagicMock(
            side_effect=make_multicall_ports_side_effect(OnpssRawOutput.RAW_IPLINK_DETAIL_OUTPUT,
                                                         OnpssRawOutput.RAW_ETHTHOOL_NO_LINK_OUTPUT,
                                                         OnpssRawOutput.RAW_READLINK_OUTPUT))
    table = ui.get_table_ports()
    assert table == [
        {'adminMode': 'Unknown',
         'duplex': 'full',
         'macAddress': 'Unknown',
         'master': None,
         'maxFrameSize': 1536,
         'mtu': 65536,
         'name': 'lo',
         'operationalStatus': 'Down',
         'pci': '03:00.0',
         'portId': 'lo',
         'speed': 40000,
         'type': 'Physical'},
        {'adminMode': 'Up',
         'duplex': 'full',
         'macAddress': '52:54:00:e6:fa:6f',
         'master': None,
         'maxFrameSize': 1536,
         'mtu': 1500,
         'name': 'virtual',
         'operationalStatus': 'Down',
         'pci': '03:00.0',
         'portId': 'virtual',
         'speed': 40000,
         'type': 'Physical'},
        {'adminMode': 'Up',
         'duplex': 'full',
         'macAddress': '52:54:00:42:60:3b',
         'master': 'ovs',
         'maxFrameSize': 1536,
         'mtu': 1500,
         'name': 'public',
         'operationalStatus': 'Down',
         'pci': '03:00.0',
         'portId': 'public',
         'speed': 40000,
         'type': 'LAGMember'},
        {'adminMode': 'Up',
         'duplex': 'full',
         'macAddress': '52:54:00:12:56:6a',
         'master': None,
         'maxFrameSize': 1536,
         'mtu': 1500,
         'name': 'mgmt',
         'operationalStatus': 'Down',
         'pci': '03:00.0',
         'portId': 'mgmt',
         'speed': 40000,
         'type': 'Physical'},
        {'adminMode': 'Up',
         'duplex': 'full',
         'macAddress': '52:54:00:cb:52:a3',
         'master': None,
         'maxFrameSize': 1536,
         'mtu': 1500,
         'name': 'inter',
         'operationalStatus': 'Down',
         'pci': '03:00.0',
         'portId': 'inter',
         'speed': 40000,
         'type': 'Physical'},
        {'adminMode': 'Down',
         'duplex': 'full',
         'macAddress': '52:54:00:7a:59:81',
         'master': None,
         'maxFrameSize': 1536,
         'mtu': 1500,
         'name': 'virbr0',
         'operationalStatus': 'Down',
         'pci': '03:00.0',
         'portId': 'virbr0',
         'speed': 40000,
         'type': 'Physical'}
    ]

def test_get_table_ports_no_ethtool(ui):
    ui.host.ssh.exec_command = MagicMock(
            side_effect=make_ports_side_effect(OnpssRawOutput.RAW_IPLINK_DETAIL_OUTPUT,
                                               "",
                                               OnpssRawOutput.RAW_READLINK_OUTPUT))
    ui.cli_multicall = MagicMock(
            side_effect=make_multicall_ports_side_effect(OnpssRawOutput.RAW_IPLINK_DETAIL_OUTPUT,
                                                         "",
                                                         OnpssRawOutput.RAW_READLINK_OUTPUT))
    table = ui.get_table_ports()
    assert table == [
        {'adminMode': 'Unknown',
         'duplex': 'unknown',
         'macAddress': 'Unknown',
         'master': None,
         'maxFrameSize': 1536,
         'mtu': 65536,
         'name': 'lo',
         'operationalStatus': 'Down',
         'pci': '03:00.0',
         'portId': 'lo',
         'speed': 0,
         'type': 'Physical'},
        {'adminMode': 'Up',
         'duplex': 'unknown',
         'macAddress': '52:54:00:e6:fa:6f',
         'master': None,
         'maxFrameSize': 1536,
         'mtu': 1500,
         'name': 'virtual',
         'operationalStatus': 'Down',
         'pci': '03:00.0',
         'portId': 'virtual',
         'speed': 0,
         'type': 'Physical'},
        {'adminMode': 'Up',
         'duplex': 'unknown',
         'macAddress': '52:54:00:42:60:3b',
         'master': 'ovs',
         'maxFrameSize': 1536,
         'mtu': 1500,
         'name': 'public',
         'operationalStatus': 'Down',
         'pci': '03:00.0',
         'portId': 'public',
         'speed': 0,
         'type': 'LAGMember'},
        {'adminMode': 'Up',
         'duplex': 'unknown',
         'macAddress': '52:54:00:12:56:6a',
         'master': None,
         'maxFrameSize': 1536,
         'mtu': 1500,
         'name': 'mgmt',
         'operationalStatus': 'Down',
         'pci': '03:00.0',
         'portId': 'mgmt',
         'speed': 0,
         'type': 'Physical'},
        {'adminMode': 'Up',
         'duplex': 'unknown',
         'macAddress': '52:54:00:cb:52:a3',
         'master': None,
         'maxFrameSize': 1536,
         'mtu': 1500,
         'name': 'inter',
         'operationalStatus': 'Down',
         'pci': '03:00.0',
         'portId': 'inter',
         'speed': 0,
         'type': 'Physical'},
        {'adminMode': 'Down',
         'duplex': 'unknown',
         'macAddress': '52:54:00:7a:59:81',
         'master': None,
         'maxFrameSize': 1536,
         'mtu': 1500,
         'name': 'virbr0',
         'operationalStatus': 'Down',
         'pci': '03:00.0',
         'portId': 'virbr0',
         'speed': 0,
         'type': 'Physical'}
    ]
