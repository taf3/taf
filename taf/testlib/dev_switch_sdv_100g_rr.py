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


"""``dev_switch_sdv_100g_rr.py``

`SDV 100G RR  switch-specific functionality`

"""
from collections import OrderedDict
from collections import namedtuple

from .switch_general import SwitchReal
from .si_fm10k import SiliconFM10K


class SwitchRR(SwitchReal):
    """SDV 100G RR device.

    """
    # has to happen here so it occurs before we create the Ui
    # in super().__init__()
    hw = SiliconFM10K()

    # Platform specific HW values
    class Attributes(namedtuple("Attributes", (
        'default', 'cpu_default', 'min', 'max', 'step', 'cpu_port', 'is_perlag'),
    )):
        # See si_fm10k for more information on attributes
        pass

    hw.master_ports = [1, 5]
    hw.pcie_ports = [20, 22]

    hw.bcast_rate = Attributes(
        715749744, 715749744, 30619, 715827712,
        OrderedDict([(89522176, 30619), (179044352, 61238),
                     (358088704, 122476), (715827712, 244952)]),
        'read_write', False)

    hw.mcast_rate = Attributes(
        715749744, 715749744, 30619, 715827712,
        OrderedDict([(89522176, 30619), (179044352, 61238),
                     (358088704, 61238), (715827712, 122476)]),
        'read_write', False)

    hw.cpu_mac_addr_rate = Attributes(
        715749744, 715749744, 30619, 715827712,
        OrderedDict([(89522176, 30619), (179044352, 122476),
                     (358088704, 122476), (715827712, 244952)]),
        'read_write', False)

    hw.reserved_mac_rate = Attributes(
        715749744, 715749744, 30619, 715827712,
        OrderedDict([(89522176, 30619), (179044352, 61238),
                     (358088704, 122476), (715827712, 244952)]),
        'read_write', False)

    hw.igmp_rate = Attributes(
        715749744, 715749744, 30619, 715827712,
        OrderedDict([(89522176, 30619), (179044352, 61238),
                     (358088704, 122476), (715827712, 244952)]),
        'read_write', False)

    hw.icmp_rate = Attributes(
        715749744, 715749744, 30619, 715827712,
        OrderedDict([(89522176, 30619), (179044352, 61238),
                     (358088704, 122476), (715827712, 122476)]),
        'read_write', False)

    hw.mtu_viol_rate = Attributes(
        715749744, 715749744, 30619, 715827712,
        OrderedDict([(89522176, 30619), (179044352, 61238),
                     (358088704, 122476), (715827712, 244952)]),
        'read_write', False)

    def __init__(self, config, opts):
        """Initialize SwitchRR class.

        """
        # has to occur before because it is used in the Ui which is created
        # in SwitchGeneral.__init__
        self.mgmt_iface = "p1p1"
        super(SwitchRR, self).__init__(config, opts)
        self.jira_platform_name = "SDV100GRR"


ENTRY_TYPE = "switch"
INSTANCES = {"rr": SwitchRR}
NAME = "switch"
LINK_NAME = "sw"
