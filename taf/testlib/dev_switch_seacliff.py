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

"""``dev_switch_seacliff.py``

`Seacliff-specific functionality`

"""

from collections import namedtuple

from .switch_ons import SwitchONS
from .si_fm6k import SiliconFM6K


class SwitchSeacliff(SwitchONS):
    """Seacliff devices class.

    """
    # has to happen here so it occurs before we create the Ui
    # in super().__init__()
    hw = SiliconFM6K()

    def __init__(self, config, opts):
        """Initialize SwitchSeacliff class.

        """
        super(SwitchSeacliff, self).__init__(config, opts)

        self.hw.master_ports = [49, 53, 57, 61]
        self.hw.snmp_path = "seacliff"
        self.jira_platform_name = "SeaCliff"

    # QOS Attributes
    class IndexedAttributes(namedtuple("IndexedAttributes", (
        'index_min', 'index_max', 'default_value_list',
        'value_min', 'value_max', 'step', 'cpu_port'),
    )):
        """These attributes have a value associated per index.

        Args:
            index_min:  The minimum value of the index.
            index_max:  The maximum value of the index.
            default_value_list: List of values for the index
            value_min:  The minimum value.
            value_max:  The maximum value.
            step:  The minimum value attribute increments by (rounded up). None denotes unknown.
            cpu_port:  Attribute is only set on cpu port (and not readable on switch port).

        """
        pass

    # Storm Control Attributes (step is rounded down; 0 means disabled)
    hw.sched_group_weight = IndexedAttributes(0, 7, (0,) * 8, 0, 65535, 1, 'read_write')


ENTRY_TYPE = "switch"
INSTANCES = {"seacliff": SwitchSeacliff}
NAME = "switch"
LINK_NAME = "sw"
