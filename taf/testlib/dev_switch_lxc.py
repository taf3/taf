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


"""``dev_switch_lxc.py``

`LXC switch-specific functionality`

"""

from .switch_ons import SwitchSimulated


class SwitchLXC(SwitchSimulated):
    """Switch in LXC containers class.

    """
    # Default value for switchpp application.
    # Could be replaced with FulcrumApp in case altamodel is detected at start().
    SWITCH_APPS = set(["SimSwitchApp", ])


ENTRY_TYPE = "switch"
INSTANCES = {"lxc": SwitchLXC}
NAME = "switch"
LINK_NAME = "sw"
