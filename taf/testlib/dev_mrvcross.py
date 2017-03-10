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

"""``dev_mrvcross.py``

`MRV cross specific functionality`

"""

from . import dev_staticcross_ons


class StaticCrossMRV(dev_staticcross_ons.StaticCrossONS):
    """Cross connection device based on MRV layer 1 switch.

    """

    pass

ENTRY_TYPE = "mrv"
INSTANCES = {"occ": StaticCrossMRV, "mcc": StaticCrossMRV}
NAME = "cross"
