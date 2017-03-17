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

"""``pytest_random_collection.py``

`Choose one test case from test suite randomly if random marker is set`

"""

import random
from collections import defaultdict

import pytest


def pytest_addoption(parser):
    """Describe plugin specified options.

    """
    group = parser.getgroup("random", "plugin random test case choice")
    group.addoption("--random", action="store", default="Module",
                    choices=["Disabled"] + list(RANDOM_MAP.keys()),
                    help="Enable/Disable random test case choice from test suite based on Class or Module. '%default' by default.")
    group.addoption("--random-seed", action="store", default=None,
                    help="Set default random seed for reproducability. '%default' by default.")


def pytest_configure(config):
    """Registering plugin.

    """
    if config.option.random in RANDOM_MAP:
        random_chooser = RandomChoice(config.option.random_seed)
        config.pluginmanager.register(random_chooser, "_random")


def pytest_unconfigure(config):
    """Unregistering plugin.

    """
    random_class = getattr(config, "_random", None)
    if random_class in RANDOM_MAP:
        del config._random
        config.pluginmanager.unregister(random_class)


RANDOM_MAP = {
    "Class": "cls",
    "Module": "module",
}


class RandomChoice(object):
    """Choose one test case from test suite randomly if random marker is set.

    """

    def __init__(self, seed):
        super(RandomChoice, self).__init__()
        # Define seed value for reproducibility
        self.seed = seed

    @pytest.mark.trylast
    def pytest_collection_modifyitems(self, session, config, items):
        group_by_attribute = RANDOM_MAP.get(config.option.random)
        if group_by_attribute:
            item_dict = defaultdict(list)
            random_items = (x for x in items if x.get_marker('random'))
            for x in random_items:
                item_dict[getattr(x, group_by_attribute)].append(x)
            for _value in item_dict.values():
                # set random seed for reproducibility
                random.seed(self.seed)
                del _value[random.randrange(len(_value))]
                for v in _value:
                    items.remove(v)
            random.seed()
