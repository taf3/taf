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

"""``pytest_start_from_case.py``

`Starting tests execution from the specified test case not from the beginning`

Examples::

    # complete test-name
    $ py.test PATH_TO_TESTS --start_from_case test_my_func

    # not complete test-name
    $ py.test PATH_TO_TESTS --start_from_case test*func

    # or
    $ py.test PATH_TO_TESTS --start_from_case *func

    # parameterized tests
    $ py.test PATH_TO_TESTS --start_from_case test*[1]

    # or
    $ py.test PATH_TO_TESTS --start_from_case test*1

"""

import re

import pytest


def pytest_addoption(parser):
    """Plugin specific options.

    """
    group = parser.getgroup("start_from_case", "plugin start from case")
    group.addoption("--start_from_case", action="store", default=None, dest="start_from_case",
                    help="Run suite from specific case. '%default' by default.")


def pytest_configure(config):
    """Registering plugin.

    """
    if config.option.start_from_case:
        config.pluginmanager.register(StartFromCase(config), "_start_from_case")


def pytest_unconfigure(config):
    """Unregistering plugin.

    """
    start_from_case = getattr(config, "_start_from_case", None)
    if start_from_case:
        del config._start_from_case
        config.pluginmanager.unregister(start_from_case)


class StartFromCase(object):
    """Execute test run starting from specified test item.

    """

    def __init__(self, config):
        self.config = config

    def pytest_collection_modifyitems(self, session, config, items):
        """Leave only necessary items in collected list.

        """
        start_case = session.config.option.start_from_case
        if start_case is not None:
            pattern = re.compile("^.*{0}.*$".format(start_case.replace("*", ".*").replace("[", '\[').replace(']', '\]')))
            for item in items:
                if pattern.search(item.name):
                    for rem_item in items[:items.index(item)]:
                        items.remove(rem_item)
                    break
            else:
                pytest.exit("'%s' not found in collection of test items!" % start_case)
