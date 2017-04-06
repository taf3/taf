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

"""``pytest_multiple_run.py``

`Re-run test case n times`

"""

import copy


def pytest_addoption(parser):
    """Plugin specific options.

    """
    group = parser.getgroup("multiplerun", "plugin multiple run")
    group.addoption("--multiple_run", type="int", default=1, dest="multiplerun",
                    metavar="int", help="multiplies run tests by N(times)")


def pytest_configure(config):
    """Registering plugin.

    """
    if config.option.multiplerun:
        config.pluginmanager.register(MultipleRun(config), "_multiple_run")


def pytest_unconfigure(config):
    """Unregistering plugin.

    """
    multiple_run = getattr(config, "_multiple_run", None)
    if multiple_run:
        del config._multiple_run
        config.pluginmanager.unregister(multiple_run)


class MultipleRun(object):

    def __init__(self, config):
        self.config = config
        self.repeat = self.config.option.multiplerun
        self.fixtures = ['suitelogger', 'autolog', 'heatcheck', 'caselogger', 'pidcheck',
                         'env', 'request', 'env_main', 'env_init', 'repeat_fixture', 'one_tg',
                         'monitor_init', 'monitor', 'test_monitor',
                         'workload_init', 'workload', 'test_workload']

    def pytest_generate_tests(self, metafunc):
        if self.repeat > 1:
            metafunc.fixturenames.append('repeat_fixture')
            metafunc.parametrize('repeat_fixture', list(range(self.repeat)))

    def pytest_runtest_call(self, item):
        if self.repeat > 1:
            # Insert copy of funcargs to avoid changing of the original params inside the test
            for funcargname in item.funcargnames:
                if funcargname not in self.fixtures:
                    item.funcargs[funcargname] = copy.deepcopy(item.funcargs[funcargname])

    def pytest_collection_modifyitems(self, items):

        if self.repeat > 1:
            # Sort items
            index = 0
            while index < len(items):
                item = items[index]
                if 'parametrize' in list(item.keywords.keys()):
                    module = item.module
                    _name, _params = item.name.split("[")
                    if "-" in _params:
                        _params = "-".join(_params.split("-")[1:])
                    counter = index + 1
                    while counter < len(items) and module == items[counter].module:
                        if _name in items[counter].name and _params in items[counter].name:
                            items.insert(index + 1, items.pop(counter))
                            index += 1
                        counter += 1
                index += 1

            # Change names - remove multirun parameter
            for item in items:
                name = item.name
                if "[" in name:
                    name, params = name.split("[")
                    if "-" in params:
                        params = "-".join(params.split("-")[1:])
                        item.name = "[".join([name, params])
                    else:
                        item.name = "%s[%s]" % (name, name)
