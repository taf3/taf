"""
@copyright Copyright (c) 2015 - 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  pytest_multipletg.py

@summary  Work with several TGs like with one instance.

@note  If setup JSON file contains several TG devices thwy will be handled as one instance.

       Use @pytest.mark.multiple_tgs class level marker in order to disable this functionality
       for particular test suites.
"""

import copy
from itertools import chain

import pytest

from . import loggers
from testlib.helpers import grouper
from testlib import multiple_tg
from testlib import custom_exceptions


def pytest_configure(config):
    """
    @brief  Registering plugin.
    """
    config.pluginmanager.register(MultipleTGPlugin(), "_multiple_tg")


def pytest_unconfigure(config):
    """
    @brief  Unregistering plugin.
    """
    multiple_tg_plugin = getattr(config, "_multiple_tg", None)
    if multiple_tg_plugin == "True":
        del config._multiple_tg
        config.pluginmanager.unregister(multiple_tg_plugin)


class MultipleTGClass(object):

    class_logger = loggers.ClassLogger()

    def __init__(self, env):
        super(MultipleTGClass, self).__init__()
        self.env = env
        self.init_tg = env.tg
        self.init_cross = copy.deepcopy(self.env.setup["cross"])
        self.cross_connections = {_id: copy.deepcopy(env.cross[_id].connections)
                                  for _id in self.env.cross}
        self.init_dut_map = copy.deepcopy(self.env.dut_map)
        self.tg = None

    def create_multiple_tg(self):
        config = {
                  'instance_type': "_".join(set((x.type for x in self.env.tg.values()))),
                  'id': "".join((x.id for x in self.env.tg.values()))
                  }
        self.tg = multiple_tg.MultipleTG(self.env.tg, config, self.env.opts)
        self.env.tg = {1: self.tg}
        self.env.dut_map['tg1'] = self.tg.id
        self.env.id_map[self.tg.id] = self.tg

    def change_cross_section(self):
        for cross_part in chain.from_iterable(iter(self.env.setup["cross"].values())):
            for _id, _port_id in grouper(cross_part, 2):
                if _id in self.tg.tgs:
                    # Change cross part using new TG id and port id
                    tg_id = self.tg.id
                    try:
                        port_id = self.tg.get_port_id(_id, _port_id)
                    except ValueError as err:
                        self.class_logger.info("Port is not in TG ports: {}".format(err))
                        raise custom_exceptions.TAFCoreException("Check setup file")
                    cross_part[cross_part.index(_id)] = tg_id
                    cross_part[cross_part.index(tg_id) + 1] = port_id
                    break

    def setup(self):
        self.create_multiple_tg()
        self.change_cross_section()

    def teardown(self):
        # Rollback all changes in environment
        self.env.tg = self.init_tg
        self.env.setup["cross"] = self.init_cross
        for _id, connections in self.cross_connections.items():
            self.env.cross[_id].connections = connections
        self.env.dut_map = self.init_dut_map
        del self.env.id_map[self.tg.id]


class MultipleTGPlugin(object):

    @pytest.fixture(scope='class', autouse=True)
    def one_tg(self, request, env_init):
        multiple_marker = next((m for m in getattr(request.cls, 'pytestmark', [])
                                    if m.name == 'multiple_tgs'), None)
        if len(getattr(env_init, 'tg', {})) > 1 and not multiple_marker:
            tg = MultipleTGClass(env_init)
            tg.setup()
            request.addfinalizer(tg.teardown)
