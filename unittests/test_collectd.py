"""
@copyright Copyright (c) 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file test_collectd.py

@summary Collectd library unittests
"""
import copy

import pytest

from testlib.linux import collectd
from unittest.mock import (patch, MagicMock)


class TestCollectd():
    @pytest.fixture(autouse=True)
    def setup_tests(self, request):
        self.fake_action = "fake_action"
        self.fake_plugin = "fake_plugin"
        self.collectd_conf = "/test/collectd.conf"
        self.cli_send_mock = MagicMock()
        self.cli_set_mock = MagicMock()

    def test_new_action(self, monkeypatch):
        fake_actions = copy.deepcopy(collectd.ACTIONS)
        fake_actions.update({self.fake_action: {}})
        monkeypatch.setattr(collectd, "ACTIONS", fake_actions)
        self.collectd_instance = collectd.Collectd(self.cli_send_mock, self.cli_set_mock, self.collectd_conf)
        fake_action_attr = getattr(self.collectd_instance, self.fake_action, None)
        assert fake_action_attr
        assert all([getattr(fake_action_attr, plugin, None) for plugin in collectd.PLUGINS])

    def test_new_plugin(self, monkeypatch):
        fake_plugins = copy.deepcopy(collectd.PLUGINS)
        monkeypatch.setattr(collectd, "PLUGINS", tuple(list(fake_plugins) + [self.fake_plugin]))
        collectd.PLUGINS = tuple(list(collectd.PLUGINS) + [self.fake_plugin])
        self.collectd_instance = collectd.Collectd(self.cli_send_mock, self.cli_set_mock, self.collectd_conf)
        action_attr = [getattr(self.collectd_instance, action, None) for action in collectd.ACTIONS]
        assert all(action_attr)
        for action in action_attr:
            assert getattr(action, self.fake_plugin, None)

    def test_collectd_start(self):
        self.collectd_instance = collectd.Collectd(self.cli_send_mock, self.cli_set_mock, self.collectd_conf)
        self.collectd_instance.start()
        assert self.cli_send_mock.call_args[0][0] == 'systemctl start collectd.service'

    def test_collectd_stop(self):
        self.collectd_instance = collectd.Collectd(self.cli_send_mock, self.cli_set_mock, self.collectd_conf)
        self.collectd_instance.stop()
        assert self.cli_send_mock.call_args[0][0] == 'systemctl stop collectd.service'

    def test_collectd_restart(self):
        self.collectd_instance = collectd.Collectd(self.cli_send_mock, self.cli_set_mock, self.collectd_conf)
        self.collectd_instance.restart()
        assert self.cli_send_mock.call_args[0][0] == 'systemctl restart collectd.service'


class TestCollectdConfCommandGenerator():
    @pytest.fixture(autouse=True)
    def setup_test(self):
        self.cli_set_mock = MagicMock()
        self.command_generator = collectd.command_generator
        self.collectd_conf = '/test.conf/'

    def test_run_disable_plugins(self):
        action = 'disable'
        collectd_conf_command_generator = collectd.CollectdConfCommandGenerator(action, self.command_generator,
                                                                                self.collectd_conf)
        self.collectd_conf_manager = collectd.CollectdPluginsManager(action, collectd_conf_command_generator,
                                                                     self.cli_set_mock)
        for plugin in collectd.PLUGINS:
            getattr(self.collectd_conf_manager, plugin, None)()
            expected = []
            for cmd in collectd.ACTIONS[action]['cmd']:
                expected.append([cmd.format(plugin=plugin, collectd_conf=self.collectd_conf)])

            assert self.cli_set_mock.call_args[0][0] == expected
