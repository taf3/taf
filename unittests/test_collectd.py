"""
@copyright Copyright (c) 2016-2017, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  test_collectd.py

@summary  Collectd library unittests
"""
import pytest

from testlib.linux import collectd
from unittest.mock import MagicMock
from testlib.custom_exceptions import CustomException


class TestCollectd(object):
    @pytest.fixture(autouse=True)
    def setup_tests(self):
        self.collectd_conf = "/test/collectd.conf"
        self.cli_send_mock = MagicMock()
        self.cli_set_mock = MagicMock()

    def test_collectd_start(self):
        self.collectd_instance = collectd.Collectd(self.cli_send_mock, self.collectd_conf)
        self.collectd_instance.start()
        assert self.cli_send_mock.call_args[0][0] == 'systemctl start collectd.service'

    def test_collectd_stop(self):
        self.collectd_instance = collectd.Collectd(self.cli_send_mock, self.collectd_conf)
        self.collectd_instance.stop()
        assert self.cli_send_mock.call_args[0][0] == 'systemctl stop collectd.service'

    def test_collectd_restart(self):
        self.collectd_instance = collectd.Collectd(self.cli_send_mock, self.collectd_conf)
        self.collectd_instance.restart()
        assert self.cli_send_mock.call_args[0][0] == 'systemctl restart collectd.service'

    def test_collect_no_plugins_config(self):
        self.collectd_instance = collectd.Collectd(self.cli_send_mock, self.collectd_conf)
        self.collectd_instance.plugins_config = {}
        with pytest.raises(CustomException, 'CustomException not raised in case of empty plugins config.'):
            self.collectd_instance.update_config_file()
