# coding=utf-8

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

"""``test_ui_helpers.py``

`Unittests for ui_helpers.py`

"""
from unittest.mock import MagicMock

import pytest

from .test_ui_onpss_shell import ports_side_effect, multicall_ports_side_effect
from testlib import ui_onpss_shell


@pytest.fixture
def ui_onpss():
    return ui_onpss_shell.UiOnpssShell(MagicMock(**{"hw": type("SiliconFM10K", (object,), {})()}))


class TestLagHelpers(object):

    @pytest.fixture(autouse=True)
    def create_ui(self, ui_onpss):
        self.ui_onpss = ui_onpss
        ui_onpss.switch.ssh.exec_command = MagicMock(side_effect=ports_side_effect)
        ui_onpss.cli_multicall = MagicMock(side_effect=multicall_ports_side_effect)

    def test_is_lag_added(self):

        assert self.ui_onpss.is_lag_added(lag_id=1234)
        assert self.ui_onpss.is_lag_added(lag_id='team1')
        assert not self.ui_onpss.is_lag_added(lag_id='1234')

    def test_is_port_added_to_lag(self):

        assert self.ui_onpss.is_port_added_to_lag(port=5, lag_id='team1')
        assert self.ui_onpss.is_port_added_to_lag(port=8, lag_id=1234)
        assert not self.ui_onpss.is_port_added_to_lag(port=5, lag_id='team2')
        assert not self.ui_onpss.is_port_added_to_lag(port=8, lag_id='1234')
