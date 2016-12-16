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

@file test_switch_driver.py

@summary Unittests for Switch Driver
"""

from unittest.mock import MagicMock

import pytest

from testlib.clissh import CmdStatus
from testlib.ui_onpss_shell import switch_driver
from testlib.custom_exceptions import UIException


class TestSwitchDriver(object):

    def test_autodetect_fm10kd(self):
        ui_mock = MagicMock()
        switch_mock = MagicMock()
        sd = switch_driver.SwitchDriver(ui_mock, switch_mock)
        ui_mock.cli_send_command.return_value = CmdStatus("   fm10kd  ", "", 0)
        sd.autodetect()
        assert (sd.name, sd.kernel_module, sd.script) == sd.SWITCH_DRIVERS["fm10kd"]

    def test_autodetect_failure_raises_exception_when_no_path(self):
        ui_mock = MagicMock()
        switch_mock = MagicMock()
        sd = switch_driver.SwitchDriver(ui_mock, switch_mock)
        ui_mock.cli_send_command.return_value = CmdStatus("        ", "", 0)
        with pytest.raises(UIException) as excinfo:
            sd.autodetect()
        assert "Cannot detect switch driver" in excinfo.exconly()

    def test_autodetect_failure_raises_exception_when_name_not_found(self):
        ui_mock = MagicMock()
        switch_mock = MagicMock()
        sd = switch_driver.SwitchDriver(ui_mock, switch_mock)
        ui_mock.cli_send_command.return_value = CmdStatus("  nosuch      ", "", 0)
        with pytest.raises(UIException) as excinfo:
            sd.autodetect()
        assert "Cannot detect switch driver" in excinfo.exconly()
