"""
@copyright Copyright (c) 2013 - 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file test_service_lib.py

@summary SystemD service library unittests
"""

import unittest

from testlib.linux import service_lib
from unittest.mock import (patch, MagicMock)

__author__ = 'rbbratta'


class TestSystemd(unittest.TestCase):

    def setUp(self):
        self.service_name = "fake_service"
        init_name = "systemd"
        command_generator = service_lib._command_generators[init_name]
        self.service_command_generator = service_lib.ServiceCommandGenerator(
            command_generator)

    def test_all_commands(self):
        for cmd in (c for c in self.service_command_generator.commands if c != "list"):
            ret = getattr(
                self.service_command_generator, cmd)(self.service_name)
            if cmd == "is_enabled":
                cmd = "is-enabled"
            elif cmd == "is_active":
                cmd = "is-active"
            assert ret == ["systemctl", cmd, "%s.service" % self.service_name]


class TestSpecificServiceManager(unittest.TestCase):

    def setUp(self):
        self.run_mock = MagicMock()
        self.init_name = "systemd"
        command_generator = service_lib.systemd_command_generator
        command_list = [c for c in service_lib.COMMANDS if c != "list"]
        service_command_generator = service_lib.ServiceCommandGenerator(
            command_generator, command_list)
        self.service_manager = service_lib.SpecificServiceManager("lldpad",
                                                                  service_command_generator,
                                                                  self.run_mock)

    def test_start(self):
        service = "lldpad"
        # should really use --generated-members, but start() is too generic
        self.service_manager.start()  # pylint: disable=no-member
        assert self.run_mock.call_args[0][
            0] == "systemctl start %s.service" % service

    def test_stop_with_args(self):
        service = "lldpad"
        self.service_manager.stop(ignore_status=True)  # pylint: disable=no-member
        assert self.run_mock.call_args[0][
                   0] == "systemctl stop %s.service" % service
        assert self.run_mock.call_args[1] == {'ignore_status': True}

    def test_list_is_not_present_in_SpecifcServiceManager(self):
        assert not hasattr(self.service_manager, "list")


class TestSystemdServiceManager(unittest.TestCase):

    def setUp(self):
        self.run_mock = MagicMock()
        self.init_name = "systemd"
        command_generator = service_lib.systemd_command_generator
        service_manager = service_lib.SystemdServiceManager
        service_command_generator = service_lib.ServiceCommandGenerator(
            command_generator)
        self.service_manager = service_manager(
            service_command_generator, self.run_mock)

    def test_start(self):
        service = "lldpad"
        self.service_manager.start(service)  # pylint: disable=no-member
        assert self.run_mock.call_args[0][
            0] == "systemctl start %s.service" % service

    def test_list(self):
        self.service_manager.list()  # pylint: disable=no-member
        assert self.run_mock.call_args[0][
            0] == "systemctl list-unit-files --type=service"

    def test_set_default_runlevel(self):
        runlevel = "multi-user.target"
        mktemp_mock = MagicMock(return_value="temp_filename")
        symlink_mock = MagicMock()
        rename_mock = MagicMock()

        @patch.object(service_lib, "mktemp", mktemp_mock)
        @patch("os.symlink", symlink_mock)
        @patch("os.rename", rename_mock)
        def _():
            self.service_manager.change_default_runlevel(runlevel)
            assert mktemp_mock.called
            assert symlink_mock.call_args[0][0] == "/usr/lib/systemd/system/multi-user.target"
            assert rename_mock.call_args[0][1] == "/etc/systemd/system/default.target"
        _()


_examples = """


    try:
        service.start("lldpad")
        pgrep("lldpad")
    except CmdError, c:
        c.err == "something"

    try:
        service.stop("fcoe", "force", ignoreStatus=True)
        if not pgrep("fcoemon"):
            pass
    except:
        pass


    try:
        service.stop("fcoe", "-HUP", ignoreStatus=True)
    except:
        pass


    try:
        service.start("boot.lldpad")
    except:
        pass

    try:

    try:
        service.start("ntp")
    except:
        pass



"""
