#!/usr/bin/env python
"""
@copyright Copyright (c) 2015-2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  test_networkd.py

@summary  NetworkD Unittests
"""
from unittest.mock import MagicMock
from testlib.linux.networkd import NetworkD


class TestNetworkD(object):

    def test_single_mgmt_port(self):
        run_command = MagicMock()
        n = NetworkD(run_command, ["test"])
        n.clear_settings()
        assert run_command.call_args_list[0][0][
            0] == "find /etc/systemd/network/ -mindepth 1 -not \\( -name 'test.network' -or " \
                  "-name 'test.netdev' -or -name 'test.link' -or -name 'test.swport' \\) -delete"

    def test_multiple_mgmt_port(self):
        run_command = MagicMock()
        n = NetworkD(run_command, ["test1", "test2"])
        n.clear_settings()
        assert run_command.call_args_list[0][0][
            0] == "find /etc/systemd/network/ -mindepth 1 -not \\( -name 'test1.network' -or " \
                  "-name 'test1.netdev' -or -name 'test1.link' -or -name 'test1.swport' -or " \
                  "-name 'test2.network' -or -name 'test2.netdev' -or -name 'test2.link' -or " \
                  "-name 'test2.swport' \\) -delete"

    def test_empty_list(self):
        run_command = MagicMock()
        n = NetworkD(run_command, [])
        n.clear_settings()
        assert run_command.call_args_list[0][0][
            0] == "find /etc/systemd/network/ -mindepth 1 -not \\(  \\) -delete"

    def test_extra_excludes_are_appended(self):
        run_command = MagicMock()
        n = NetworkD(run_command, ["test1", "test2"])
        n.clear_settings(exclude_ports=["extra1", "extra2"])
        assert run_command.call_args_list[0][0][
            0] == "find /etc/systemd/network/ -mindepth 1 -not \\( -name 'test1.network' -or " \
                  "-name 'test1.netdev' -or -name 'test1.link' -or -name 'test1.swport' -or " \
                  "-name 'test2.network' -or -name 'test2.netdev' -or -name 'test2.link' -or " \
                  "-name 'test2.swport' -or -name 'extra1.network' -or -name 'extra1.netdev' -or " \
                  "-name 'extra1.link' -or -name 'extra1.swport' -or -name 'extra2.network' -or " \
                  "-name 'extra2.netdev' -or -name 'extra2.link' -or -name 'extra2.swport' \\) -delete"

    def test_just_extra_excludes(self):
        run_command = MagicMock()
        n = NetworkD(run_command, [])
        n.clear_settings(exclude_ports=["extra1", "extra2"])
        assert run_command.call_args_list[0][0][
            0] == "find /etc/systemd/network/ -mindepth 1 -not \\( -name 'extra1.network' -or " \
                  "-name 'extra1.netdev' -or -name 'extra1.link' -or -name 'extra1.swport' -or " \
                  "-name 'extra2.network' -or -name 'extra2.netdev' -or -name 'extra2.link' -or " \
                  "-name 'extra2.swport' \\) -delete"
