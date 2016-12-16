#!/usr/bin/env python
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

@file  test_tool_generate.py

@summary  ToolGeneral Unittests
"""
from unittest.mock import Mock, MagicMock

import pytest
import itertools

from testlib import clissh
from testlib import dev_linux_host
from testlib.dev_linux_host import GenericLinuxHost
from testlib.cli_template import CmdStatus
from testlib.custom_exceptions import UICmdException
from testlib.linux import service_lib

from testlib.linux.tool_general import GenericTool, RC_SERVICE_INACTIVE


class CmdExecSimul(object):
    """
    @brief  Simulate clissh (blackbox).
            Specify commands behavior - an (sequence of) input command(s) to output(s)
            including side effect(s).
    """

    MAKE_ITER_MAP = [
        iter,
        itertools.cycle
    ]

    def __init__(self, cmd_exec_sim, cycle=False):
        super(CmdExecSimul, self).__init__()
        self.sim_cmd_iter = None

        if cmd_exec_sim:
            self.set_simul(cmd_exec_sim, cycle=cycle)

    def set_simul(self, cmd_exec_sim, cycle=False):
        make_iterable = self.MAKE_ITER_MAP[cycle]
        if isinstance(cmd_exec_sim, list):
            pass
        else:
            cmd_exec_sim = [cmd_exec_sim]
        self.sim_cmd_iter = make_iterable(cmd_exec_sim)

    def __call__(self, *args, **kwargs):
        """
        @breif  Any exception raised is considered an expected behavior (side_effect).
        The mocked signature: exec_command(command, timeout=None)
        """
        if args:
            command = args[0]
            mock_obj = self._find_match(command)
            if not mock_obj:
                raise self.InputCommandNoMatch(command)
            return mock_obj()
        else:
            raise self.InputCommandNoMatch(None)

    def _find_match(self, command):
        sim_cmd = None
        try:
            sim_cmd = next(self.sim_cmd_iter)
        except StopIteration:
            assert False

        if isinstance(sim_cmd, MagicMock):
            mock_obj = sim_cmd
        elif isinstance(sim_cmd, dict):
            mock_obj = sim_cmd.get(command)

        # TODO; implement other match representatinos

        if isinstance(mock_obj, Mock):
            return mock_obj
        if isinstance(mock_obj, dict):
            return MagicMock(**mock_obj)

        # TODO; implement other mock representatinos

    class InputCommandNoMatch(Exception):
        def __init__(self, command):
            super(CmdExecSimul.InputCommandNoMatch, self).__init__()


class FakeSSH(clissh.CLISSH):
    login_status = True

    def __init__(self, *args, **kwargs):
        pass

    def shell_read(self, *args, **kwargs):
        pass

    def exec_command(self, *args, **kwargs):
        pass


class MockSSH(FakeSSH):
    def __init__(self, *args, **kwargs):
        self.exec_command = MagicMock(wraps=self._exec_cmd_wrappee, **kwargs)

    _exec_cmd_wrappee = FakeSSH.exec_command


class SimulatedSSH(MockSSH, CmdExecSimul):
    def __init__(self, *args, **kwargs):
        MockSSH.__init__(self, *args, **kwargs)
        CmdExecSimul.__init__(self, None)

    _exec_cmd_wrappee = CmdExecSimul.__call__


class FakeLinuxHost(GenericLinuxHost):
    FAKE_CFG = {
        'name': 'FakeHost',
        'id': 'FakeID',
        'instance_type': 'generic_linux_host',
        'ipaddr': 'localhost',
        'ssh_user': 'fake_user',
        'ssh_pass': 'fake_pass'
    }

    def __init__(self, config=None, opts=None):
        if not config:
            config = self.FAKE_CFG
        if not opts:
            opts = self.FakeOpts()

        super(FakeLinuxHost, self).__init__(config, opts)

    class FakeOpts(object):
        setup = 'fake.setup.json'
        env = 'fake.env.json'
        gen_only = False
        lhost_ui = 'linux_bash'


@pytest.fixture
def patch_clissh_sim(monkeypatch):
    monkeypatch.setattr(dev_linux_host.clissh, 'CLISSH', SimulatedSSH)


@pytest.fixture
def lh(request, patch_clissh_sim):
    lh = FakeLinuxHost()
    request.addfinalizer(lh.destroy)
    return lh


SERVICE_NAME = 'generic_tool'


@pytest.fixture
def gen_tool(request, lh):
    gen_tool = GenericTool(lh.ui.cli_send_command, SERVICE_NAME)
    request.addfinalizer(gen_tool.cleanup)  # destroy?
    return gen_tool


@pytest.fixture
def systemctl(gen_tool):
    service_factory = service_lib.specific_service_manager_factory
    systemctl = service_factory(SERVICE_NAME, gen_tool.run_command)
    return systemctl


@pytest.fixture
def tool(gen_tool, systemctl):
    tool_iid = gen_tool.next_id()
    tool = {
        'instance_id': tool_iid,
        'service_name': SERVICE_NAME,
        'service_manager': systemctl
    }
    gen_tool.instances[tool_iid] = tool
    return tool


class TestToolGeneral(object):
    ARG_SYSTEMCTL_STOP = 'systemctl stop {0}.service'.format(SERVICE_NAME)
    RET_VAL_INACTIVE = {
        'return_value': CmdStatus('stdout', 'stderr', RC_SERVICE_INACTIVE)
    }

    def test_stop_raises_when_ignore_false(self, lh, gen_tool, tool):
        cmd_exec_simul = [
            {
                self.ARG_SYSTEMCTL_STOP: MagicMock(**self.RET_VAL_INACTIVE)
            }
        ]
        lh.ssh.set_simul(cmd_exec_simul)

        with pytest.raises(UICmdException):
            gen_tool.stop(tool['instance_id'], ignore_inactive=False)

    def test_stop_doesnt_raises_when_ignore_true(self, lh, gen_tool, tool):
        cmd_exec_simul = [
            {
                self.ARG_SYSTEMCTL_STOP: MagicMock(**self.RET_VAL_INACTIVE)
            }
        ]
        lh.ssh.set_simul(cmd_exec_simul)

        gen_tool.stop(tool['instance_id'], ignore_inactive=True)

    def test_stop_succeds_when_no_exception(self, gen_tool):
        instance_id = 1
        gen_tool.instances[instance_id] = {'service_manager': MagicMock()}
        gen_tool.stop(instance_id)
        gen_tool.stop(instance_id)

    def test_start_with_prefix(self, lh, gen_tool, tool):
        cmd_exec_simul = [
            MagicMock(return_value=CmdStatus("active", "", 0)),  # systemd-run
            MagicMock(return_value=CmdStatus("active", "", 0))   # systemctl is-active
        ]
        lh.ssh.set_simul(cmd_exec_simul)

        gen_tool.start(command='a b c', prefix='Foo ')
        args_list = lh.ssh.exec_command.call_args_list[0][0][0].split()
        assert args_list[-3:] == ['a', 'b', 'c']
        assert args_list[0] == 'Foo'
