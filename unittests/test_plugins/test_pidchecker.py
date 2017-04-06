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

"""``test_pidchecker.py``

`Unittests for pytest_pidchecker.py`

"""

from testlib.common3 import Environment
from plugins.pytest_pidchecker import PidChecker

# golden setup with TG
SETUP = {"env": [{"id": 0, "ports": [[1, 1, 1]]},
                 {"id": 412},
                 {"id": "31"}],
         "cross": {"31": [[0, 1, 412, 1]]}}

# config of environment
ENV = [{"name": "IXIA-103", "entry_type": "tg", "instance_type": "ixiahl", "id": 0, "ip_host": "121.224.187.103"},
       {"name": "Zero Cross", "entry_type": "cross", "instance_type": "zero", "id": "31"},
       {"name": "seacliff12", "entry_type": "switch", "instance_type": "seacliff", "id": 412,
        "ip_host": "127.0.0.1", "ip_port": "8081",
        "use_sshtun": 1, "sshtun_user": "unittester", "sshtun_pass": "unittester", "sshtun_port": 22,
        "default_gw": "121.224.187.1", "net_mask": "255.255.255.0",
        "ports_count": "52", "pwboard_host": "121.224.187.94", "pwboard_port": "12", "halt": 0,
        "portserv_host": "121.224.187.93", "portserv_user": "root", "portserv_pass": "dbps", "portserv_tty": 12, "portserv_port": 2012,
        "telnet_loginprompt": "seacliff12 login:", "telnet_passprompt": "Password:",
        "telnet_user": "admin", "telnet_pass": "admin", "telnet_prompt": "[admin@seacliff12 ~]$",
        "cli_user": "admin", "cli_user_passw": "admin", "cli_user_prompt": "Switch",
        "ports": [24, 25, 26],
        "related_id": ["31", "156"]},
       {"name": "loghost", "entry_type": "linux_host", "instance_type": "generic", "id": "156",
        "ip_host": "127.0.0.1", "sshtun_port": 22, "sshtun_user": "unittester", "sshtun_pass": "unittester"}]


class Config(object):
    def __init__(self, pidchecker):
        # self.pytest_runtest_call_status = True
        self.option = Option(pidchecker)

    def __call__(self, x):
        """
        """
        return ENV


class Option(object):
    def __init__(self, pidchecker):
        self.pidchecker = pidchecker


class Setup(object):
    def __call__(self, x):
        """
        """
        return SETUP


class FakeOpts(object):
    def __init__(self):
        """
        """
        self.setup = "setup.json"
        self.env = ""
        self.get_only = False
        self.build_path = ''
        self.ui = 'ons_xmlrpc'
        self.lhost_ui = 'linux_bash'


class GetProc(object):
    def __call__(self, x, skip_prcheck=None):
        """
        """
        return {x: 1}


class FakeItem(object):
    def __init__(self, monkeypatch, pidchecker):
        self.keywords = []
        self.runtest_protocol_status = {"skipped": False, "skipped_on_call": False, "call_status": True}
        self.name = "some_name"
        self.actual_pidchecker = False
        self.config = Config(pidchecker)
        self.get_marker = GetMarker()
        monkeypatch.setattr(Environment, "_get_conf", Config(pidchecker))
        monkeypatch.setattr(Environment, "_get_setup", Setup())
        self.config.env = Environment(FakeOpts())
        for switch in list(self.config.env.switch.values()):  # pylint: disable=no-member
            switch.status = True
            monkeypatch.setattr(switch, "get_processes", GetProc())


class GetMarker(object):
    def __call__(self, x):
        """
        """
        return None


# Test cases:
def test_pidchecker_setup_true(monkeypatch):
    """
    """
    item = FakeItem(monkeypatch, True)
    pidchecker = PidChecker(item.config.env, True, item)
    pidchecker.setup()
    assert list(pidchecker.processes.values()) == [{'some_name': 1}]


def test_pidchecker_setup_false(monkeypatch):
    """
    """
    item = FakeItem(monkeypatch, False)
    pidchecker = PidChecker(item.config.env, False, item)
    pidchecker.setup()
    assert list(pidchecker.processes.values()) == []


def test_pidchecker_teardown_true(monkeypatch):
    """
    """
    item = FakeItem(monkeypatch, True)
    pidchecker = PidChecker(item.config.env, True, item)
    pidchecker.setup()
    pidchecker.teardown()


def test_pidchecker_teardown_false(monkeypatch):
    """
    """
    item = FakeItem(monkeypatch, False)
    pidchecker = PidChecker(item.config.env, False, item)
    pidchecker.setup()
    pidchecker.teardown()
