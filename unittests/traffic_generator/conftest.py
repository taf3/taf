"""
@copyright Copyright (c) 2011 - 2017, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file conftest.py

@summary Configuration for traffic generator unittests.
"""

import pytest

from testlib import dev_ixia
from testlib import dev_pypacker
from testlib import dev_rpypacker

IXIA_CONFIGURATION_SCRIPT = """\
ixClearPortStats {chassis} {card} {port}
port get {chassis} {card} {port}
port config -rxTxMode gigLoopback
port config -loopback portLoopback
port set {chassis} {card} {port}
port write {chassis} {card} {port}
"""

# Environment configs
IXIA_CONFIG = {"name": "IXIA", "entry_type": "tg", "instance_type": "ixiahl", "id": 1, "ip_host": "X.X.X.X",
               "ports": [[1, 6, 13]]}

PYPACKER_CONFIG = {"name": "Pypacker", "entry_type": "tg", "instance_type": "pypacker", "id": 2, "ports": ["eth0"]}

RPYPACKER_CONFIG = {"name": "Pypacker", "entry_type": "tg", "instance_type": "rpypacker", "id": 3,
                    "ipaddr": "localhost", "ssh_user": "user_name", "ssh_pass": "user_password", "ports": ["eth0"]}


def pytest_addoption(parser):
    parser.addoption("--tgtype", action="append", default=["pypacker"],
                     choices=["ixiahl", "pypacker", "rpypacker"],
                     help="TG type, '%default' by default.")


class FakeOpts(object):
    def __init__(self):
        self.setup = "setup.json"
        self.env = ""
        self.get_only = False
        self.lhost_ui = "linux_bash"


@pytest.fixture(scope="session", params=["pypacker", "rpypacker", "ixiahl"])
def traffic_generator(request):
    if request.param not in request.config.option.tgtype:
        pytest.skip("{0} API is skipped for test.".format(request.param.upper()))
    if request.param == "pypacker":
        tg = dev_pypacker.PypackerTG(PYPACKER_CONFIG, request.config.option)
    elif request.param == "rpypacker":
        tg = dev_rpypacker.RemotePypackerTG(RPYPACKER_CONFIG, FakeOpts())
    elif request.param == "ixiahl":
        tg = dev_ixia.Ixia(IXIA_CONFIG, request.config.option)
    request.addfinalizer(tg.destroy)
    tg.create()
    return tg


@pytest.fixture
def tg(request, traffic_generator):
    traffic_generator.cleanup()
    if traffic_generator.type == "ixiahl":
        keys = ['chassis', 'card', 'port']
        data = {key: value for key, value in zip(keys, traffic_generator.ports[0])}
        traffic_generator.tcl(IXIA_CONFIGURATION_SCRIPT.format(**data))

    return traffic_generator
