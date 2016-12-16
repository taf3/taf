"""
@copyright Copyright (c) 2011 - 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file test_staticcross.py

@summary Unittests for static cross functions.
"""

import pytest

from testlib.dev_staticcross_ons import StaticCrossONS

# setup config
SETUP = {"env": [{"id": 0, "ports": [[1, 5, 11], [1, 5, 12], [1, 5, 13], [1, 5, 14], [1, 1, 16]]},
                 {"id": 412},
                 {"id": "31", "related_id": [0, 412]},
                 {"id": 201}],
         "cross": {"31": [[0, 1, 412, 1], [0, 2, 412, 2], [0, 3, 412, 3], [0, 4, 412, 4], [0, 5, 412, 5]]}}

# config of environment
ENV = {"name": "Zero Cross", "entry_type": "cross", "instance_type": "static_ons", "id": "31"}


# fake class for options
class FakeOpts(object):
    # fake json file
    setup = "setup.json"
    # fake json file
    env = ""
    get_only = False
    build_path = ''


class FakeDev1(object):
    def __init__(self):
        self.ports = ["eth0", "eth2"]

    def connect_port(self, port):
        return True

    def disconnect_port(self, port):
        return True


class FakeDev2(object):
    def __init__(self):
        self.ports = ["eth3", "eth4"]

    def connect_port(self, port):
        return True

    def disconnect_port(self, port):
        return True


@pytest.fixture()
def cross(request, monkeypatch):
    """
    """
    # first method for monkeypatching
    def _setup(self, x):
        return SETUP

    # second method for monkeypatching
    def _conf(self, x):
        return ENV

    # define environment with fake class
    cross = StaticCrossONS(ENV, FakeOpts())
    cross.connections = SETUP['cross']['31']
    cross.related_conf = {0: {}, 412: {}}
    cross.related_obj = {0: FakeDev1(), 412: FakeDev2()}
    return cross


def test_staticcross_get_device(cross):
    """
    """
    result = cross._get_device(412)
    assert isinstance(result, object)


def test_staticcross_connect(cross):
    """
    """
    cross.xconnect(conn=SETUP["cross"]["31"][0])


def test_staticcross_disconnect(cross):
    """
    """
    cross.xdisconnect(conn=SETUP["cross"]["31"][0])
