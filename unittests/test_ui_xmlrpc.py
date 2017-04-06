# Copyright (c) 2015 - 2017, Intel Corporation.
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

"""``test_ui_xmlrpc.py``

`XMLRPC UI wrappers.unittests`

"""

from unittest.mock import MagicMock

import pytest

from testlib import ui_ons_xmlrpc


@pytest.fixture
def ui():
    return ui_ons_xmlrpc.UiOnsXmlrpc(MagicMock())


class TestInvalidPorts(object):

    # this does in fact create a fresh UiOnsXmlrpc for each test case
    @pytest.fixture(autouse=True)
    def create_ui(self, ui):
        self.ui = ui

    def test_create_invalid_ports_multiple_port(self):
        self.ui.get_table_ports = MagicMock(return_value=range(20))
        with self.ui.create_invalid_ports(num=5) as ports:
            assert ports == list(range(30, 35))

    def test_create_invalid_ports_port_ids(self):
        self.ui.get_table_ports = MagicMock(return_value=range(20))
        with self.ui.create_invalid_ports([1, 3, 5]) as ports:
            assert ports == [1, 3, 5]
