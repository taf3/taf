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

"""``test_ui_onp_jsonrpc.py``

`Unittests for JSONRPC UI wrappers`

"""

import os
import urllib.parse
import threading
from unittest.mock import MagicMock

import pytest
import jsonrpclib
from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer

from testlib import ui_onpss_jsonrpc
from testlib.custom_exceptions import SwitchException, UIException

# make unique per pid to avoid errno 98 Address already in use unittest races
# /proc/sys/kernel/pid_max is usually 32768
CONFIG = {"ip_host": "localhost", "json_port": 20000 + os.getpid(), "hw": type("SiliconFM10K", (object,), {})()}
REPLY = {"state": "Enabled"}


@pytest.fixture(scope="module")
def server(request):
    """Fixture of environment with Json-Rpc server.

    """

    def close():
        server.shutdown()
        server.server_close()
        thread.join()

    def switch_info(**kwargs):
        return REPLY

    server = SimpleJSONRPCServer((CONFIG["ip_host"], CONFIG["json_port"]))
    # Register method
    server.register_function(switch_info, "getSwitchInfo")

    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    request.addfinalizer(close)
    return server


@pytest.fixture()
def ui(request, server):
    """Fixture of environment for unittests JSONRPC UI wrappers.

    """
    ui = ui_onpss_jsonrpc.UiOnpssJsonrpc(MagicMock(**CONFIG))
    url = urllib.parse.urlunsplit(('http', '{0}:{1}'.format(CONFIG["ip_host"], CONFIG["json_port"]), '', '', ''))
    ui.jsonrpc = jsonrpclib.ServerProxy(url)
    return ui


class TestClientRequest(object):

    def test_request(self, ui, server):
        """Verify that request() method sends and receives the JSON-RPC strings.

        """
        res = ui.request("getSwitchInfo", {})
        assert res == REPLY

    def test_response_with_error(self, ui, server):
        """Verify UIException in case server is responding with error.

        """
        method = "echo"
        params = []
        err_code = -32601
        err_msg = "Method {0} not supported.".format(method)
        # Catch exception
        with pytest.raises(UIException) as excinfo:
            ui.request(method, params)
        # Verify error message
        expected_err_msg = "{0} command with parameters {1} returned error {2}: {3}".format(
            method, params, err_code, err_msg)
        assert excinfo.value.parameter == expected_err_msg

    def test_multicall(self, ui, server):
        """Verify that request() method sends and receives the JSON-RPC strings.

        """
        calls_list = [{} for i in range(1, 5)]
        res = ui.multicall([{"method": "getSwitchInfo", "params": calls_list}])
        assert len(res) == len(calls_list)

    def test_multicall_reply_with_error(self, ui, server):
        """Verify UIException in case server is responding with error for multicall.

        """
        method = "echo"
        param = {"data": ""}
        err_code = -32601
        err_msg = "Method {0} not supported.".format(method)
        # Catch exception
        with pytest.raises(UIException) as excinfo:
            ui.multicall([{"method": "getSwitchInfo", "params": [{}]},
                          {"method": method, "params": [param]}])
        # Verify error message
        expected_err_msg = "{0} command with parameters {1} returned error {2}: {3}".format(method, param, err_code, err_msg)
        assert excinfo.value.parameter == expected_err_msg
