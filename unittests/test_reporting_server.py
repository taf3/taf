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

"""``test_reporting_server.py``

`Unittests for reporting server functions`

"""

import sys
import os

import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../reporting')))
from reporting.reporting_server import XMLReportingServer, imp_plugins

xmlrpcsrv = XMLReportingServer()


@pytest.fixture(scope="function", autouse=True)
def reporting_server():
    opts = {'loglevel': 'DEBUG', 'logprefix': 'main', 'port': '18081', 'logdir': 'logs', 'multiuser': True}

    class CustomOptsParser(object):
        def __init__(self):
            self.multiuser = True
            self.port = '18081'
            self.logprefix = 'main'
            self.logdir = 'logs'
            self.loglevel = 'DEBUG'
    opts = CustomOptsParser()
    xmlrpcsrv = XMLReportingServer()
    xmlrpcsrv.setup(opts)
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../plugins/", './')))
    imp_plugins("reports")
    imp_plugins("connectors")
    return xmlrpcsrv


@pytest.fixture(scope="function", autouse=True)
def reporting_server_with_config(reporting_server):
    reporting_server.xmlrpc_open("test_client-1")
    reporting_server.xmlrpc_reportadd("test_client-1", "xml")
    reporting_server.xmlrpc_reportconfig("test_client-1", "xml", "options", [['update', None]])
    reporting_server.xmlrpc_reportconfig("test_client-1", "xml", "cfgfile", None)
    reporting_server.xmlrpc_reportconfig("test_client-1", "xml", "info_dict", None)
    reporting_server.xmlrpc_reportconfig("test_client-1", "xml", "info_dict", ['chipName', 'SomeSwitch'])
    reporting_server.xmlrpc_reportconfig("test_client-1", "xml", "info_dict", ['TM buildname', '1.2.3.4-SomeSwitch'])
    reporting_server.xmlrpc_reportconfig("test_client-1", "xml", "htmlfile", "1.html")
    reporting_server.xmlrpc_reportconfig("test_client-1", "xml", "htmlcfg", None)

    return reporting_server


def test_client_config(reporting_server):
    """Verify that client config can be created and reports can be removed.

    """
    reporting_server.xmlrpc_open("test_client-1")
    # check if status of client is Active
    assert reporting_server.clients.get("test_client-1", "status") == "Active"
    # add xml report
    reporting_server.xmlrpc_reportadd("test_client-1", "xml")
    assert reporting_server.clients.get("test_client-1", "reports") == {"xml": True}
    reporting_server.xmlrpc_reportconfig("test_client-1", "xml", "htmlfile", "1.html")
    # check attr on report object
    assert reporting_server._reports['XML']['test_client-1'].htmlfile == "1.html"
    reporting_server.xmlrpc_shutdown()


def test_post(reporting_server_with_config):
    """Verify that post command is True.

    """
    post_data1 = ["test_client-1", "SomeSwitch", "test.test_suite", "test_tcname",
                  "Run", ['Simple brief of test case', '-# First step\n-# Second step'],
                  {'platform': 'SomeSwitch', 'build': '1.2.3.4-SomeSwitch'}, "None"]
    # Check if post successful
    assert reporting_server_with_config.xmlrpc_post(*post_data1), "xmlrpc_post operation is False"
    # Check if queuelen works


def test_queue(reporting_server_with_config):
    """Verify that operation with queue is working.

    """
    expected_queuelist = [{'status': 'Run', 'info': {'platform': 'SomeSwitch',
                           'build': '1.2.3.4-SomeSwitch'}, 'client': 'test_client-1',
                           'build': 'SomeSwitch',
                           'report': ['Simple brief of test case', '-# First step\n-# Second step'],
                           'suite': 'test.test_suite', 'tc': 'test_tcname', 'build_info': 'None'}]

    post_data1 = ["test_client-1", "SomeSwitch", "test.test_suite", "test_tcname",
                  "Run", ['Simple brief of test case', '-# First step\n-# Second step'],
                  {'platform': 'SomeSwitch', 'build': '1.2.3.4-SomeSwitch'}, "None"]

    # Check if queue is empty
    assert reporting_server_with_config.xmlrpc_queuelist() == [], "Queuelen is not empty"
    # Send post request

    reporting_server_with_config.xmlrpc_post(*post_data1)
    # Get queue list
    assert reporting_server_with_config.xmlrpc_queuelist() == expected_queuelist
    # Check if queuelen is 1
    assert reporting_server_with_config.xmlrpc_queuelen() == 1, "Queuelen is not right"
    # Call queuedropcmd and check queuelen
    assert reporting_server_with_config.xmlrpc_queuedropcmd(0) == expected_queuelist[0]
    assert reporting_server_with_config.xmlrpc_queuelen() == 0


def test_cmdproc(reporting_server_with_config):
    """Verify that operation with cmdproc is work.

    """
    reporting_server_with_config.xmlrpc_cmdprocdisable()
    assert reporting_server_with_config.xmlrpc_cmdproccheck() == "Watchdog is False and cmdproc is True", "Watchdog is False. cmdprocdisable doesn't work."
    reporting_server_with_config.xmlrpc_cmdprocenable()
    assert reporting_server_with_config.xmlrpc_cmdproccheck() == "Watchdog is True and cmdproc is True", "Watchdog is True. cmdprocdisable doesn't work."
