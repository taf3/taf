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

@file test_pytest_helpers.py

@summary Unittests for helpers functions.
"""

import sys
import os
from unittest.mock import MagicMock

import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'plugins')))
from pytest_helpers import get_failure_reason, get_suite_name, get_tcname, get_steps, get_brief, \
    get_skipped_reason, get_html_xml_path


@pytest.fixture()
def report():
    class Report(object):
        def __init__(self):
            self.nodeid = None
            self.keywords = {}

    return Report()


def test_tcname_basic(report):
    '''Test of pytest_helpers.get_tcname() function'''

    report.nodeid = "ons_tests/test_synapsert.py::test_demo_synapsert1"
    report.keywords = None
    report.keywords = {"test_demo_synapsert1": 1, "tests": 1, "ons_tests/test_synapsert.py": 1}
    assert get_tcname(report) == "test_demo_synapsert1"


def test_tcname_argvalue(report):
    report.nodeid = "ons_tests/test_synapsert_param.py::TestCaseCreation::()::test_case[test_1-doc0-1]"
    report.keywords = None
    report.keywords = {'test_1-doc0-1': 1, 'tests': 1, 'parametrize': 1, 'ons_tests/test_synapsert_param.py': 1,
                       'test_case[test_1-doc0-1]': 1, '()': 1, 'TestCaseCreation': 1}
    assert get_tcname(report) == "test_1"


def test_tcname_keywords(report):
    report.nodeid = "ons_tests/ui/test_ui.py::TestSnmpCliXmlrpc::()::test_cli_set__xmlrpc_get[" \
                    "test_cli_set__xmlrpc_get_simplified_ons_lag__LagsLocal_selected_get_Unselected_value_for_dynamic_lag]"
    report.keywords = None
    report.keywords = {'tests': 1, 'skipif': 1, 'TestSnmpCliXmlrpc': 1, '()': 1, 'simplified': 1,
                       'test_cli_set__xmlrpc_get_simplified_ons_lag__LagsLocal_selected_get_Unselected_value_for_dynamic_lag': 1,
                       'cli_set': 1,
                       'test_cli_set__xmlrpc_get[test_cli_set__xmlrpc_get_simplified_ons_lag__LagsLocal_selected_get_Unselected_value_for_dynamic_lag]': 1,
                       'ons_tests/ui/test_ui.py': 1}
    assert get_tcname(report) == "test_cli_set__xmlrpc_get_simplified_ons_lag__LagsLocal_selected_get_Unselected_value_for_dynamic_lag"


def test_brackets_are_removed():
    report.nodeid = "ons_tests/test_synapsert.py::test_properly_formed_pfc_frames_are_transmitted_01[Manual]"
    report.keywords = None
    report.keywords = {"test_demo_synapsert1": 1, "tests": 1, "ons_tests/test_synapsert.py": 1}
    assert get_tcname(report) == "test_properly_formed_pfc_frames_are_transmitted_01"


def test_bad_fixture_param_value_is_handled():
    report.nodeid = "ons_tests/test_synapsert.py::test_func_01[Manual-test_none_priority_paused_if_priority_enable_vector_set_to_0_part1_13]"
    report.keywords = None
    report.keywords = {"test_demo_synapsert1": 1, "tests": 1, "ons_tests/test_synapsert.py": 1}
    assert get_tcname(report) == "test_none_priority_paused_if_priority_enable_vector_set_to_0_part1_13"


def test_bad_fixture_param_value_is_handled_with_parametrize():
    report.nodeid = "ons_tests/test_synapsert.py::test_func_01[Manual-test_none_priority_paused_if_priority_enable_vector_set_to_0_part1_13]"
    report.keywords = None
    report.keywords = {"test_demo_synapsert1": 1, "tests": 1, "ons_tests/test_synapsert.py": 1, 'parametrize': 1}
    assert get_tcname(report) == "test_none_priority_paused_if_priority_enable_vector_set_to_0_part1_13"


def test_get_failure_reason():
    """
    @brief: Check if get_failure_reason(data) is work correct
    """
    data1 = '''
env = {\'switches\': [{\'instance\': &lt;ServerProxy for 10.0.5.102:8082/RPC2&gt;, \'ports_coun...3\', \'vlab4\', \'vlab5\', \'vlab6\', \'vlab7\', \'vlab8\',
\'vlab9\', \'vlab10\', \'vlab11\']}}\n\n    def test_demo_synapsert1(env):\n        """\n        @brief  Simple test links synapsert test1\n
@steps\n            -# First step\n            -# Second step\n        @endsteps\n        """\n&gt;       assert False, "Some Undetermined Exception"\n
E       AssertionError: Some Undetermined Exception\n\nenv        = {\'switches\': [{\'instance\': &lt;ServerProxy for 10.0.5.102:8082/RPC2&gt;,
\'ports_coun...3\', \'vlab4\', \'vlab5\', \'vlab6\', \'vlab7\', \'vlab8\', \'vlab9\', \'vlab10\', \'vlab11\']}}\n\n
ons_tests/test_synapsert.py:17: AssertionError
'''

    data2 = """
ons_tests/test_synapsert.py:17: in test_demo_synapsert1\n
&gt;       assert False, "Some Undetermined Exception"\nE       AssertionError: Some Undetermined Exception"""

    data3 = """test failure

ons_tests/ui/test_ui.py:1026: in test_xmlrpc_set__snmp_get
                                                                                   (name, snmp_get_results, argvalues_dictionary['snmp_get_result'])
E               AssertionError: In test_xmlrpc_set__snmp_get_standalone_ons_lag__Ports2LagAdmin_partnerAdminPortNumber_set_max_valid_value test case, \
snmp-get result is not correct: [{u'1': [[Gauge32(400)], [Gauge32(1)]]}] == [{u'1': [[400], [400]]}]"""

    data4 = """test failure

ons_tests/ui/test_ui.py:1014: in test_xmlrpc_set__snmp_get
           xmlrpc_set_res = self._xmlrpc_run(env.switch, argvalues_dictionary['xmlrpc_set'])
ons_tests/ui/test_ui.py:538: in _xmlrpc_run
                           helpers.wait_until_value_is_changed(switches[int(key)], *xml_call[1:])
../testlib/helpers.py:765: in wait_until_value_is_changed
                   parameter = switch_instance.getprop(table_name, parameter_name, row_id)
../testlib/switches.py:341: in getprop
       return getattr(self.xmlproxy, "%s.%s.get.%s" % (dst, table, param))(row_id)
../testlib/xmlrpc_proxy.py:118: in __call__
       return self.__send(self.__name, args)
/usr/lib/python2.7/xmlrpclib.py:1578: in __request
           verbose=self.__verbose
/usr/lib/python2.7/xmlrpclib.py:1264: in request
               return self.single_request(host, handler, request_body, verbose)
/usr/lib/python2.7/xmlrpclib.py:1297: in single_request
               return self.parse_response(response)
/usr/lib/python2.7/xmlrpclib.py:1473: in parse_response
       return u.close()
/usr/lib/python2.7/xmlrpclib.py:793: in close
           raise Fault(**self._stack[0])
E           Fault: Fault -701: 'Invalid row ID:param1'"""
    assert get_failure_reason(data1) == "AssertionError: Some Undetermined Exception", "It is not work with tb_long"
    assert get_failure_reason(data2) == "AssertionError: Some Undetermined Exception", "It is not work with tb_short"
    assert get_failure_reason(data3) == \
        "AssertionError: In test_xmlrpc_set__snmp_get_standalone_ons_lag__Ports2LagAdmin_partnerAdminPortNumber_set_max_valid_value test case, " \
        "snmp-get result is not correct: [{u'1': [[Gauge32(400)], [Gauge32(1)]]}] == [{u'1': [[400], [400]]}]"
    assert get_failure_reason(data4) == "Fault: Fault -701: 'Invalid row ID:param1'"


def test_get_suite_name():
    '''Test of pytest_helpers.get_tcname() function'''

    nodeid1 = "ons_tests/test_synapsert.py::test_demo_synapsert2"
    assert get_suite_name(nodeid1) == "ons_tests.test_synapsert"

STEP_STRING = """
@brief  Verify that ports can be added to LAG.
@steps
    -# Delete LAGs table.
    -# Create test LAG.
    -# Assign 2 ports to test LAG.
    -# Verify that there are 2 ports in test LAG.
    -# Remove the ports in test LAG
    -# Delete test LAG.
@endsteps
"""

GOOD_STEPS = """\
-# Delete LAGs table.
-# Create test LAG.
-# Assign 2 ports to test LAG.
-# Verify that there are 2 ports in test LAG.
-# Remove the ports in test LAG
-# Delete test LAG."""


def test_get_steps_doc():
    test_item = MagicMock(**{"funcargs": {"doc": [STEP_STRING]}})
    steps = get_steps(test_item, "")
    assert steps == GOOD_STEPS


def test_get_steps_docstring():
    test_item = MagicMock(**{"funcargs": {"doc_string": [STEP_STRING]}})
    steps = get_steps(test_item, "")
    assert steps == GOOD_STEPS


def test_get_steps_callspec():
    test_item = MagicMock(**{"callspec.params": {"doc": [STEP_STRING]}, "funcargs": {}})
    steps = get_steps(test_item, "")
    assert steps == GOOD_STEPS


def test_get_steps_inspect():
    def something():
        """
        @brief  Verify that ports can be added to LAG.
        @steps
            -# Delete LAGs table.
            -# Create test LAG.
            -# Assign 2 ports to test LAG.
            -# Verify that there are 2 ports in test LAG.
            -# Remove the ports in test LAG
            -# Delete test LAG.
        @endsteps
        """
        pass
    test_item = MagicMock(
        **{
            "function": something,
            "callspec.params": {},
            "funcargs": {}})
    steps = get_steps(test_item, "")
    assert steps == GOOD_STEPS


GOOD_BRIEF = "Verify that ports can be added to LAG."


def test_get_brief_doc():
    test_item = MagicMock(**{"funcargs": {"doc": [STEP_STRING]}})
    steps = get_brief(test_item, "")
    assert steps == GOOD_BRIEF


def test_get_brief_docstring():
    test_item = MagicMock(**{"funcargs": {"doc_string": [STEP_STRING]}})
    steps = get_brief(test_item, "")
    assert steps == GOOD_BRIEF


def test_get_brief_callspec():
    test_item = MagicMock(**{"callspec.params": {"doc": [STEP_STRING]}, "funcargs": {}})
    steps = get_brief(test_item, "")
    assert steps == GOOD_BRIEF


def test_get_brief_inspect():
    def something():
        """
        @brief  Verify that ports can be added to LAG.
        @steps
            -# Delete LAGs table.
            -# Create test LAG.
            -# Assign 2 ports to test LAG.
            -# Verify that there are 2 ports in test LAG.
            -# Remove the ports in test LAG
            -# Delete test LAG.
        @endsteps
        """
        pass
    test_item = MagicMock(
        **{
            "function": something,
            "callspec.params": {},
            "funcargs": {}})
    steps = get_brief(test_item, "")
    assert steps == GOOD_BRIEF


def test_get_failure_reason_TypeError_returns_None():
    assert get_failure_reason(1) is None
    assert get_failure_reason(object()) is None
    assert get_failure_reason(lambda x: 1.0) is None


def test_get_skipped_reason_TypeError_returns_None():
    assert get_skipped_reason(1) is None
    assert get_skipped_reason(object()) is None
    assert get_skipped_reason(lambda x: 1.0) is None


def test_get_html_xml_path_non_string():
    assert get_html_xml_path(1, 1) is "undetermined"
    assert get_html_xml_path({}, 1) is "undetermined"
