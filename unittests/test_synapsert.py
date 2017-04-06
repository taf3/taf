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

"""``test_synapsert.py``

`Unittests for synapsert functions`

"""

import sys
import os
import hashlib
import time

import pytest


@pytest.fixture(scope="module", autouse=True)
def synapsert(request):
    """Return synapsert instant.

    "--synapsert_config" option set path to synapsert config file, if not defined, current synapsert config will be use

    """
    if not request.config.option.with_jira:
        pytest.skip("--with_jira option is not set to run JIRA unittests")

    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'plugins/connectors')))
    import SYNAPSERT

    if request.config.getoption("--synapsert_config") is not None:
        test_config = request.config.getoption("--synapsert_config")
        if not os.path.isfile(test_config):
            assert False, "Config file is undetermined"
        else:
            test_config = os.path.abspath(test_config)

        synapsert_instance = SYNAPSERT.SYNAPSERT(test_config)
        synapsert_instance._set_default_cfs()
    else:
        assert False, "Config file is undetermined"

    return synapsert_instance


@pytest.fixture()
def tp_name(synapsert, request):
    _hash = hashlib.sha1(str(time.time()))

    def fin():
        issue = synapsert.get_issue_by_name(_hash.hexdigest(), "Test Plan")
        if issue is not None:
            issue.delete()
    request.addfinalizer(fin)
    return _hash.hexdigest()


@pytest.fixture()
def tc_name(synapsert, request):
    _hash = hashlib.sha1(str(time.time()))

    def fin():
        issue = synapsert.get_issue_by_name(_hash.hexdigest(), "Test Case")
        if issue is not None:
            issue.delete()
    request.addfinalizer(fin)
    return _hash.hexdigest()


def test_jira_exist(synapsert):
    assert synapsert.get_tracker()


def test_get_issue_type(synapsert):
    """Verify if issue exists.

    """
    issue_type = None
    from jira.exceptions import JIRAError
    try:
        issue_type = "Test Case"
        synapsert.jira.search_issues("project='ONS' AND issuetype='%s'" % (issue_type,), maxResults=1)
        issue_type = "Test Plan"
        synapsert.jira.search_issues("project='ONS' AND issuetype='%s'" % (issue_type,), maxResults=1)
    except JIRAError as err:
        pytest.fail("%s issue not found: %s" % (issue_type, err, ))


def test_get_custom_fields(synapsert):
    """Verify if all customfields created.

    """
    custom_fields = synapsert.get_custom_fields("Test Case")

    assert custom_fields, "Cannot get custom fields"
    assert custom_fields.get('Automated TC Name') is not None, "Automated TC Name customfield is not defined"
    assert custom_fields.get('Test Case State') is not None, "Test Case State customfield is not defined"
    assert custom_fields.get('Failure Reason') is not None, "Failure Reason customfield is not defined"
    assert custom_fields.get('Build number') is not None, "Build number customfield is not defined"
    assert custom_fields.get('Platform') is not None, "Platform customfield is not defined"

    # Check if get_config works
    assert synapsert.get_config() is not None


def test_create_test_plan(synapsert, tp_issue):
    assert synapsert.get_issue_by_name(tp_issue["name"], "Test Plan") is not None


@pytest.fixture()
def tc_issue(synapsert, tc_name):
    descr = tc_name + "_descr"
    auto_tc_name = tc_name + "_auto_tc_name"
    issue = synapsert.create_tc(tc_name, descr, auto_tc_name)
    return {"issue": issue, "auto_tc_name": auto_tc_name, "descr": descr}


@pytest.fixture()
def tp_issue(synapsert, tp_name):
    return {"issue": synapsert.create_tp(tp_name), "name": tp_name}


def test_transition(synapsert, tc_issue, tp_issue):
    # Test transitions of Test Case
    assert synapsert.get_transitions(tc_issue["issue"]) == ['Pass', 'Fail', "Can't Test"]
    synapsert._do_transition(tc_issue["issue"], "Pass")
    assert synapsert.get_transitions(tc_issue["issue"]) == ['Restart', 'Close']
    synapsert._do_transition(tc_issue["issue"], "Restart")
    assert synapsert.get_transitions(tc_issue["issue"]) == ['Pass', 'Fail', "Can't Test"]
    synapsert._do_transition(tc_issue["issue"], "Fail")
    assert synapsert.get_transitions(tc_issue["issue"]) == ['Restart', 'Close']
    synapsert._do_transition(tc_issue["issue"], "Restart")
    assert synapsert.get_transitions(tc_issue["issue"]) == ['Pass', 'Fail', "Can't Test"]
    synapsert._do_transition(tc_issue["issue"], "Pass")
    assert synapsert.get_transitions(tc_issue["issue"]) == ['Restart', 'Close']
    synapsert._do_transition(tc_issue["issue"], "Close")
    assert synapsert.get_transitions(tc_issue["issue"]) == ['Re-open']

    # Test transition of Test Plan
    assert synapsert.get_transitions(tp_issue["issue"]) == ['Start Test Plan']
    synapsert._do_transition(tp_issue["issue"], "Start Test Plan")
    assert synapsert.get_transitions(tp_issue["issue"]) == ['Close Test Plan']
    synapsert._do_transition(tp_issue["issue"], "Close Test Plan")
    assert synapsert.get_transitions(tp_issue["issue"]) == []


def test_create_test_case(synapsert, tc_issue):
    assert tc_issue["issue"] is not None, "Test Case doesn't created"
    assert tc_issue["issue"].fields.description == tc_issue["descr"]
    assert synapsert.get_cf_value(tc_issue["issue"], "Automated TC Name") == tc_issue["auto_tc_name"]


def test_get_suite_value(synapsert):
    """Verify value of suites.

    """
    value = synapsert._get_suite_value("ons_tests.functional_l2.dcbx.test_synapsert")
    assert value == "functional_l2.dcbx.synapsert"


def test_get_tc_by_auto_tc_name(synapsert, tc_issue):
    issue = synapsert.get_tc_by_auto_tc_name(tc_issue["auto_tc_name"])
    # Check if issue is exists
    assert issue is not None, "Cannot get Automated TC Name"
    # Check if issue has expected key
    assert synapsert.get_issue_key(issue) == synapsert.get_issue_key(tc_issue["issue"])


def test_set_suite(synapsert, tc_issue):
    synapsert._set_suite(tc_issue["issue"], "test_suite")
    # Check if issue is exists
    assert synapsert.get_cf_value(tc_issue["issue"], "Test Suite") == "test_suite"
