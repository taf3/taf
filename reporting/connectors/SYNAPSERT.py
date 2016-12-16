#!/usr/bin/env python
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

@file  SYNAPSERT.py

@summary  SYNAPSERT class
"""

import os
import json
import sys
import base64
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
import time

from jira.client import JIRA
from jira.exceptions import JIRAError

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', './')))
import loggers


class SYNAPSERT(object):
    """
    @description  Class for TCMS interaction
    """
    jira = None
    class_logger = loggers.ClassLogger()
    name = "SynapseRT"

    def __init__(self, config_file="synapsert_client.json"):
        """
        @brief  Class initialization
        @param  config_file:  SYNAPSERT configuration file
        @type  config_file:  str
        """
        self.host = None
        self.username = None
        self.password = None
        self.project = None
        self.default_platform = None

        self.tc_custom_fields = {}
        self.allowed_suites = []
        self.subtests = {}
        self.test_plan = {'name': None, 'key': None}

        # Define config file location if one
        self.__config_file = os.path.join(os.path.dirname(__file__), config_file)

        # Read credentials from config if one
        if self.__config_file is not None:
            config = json.loads(open(self.__config_file).read(), encoding="latin-1")
            for key in config:
                setattr(self, key, config[key])

        # Get jira client
        self.jira = self._init_jira_client()

    # Run it when you got first test case
    def _set_default_custom_fields(self):
        """
        @brief Find and set custom fields
        @note  Serve for operating with custom fields.
        """
        # Init urllib for TS
        # Set cookie
        cookie = http.cookiejar.CookieJar()
        urllib.request.install_opener(urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie)))
        if not self.tc_custom_fields:
            # Found test case
            self.tc_custom_fields = self.get_custom_fields("Test Case")

    def _set_allowed_suites(self, test_case):
        """
        @brief  Set allowed suites
        @param  test_case:  Instance of Test Case
        @type  test_case:  JIRA.Issue
        @note  Get allowed values from 'Test Suite' custom field and store them
        """
#        self._generate_servlet(issue_type="ts")
        try:
            cfs = self.jira.editmeta(test_case)['fields']['customfield_' + self.tc_custom_fields['Test Suite']]['allowedValues']
        except JIRAError as err:
            self.class_logger.error("Cannot get list of allowedValues:%s\n Possible provided object is not a TP.", err)
        except AttributeError:
            self.class_logger.error("Cannot get list of allowedValues. Possible provided object is not a TP.")
            return None
        for custom_field in cfs:
            self.allowed_suites.append(custom_field['value'])

    def _init_jira_client(self):
        """
        @brief Return Jira client.
        @rtype:  JIRA
        @return:  jira-instance
        """
        try:
            self.jira = JIRA(options={'server': self.host}, basic_auth=(self.username, self.password))
            self.class_logger.info("Init jira client")
            return self.jira
        except Exception as err:
            self.class_logger.error("Exception: %s" % (err, ))
            self.class_logger.error("Cannot create jira instants")
            return None

    def get_tracker(self):
        """
        @brief Check if tracker exists and sleep on 30 seconds
        @rtype:  bool
        @return: True if connect to Jira host
        """
        try:
            connection = urllib.request.urlopen(self.host)
            connection.close()
            return True
        except Exception as err:
            self.class_logger.error(err)
            self.class_logger.error("Waiting connection to jira")
            time.sleep(30)
            self._init_jira_client()
            return False

    def get_config(self):
        """
        @brief Return config fields
        @rtype:  tuple(str)
        @return:  host, project name, build number, test case  state, fail reason, automated test case name, platform
        """
        if not self.tc_custom_fields:
            self.tc_custom_fields = self.get_custom_fields("Test Case")
        try:
            return \
                self.host, self.project, self.tc_custom_fields['Build number'], self.tc_custom_fields['Test Case State'], \
                self.tc_custom_fields['Failure Reason'], self.tc_custom_fields['Automated TC Name'], self.tc_custom_fields['Platform']
        except Exception as err:
            self.class_logger.warning("Cannot get config data: %s" % err)
            return None

    def get_tc_by_auto_tc_name(self, auto_tc_name):
        """
        @brief  Get Test Case by auto_tc_name
        @param  auto_tc_name:  Automated TC Name of Test Case
        @type  auto_tc_name:  str
        @rtype:  JIRA.Issue
        @return:  Instance of Test Case in JIRA

        """
        # Search only test cases
        jql_str = "project='%s' AND type='Test Case' and 'Automated TC Name'~'%s'" % (self.project, auto_tc_name)
        tcs = []
        try:
            tcs = self.jira.search_issues(jql_str)
        except JIRAError as err:
            self.class_logger.warning("Cannot find requested TC %s: %s" % (auto_tc_name, err))

        for test_case in tcs:
            try:
                if auto_tc_name == self.get_cf_value(test_case, 'Automated TC Name'):
                    self.class_logger.debug("Found TC: '%s'" % (self.get_issue_key(test_case)))
                    return test_case
            except Exception as err:
                self.class_logger.warning("Cannot find requested TC %s: %s" % (auto_tc_name, err))

        self.class_logger.warning("Cannot find requested TC: %s" % (auto_tc_name, ))
        return None

    def get_issue_by_name(self, name, issue_type="Test Case"):
        """
        @brief Get Jira issue by name
        @param  name:  Summary of Test Plan
        @type  name:  str
        @param  issue_type:  Jira issue type
        @type  issue_type:  str
        @rtype:  JIRA.Issue
        @return:  JIRA issue
        """
        self._set_default_custom_fields()
        jql_str = "project='%s' AND issuetype='%s' AND summary ~ '%s'" % (self.project, issue_type, name, )
        try:
            issues = self._get_all_issues(jql_str)
            for issue in issues:
                if self.get_summary(issue) == name:
                    self.class_logger.debug("Found %s: '%s'" % (issue_type, name))
                    return issue
            return None
        except IndexError:
            return None

    def _do_transition(self, item, value):
        """
        @brief Do transition of JIRA issue
        @param  item:  Instance of issue
        @type  item:  JIRA.Issue
        @param  value:  Name of button
        @type  value:  str
        @rtype:  bool
        @return:  True in case has been pushed successfully
        @note Push buttons on issue: Pass, Fail, Cant Test, etc...`
        """
        try:
            transitions = self.jira.transitions(item)
            for transition in transitions:
                if transition['name'] == value:
                    self.jira.transition_issue(item, transition['id'])
                    self.class_logger.debug("The button '%s'  was pushed" % value)
                    return True
            return False
        except Exception as err:
            self.class_logger.error("Cannot push the button: '%s'. Maybe issue does not exist: %s" % (value, err))
            return False

    def get_last_tp_by_platform(self, platform):
        """
        @brief  Get latest Test Plan by platform
        @param  platform:  Platform name
        @type  platform:  str
        @rtype:  JIRA.Issue
        @return:  Latest Test Plan by platform
        """
        jql_str = "project='%s' AND type='Test Plan' ORDER BY updated DESC" % (self.project, )
        try:
            # TODO::: investigate how it works with big count of Test Plans
            issues = self.jira.search_issues(jql_str, maxResults=200)
            for issue in issues:
                _summary = self.get_summary(issue)
                if platform in _summary and "sanity" not in _summary:
                    self.class_logger.debug("Found Test Plan: %s " % (_summary, ))
                    return issue
        except JIRAError as err:
            self.class_logger.warning("Cannot find TP by platform %s: %s" % (platform, err))

    def get_last_open_tp(self, tp_name):
        """
        @brief Return last open Test Plan
        @param  tp_name:  Jira Test Plan name
        @type  tp_name:  str
        @rtype:  JIRA.Issue
        @return:  Last open Test Plan in JIRA
        """
        jql_str = "project='%s' AND issuetype='Test Plan'" % (self.project, )
        issues = self.jira.search_issues(jql_str)
        cur_ver = 0
        # Find all child of test plan
        for issue in issues:
            _summary_arr = self.get_summary(issue).split('-')
            # Split number from tp name
            if self.get_summary(issue)[:-(len(_summary_arr[-1]) + 1)] == tp_name \
                    and _summary_arr[-1].isdigit():
                # Find first open test plan and return it
                if self.get_issue_status(issue) != "Closed" and '-sanity' not in tp_name:
                    self.class_logger.debug("Get TP: '%s'" % (self.get_issue_key(issue)))
                    return issue
                issue_ver = issue.fields.summary[len(tp_name) + 1:]
                # get current version
                issue_ver = _summary_arr[-1]
                if issue_ver.isdigit() and int(issue_ver) > cur_ver:
                    cur_ver = int(issue_ver)

        # Create and return new test plan by template: TEST_PLAN-max_ver
        return self.create_tp(tp_name + "-" + str(cur_ver + 1))

    def _create_test_suite(self, ts_name):
        """
        @brief Create test suite
        @param  ts_name:  Jira Test Suite name
        @type  ts_name:  str
        """
        # Api to update Test Suite in the SynapseRT plugin storage. Use manageTestSuitesServlet servlet url: http://hostname/browse/<Project KEY>
        suite_data = {
            "action": "create",
            "testSuiteName": ts_name,
            "projectKey": "%s" % self.project
        }

        params = urllib.parse.urlencode(suite_data)
        try:
            conn = urllib.request.Request("%s/plugins/servlet/manageTestSuitesServlet" % (self.host, ), params.encode())
            urllib.request.urlopen(conn)
            self.allowed_suites.append(ts_name)
        except Exception as err:
            self.class_logger.error("Cannot create test suite '%s': %s" % (ts_name, err))

    @staticmethod
    def _get_suite_value(suite):
        """
        @brief  Get suite value without _test_
        @param  suite:  Full test suite name
        @type  suite:  str
        @rtype:  str
        @return:  Suite name without _test_
        """
        _arr = suite.split(".")
        _value = ""
        if _arr:
            if not _arr[len(_arr) - 1].startswith("test_"):
                _value = suite[(len(_arr[0]) + 1):-len(_arr[len(_arr) - 1]) - 1]
            else:
                _value = suite[(len(_arr[0]) + 1):]
        else:
            _value = suite

        _value = _value.replace("test_", "")
        return _value

    def _set_suite(self, test_case, suite):
        """
        @brief Set Test Suite
        @param  test_case:  Jira test case
        @type  test_case:  JIRA.Issue
        @param  suite:  Test suite name
        @type  suite:  str
        """
        # If suite doesn't exists create it

        if suite is None:
            return None

        _suite = self._get_suite_value(suite)

        if _suite not in self.allowed_suites:
            self._create_test_suite(_suite)
            # Need to data storage of synapseRT plugin
            self._generate_servlet(_suite, issue_type="ts")
        self._update_cf(test_case, "Test Suite", [{'value': _suite}])

    def create_tc(self, name, description, auto_tc_name, suite=None):
        """
        @brief Create test case
        @param  name:  Summary of Test Case
        @type  name:  str
        @param  description:  Description of Test Case
        @type  description:  str
        @param  auto_tc_name:  Automated TC Name customfield.
        @type  auto_tc_name:  str
        @param  suite:  Test Suite name.
        @type  suite:  str
        @rtype:  JIRA.Issue
        @return:  instance of Test Case
        """
        # Find test case by name
        if not name:
            self.class_logger.error("Cannot create requested TC: Empty Name")
            return None
        # TODO: Pass test suite name as an argument
        issue_dict = {
            'project': {'key': self.project},
            'summary': '%s' % (name, ),
            'description': '%s' % (description, ),
            'issuetype': {'name': 'Test Case'},
            'customfield_' + self.tc_custom_fields['Automated TC Name']: '%s' % (auto_tc_name, )}
        test_case = None
        try:
            test_case = self.jira.create_issue(fields=issue_dict)
#            self.class_logger.debug("Created TC with ID: '%s'" % (self.get_issue_key(test_case), ))
        except JIRAError as err:
            self.class_logger.error("Cannot create requested TC '%s' : %s" % (name, err, ))
            return None
        # Generate servlet for new Test Case
        self._generate_servlet(self.get_issue_key(test_case), "tc")
        # TODO: Comment for disable Test Suites
        self._set_suite(test_case, suite)
        self.class_logger.debug("Created TC: '%s'" % (self.get_issue_key(test_case)))
        return test_case

    def create_tp(self, tp_name):
        """
        @brief Create test plan
        @param  tp_name:  Summary of Test Plan
        @type  tp_name:  str
        @rtype:  JIRA.Issue
        @return:  Instance of Jira Test Plan
        """
        # Check if test plan exists
        issue_dict = {
            'project': {'key': '%s' % self.project},
            'summary': '%s' % (tp_name, ),
            'description': '%s' % (tp_name, ),
            'issuetype': {'name': 'Test Plan'}, }
        test_plan = self.jira.create_issue(fields=issue_dict)
        self.class_logger.debug("Created TP: '%s'" % (self.get_issue_key(test_plan)))
        return test_plan

    def _update_cf(self, test_case, custom_field=None, data=None):
        """
        @brief Update Custom Field
        @param  test_case:  Jira test case
        @type  test_case:  JIRA.Issue
        @param  custom_field:  Name of custon field
        @type  custom_field:  str
        @param  data:  Custom field value
        @type  data:  str
        @note  Get customfield_id from allowed values
        """
        try:
            test_case.update(fields={'customfield_%s' % (self.tc_custom_fields[custom_field],): data})
            self.class_logger.debug("Set custom field: %s to TC: %s" % (custom_field, self.get_issue_key(test_case)))
        except Exception as err:
            self.class_logger.warning("Can\'t set custom field '%s': %s" % (custom_field, err))

    def _generate_servlet(self, key, issue_type=None):
        """
        @brief Generate OptionServlet issue or suite to OptionField
        @param  key:  Jira Issue key
        @type  key:  str
        @param  issue_type:  Type of Jira issues
        @type  issue_type:  str
        """
        try:
            connection = None
            if issue_type in ["tc", "ts"]:
                connection = urllib.request.urlopen('%s/plugins/servlet/generateOptionsServlet?value=%s&type=%s' % (self.host, key, issue_type))
            else:
                connection = urllib.request.urlopen('%s/plugins/servlet/generateOptionsServlet?issueKey=%s' % (self.host, key))
            connection.close()
        except urllib.error.HTTPError as err:
            self.class_logger.warning('Can\'t generate options of servlet:  %s' % key)
            self.class_logger.warning(err)

    def set_failure_reason(self, test_case, value, platform=None, prefix=None):
        """
        @brief Set Failure Reason
        @param  test_case:  Instance of Test Case
        @type  test_case:  JIRA.Issue
        @param  value:  Value of failure reason
        @type  value:  str
        @param  platform:  Platform of failed issue
        @type  platform:  str
        @param  prefix:  Prefix of Test Plan
        @type  prefix:  str
        """
        try:
            self._update_cf(test_case, "Failure Reason", value)
            auto_tc_name = self.get_cf_value(test_case, "Automated TC Name")
            if auto_tc_name is not None:
                defects = self._get_linked_defects(value, auto_tc_name, platform, prefix)
                if defects is not None:
                    self._link_issues(test_case, defects)

            self.class_logger.debug("Set Failure Reason: '%s' to TC: '%s'",
                                    value, self.get_issue_key(test_case))
        except TypeError as err:
            self.class_logger.error("Can\'t set failure reason to TC: '%s'. TypeError: %s",
                                    self.get_issue_key(test_case), err)
        except Exception as err:
            self.class_logger.error("Can\'t set failure reason to TC: '%s'. Error: %s",
                                    self.get_issue_key(test_case), err)

    def _get_linked_defects(self, value, auto_tc_name, platform, prefix):
        """
        @brief Get linked defects
        @param  value:  Value of failure reason
        @type  value:  str
        @param  auto_tc_name:  Automated TC Name customfield.
        @type  auto_tc_name:  str
        @param  platform:  Platform of failed issue
        @type  platform:  str
        @param  prefix:  Prefix of Test Plan
        @type  prefix:  str
        @rtype:  list[JIRA.Issue]
        @return:  list of linked defetcs
        @note Get list of linked defects of SubTests by auto_tc_name, platform and/or prefix
        """
        try:
            # issue_links = []
            _platform = ""
            _platform = "AND Platform = %s" % (platform, )

            jql_str = "project='%s' %s AND (issueFunction in hasLinks('testing discovered') OR \
                       issueFunction in hasLinks('automated testing discovered')) \
                       AND 'Automated TC Name'~'%s' AND ('Test Case State'='Failed' OR 'Test Case State'='Cant Test') \
                       ORDER BY updated DESC" % (self.project, _platform, auto_tc_name)
            issues = self.jira.search_issues(jql_str)
            if issues is not None:
                for issue in issues:
                    if (self.get_cf_value(issue, 'Automated TC Name') == auto_tc_name and self._check_prefix(issue, prefix, platform) and
                            self.get_cf_value(issue, 'Failure Reason') == value):
                        # TODO:::Change it back
                        return self.get_defects_list(self.get_issue_key(issue))
            return None
        except Exception as err:
            self.class_logger.error("Can\'t link defects to issue. Error: %s" % (err, ))
            return None

    def _check_prefix(self, issue, prefix, platform):
        """
        @brief Check if summary of Test Case containts prefix. Return True or prefix is None or prefix exists
        @param  issue:  Jira issue
        @type  issue:  JIRA.Issue
        @param  prefix:  Prefix of Test Plan
        @type  prefix:  str
        @param  platform:  Platform of failed issue
        @type  platform:  str
        @rtype:  bool
        @return:  True if platform or prefix in issue
        """
        if prefix is None:
            return platform in self.get_summary(issue).split(':')[0].split("-")
        else:
            return any(item.endswith(prefix) for item in self.get_summary(issue).split(':')[0].split("-"))

    def _link_issues(self, test_case, defect_keys):
        """
        @brief Relink defects to subtest
        @param  test_case:  Instance of Test Case
        @type  test_case:  JIRA.Issue
        @param  defect_keys:  List of defect keys
        @type  defect_keys:  list[str]
        @rtype:  bool
        @return:  True if defect list updated successfully
        """
        try:
            if test_case is not None and defect_keys is not None:
                for defect in defect_keys:
                    data = json.dumps({
                        "type": {
                            "name": "Automated Testing"
                        },
                        "inwardIssue": {
                            "key": test_case.key
                        },
                        "outwardIssue": {
                            "key": defect
                        }
                    })
                    url = '%s/rest/api/2/issueLink' % self.host
                    conn = urllib.request.Request(url, data)
                    base64string = base64.encodestring(('%s:%s' % (self.username, self.password)).encode()).replace(b'\n', b'')
                    conn.add_header("Authorization", "Basic %s" % base64string.decode())
                    conn.add_header('Content-Type', 'application/json')
                    conn.get_method = lambda: 'POST'
                    # TODO::: Check if value required
                    urllib.request.urlopen(conn)
                return True
            raise Exception("NoneType exception")
        except Exception as err:
            self.class_logger.error("Can\'t link defects to issue. Error: %s" % (err, ))
            return False

    def update_tc_status(self, test_case, status):
        """
        @brief  Update status of test case
        @param  test_case:  Instance of Test Case
        @type  test_case:  JIRA.Issue
        @param  status:  Test case status
        @type  status:  str
        @raise  ValueError:  unknown status
        """
        status_list = ('Pass', 'Fail', 'Can\'t Test', 'Re-open')
        if status not in status_list:
            raise ValueError("Incorrect status provided: %s. Should be one of: %s" % (status, status_list))
        if test_case is not None:
            self._do_transition(test_case, status)
            self.class_logger.debug("Update TC: '%s' status on: '%s'" % (self.get_issue_key(test_case), status))
            # Push Close after each test
            if status != "Re-open":
                self._do_transition(test_case, 'Close')

    @staticmethod
    def get_summary(issue):
        """
        @brief  Get summary of Jira issue
        @param  issue:  Instance of Test Case
        @type  issue:  JIRA.Issue
        @rtype:  str
        @return:  Summary of Jira issue
        """
        try:
            return issue.fields.summary
        except JIRAError:
            return None

    def get_tc_by_key(self, tc_key):
        """
        @brief  Get test case by key
        @param  tc_key:  Jira issue key
        @type  tc_key:  str
        @rtype:  JIRA.Issue
        @return:  Jira Test Case issue
        """
        try:
            test_case = self.jira.issue(tc_key)
            self.class_logger.debug("Get TC: '%s' by key" % (self.get_issue_key(test_case)))
            return test_case
        except JIRAError as err:
            # if self.class_logger.level == logging.DEBUG:
            #       traceback.print_tb(sys.exc_info()[2])
            self.class_logger.error(err)
            return None
        except Exception:
            self.class_logger.error("Cannot find TC by key: '%s'", tc_key)
            return None

    def get_issue_status(self, issue):
        """
        @brief  Get issue status
        @param  issue:  Instance of Test Case
        @type  issue:  JIRA.Issue
        @rtype:  str
        @return:  Test case status
        """
        try:
            status = issue.fields.status.name
            self.class_logger.debug("Get status: '%s' for TC: '%s'" % (status, self.get_issue_key(issue)))
            return status
        except Exception:
            self.class_logger.error("Can't get status for TC: '%s'" % (self.get_issue_key(issue)))

    def get_custom_fields(self, issue_type):
        """
        @brief  Get custom fields
        @param  issue_type:  Jira issue type
        @type  issue_type:  str
        @rtype:  dict{}
        @return:  Dictionary with custom field name, value pairs
        """
        try:
            url = '%s/rest/api/latest/issue/createmeta?projectKeys=%s&issuetypeName=Bug&expand=projects.issuetypes.fields' % (self.host, self.project)

            conn = urllib.request.Request(url)
            base64string = base64.encodestring(('%s:%s' % (self.username, self.password)).encode()).replace(b'\n', b'')
            conn.add_header("Authorization", "Basic %s" % base64string.decode())
            conn.add_header('Content-Type', 'application/json')
            conn.get_method = lambda: 'GET'
            response = urllib.request.urlopen(conn)
            data = json.loads(response.read().decode())
            _project = [x for x in data['projects'] if x['key'] == self.project][0]
            issue = [x for x in _project['issuetypes'] if x['name'] == issue_type][0]
            assert issue is not None
            custom_dict = {}
            for _key, _value in issue['fields'].items():
                if _key.startswith('customfield_'):
                    custom_dict[_value['name']] = _key[12:]
            return custom_dict
        except Exception as err:
            self.class_logger.error("Cannot get customfield of %s" % issue_type)

    def get_available_platforms(self):
        """
        @brief  Get platform field values
        @rtype:  list
        @return:  List with available platforms
        """
        try:
            url = '%s/rest/api/latest/issue/createmeta?projectKeys=%s&issuetypeName=Bug&expand=projects.issuetypes.fields' % (self.host, self.project)

            conn = urllib.request.Request(url)
            base64string = base64.encodestring(('%s:%s' % (self.username, self.password)).encode()).replace(b'\n', b'')
            conn.add_header("Authorization", "Basic %s" % base64string.decode())
            conn.add_header('Content-Type', 'application/json')
            conn.get_method = lambda: 'GET'
            response = urllib.request.urlopen(conn)
            data = json.loads(response.read().decode())
            _project = [x for x in data['projects'] if x['key'] == self.project][0]
            issue = [x for x in _project['issuetypes'] if x['name'] == 'SubTest'][0]
            platform_info = [y for x, y in issue['fields'].items() if y['name'] == 'Platform'][0]
            assert platform_info is not None
            platforms = [x['value'] for x in platform_info['allowedValues']]
            return platforms
        except Exception as err:
            self.class_logger.error("Cannot get all available platforms for SubTest")

    def _get_all_statuses(self):
        """
        @brief  Get all available statuses
        @rtype:  list[str]
        @return:  Get all available Jira statuses
        """
        statuses = []
        try:
            url = '%s/rest/api/2/status' % (self.host, )

            conn = urllib.request.Request(url)
            base64string = base64.encodestring(('%s:%s' % (self.username, self.password)).encode()).replace(b'\n', b'')
            conn.add_header("Authorization", "Basic %s" % base64string.decode())
            conn.add_header('Content-Type', 'application/json')
            conn.get_method = lambda: 'GET'
            response = urllib.request.urlopen(conn)
            statuses = json.loads(response.read().decode())
        except Exception:
            self.class_logger.error("Cannot get statuses")

        return statuses

    def get_issue_type_id(self, issue_type):
        """
        @brief Get Jira issue type ID
        @param  issue_type: Jira issue type
        @type  issue_type:  str
        @rtype:  int
        @return:  Jira issue type ID
        """
        issue_id = "20"
        try:
            url = '%s/rest/api/2/issuetype' % (self.host, )

            conn = urllib.request.Request(url)
            base64string = base64.encodestring(('%s:%s' % (self.username, self.password)).encode()).replace(b'\n', b'')
            conn.add_header("Authorization", "Basic %s" % base64string.decode())
            conn.add_header('Content-Type', 'application/json')
            conn.get_method = lambda: 'GET'
            response = urllib.request.urlopen(conn)
            data = json.loads(response.read().decode())
            if data:
                for _row in data:
                    if _row['name'] == issue_type:
                        issue_id = str(_row['id'])
        except Exception:
            self.class_logger.error("Cannot get Id of %s" % issue_type)

        return issue_id

    def get_cf_value(self, issue, name):
        """
        @brief  Get custom field value
        @param  issue:  Jira Issue
        @type  issue:  JIRA.Issue
        @param  name:  Name of custom field
        @type  name:  str
        @rtype:  str
        @return:  Custom field value
        """
        try:
            if not self.tc_custom_fields:
                self.tc_custom_fields = self.get_custom_fields("Test Case")

            attr = 'customfield_' + self.tc_custom_fields[name]
            value = getattr(issue.fields, attr)
#            self.class_logger.debug("Get custom field value: '%s' for field: '%s' for TC: '%s'" % (value, name, self.get_issue_key(issue)))
            return value
        except Exception:
            self.class_logger.warning("Can\'t get value for field: %s " % name)
            return None

    def get_previous_subtask(self, auto_tc_name, current_key, platform):
        """
        @brief Get previous subtask
        @param  auto_tc_name:  Automated Test Case name
        @type  auto_tc_name:  str
        @param  current_key:  Jira issue key
        @type  current_key:  str
        @param  platform:  Platform of Jira issue
        @type  platform:  str
        @rtype:  JIRA.Issue
        @return:  Previous Jira issue
        """
        jql_str = "project='%s' AND 'Automated TC Name' ~ '%s' AND 'Platform' = '%s' AND 'Test Case State' != 'In Progress' ORDER BY updated DESC" % \
                  (self.project, auto_tc_name, platform)
        self.class_logger.debug("Get previous subtask by AutoName: '%s' by JQL: %s" % (auto_tc_name, jql_str))
        issues = self.jira.search_issues(jql_str)
        # If first sub test
        for issue in issues:
            if auto_tc_name == self.get_cf_value(issue, 'Automated TC Name') and issue.key != current_key:
                self.class_logger.debug("Get previous subtask. Found TC: %s" % issue.key)
                return issue
        self.class_logger.debug("Can't find previous subtask")
        return None

    def get_transitions(self, issue):
        """
        @brief Get available transitions of issue
        @param  issue:  Jira issue
        @type  issue:  JIRA.Issue
        @rtype:  list[str]
        @return:  List of available transitions
        """
        try:
            transitions = self.jira.transitions(issue)
            return[t['name'] for t in transitions]
        except Exception:
            self.class_logger.error("Can\'t get transitions")
            return None

    def get_issue_link(self, tc_key):
        """
        @brief Get issue links of Test Case
        @param  tc_key:  Jira issue key
        @type  tc_key:  str
        @rtype:  str
        @return:  Link to Jira issue
        """
        return self.host + "/browse/" + tc_key

    def get_issue_key(self, test_case):
        """
        @brief  Get Issue key
        @param  test_case:  Jira issue
        @type  test_case:  JIRA.Issue
        @rtype:  str
        @return:  Jira issue key
        """
        try:
            return test_case.key
        except Exception:
            self.class_logger.warning("Can\'t get key")
            return None

    def get_defects_list(self, tc_key):
        """
        @brief  Get defects of Issue
        @param  tc_key:  Jira issue key
        @type  tc_key:  str
        @rtype:  list[str]
        @return:  List of linked defects
        """
        try:
            issue_links = []
            bug_jql_str = "project='%s' AND issue in linkedIssues('%s') AND type=bug AND status!=Closed" % (self.project, tc_key, )
            # get statuses
            statuses = [x['name'] for x in self._get_all_statuses()]
            if 'Verified' in statuses:
                bug_jql_str = "project='%s' AND issue in linkedIssues('%s') AND type=bug AND status!=Closed AND status!=Verified" % (self.project, tc_key, )
            bugs = self.jira.search_issues(bug_jql_str)
            issue_links += [self.get_issue_key(bug) for bug in bugs if self.get_issue_key(bug) not in issue_links]
            self.class_logger.debug("Get list of issues with JQL: '%s'" % bug_jql_str)
            return list(set(issue_links))
        except JIRAError as err:
            self.class_logger.warning("JIRAError: %s" % (err, ))
        except Exception as err:
            self.class_logger.warning("Can\'t get list of issues for. Error: %s" % (err, ))
            return None

    def get_st_history(self, auto_tc_name, tp_names):
        """
        @brief Get history of SubTests
        @param  auto_tc_name:  Jira issue key
        @type  auto_tc_name:  str
        @param  tp_names:  Jira Test Plans
        @type  tp_names:  str
        @rtype:  dict
        @return:  SubTest history
        """
        for test_plan in tp_names.split(";"):
            jql_str = "project='%s' AND summary ~ '%s:' AND 'Automated TC Name'~'%s' \
                       AND issuetype='SubTest' AND 'Test Case State' != 'In Progress'" % (self.project, test_plan, auto_tc_name)
            issues = self.jira.search_issues(jql_str, maxResults=30000)
            state = {"Passed": 0, "Failed": 0, "Can't Test": 0}
            for issue in issues:
                test_case_state = self.get_cf_value(issue, "Test Case State")
                state[test_case_state] += 1
        return state

    def get_last_failed_issues_from_tps(self, tp_names, linked_defects):
        """
        @brief Get last failed issues by test plan name
        @param  tp_names: Jira Test Plan name
        @type  tp_names:  str
        @param  linked_defects:  Look for linked defects
        @type  linked_defects:  bool
        @raise  Exception:  Test Plan does not exist
        @rtype:  list[str]
        @return:  List of failed test cases
        """
        try:
            items = {}
            # Split TestPlans by &
            for test_plan in tp_names.split(";"):
                # Check if Test Plan exist
                if self.get_issue_by_name(test_plan, "Test Plan") is None:
                    raise Exception("Test Plan does not exist")
                # Find issues with Test Case State "Failed" and "Cant Test" only
                jql_str = "project='%s' AND summary~'%s: ' AND issuetype=SubTest AND 'Test Case State' != 'In Progress' ORDER BY updated" % \
                          (self.project, test_plan)
                issues = self._get_all_issues(jql_str)
                for issue in issues:
                    _auto_tc_name = self.get_cf_value(issue, 'Automated TC Name')
                    if _auto_tc_name is not None and self.get_summary(issue).startswith(test_plan + ": "):
                        if _auto_tc_name not in list(items.keys()) or items.get(_auto_tc_name).fields.updated < issue.fields.updated:
                            items[_auto_tc_name] = issue
            filtered_results = []
            for _auto_tc_name in items:
                test_case_state = self.get_cf_value(items[_auto_tc_name], "Test Case State")
                # TODO: Add support of defects
                # Check if list of linked issue > 0
                if test_case_state not in ["Failed", "Can't Test"] or (linked_defects is False and len(items[_auto_tc_name].fields.issuelinks) > 0):
                    continue
                filtered_results.append(_auto_tc_name)

            return filtered_results
        except AttributeError:
            self.class_logger.error("Test Plan is None")
            return None
        except Exception:
            self.class_logger.error("Undetermined exception when get last failed issues")
            return None

    def _get_all_issues(self, jql):
        """
        @brief Get all issue because one request can get only 1,000-2,000 issues
        @param  jql:  jql request
        @type  jql:  str
        @rtype:  list[JIRA.Issue]
        @return:  List of Jira issues
        """
        block_size = 1000
        block_num = 0
        total_num_issues = 0
        all_issues = []
        while True:
            start_idx = block_num * block_size

            issues = self.jira.search_issues(jql,
                                             start_idx,
                                             block_size)
            num_issues = len(issues)
            total_num_issues += num_issues
            self.class_logger.debug("Block %s, %s issues" % (block_num, num_issues))
            block_num += 1

            if num_issues == 0:
                self.class_logger.debug("Finished retrieving information from %s issues" % total_num_issues)
                break

            all_issues.extend(issues)

        return all_issues

    def update_test_case(self, test_case, info, suite):
        """
        @brief Update summary, description, suite of Test Case
        @param  test_case: Jira issue
        @type  test_case:  JIRA.Issue
        @param  info:  Jira issue info
        @type  info:  dict
        @param  suite:  Test suite name
        @type  suite:  str
        """
        if test_case is not None:
            current_brief = self.get_summary(test_case)
            current_description = test_case.fields.description
            current_suite = ""

            try:
                current_suite = self.get_cf_value(test_case, 'Test Suite')[0].value
            except TypeError:
                self.class_logger.warning("Test Suite is not set")

            if info and "brief" in list(info.keys()) and info['brief'] and info['brief'] != current_brief:
                test_case.update(fields={'summary': info['brief']})
            if info and "description" in list(info.keys()) and info['description'] and info['description'] != current_description:
                test_case.update(fields={'description': info['description']})
            if current_suite and current_suite != self._get_suite_value(suite):
                self._set_suite(test_case, suite)

    def create_subtest(self, test_plan, test_case, client=None, build_info=None):
        """
        @brief Create subtest
        @param  test_plan: Jira test plan
        @type  test_plan:  JIRA.Issue
        @param  test_case:  Jira test case
        @type  test_case:  JIRA.Issue
        @param  client:  Client info
        @type  client:  dict
        @param  build_info:  Build info
        @type  build_info:  dict
        @rtype:  JIRA.Issue
        @return:  Jira SubTest instance
        """
        if test_case is None:
            self.class_logger.error("Test Case is None")
            return
        _test_case_suite = None
        try:
            _test_case_suite = self.get_cf_value(test_case, 'Test Suite')[0].value
        except TypeError:
            self.class_logger.warning("Test Suite is not set")
        _platform = None
        if build_info['platform'] is not None and build_info['platform'] != 'undetermined':
            _platform = {'value': build_info['platform']}
        if _platform and _platform['value'] not in self.get_available_platforms():
            _platform = {'value': self.default_platform}
        _build_number = None
        if build_info['build'] is not None:
            _build_number = build_info['build']

        auto_tc_name = self.get_cf_value(test_case, 'Automated TC Name')
        if auto_tc_name is None:
            self.class_logger.warning("Tc name is not allowed")
            return

        _subtest = self.jira.create_issue(fields={
            "project":
                {"key": "%s" % (self.project, )},
            "parent":
                {"id": "%s" % (test_case.id, )},
            "summary": "%s: %s" % (self.get_summary(test_plan), self.get_summary(test_case), ),
            "description": test_case.fields.description if test_case.fields.description else "",
            "customfield_" + self.tc_custom_fields['Automated TC Name']: auto_tc_name,
            "customfield_" + self.tc_custom_fields['Build number']: _build_number,
            "customfield_" + self.tc_custom_fields['Platform']: _platform,
            "customfield_" + self.tc_custom_fields['Test Suite']: [{'value': _test_case_suite}],
            "issuetype": {"id": self.get_issue_type_id('SubTest')}})
#                                "issuetype": {"id": "11"}})

        if not self.subtests.get(client):
            self.subtests[client] = {}

        if not self.test_plan.get(client):
            self.test_plan[client] = {}
            self.test_plan[client]['name'] = self.get_summary(test_plan)
            self.test_plan[client]['key'] = self.get_issue_key(test_plan)

        if _subtest:
            self.subtests[client][auto_tc_name] = {}
            self.subtests[client][auto_tc_name]["stkey"] = self.get_issue_key(_subtest)

        if not self.allowed_suites:
            try:
                # Get one Test Case to parsing Test Suite
                jql_str = "project='%s' AND  type='Test Case'" % self.project
                issues = self.jira.search_issues(jql_str, maxResults=1)
            except JIRAError as err:
                self.class_logger.error("Cannot get custom_filed ID: %s" % (err, ))

            self._set_allowed_suites(issues[0])

        return _subtest
