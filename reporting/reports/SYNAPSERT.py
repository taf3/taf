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

"""``SYNAPSERT.py``

`SYNAPSERT class`

"""

import loggers
from plugins.pytest_helpers import get_failure_reason


class SYNAPSERT(object):
    """SYNAPSERT report specific functionality.

    """

    class_logger = loggers.ClassLogger()

    def __init__(self, connectors=None):
        """Initialize SYNAPSERT class.

        """
        self.synapsert = connectors['SYNAPSERT']
        self.test_plan = None
        self.subtest = None
        self.platform = None
        self.current_client = None
        # cmd option
        self.append_tcs = False
        self.force_update = False
        self.prefix = None
        self.wait_stop_button = True

    def _set_test_plan(self, cmd):
        """Get test plan or create if doesn't exist.

        Args:
            cmd(dict):  Command

        """
        # try to get test plan by name
        tp_name = cmd['build']

        if self.prefix is not None:
            tp_name += self.prefix

        if self.current_client is None and cmd['client'] is not None:
            self.current_client = cmd['client']
        else:
            return

        _current_test_plan = self.synapsert.get_issue_by_name(tp_name, "Test Plan")
        # if not found create new test plan
        if _current_test_plan is None:
            self.test_plan = self.synapsert.create_tp(tp_name)
        elif self.synapsert.get_issue_status(_current_test_plan) == "Closed" or "-sanity" in tp_name and self.test_plan is None:
            # if current test plan is Closed, try to find first opened test plan or create it
            self.test_plan = self.synapsert.get_last_open_tp(tp_name)
        else:
            self.test_plan = _current_test_plan

    def _set_test_case(self, cmd):
        """Create subtest in test plan.

        Args:
            cmd(dict):  Command

        """
        _test_case = self.synapsert.get_tc_by_auto_tc_name(cmd['tc'])
        if _test_case is not None and 'build_info' in list(cmd.keys()):
            if self.platform is None:
                self.platform = cmd['build_info']['platform']
            # Add test case to tp. Return None if sub task was not created
            self.subtest = self.synapsert.create_subtest(self.test_plan, _test_case, self.current_client, cmd['build_info'])

    def process_cmd(self, cmd):
        """Get and process command from client.

        Args:
            cmd(dict):  Command

        """
        if 'status' in list(cmd.keys()) and self.synapsert.get_tracker():
            # Create test case and test plan on start test
            if cmd['status'] == 'Run':
                self.subtest = None
                if self.test_plan is None:
                    self._set_test_plan(cmd)

                _test_case = None
                if self.append_tcs or self.force_update:
                    _test_case = self.synapsert.get_tc_by_auto_tc_name(cmd['tc'])

                if _test_case is None and self.append_tcs:
                    if cmd['info'] and "brief" in list(cmd['info'].keys()) and "description" in list(cmd['info'].keys()):
                        _test_case = self.synapsert.create_tc(cmd["info"]["brief"], cmd["info"]["description"], cmd["tc"], cmd["suite"])
                    else:
                        self.class_logger.warning("Check: '%s' maybe brief is not valid" % (cmd["tc"]))

                if self.force_update and _test_case:
                    self.synapsert.update_test_case(_test_case, cmd["info"], cmd["suite"])
                return

            elif cmd['status'] == 'Error':

                if self.test_plan is None:
                    self._set_test_plan(cmd)

                if cmd['report']['when'] == 'setup':
                    _test_case = self.synapsert.get_tc_by_auto_tc_name(cmd['tc'])
                    if _test_case is not None:
                        self.subtest = self.synapsert.create_subtest(self.test_plan, _test_case, self.current_client, cmd['build_info'])
                        self.set_cant_test(cmd)
                    else:
                        self.class_logger.warning("Cannot create subtest to: '%s'" % (cmd["tc"]))
                elif self.subtest is None:
                    return
                else:
                    if "Re-open" in self.synapsert.get_transitions(self.subtest):
                        self.synapsert.update_tc_status(self.subtest, 'Re-open')
                    self.set_cant_test(cmd)
            # Show warning message if test skipped on setup and push "Can't Test" if test case already added
            elif cmd['status'] == "Passed":
                self._set_test_case(cmd)

                if self.subtest is None:
                    return
                self.synapsert.update_tc_status(self.subtest, 'Pass')
            elif cmd['status'] == 'Failed':
                self._set_test_case(cmd)
                if self.subtest is None:
                    return
                # If test crashed on setup it can't run
                if 'when' in list(cmd.keys()) and cmd['when'] == 'setup':
                    self.synapsert.update_tc_status(self.subtest, 'Can\'t Test')
                else:
                    self.synapsert.update_tc_status(self.subtest, 'Fail')
                    if 'longrepr' in list(cmd['report'].keys()):
                        result = get_failure_reason(cmd['report']['longrepr'])
                        if result:
                            self.synapsert.set_failure_reason(self.subtest, result, self.platform, self.prefix)
            elif cmd['status'] == 'Skipped':
                self.class_logger.warning('Test: %s is skipped' % (cmd['tc']))
            else:
                self.class_logger.warning('Unknown test case status')

    def set_cant_test(self, cmd):
        """Update subtest status to 'Can't test'.

        Args:
            cmd(dict):  Command

        """
        self.synapsert.update_tc_status(self.subtest, 'Can\'t Test')
        if 'longrepr' in list(cmd['report'].keys()):
            # get failure reason on call
            call_fr = self.synapsert.get_cf_value(self.subtest, 'Failure Reason')
            # get failure reason on teardown
            teardown_fr = get_failure_reason(cmd['report']['longrepr'])
            if teardown_fr:
                self.synapsert.set_failure_reason(self.subtest, "%s%s" % (teardown_fr, "" if call_fr is None else ";" + call_fr), self.platform, self.prefix)

    def info(self):
        """Return report settings.

        """
        return str({'Test Plan': self.synapsert.get_issue_key(self.test_plan),
                    'Test Case': self.synapsert.get_issue_key(self.subtest),
                    'Platform': self.platform,
                    'Option append_tcs': self.append_tcs,
                    'Option force_update': self.force_update, })
