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

"""``pytest_returns.py``

`Collect return results from testcases instead of 'PASSED' message`

"""

import operator
import pytest

from contextlib import suppress


def pytest_configure(config):
    """Registering plugin.

    """
    config.pluginmanager.register(ReturnsPlugin(), "returns")
    config.addinivalue_line("markers", "returns: collect this testcase's return results")


def pytest_unconfigure(config):
    """Unregistering plugin.

    """
    returns = getattr(config, "returns", None)
    if returns:
        del config.returns
        config.pluginmanager.unregister(returns)


class ReturnsPlugin(object):
    RESULT_PASSED = 'passed'
    RESULT_SKIPPED = 'skipped'
    RESULT_FAILED = 'failed'
    PYTEST_REPORT_STATUSES = {}
    REPORT_RESULT_GETTER = operator.itemgetter('outcome', 'letter', 'msg')

    @classmethod
    def class_init(cls):
        cls.PYTEST_REPORT_STATUSES = {
            cls.RESULT_PASSED: {
                'outcome': cls.RESULT_PASSED,
                'letter': 'P',
                'msg': 'PASSED',
            },
            cls.RESULT_SKIPPED: {
                'outcome': cls.RESULT_SKIPPED,
                'letter': 'S',
                'msg': 'SKIPPED',
            },
            cls.RESULT_FAILED: {
                'outcome': cls.RESULT_FAILED,
                'letter': 'F',
                'msg': 'FAILED',
            },
        }

    @classmethod
    def get_result(cls, result):
        res_dict = cls.PYTEST_REPORT_STATUSES[result]
        return cls.REPORT_RESULT_GETTER(res_dict)

    @pytest.hookimpl(tryfirst=True, hookwrapper=True)
    def pytest_report_teststatus(self, report):
        outcome = yield
        if report.when == 'call':
            if report.passed:
                result = self.RESULT_PASSED
            elif report.skipped:
                result = self.RESULT_SKIPPED
            else:  # if report.failed:
                result = self.RESULT_FAILED

            status, letter, msg = self.get_result(result)

            if report.passed:
                # print return result instead of 'PASSED'
                with suppress(AttributeError):
                    msg = report.retval

            outcome.result = status, letter, msg

    def pytest_pyfunc_call(self, pyfuncitem):
        # execute testcase and collect return result
        testfunction = pyfuncitem.obj
        if pyfuncitem._isyieldedfunction():  # pylint: disable=protected-access
            res = testfunction(*pyfuncitem._args)  # pylint: disable=protected-access
        else:
            funcargs = pyfuncitem.funcargs
            testargs = {}
            for arg in pyfuncitem._fixtureinfo.argnames:  # pylint: disable=protected-access
                testargs[arg] = funcargs[arg]
            res = testfunction(**testargs)
        pyfuncitem.retval = res
        return True

    @pytest.hookimpl(tryfirst=True, hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        outcome = yield
        report = outcome.get_result()

        if call.when == 'call' and report.passed:
            if hasattr(item.function, 'returns'):
                setattr(report, 'retval', str(item.retval))


ReturnsPlugin.class_init()
