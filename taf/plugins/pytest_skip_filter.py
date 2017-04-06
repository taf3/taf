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

"""``pytest_skip_filter.py``

`Verify skipif condition on collect stage and remove skipped tests from test run`

"""

import py

import pytest
from _pytest.skipping import cached_eval
from _pytest.skipping import MarkEvaluator


# Modified MarkEvaluator._istrue in order to handle nested skipif markers in parametrized tests
def _istrue(self):
    if self.holder:
        d = self._getglobals()  # pylint: disable=protected-access
        if self.holder.args:
            self.result = False
            skipif_cond = list(self.holder.args)
            try:
                skipif_cond.extend(self.item.function.skipif.args)
            except AttributeError:
                pass
            for expr in skipif_cond:
                self.expr = expr
                if isinstance(expr, py.builtin._basestring):  # pylint: disable=no-member, protected-access
                    result = cached_eval(self.item.config, expr, d)
                else:
                    if self.get("reason") is None:
                        # XXX better be checked at collection time
                        pytest.fail("you need to specify reason=STRING "
                                    "when using booleans as conditions.")
                    result = bool(expr)
                if result:
                    self.result = True
                    self.expr = expr
                    break
        else:
            self.result = True
    return getattr(self, 'result', False)


MarkEvaluator._istrue = _istrue  # pylint: disable=protected-access


def pytest_configure(config):
    """Registering plugin.

    """
    config.pluginmanager.register(SkipFilterPlugin(), "_skip_filter")


def pytest_unconfigure(config):
    """Unregistering plugin.

    """
    skip_filter = getattr(config, "_skip_filter", None)
    if skip_filter:
        del config._skip_filter
        config.pluginmanager.unregister(skip_filter)


class SkipFilterPlugin(object):
    """Verify skipif reason and remove skipped tests from test run.

    """

    @pytest.mark.trylast
    def pytest_collection_modifyitems(self, session, config, items):
        """Handle skipif condition and remove skipped tests from test run.

        """
        self.items_count = len(items)  # pylint: disable=attribute-defined-outside-init
        self.reasons = set()  # pylint: disable=attribute-defined-outside-init
        for item in items[:]:
            evalskip = MarkEvaluator(item, 'skipif')
            if evalskip.istrue():
                self.reasons.add(evalskip.getexplanation())
                items.remove(item)
        self.filtered_count = len(items)  # pylint: disable=attribute-defined-outside-init

    def pytest_terminal_summary(self, terminalreporter):
        """Add info in summary about removed tests.

        """
        deselected = self.items_count - self.filtered_count
        if deselected:
            w = terminalreporter
            w.section("Skipif filtering summary")
            w.line("Total tests count: %s" % self.items_count)
            w.line("Deselected tests count: %s" % deselected)
            w.line("Reasons:")
            for x in self.reasons:
                w.line("\t%s" % x)
            w.line("Filtered tests count: %s" % self.filtered_count)
