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

@file test_multiple_run.py

@summary Unittests for pytest_multiple_run plugin.
"""
import pytest

from plugins import pytest_multiple_run


SIMPLE_TESTS = """
                  def test_fake_fail():
                      assert 1/1 == 0

                  def test_fake_pass():
                      assert 1/1 == 1
               """

FAILED_TEST = """
                  def test_fake_fail():
                      assert 1/1 == 0
               """

XFAILED_TEST = """
                  import pytest
                  @pytest.mark.xfail
                  def test_fake_fail():
                      assert 1/1 == 0
               """


class TestPluginMultipleRun(object):

    def test_rerun_passed_test(self, testdir):
        """ Verify that can rerun success test 7 times."""
        test_file = testdir.makepyfile("""
                                        def test_fake_pass():
                                            assert 1/1 == 1
                                        """)
        result = testdir.inline_run("--multiple_run=7", test_file, plugins=[pytest_multiple_run])
        passed, skipped, failed = result.listoutcomes()
        assert len(passed) == 7
        assert len(skipped) == 0
        assert len(failed) == 0

    def test_rerun_failed_test(self, testdir):
        """ Verify that can rerun failed test 7 times."""
        test_file = testdir.makepyfile(FAILED_TEST)
        result = testdir.inline_run("--multiple_run=7", test_file, plugins=[pytest_multiple_run])
        passed, skipped, failed = result.listoutcomes()
        assert len(failed) == 7
        assert len(skipped) == 0
        assert len(passed) == 0

    def test_rerun_all_test_suite(self, testdir):
        """ Verify that can rerun 3 times test module."""
        test_file = testdir.makepyfile(SIMPLE_TESTS)
        result = testdir.inline_run("--multiple_run=3", test_file, plugins=[pytest_multiple_run])
        passed, skipped, failed = result.listoutcomes()
        assert len(failed) == 3
        assert len(passed) == 3
        assert len(skipped) == 0

    def test_rerun_extra_keyword_1(self, testdir):
        """ Verify that can rerun 3 times only matched extra keywords(option "-k")."""
        test_file = testdir.makepyfile(SIMPLE_TESTS)
        result = testdir.inline_run("--multiple_run=3", "-k test_fake_pass", test_file, plugins=[pytest_multiple_run])
        passed, skipped, failed = result.listoutcomes()
        assert len(failed) == 0
        assert len(passed) == 3
        assert len(skipped) == 0

    def test_rerun_extra_keyword_2(self, testdir):
        """ Verify that can rerun 3 times only matched extra keywords(option "-k")."""
        test_file = testdir.makepyfile(SIMPLE_TESTS)
        result = testdir.inline_run("--multiple_run=3", "-k test_fake_fail", test_file, plugins=[pytest_multiple_run])
        passed, skipped, failed = result.listoutcomes()
        assert len(failed) == 3
        assert len(passed) == 0
        assert len(skipped) == 0

    def test_rerun_test_with_exitfirst_option(self, testdir):
        """ Verify that exits instantly on first error or failed test."""
        test_file = testdir.makepyfile(FAILED_TEST)
        result = testdir.inline_run("--multiple_run=5", "-x", test_file, plugins=[pytest_multiple_run])
        passed, skipped, failed = result.listoutcomes()
        assert len(failed) == 1
        assert len(skipped) == 0
        assert len(passed) == 0

    def test_rerun_test_with_collectonly_option(self, testdir):
        """Verify that only collects tests, don't executes them."""
        test_file = testdir.makepyfile(FAILED_TEST)
        result = testdir.inline_run("--multiple_run=5", "--collectonly", test_file, plugins=[pytest_multiple_run])
        passed, skipped, failed = result.listoutcomes()
        assert len(failed) == 0
        assert len(skipped) == 0
        assert len(passed) == 0

    def test_rerun_test_with_xfail_mark(self, testdir):
        """ Verify that can rerun test 5 times with mark xfail."""
        test_file = testdir.makepyfile(XFAILED_TEST)
        result = testdir.inline_run("--multiple_run=5", test_file, plugins=[pytest_multiple_run])
        passed, skipped, failed = result.listoutcomes()
        assert len(failed) == 0
        assert len(skipped) == 5
        assert len(passed) == 0

    def test_rerun_test_with_runxfail_option(self, testdir):
        """ Verify that can rerun test 5 times with mark xfail and option runxfail"""
        test_file = testdir.makepyfile(XFAILED_TEST)
        result = testdir.inline_run("--multiple_run=5", "--runxfail", test_file, plugins=[pytest_multiple_run])
        passed, skipped, failed = result.listoutcomes()
        assert len(failed) == 5
        assert len(skipped) == 0
        assert len(passed) == 0

    def test_rerun_test_with_skipif_mark(self, testdir):
        """ Verify that can rerun test 5 times with mark skipif."""
        test_file = testdir.makepyfile("""
                                          import pytest
                                          @pytest.mark.skipif("True")
                                          def test_fake_pass():
                                              assert 1/1 == 1
                                       """)
        result = testdir.inline_run("--multiple_run=5", test_file, plugins=[pytest_multiple_run])
        passed, skipped, failed = result.listoutcomes()
        assert len(failed) == 0
        assert len(skipped) == 5
        assert len(passed) == 0

    def test_rerun_skipped_test(self, testdir):
        """Verify that can rerun skipped test 5 times."""
        test_file = testdir.makepyfile("""
                                          import pytest
                                          def test_fake_pass():
                                              pytest.skip("For test")
                                              assert 1/1 == 1
                                       """)
        result = testdir.inline_run("--multiple_run=5", test_file, plugins=[pytest_multiple_run])
        passed, skipped, failed = result.listoutcomes()
        assert len(failed) == 0
        assert len(skipped) == 5
        assert len(passed) == 0

    def test_rerun_parametrizing_tests(self, testdir):
        """ Verify that can rerun parametrizing test 2 times."""
        test_file = testdir.makepyfile("""
                                          import pytest
                                          @pytest.mark.parametrize("input,expected", [
                                            ("3+5", 8),
                                            ("4-2", 2),
                                            ("6*9", 42)])
                                          def test_eval(input, expected):
                                                assert eval(input) == expected
                                       """)
        result = testdir.inline_run("--multiple_run=2", test_file, plugins=[pytest_multiple_run])
        passed, skipped, failed = result.listoutcomes()
        assert len(failed) == 2
        assert len(skipped) == 0
        assert len(passed) == 4

    def test_rerun_test_with_own_mark(self, testdir):
        """ Verify that can rerun test 2 times with own mark."""
        test_file = testdir.makepyfile("""
                                          import pytest

                                          @pytest.mark.marker
                                          def test_fail():
                                                assert 1/1 == 0

                                          def test_pass():
                                                assert 1/1 == 1
                                       """)
        result = testdir.inline_run("--multiple_run=2", "-m marker", test_file, plugins=[pytest_multiple_run])
        passed, skipped, failed = result.listoutcomes()
        assert len(failed) == 2
        assert len(skipped) == 0
        assert len(passed) == 0

    def test_rerun_test_with_fixture(self, testdir):
        """ Verify that can rerun test 2 times with fixture."""
        test_file = testdir.makepyfile("""
                                          import pytest

                                          @pytest.fixture()
                                          def simple(request):
                                              return 1

                                          class TestFake():
                                              def test_fail(self, simple):
                                                  assert 1/simple == 0

                                              def test_pass(self):
                                                  assert 1/1 == 1
                                       """)
        result = testdir.inline_run("--multiple_run=2", test_file, plugins=[pytest_multiple_run])
        passed, skipped, failed = result.listoutcomes()
        assert len(passed) == 2
        assert len(skipped) == 0
        assert len(failed) == 2
