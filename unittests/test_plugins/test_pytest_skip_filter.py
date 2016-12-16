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

@file test_skip_filter.py

@summary Unittests for pytest_skip_filter plugin.
"""
from collections import namedtuple

import pytest

from plugins import pytest_skip_filter


SIMPLE_SKIP = """
                  import pytest

                  def test_fail():
                      assert 0

                  def test_pass():
                      assert 1

                  @pytest.mark.skipif("True", reason="Skip")
                  def test_skip():
                      assert 1
               """

CLASS_SIMPLE_SKIP = """
                      import pytest

                      class TestClass(object):
                          def test_fail(self):
                              assert 0

                          def test_pass(self):
                              assert 1

                          @pytest.mark.skipif("True", reason="Skip")
                          def test_skip(self):
                              assert 1
                   """

CLASS_DOUBLE_SKIP_FUNCTION_LEVEL = """
                                      import pytest

                                      class TestClass(object):
                                          def test_fail(self):
                                              assert 0

                                          def test_pass(self):
                                              assert 1

                                          @pytest.mark.skipif("True", reason="Skip")
                                          @pytest.mark.skipif("False", reason="Skip")
                                          def test_skip(self):
                                              assert 1
                                   """

CLASS_DOUBLE_SKIP_CLASS_LEVEL_1 = """
                                   import pytest

                                   @pytest.mark.skipif("True", reason="Skip")
                                   class TestClass(object):
                                       def test_fail(self):
                                           assert 0

                                       def test_pass(self):
                                           assert 1

                                       @pytest.mark.skipif("False", reason="Skip")
                                       def test_skip(self):
                                           assert 1
                                """

CLASS_DOUBLE_SKIP_CLASS_LEVEL_2 = """
                                   import pytest

                                   @pytest.mark.skipif("True", reason="Skip")
                                   @pytest.mark.skipif("False", reason="Skip")
                                   class TestClass(object):
                                       def test_fail(self):
                                           assert 0

                                       def test_pass(self):
                                           assert 1

                                       def test_skip(self):
                                           assert 1
                                """

CLASS_PARAMETRIZE_SKIP_1 = """
                              import pytest

                              class TestClass(object):
                                  def test_fail(self):
                                      assert 0

                                  def test_pass(self):
                                      assert 1

                                  @pytest.mark.skipif("True", reason="Skip")
                                  @pytest.mark.parametrize("a", [1,2])
                                  def test_skip(self, a):
                                      assert a == 2
                           """

CLASS_PARAMETRIZE_SKIP_2 = """
                              import pytest

                              class TestClass(object):
                                  def test_fail(self):
                                      assert 0

                                  def test_pass(self):
                                      assert 1

                                  @pytest.mark.parametrize("a", [1,pytest.mark.skipif("True", reason="Skip")(2)])
                                  def test_skip(self, a):
                                      assert a == 2
                           """

CLASS_PARAMETRIZE_SKIP_3 = """
                              import pytest

                              class TestClass(object):
                                  def test_fail(self):
                                      assert 0

                                  def test_pass(self):
                                      assert 1

                                  @pytest.mark.skipif("True", reason="Skip")
                                  @pytest.mark.parametrize("a", [1,pytest.mark.skipif("False", reason="Skip")(2)])
                                  def test_skip(self, a):
                                      assert a == 2
                           """

CLASS_PARAMETRIZE_SKIP_4 = """
                              import pytest

                              @pytest.mark.skipif("True", reason="Skip")
                              class TestClass(object):
                                  def test_fail(self):
                                      assert 0

                                  def test_pass(self):
                                      assert 1

                                  @pytest.mark.parametrize("a", [1,pytest.mark.skipif("False", reason="Skip")(2)])
                                  def test_skip(self, a):
                                      assert a == 2
                           """


class TestPluginSkipFilter(object):

    argnames = (
        "name",
        "file_text",
        "counts",
    )

    Param = namedtuple("Param", argnames)

    argvalues = [
        Param(
            name="test_skip_test",
            file_text=SIMPLE_SKIP, counts=[1, 0, 1]),
        Param(
            name="test_skip_in_class",
            file_text=CLASS_SIMPLE_SKIP, counts=[1, 0, 1]),
        Param(
            name="test_double_skip_in_class",
            file_text=CLASS_DOUBLE_SKIP_FUNCTION_LEVEL, counts=[1, 0, 1]),
        Param(
            name="test_double_skip_class_level_1",
            file_text=CLASS_DOUBLE_SKIP_CLASS_LEVEL_1, counts=[0, 0, 0]),
        Param(
            name="test_double_skip_class_level_2",
            file_text=CLASS_DOUBLE_SKIP_CLASS_LEVEL_2, counts=[0, 0, 0]),
        Param(
            name="test_parametrize_skip_1",
            file_text=CLASS_PARAMETRIZE_SKIP_1, counts=[1, 0, 1]),
        Param(
            name="test_parametrize_skip_2",
            file_text=CLASS_PARAMETRIZE_SKIP_2, counts=[1, 0, 2]),
        Param(
            name="test_parametrize_skip_3",
            file_text=CLASS_PARAMETRIZE_SKIP_3, counts=[1, 0, 1]),
        Param(
            name="test_parametrize_skip_4",
            file_text=CLASS_PARAMETRIZE_SKIP_4, counts=[0, 0, 0]),
    ]
    ids = [r.name for r in argvalues]

    @pytest.mark.parametrize(argnames, argvalues, ids=ids)
    def test_string_condition(self, testdir, name, file_text, counts):
        test_file = testdir.makepyfile(file_text)
        result = testdir.inline_run(test_file, plugins=[pytest_skip_filter])
        outcomes = result.listoutcomes()
        assert [len(x) for x in outcomes] == counts

    @pytest.mark.parametrize(argnames, argvalues, ids=ids)
    def test_boolean_condition(self, testdir, name, file_text, counts):
        """
        Test if we can use boolean conditions instead of string conditions
        """
        file_text = file_text.replace('"True"', 'True').replace('"False"', 'False')
        test_file = testdir.makepyfile(file_text)
        result = testdir.inline_run(test_file, plugins=[pytest_skip_filter])
        outcomes = result.listoutcomes()
        assert [len(x) for x in outcomes] == counts

    @pytest.mark.parametrize(argnames, argvalues, ids=ids)
    def test_boolean_config_getoption(self, testdir, name, file_text, counts):
        """
        Test if we can use pytest.config.getoption in a non-string condition
        """
        file_text = file_text.replace('"True"', 'pytest.config.getoption("nosuch", default=True)')
        file_text = file_text.replace('"False"', 'False')
        test_file = testdir.makepyfile(file_text)
        result = testdir.inline_run(test_file, plugins=[pytest_skip_filter])
        outcomes = result.listoutcomes()
        assert [len(x) for x in outcomes] == counts
