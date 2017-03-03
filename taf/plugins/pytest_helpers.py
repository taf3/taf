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

"""``pytest_helpers.py``

`pytest specific helpers functions`

"""

import inspect
import re

from testlib import loggers

class_logger = loggers.ClassLogger()


def get_tcname(report):
    """Return TC name from pytest report object.

    Args:
        report(pytest.report): pytest report object

    Returns:
        str: test case name

    Note:
        This function allows to get proper name without parameters string from normal and parametrized TCs.

    """
    name = None
    full_name = report.nodeid.split("::")[-1]
    # split on first left bracket
    split = full_name.split('[', 1)
    # this works even if we have no left bracket
    before_bracket = split[0]
    try:
        after_bracket = split[1].rstrip(']')
        # normal paremetrize adds all args after id using '-' to separate
        params_list = after_bracket.split("-")
        # valid ids must start with "test_"
        # use list so we get IndexError
        name_from_param_otherwise_full_name = [x for x in params_list if "test_" in x][0]
    except IndexError:
        # this will occur if there are no dashes, or if we can't find test_
        name_from_param_otherwise_full_name = before_bracket

    if "unittests" in report.keywords:
        # only use full full name if unittest
        name = full_name
    else:
        # if we are parametrized or web_ui just use the name from inside the brackets
        #
        # metafunc will hide a 'parametrize' mark from the report.keywords so we get here
        # and randomly pick the first arg.  But this fails because
        # metafunc on top of parametrize prepends its argvalue
        #
        # don't just randomly pick the first argvalue use the name from param
        name = name_from_param_otherwise_full_name

    return name


def get_suite_name(nodeid):
    """Return suitename from nodeid string.

    Args:
        nodeid(str):  pytest.Item nodeid string

    Returns:
        str: test suite name

    """
    names = nodeid.split("::")
    names[0] = names[0].replace("/", '.')
    names = [x.replace(".py", "") for x in names if x != "()"]
    classnames = names[:-1]
    return ".".join(classnames)


def get_test_keys(data):
    """Return case keys from report string.

    Args:
        data(str):  test case results

    Returns:
        list[str]: list of report keys

    """
    keys_rules = re.compile('<success>(.*?)</success>')
    return keys_rules.findall(data)


def get_steps(item, tc_name):
    """Parse and return test steps.

    Args:
        item(pytest.Item):  pytest test case item
        tc_name(str):  test case name

    Returns:
        str: test case's steps

    """
    # Get source of test function
    steps_list = []
    steps_rules = re.compile(r'@steps([\s\S]*?)@endsteps')
    step_rules = re.compile('@step (.*?)\n')
    data = get_doc_from_item(item)
    # Split and strip steps from docstring
    for line in steps_rules.findall(data):
        steps_list.extend((x.strip() for x in line.splitlines() if x.strip()))
    steps_list.extend((x.strip() for x in step_rules.findall(data) if x))
    # join on empty list returns ''
    return '\n'.join(steps_list)


def get_doc_from_item(item):
    data = ''
    try:
        data = item.funcargs['doc'][0]
    except KeyError:
        try:
            data = item.funcargs['doc_string'][0]
        except KeyError:
            try:
                data = item.callspec.params["doc"][0]
            except (AttributeError, KeyError):
                data = inspect.getsource(item.function)
    return data


def get_brief(item, tc_name):
    """Parse doc-string and return brief.

    Args:
        item(pytest.Item):  pytest test case item
        tc_name(str):  test case name

    Returns:
        str: test case docstring's brief

    """
    brief = ''
    data = get_doc_from_item(item)
    brief_rules = re.compile('@brief (.*?)\n')
    brief_list = brief_rules.findall(str(data))
    try:
        if not brief_list:
            brief = str(data)[6:]
        else:
            brief = ('\n'.join(brief_list))
        return brief.strip()[:255]
    except IndexError:
        return ""


def get_failure_reason(data):
    """Return test case failure reason from report string.

    Args:
        data(str): test case report

    Returns:
        str: failure reason or None

    """
    try:
        reason_rules = re.compile('\nE    (.*)')
        return ('\n'.join(reason_rules.findall(data))).strip()
    except TypeError:
        return None


def get_skipped_reason(data):
    """Return test case skip reason from report string.

    Args:
        data(str): test case report

    Returns:
        str: skip reason or None

    """
    try:
        reason_rules = re.compile("Skipped:(.*?)..$")
        return ('\n'.join(reason_rules.findall(data))).strip()
    except TypeError:
        return None


def get_html_xml_path(path, build_name):
    """Parse and replace $BUILD_NAME variable in the path.

    Args:
        path(str):  path to html report
        build_name(str):  software build number

    Returns:
        str: modified path to html report

    """
    try:
        return path.replace("__BUILD_NAME__", build_name)
    except AttributeError:
        return "undetermined"
