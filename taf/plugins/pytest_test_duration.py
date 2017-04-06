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

"""``pytest_test_duration.py``

`Plugin is controlling test execution by time or count of iteration`

"""

import re
import pytest
import datetime


_PLUGIN_NAME = "_test_duration"


def pytest_addoption(parser):
    """Plugin specific options.

    """
    group = parser.getgroup("Test duration", "plugin test duration")
    group.addoption("--test_duration", action="store", default=None,
                    help="Set time to control long-run tests where is used 'duration' fixture."
                         "E.g. --test_duration=30s, --test_duration=1.5H")


def pytest_configure(config):
    """Registering plugin.

    """
    config.pluginmanager.register(TestDurationPlugin(), _PLUGIN_NAME)


def pytest_unconfigure(config):
    """Unregistering plugin.

    """
    dur = getattr(config, _PLUGIN_NAME, None)
    if dur:
        del config.test_duration
        config.pluginmanager.unregister(dur)


class Duration(object):
    """Main functionality for test duration manipulation.

    """

    def __init__(self, option=None):
        """Initialize Duration object instance.

        Args:
            option(str, e.g "30s", "2.5H"): time to interrupt test(cmd option)

        """
        self.opt_duration = self._parse_and_define_delta_time(option)

    def _parse_and_define_delta_time(self, timing):
        """Parse time string.

        Args:
            timing(str, e.g "30s", "2.5H"): time to interrupt test

        """
        if timing:
            time_int = re.search(r'^\d+', timing)
            time_type = re.search(r'[s,h,m,S,H,M]', timing)
            time_float = re.search(r'[.]', timing)
            test_number = None
            if time_float and time_type:
                time_number_float = re.search(r'\d+\.\d+', timing)
                test_number = float(time_number_float.group())
            elif time_int and time_type:
                test_number = int(time_int.group())
            if test_number:
                if time_type.group().lower().startswith('s'):
                    return datetime.timedelta(seconds=test_number)
                elif time_type.group().lower().startswith('m'):
                    return datetime.timedelta(minutes=test_number)
                elif time_type.group().lower().startswith('h'):
                    return datetime.timedelta(hours=test_number)

    def control_duration(self, timing=None, count=None):
        """Control duration test by timing, option or count.

        Args:
            timing(str, e.g "30s", "2.5H"): time to interrupt test
            count(int|float): interrupt test after iterated count

        """
        default_duration = self._parse_and_define_delta_time(timing)
        current_time = datetime.datetime.now()
        if self.opt_duration and default_duration:
            expire_time = current_time + min(self.opt_duration, default_duration)
        elif default_duration:
            expire_time = current_time + default_duration
        elif self.opt_duration:
            expire_time = current_time + self.opt_duration
        elif count:
            expire_time = 0
            if count < 1:
                count = 1
            elif isinstance(count, float):
                count = int(count)
        else:
            count = 1

        inner_count = 1
        while True:
            duration = datetime.datetime.now() - current_time
            yield inner_count, duration.total_seconds()
            inner_count += 1
            if count and inner_count >= count + 1:
                break
            if expire_time and datetime.datetime.now() >= expire_time:
                break


class TestDurationPlugin(object):
    """TestDurationPlugin implementation.

    """

    @pytest.fixture
    def duration(self, request):
        """Initialize Duration fixture.

        """
        return Duration(request.config.option.test_duration)
