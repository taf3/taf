"""
@copyright Copyright (c) 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file test_tc_duration.py

@summary Unittests for pytest_test_duration plugin.
"""

from plugins.pytest_test_duration import Duration


class TestCountTiming(object):
    """
    Class verifies count and timing parameters of test duration.
    """
    def test_timing_less_than_count(self):
        """
        Verify that test ends after value of timing when timing less than time of count is passed.
        """
        duration = Duration()
        test_time = 1
        iter_time = 0
        test_count = 10000000
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time), count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time + 1:
                break
        # Verify that test ends after 1 second.
        assert test_time * 0.97 <= iter_time <= test_time * 1.02

    def test_count_less_than_timing(self):
        """
        Verify that test ends after value of count when time of count less than timing is passed.
        """
        duration = Duration()
        test_time = 1
        test_count = 10
        iter_count = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time), count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time + 1:
                break
        # Verify that test ends after 10 iterated count.
        assert iter_count == test_count

    def test_count_when_timing_zero(self):
        """
        Verify that test ends after value of count when zero value of timing is passed.
        """
        duration = Duration()
        test_time = 0
        test_count = 10
        iter_count = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time), count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time + 1:
                break
        # Verify that test ends after 10 iterated count.
        assert iter_count == test_count

    def test_timing_when_count_zero(self):
        """
        Verify that test ends after value of timing when zero value of count is passed.
        """
        duration = Duration()
        test_time = 1
        test_count = 0
        iter_time = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time), count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time + 1:
                break
        # Verify that test ends after 1 second.
        assert test_time * 0.97 <= iter_time <= test_time * 1.02

    def test_timing_second(self):
        """
        Verify that test ends after value of timing when timing is passed.
        """
        duration = Duration()
        test_time = 1
        iter_time = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time)):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time + 1:
                break
        # Verify that test ends after 1 second.
        assert test_time * 0.97 <= iter_time <= test_time * 1.02

    def test_timing_zero(self):
        """
        Verify that test ends after 1 count when zero value of timing is passed.
        """
        duration = Duration()
        test_time = 0
        iter_count = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time)):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time + 1:
                break
        # Verify that test ends after 1 iterated count.
        assert iter_count == 1

    def test_timing_negative(self):
        """
        Verify that test ends after 1 count when negative value of timing is passed.
        """
        duration = Duration()
        test_time = -1
        iter_count = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time)):
            # if test goes into an endless loop interrupt test
            if iter_time >= 1:
                break
        # Verify that test ends after 1 iterated count.
        assert iter_count == 1

    def test_timing_float(self):
        """
        Verify that test ends after value of timing when float value of timing is passed.
        """
        duration = Duration()
        test_time = 2.5
        iter_time = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time)):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time + 1:
                break
        # Verify that test ends after 2.5 seconds.
        assert test_time * 0.97 <= iter_time <= test_time * 1.02

    def test_nonexistent_time(self):
        """
        Verify that test ends after 1 count when timing by nonexistent time is passed.
        """
        duration = Duration()
        test_time = 1
        iter_count = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}k'.format(test_time)):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time + 1:
                break
        # Verify that test ends after 1 iterated count.
        assert iter_count == 1

    def test_no_parameter(self):
        """
        Verify that test ends after 1 count when no parameter is passed.
        """
        duration = Duration()
        iter_count = 0
        # run test
        for iter_count, iter_time in duration.control_duration():
            # if test goes into an endless loop interrupt test
            if iter_time >= 1:
                break
        # Verify that test ends after 1 iterated count.
        assert iter_count == 1

    def test_count(self):
        """
        Verify that test ends after value of count when count is passed.
        """
        duration = Duration()
        test_count = 1
        iter_count = 0
        # run test
        for iter_count, iter_time in duration.control_duration(count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= 1:
                break
        # Verify that test ends after 1 iterated count.
        assert iter_count == test_count

    def test_count_zero(self):
        """
        Verify that test ends after 1 count when zero value of count is passed.
        """
        duration = Duration()
        test_count = 0
        iter_count = 0
        # run test
        for iter_count, iter_time in duration.control_duration(count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= 1:
                break
        # Verify that test ends after 1 iterated count.
        assert iter_count == 1

    def test_count_negative(self):
        """
        Verify that test ends after 1 count when negative value of count is passed.
        """
        duration = Duration()
        test_count = -1
        iter_count = 0
        # run test
        for iter_count, iter_time in duration.control_duration(count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= 1:
                break
        # Verify that test ends after 1 iterated count.
        assert iter_count == 1

    def test_count_float(self):
        """
        Verify that test ends after integer value of count when float value of count is passed.
        """
        duration = Duration()
        test_count = 2.5
        iter_count = 0
        # run test
        for iter_count, iter_time in duration.control_duration(count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= 1:
                break
        # Verify that test ends after 2 iterated count.
        assert iter_count == int(test_count)


class TestOptionCountTiming(object):
    """
    Class verifies count, timing and option parameters of test duration.
    """
    def test_option_second(self):
        """
        Verify that test ends after value of option when option is passed.
        """
        test_time_option = 1
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_time = 0
        # run test
        for iter_count, iter_time in duration.control_duration():
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time_option + 1:
                break
        # Verify that test ends after 1 second.
        assert test_time_option * 0.97 <= iter_time <= test_time_option * 1.02

    def test_option_zero(self):
        """
        Verify that test ends after 1 count when zero value of option is passed.
        """
        test_time_option = 0
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_count = 0
        # run test
        for iter_count, iter_time in duration.control_duration():
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time_option + 1:
                break
        # Verify that test ends after 1 iterated count.
        assert iter_count == 1

    def test_option_float(self):
        """
        Verify that test ends after value of option when float value of option is passed.
        """
        test_time_option = 2.5
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_time = 0
        # run test
        for iter_count, iter_time in duration.control_duration():
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time_option + 1:
                break
        # Verify that test ends after 2.5 seconds.
        assert test_time_option * 0.97 <= iter_time <= test_time_option * 1.02

    def test_option_negative(self):
        """
        Verify that test ends after 1 count when negative value of option is passed.
        """
        test_time_option = -1
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_count = 0
        # run test
        for iter_count, iter_time in duration.control_duration():
            # if test goes into an endless loop interrupt test
            if iter_time >= 1:
                break
        # Verify that test ends after 1 iterated count.
        assert iter_count == 1

    def test_timing_less_than_option(self):
        """
        Verify that test ends after value of timing when timing less than option is passed.
        """
        test_time_option = 2
        test_time = 1
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_time = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time)):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time + 1:
                break
        # Verify that test ends after 1 second.
        assert test_time * 0.97 <= iter_time <= test_time * 1.02

    def test_timing_when_option_zero(self):
        """
        Verify that test ends after value of timing when zero value of option is passed.
        """
        test_time_option = 0
        test_time = 1
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_time = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time)):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time + 1:
                break
        # Verify that test ends after 1 second.
        assert test_time * 0.97 <= iter_time <= test_time * 1.02

    def test_option_less_than_timing(self):
        """
        Verify that test ends after value of option when option less than timing is passed.
        """
        test_time_option = 1
        test_time = 2
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_time = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time)):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time_option + 1:
                break
        # Verify that test ends after 1 second.
        assert test_time_option * 0.97 <= iter_time <= test_time_option * 1.02

    def test_option_when_timing_zero(self):
        """
        Verify that test ends after value of option when zero value of timing is passed.
        """
        test_time_option = 1
        test_time = 0
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_time = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time)):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time_option + 1:
                break
        # Verify that test ends after 1 second.
        assert test_time_option * 0.97 <= iter_time <= test_time_option * 1.02

    def test_option_less_than_count(self):
        """
        Verify that test ends after value of option when option less than time of count is passed.
        """
        test_time_option = 1
        test_count = 1000000
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_time = 0
        # run test
        for iter_count, iter_time in duration.control_duration(count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time_option + 1:
                break
        # Verify that test ends after 1 second.
        assert test_time_option * 0.97 <= iter_time <= test_time_option * 1.02

    def test_count_less_than_option(self):
        """
        Verify that test ends after value of count when time of count less than option is passed.
        """
        test_time_option = 1
        test_count = 10
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_count = 0
        # run test
        for iter_count, iter_time in duration.control_duration(count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time_option + 1:
                break
        # Verify that test ends after 10 iterated counts.
        assert iter_count == test_count

    def test_option_when_count_zero(self):
        """
        Verify that test ends after value of option when zero value of count is passed.
        """
        test_time_option = 1
        test_count = 0
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_time = 0
        # run test
        for iter_count, iter_time in duration.control_duration(count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time_option + 1:
                break
        # Verify that test ends after 1 second.
        assert test_time_option * 0.97 <= iter_time <= test_time_option * 1.02

    def test_count_when_option_zero(self):
        """
        Verify that test ends after value of count when zero value of option is passed.
        """
        test_time_option = 0
        test_count = 10
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_count = 0
        # run test
        for iter_count, iter_time in duration.control_duration(count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= 1:
                break
        # Verify that test ends after 10 counts.
        assert iter_count == test_count

    def test_count_less_than_option_and_timing(self):
        """
        Verify that test ends after value of count when count less than option and timing is passed.
        """
        test_time_option = 1
        test_time = 2
        test_count = 1
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_count = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time), count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time_option + 1:
                break
        # Verify that test ends after 1 iterated count.
        assert iter_count == test_count

    def test_option_less_timing_and_count(self):
        """
        Verify that test ends after value of option when option less than timing and count is passed.
        """
        test_time_option = 1
        test_time = 2
        test_count = 1000000
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_time = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time), count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time_option + 1:
                break
        # Verify that test ends after 1 second.
        assert test_time_option * 0.97 <= iter_time <= test_time_option * 1.02

    def test_timing_less_than_option_and_count(self):
        """
        Verify that test ends after value of timing when timing less than option and count is passed.
        """
        test_time_option = 2
        test_time = 1
        test_count = 1000000
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_time = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time), count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time + 1:
                break
        # Verify that test ends after 1 second.
        assert test_time * 0.97 <= iter_time <= test_time * 1.02

    def test_option_when_timing_and_count_zero(self):
        """
        Verify that test ends after value of option when zero value of timing and count is passed.
        """
        test_time_option = 1
        test_time = 0
        test_count = 0
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_time = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time), count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time_option + 1:
                break
        # Verify that test ends after 1 second.
        assert test_time_option * 0.97 <= iter_time <= test_time_option * 1.02

    def test_timing_when_option_and_count_zero(self):
        """
        Verify that test ends after value of timing when zero value of option and count is passed.
        """
        test_time_option = 0
        test_time = 1
        test_count = 0
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_time = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time), count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= test_time + 1:
                break
        # Verify that test ends after 1 second.
        assert test_time * 0.97 <= iter_time <= test_time * 1.02

    def test_count_when_timing_and_option_zero(self):
        """
        Verify that test ends after value of count when zero value of option and timing is passed.
        """
        test_time_option = 0
        test_time = 0
        test_count = 2
        duration = Duration(option='{0}s'.format(test_time_option))
        iter_count = 0
        # run test
        for iter_count, iter_time in duration.control_duration(timing='{0}s'.format(test_time), count=test_count):
            # if test goes into an endless loop interrupt test
            if iter_time >= 1:
                break
        # Verify that test ends after 1 count.
        assert iter_count == test_count
