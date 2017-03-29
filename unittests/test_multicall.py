#!/usr/bin/env python
# Copyright (c) 2015 - 2017, Intel Corporation.
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

"""``test_multicall.py``

`Test Multicall`

"""
from testlib import multicall


class TestMultiCall(object):

    def test_original_list_if_small_enough(self):
        payload_gen = list
        res = multicall.bisect_if_too_large(list(range(4096)), payload_gen)
        assert res == [payload_gen(list(range(4096)))]

    def test_individual_element_lists_in_worst_case(self):
        payload_gen = list
        res = multicall.bisect_if_too_large(list(range(40)), payload_gen, 1)
        res = list(res)
        assert len(res) == len(list(range(40)))
        assert res == [payload_gen([x]) for x in range(40)]

    def test_single_split(self):
        payload_gen = list
        res = multicall.bisect_if_too_large(list(range(4096)), payload_gen, 2049)
        res = list(res)
        assert len(res) == 2
        assert res == [payload_gen(list(range(2048))), payload_gen(list(range(2048, 4096)))]
