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

"""``test_pwsw.py``

`Unittests powerboard functions`

"""

import pytest

from testlib import powerboard

host = '127.0.0.1'
port = '12'
rw_community_string = 'private'


@pytest.mark.skipif("True", reason="Test case skipped by 'skiptest' marker")
def test_pwsw1():
    status = powerboard.get_status(host, port, rw_community_string)
    if status == "On":
        powerboard.do_action(host, port, rw_community_string, powerboard.commands["Reset"])
    elif status == "Off":
        powerboard.do_action(host, port, rw_community_string, powerboard.commands["On"])
    else:
        raise Exception("Cannot determine device status.")
