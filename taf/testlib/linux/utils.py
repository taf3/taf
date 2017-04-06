# Copyright (c) 2016 - 2017, Intel Corporation.
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

"""``utils.py``

"""
import time
import os
from contextlib import suppress


class TimerContext(object):

    def __init__(self, func=None):
        self.start = None
        self.end = None
        self.delta = None
        self.func = func

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, *args, **kwargs):
        self.end = time.time()
        self.delta = self.end - self.start
        if self.func:
            self.func(self)

    def __str__(self):
        return str(self.delta)


def create_directory(path):
    with suppress(FileExistsError):
        os.makedirs(path)


def recursive_format(container, kwargs):

    if isinstance(container, str):
        return container.format(**kwargs)

    if isinstance(container, list):
        return [recursive_format(item, kwargs) for item in container]

    if isinstance(container, dict):
        return {recursive_format(k, kwargs): recursive_format(v, kwargs)
                for k, v in container.items()}

    return container


class TimeoutExceeded(Exception):
    pass


def wait_for(iterator, timeout):
    for index in iterator:
        if index > timeout:
            raise TimeoutExceeded
        time.sleep(1)
