"""
@copyright Copyright (c) 2016 - 2017, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file: ab_parser.py

"""

import io
import re
from collections import defaultdict, ChainMap
from pprint import pformat
from testlib.helpers import merge_dicts


class Ab(object):

    TIMES_FIELDS = ('min', 'mean', 'sd', 'median', 'max')

    @classmethod
    def store_connection_times(cls, dictionary, key, match):
        dictionary[key] = {}
        for subkey, value in zip(cls.TIMES_FIELDS, match.groups()):
            dictionary[key][subkey] = value


class AbParser(object):
    NOT_WHITE_SPACE = r'\S+'
    WHITE_SPACE = r'\s+'
    FLOAT_NUMBER = r'\S+'
    EOL = r'$'

    SECONDS = r'seconds'
    RECEIVED = r'received'
    BYTES = r'bytes'
    NUMBER_PER_SEC = r'\[\#/sec\]'
    KILOBYTES_PER_SEC = r'\[Kbytes/sec\]'
    MILISECONDS = r'\[ms\]'
    MEAN = r'\(mean\)'
    MEAN_ALL = r'\(mean, across all concurrent requests\)'

    GROUP_VALUE = r'({})'.format(NOT_WHITE_SPACE)

    LINE_FRAME = r'^{keyword}:{cls.WHITE_SPACE}{regexp}{cls.EOL}'
    VALUE_BYTES = WHITE_SPACE.join([GROUP_VALUE, BYTES])

    GROUP_FLOAT_NUMBER = r'({})'.format(FLOAT_NUMBER)
    CONNECTION_TIMES_GROUPS = ((GROUP_FLOAT_NUMBER + WHITE_SPACE) * 4 + GROUP_FLOAT_NUMBER) + EOL

    KEYWORD_VALUE_MAPPING = (
        # tag, regexp, dict key, setter function
        ('Server Software', GROUP_VALUE, 'server_software', None),
        ('Server Hostname', GROUP_VALUE, 'server_hostname', None),
        ('Server Port', GROUP_VALUE, 'server_port', None),
        ('Document Path', GROUP_VALUE, 'document_path', None),
        ('Concurrency Level', GROUP_VALUE, 'concurency_level', None),
        ('Complete requests', GROUP_VALUE, 'complete_requests', None),
        ('Failed requests', GROUP_VALUE, 'failed_requests', None),
        ('Non-2xx responses', GROUP_VALUE, 'non-2xx_responses', None),
        ('Document Length', VALUE_BYTES, 'document_length', None),
        ('Total transferred', VALUE_BYTES, 'total_transferred', None),
        ('HTML transferred', VALUE_BYTES, 'html_transferred', None),
        ('Time taken for tests', WHITE_SPACE.join([GROUP_VALUE, SECONDS]), 'time_taken_for_tests', None),
        ('Requests per second', WHITE_SPACE.join([GROUP_VALUE, NUMBER_PER_SEC, MEAN]), 'requests_per_second', None),
        ('Time per request', WHITE_SPACE.join([GROUP_VALUE, MILISECONDS, MEAN]), 'time_per_request_mean', None),
        ('Time per request', WHITE_SPACE.join([GROUP_VALUE, MILISECONDS, MEAN_ALL]), 'time_per_request_mean_all', None),
        ('Transfer rate', WHITE_SPACE.join([GROUP_VALUE, KILOBYTES_PER_SEC, RECEIVED]), 'transfer_rate', None),
        ('Connect', CONNECTION_TIMES_GROUPS, 'connect_times', Ab.store_connection_times),
        ('Processing', CONNECTION_TIMES_GROUPS, 'processing_times', Ab.store_connection_times),
        ('Waiting', CONNECTION_TIMES_GROUPS, 'waiting_times', Ab.store_connection_times),
        ('Total', CONNECTION_TIMES_GROUPS, 'total_times', Ab.store_connection_times),
    )

    TOKENS = []

    @classmethod
    def _set_class_attrs(cls):
        for keyword, regexp, key, func in cls.KEYWORD_VALUE_MAPPING:
            cls.TOKENS.append(
                [
                    re.compile(cls.LINE_FRAME.format(cls=cls, keyword=keyword, regexp=regexp)),
                    key,
                    func
                ]
            )

    def __init__(self):
        super().__init__()
        AbParser._set_class_attrs()
        self.ab_output = {}

    def parse(self, input_buffer):
        string_io = io.StringIO(input_buffer)

        self.ab_output = {}
        for line in iter(string_io.readline, ''):
            for regexp, key, setter in self.TOKENS:
                matches = regexp.match(line)
                if not matches:
                    continue

                if setter is None:
                    self.ab_output[key] = matches.group(1)
                else:
                    setter(self.ab_output, key, matches)

                break

        return self.ab_output


def num(s):
    try:
        return int(s)
    except ValueError:
        return float(s)


class AbAggregator(object):

    FIX_KEYS = [
        'server_software',
        'server_port',
        'document_path',
        'document_length',
        'server_hostname',
    ]

    KEYS_TO_ADD = [
        'number_of_clients',
        'complete_requests',
        'failed_requests',
        'non-2xx_responses',
        'total_transferred',
        'html_transferred',
        'requests_per_second',
        'concurency_level',
        'time_taken_for_tests',
        'transfer_rate',
    ]

    TIMES_KEYS = [
        'connect_times',
        'processing_times',
        'waiting_times',
        'total_times',
    ]

    IGNORE = [
        'time_per_request_mean',
        'time_per_request_mean_all',
        'server_hostname',
    ]

    KEY_FUNC_MAPPING = {}

    @staticmethod
    def min_max_default():
        return {'min': float('inf'), 'max': 0}

    @classmethod
    def _set_mappings(cls):
        for key in cls.FIX_KEYS:
            cls.KEY_FUNC_MAPPING[key] = cls._normal_assignment
        for key in cls.KEYS_TO_ADD:
            cls.KEY_FUNC_MAPPING[key] = cls._int_addition
        for key in cls.TIMES_KEYS:
            cls.KEY_FUNC_MAPPING[key] = cls._min_max_eval
        for key in cls.IGNORE:
            cls.KEY_FUNC_MAPPING[key] = cls._no_op

    def __init__(self):
        super().__init__()
        AbAggregator._set_mappings()
        self._status = {}
        self._add_status = defaultdict(int)
        self._min_max_status = defaultdict(self.min_max_default)
        self.status = ChainMap(self._status,
                               self._add_status,
                               self._min_max_status)

    def _int_addition(self, key, value):
        self._add_status[key] += num(value)

    def _min_max_eval(self, key, value):
        status = self._min_max_status[key]
        status['min'] = min(status['min'], float(value['min']))
        status['max'] = max(status['max'], float(value['max']))

    def _normal_assignment(self, key, value):
        self._status[key] = value

    def _no_op(self, key, value):
        pass

    def __iadd__(self, item):
        self._int_addition('number_of_clients', 1)
        for key, value in item.items():
            self.KEY_FUNC_MAPPING[key](self, key, value)
        return self

    @property
    def dictionary(self):
        return merge_dicts(*self.status.maps)

    def __eq__(self, other):
        return self.dictionary == other

    def to_str(self):
        return pformat(self.dictionary)

    def __str__(self):
        return self.to_str()

    def __repr__(self):
        return self.to_str()
