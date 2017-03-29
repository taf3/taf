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

"""``test_ab_parser.py``

"""

from utils.ab_parser import AbParser, AbAggregator

APACHEBENCH_OUTPUT_1 = """
This is ApacheBench, Version 2.3 <$Revision: 1748469 $>
Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
Licensed to The Apache Software Foundation, http://www.apache.org/

Benchmarking 10.100.90.2 (be patient)


Server Software:        nginx/1.8.1
Server Hostname:        10.100.90.2
Server Port:            80

Document Path:          /4_mb_file
Document Length:        4158056 bytes

Concurrency Level:      10
Time taken for tests:   43.941 seconds
Complete requests:      999
Failed requests:        0
Total transferred:      4154151690 bytes
HTML transferred:       4153897944 bytes
Requests per second:    22.74 [#/sec] (mean)
Time per request:       439.848 [ms] (mean)
Time per request:       43.985 [ms] (mean, across all concurrent requests)
Transfer rate:          92323.99 [Kbytes/sec] received

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        1    5   2.3      4      36
Processing:   211  434  77.6    428     975
Waiting:        1    5   5.8      4      55
Total:        213  438  78.2    433     983

Percentage of the requests served within a certain time (ms)
  50%    433
  66%    455
  75%    471
  80%    482
  90%    526
  95%    564
  98%    622
  99%    712
 100%    983 (longest request)
"""

APACHEBENCH_OUTPUT_2 = """
This is ApacheBench, Version 2.3 <$Revision: 1748469 $>
Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
Licensed to The Apache Software Foundation, http://www.apache.org/

Benchmarking 10.100.71.2 (be patient)


Server Software:        nginx/1.8.1
Server Hostname:        10.100.71.2
Server Port:            80

Document Path:          /4_mb_file
Document Length:        4158056 bytes

Concurrency Level:      10
Time taken for tests:   24.851 seconds
Complete requests:      999
Failed requests:        0
Total transferred:      4154151690 bytes
HTML transferred:       4153897944 bytes
Requests per second:    40.20 [#/sec] (mean)
Time per request:       248.762 [ms] (mean)
Time per request:       24.876 [ms] (mean, across all concurrent requests)
Transfer rate:          163242.62 [Kbytes/sec] received

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        1    4   1.2      4      10
Processing:   115  244  42.1    240     462
Waiting:        1    5   3.0      4      38
Total:        119  248  42.0    243     467

Percentage of the requests served within a certain time (ms)
  50%    243
  66%    261
  75%    272
  80%    279
  90%    298
  95%    313
  98%    349
  99%    374
 100%    467 (longest request)
"""


class TestAbParser(object):

    def test_parsing_of_single_ab_output(self):
        ab_parser = AbParser()

        ab_parsed = ab_parser.parse(APACHEBENCH_OUTPUT_1)

        assert ab_parsed == {
            'complete_requests': '999',
            'concurency_level': '10',
            'connect_times': {
                'max': '36',
                'mean': '5',
                'median': '4',
                'min': '1',
                'sd': '2.3',
            },
            'document_length': '4158056',
            'document_path': '/4_mb_file',
            'failed_requests': '0',
            'html_transferred': '4153897944',
            'processing_times': {
                'max': '975',
                'mean': '434',
                'median': '428',
                'min': '211',
                'sd': '77.6',
            },
            'requests_per_second': '22.74',
            'server_hostname': '10.100.90.2',
            'server_port': '80',
            'server_software': 'nginx/1.8.1',
            'time_per_request_mean': '439.848',
            'time_per_request_mean_all': '43.985',
            'time_taken_for_tests': '43.941',
            'total_times': {
                'max': '983',
                'mean': '438',
                'median': '433',
                'min': '213',
                'sd': '78.2',
            },
            'total_transferred': '4154151690',
            'transfer_rate': '92323.99',
            'waiting_times': {
                'max': '55',
                'mean': '5',
                'median': '4',
                'min': '1',
                'sd': '5.8',
            },
        }

    def test_aggregation(self):
        parser = AbParser()
        aggregator = AbAggregator()
        aggregator += parser.parse(APACHEBENCH_OUTPUT_1)
        aggregator += parser.parse(APACHEBENCH_OUTPUT_2)

        expected_result = {
            'complete_requests': 1998,
            'concurency_level': 20,
            'connect_times': {'max': 36.0, 'min': 1.0},
            'document_length': '4158056',
            'document_path': '/4_mb_file',
            'failed_requests': 0,
            'html_transferred': 8307795888,
            'number_of_clients': 2,
            'processing_times': {'max': 975.0, 'min': 115.0},
            'requests_per_second': 62.94,
            'server_port': '80',
            'server_software': 'nginx/1.8.1',
            'time_taken_for_tests': 68.792,
            'total_times': {'max': 983.0, 'min': 119.0},
            'total_transferred': 8308303380,
            'transfer_rate': 255566.61,
            'waiting_times': {'max': 55.0, 'min': 1.0},
        }

        assert aggregator == expected_result
