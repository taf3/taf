# # Comments are stripped during encoding for multicall
# @copyright Copyright (c) 2015 - 2016, Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# @file  remote_multicall_template.py
import json
from subprocess import Popen, PIPE
import itertools
import sys
import cgitb
import os
import resource

cgitb.enable(format="text")


def grouper_it(iterable, n):
    # Copied from http://stackoverflow.com/users/1052325/reclosedev 's modification
    # of http://stackoverflow.com/users/279627/sven-marnach 's answer
    #
    # http://stackoverflow.com/a/8998040
    it = iter(iterable)
    while True:
        chunk_it = itertools.islice(it, n)
        # look ahead to check for StopIteration
        try:
            first_el = next(chunk_it)
        except StopIteration:
            return
        yield itertools.chain((first_el,), chunk_it)


def main():
    # use number of open files soft limit and num cores to determinate Popen limit
    # use lesser of 4 * num cores or half max open files - 10
    default_parallel_limit = os.sysconf('SC_NPROCESSORS_ONLN') * 4
    parallel_limit = globals().get("parallel_limit", None)
    if parallel_limit is None:
        parallel_limit = default_parallel_limit
    parallel_limit = min(parallel_limit, (resource.getrlimit(resource.RLIMIT_NOFILE)[0] - 20) / 2)
    cmd_list = globals()["cmd_list"]
    results = list(multicall(cmd_list, parallel_limit))
    json.dump(results, sys.stdout)


def call(cmd):
    shell = True if hasattr(cmd, "strip") else False
    return Popen(cmd, stdout=PIPE, stderr=PIPE, shell=shell)


def multicall(cmd_list, chunk):
    for batch in grouper_it(cmd_list, chunk):
        started_procs = [(cmd, call(cmd)) for cmd in batch]
        for cmd, p in started_procs:
            out, err = p.communicate()
            yield (cmd, out.decode("utf-8"), err.decode("utf-8"), p.wait())


# __name__ is  __builtin__ when called remotely via exec
if __name__ in {"__main__", "__builtin__"}:
    main()
