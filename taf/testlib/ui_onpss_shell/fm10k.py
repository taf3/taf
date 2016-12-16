#!/usr/bin/env python
"""
@copyright Copyright (c) 2015 - 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  fm10k.py

@summary  UiOnpssShell specific FM10K commands
"""


def gen_cpu_rate_limiting_command(daemon, log_file):
    return "nohup {0} -c </dev/null &>{1} &".format(daemon, log_file)