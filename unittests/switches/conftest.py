"""
@copyright Copyright (c) 2011 - 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  conftest.py

@summary  test switches common options.
"""


def pytest_addoption(parser):
    """
    @brief  TAF specific options
    """
    parser.addoption("--build_path", action="store", default="/home",
                     help="Path to build, '%default' by default.")
    parser.addoption("--ui", action="store", default="ons_xmlrpc",
                     choices=["ons_xmlrpc", "ons_cli", "onpss_shell"],
                     help="User Interface to configure switch (ons_xmlrpc | ons_cli | onpss_shell). '%default' by default.")
