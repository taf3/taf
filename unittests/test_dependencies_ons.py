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

@file  test_dependencies_ons.py

@summary  Unittests for dependencies functions.
"""

import pytest


def check_module_name_error_status(module_name):
    """
    @brief  The function return True if name error is present in module during importing
    """
    try:
        __import__("testlib.%s" % module_name)
    except NameError:
        return True
    except Exception:
        return False
    else:
        return False


def test_import_helpers_module():
    """
    @brief  Verify that all modules can be imported within 'helpers' module and classes objects can be created
    """
    module_name = "helpers"
    try:
        # define test data
        def assertion_error_func():
            """
            @brief  Assertion error
            """
            assert 0

        from testlib import helpers
        helpers.raises(AssertionError, "", assertion_error_func)
    except ImportError as err:
        pytest.fail("Import failure in '%s' module: %s" % (module_name, err))


def test_import_dev_staticcross_ons_module():
    """
    @brief  Verify that all modules can be imported within 'dev_staticcross_ons' module and classes objects can be created
    """
    module_name = "dev_staticcross_ons"
    try:
        # define parameters for object constructor
        config = {'instance_type': None, 'id': None}

        from testlib import dev_staticcross_ons
        dev_staticcross_ons.StaticCrossONS(config, None)
    except ImportError as err:
        pytest.fail("Import failure in '%s' module: %s" % (module_name, err))


def test_import_dev_switches_module():
    """
    @brief  Verify that all modules can be imported within 'dev_switches' module and classes objects can be created
    """
    class FakeOpts(object):
        """
        @brief  FakeOpts class
        """
        def __init__(self):
            """
            @brief  Initialize FakeOpts class
            """
            self.build_path = ""
            self.get_only = None
            self.ui = 'ons_xmlrpc'

    module_name = "dev_switches"
    try:
        # define parameters for object constructor
        config = {'instance_type': None, 'id': None, "ip_host": "1.1.1.1", "ip_port": 22, "ports_count": 0,
                  "related_conf": {}, 'cli_user': "", 'cli_user_passw': "", "cli_user_prompt": "", "cli_img_path": "",
                  "ver": "", 'pwboard_host': "", 'pwboard_port': "", 'default_gw': "", "net_mask": "", 'sshtun_port': "",
                  "sshtun_user": "", "sshtun_pass": ""}

        from testlib import switch_general
        switch_general.SwitchReal(config, FakeOpts())

        from testlib import switch_userver
        switch_userver.SwitchUServer(config, FakeOpts())

    except ImportError as err:
        pytest.fail("Import failure in '%s' module: %s" % (module_name, err))
