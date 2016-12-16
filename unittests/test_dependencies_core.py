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

@file  test_dependencies_core.py

@summary  Unittests for dependencies core functions.
"""

import pytest

class FakeOpts(object):
    """
    @brief  FakeOpts class
    """
    def __init__(self):
        """
        @brief  Initialize FakeOpts class
        """
        self.setup = "path"
        self.env = None
        self.ui = 'ons_xmlrpc'
        self.lhost_ui = 'linux_bash'


def test_import_afs_module():
    """
    @brief  Verify that all modules can be imported within 'afs' module and 'AFS' object can be created
    """
    module_name = "afs"
    try:
        # define parameters for object constructor
        config = {'id': None, 'instance_type': None, 'portmap': None, 'ip_host': None, 'user': None, 'password': None}

        from testlib import afs
        afs.AFS(config)
    except ImportError as err:
        pytest.fail("Import failure in '%s' module: %s" % (module_name, err))


def test_import_afscross_module():
    """
    @brief  Verify that all modules can be imported within 'afs' module and 'AFS' object can be created
    """
    module_name = "afscross"
    try:
        # define parameters for object constructor
        config = {'id': None, 'instance_type': None, 'ip_host': None, 'user': None, 'password': None, 'portmap': None}

        from testlib import afscross
        afscross.AFS(config, None, None)
    except ImportError as err:
        pytest.fail("Import failure in '%s' module: %s" % (module_name, err))


def test_import_clicmd_module():
    """
    @brief  Verify that all modules can be imported within 'clicmd' module and 'CLICmd' object can be created
    """
    module_name = "clicmd_ons"
    try:
        from testlib import clicmd_ons
        clicmd_ons.CLICmd(None, None, None, None, None, None)
    except ImportError as err:
        pytest.fail("Import failure in '%s' module: %s" % (module_name, err))


def test_import_clissh_module():
    """
    @brief  Verify that all modules can be imported within 'clissh' module and 'CLISSH' object can be created
    """
    module_name = "clissh"
    try:
        from testlib import clissh

        clissh.CLISSH(None)
    except ImportError as err:
        pytest.fail("Import failure in '%s' module: %s" % (module_name, err))


def test_import_common3_module(monkeypatch):
    """
    @brief  Verify that all modules can be imported within 'common3' module and 'Cross'/'Environment' objects can be created
    """


    def fake_get_conf(env_object, path_string):
        """
        @brief  Get config
        """
        return {'env': []}

    module_name = "common3"
    try:
        from testlib import common3
        common3.Cross(None, None)

        # replace Environment _get_setup method
        monkeypatch.setattr(common3.Environment, "_get_setup", fake_get_conf)
        common3.Environment(FakeOpts())
    except ImportError as err:
        pytest.fail("Import failure in '%s' module: %s" % (module_name, err))


def test_import_connpool_module():
    """
    @brief  Verify that all modules can be imported within 'connpool' module and 'ConnectionPool' object can be created
    """
    module_name = "connpool"
    try:
        from testlib import connpool
        connpool.ConnectionPool()
    except ImportError as err:
        pytest.fail("Import failure in '%s' module: %s" % (module_name, err))


def test_import_custom_exception_module():
    """
    @brief  Verify that all modules can be imported within 'custom_exception' module and object of classes can be created
    """
    module_name = "custom_exception"
    try:
        from testlib import custom_exceptions
        custom_exceptions.CustomException(None)
        custom_exceptions.TAFCoreException(None)
        custom_exceptions.SwitchException(None)
        custom_exceptions.TGException(None)
        custom_exceptions.IxiaException(None)
        custom_exceptions.PypackerException(None)
        custom_exceptions.HubException(None)
        custom_exceptions.CrossException(None)
        custom_exceptions.TAFLegacyException(None)
        custom_exceptions.OvsControllerException(None)
        custom_exceptions.AFSException(None)
        custom_exceptions.CLIException(None)
        custom_exceptions.ConnPoolException(None)
        custom_exceptions.SysLogException(None)
        custom_exceptions.CLISSHException(None)
        custom_exceptions.CLICMDException(None)
        custom_exceptions.UIException(None)
    except ImportError as err:
        pytest.fail("Import failure in '%s' module: %s" % (module_name, err))


def test_import_dev_basecross_module():
    """
    @brief  Verify that all modules can be imported within 'dev_basecross' module and classes objects can be created
    """
    module_name = "dev_basecross"
    try:
        # define parameters for object constructor
        config = {'instance_type': None, 'id': None}

        from testlib import dev_basecross
        dev_basecross.GenericXConnectMixin(config, None)
        dev_basecross.ZeroCross(config, None)
    except ImportError as err:
        pytest.fail("Import failure in '%s' module: %s" % (module_name, err))


def test_import_dev_linux_host_module():
    """
    @brief  Verify that all modules can be imported within 'dev_linux_host' module and classes objects can be created
    """
    module_name = "dev_linux_host"
    try:
        # define parameters for object constructor
        config = {'name': None, 'id': None, 'instance_type': None, "ipaddr": "1.1.1.1"}

        from testlib import dev_linux_host
        dev_linux_host.GenericLinuxHost(config, FakeOpts())
        dev_linux_host.IpNetworkNamespace(config, FakeOpts())
    except ImportError as err:
        pytest.fail("Import failure in '%s' module: %s" % (module_name, err))
