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

@file  pytest_tempest.py

@summary  Prepares sys path for tempest.
"""
import sys
import os
from itertools import chain


_PLUGIN_NAME = "_tempest"


def prepend_path(path):
    # equivalent to sys.path[:] = [path] + [x for x in sys.path if x != path]
    # use sys.path[:] to mutate in place
    sys.path[:] = list(chain([path], (x for x in sys.path if x != path)))
    os.environ['TEMPEST_CONFIG_DIR'] = os.path.join(path, 'etc')


# need to add plugins.pytest_tempest to conftest.py in tempest test directory


def pytest_addoption(parser):
    """
    @brief  tempest specific options
    """
    options = {
        '--tempest_path': {
            'action': 'store',
            'default': None,
            'help': "Path to tempest modules, '%default' by default."
        },
        '--reuse_venv': {
            'action': 'store',
            'default': True,
            'help': "Reuse(=True) or Delete(=False) existing public networks/routers\
            , '%default' by default."
        }
    }

    for opt, opt_kwargs in options.items():
        parser.addoption(opt, **opt_kwargs)


def pytest_configure(config):
    """
    @brief  Registering plugin.
    """
    if config.option.tempest_path:
        prepend_path(config.option.tempest_path)
        config.pluginmanager.register(config.option.tempest_path, _PLUGIN_NAME)


def pytest_unconfigure(config):
    """
    @brief  Unregistering plugin.
    """
    rem = getattr(config, _PLUGIN_NAME, None)
    if rem:
        del config.tempest
        config.pluginmanager.unregister(rem)
