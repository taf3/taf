#! /usr/bin/env python
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

@file  environment.py

@summary  Environment-specific functionality.
"""

import os.path

from . import loggers

from .custom_exceptions import CustomException

# create logger for module
mod_logger = loggers.module_logger(name=__name__)


def get_conf_file(conf_name=None, conf_type="env"):
    """
    @brief  Return full path to conf file
    @param  conf_name:  path to config file in json format.
    @type  conf_name:  str
    @param  conf_type:  type of config: "env" - environment, "setup" - used setup. This value will be added to path as a last directory name.
    @type  conf_type:  str
    @raise  CustomException:  conf_name is None
    @rtype:  str
    @return:  absolute path to configuration file if one exists or None if else.
    @note  Discovery order: 1) search if current folder;
                            2) search in /usr/local/bin/taf/<conf_type>/;
                            3) search in /etc/taf/<conf_type>/.
    @par  Example:
    @code
    get_conf_file(conf_name="simplified_setup.json", conf_type='cross')
    @endcode
    """
    if not conf_name:
        message = "Parameter conf_name must be specified."
        mod_logger.error(message)
        raise CustomException(message)
    conf_path = None
    # Path to search configs.
    search_path = [os.curdir,
                   os.path.join("/usr/local/etc/taf/", conf_type),
                   os.path.join("/etc/taf/", conf_type)]
    for path in search_path:
        conf_path = os.path.join(path, conf_name)
        if os.path.isfile(conf_path):
            break
        else:
            conf_path = None
    return conf_path


def get_absolute_build_path(build_path=None):
    """
    @brief  Return absolute path to switchpp binaries.
    @param  build_path:  path to switchpp binaries .
    @type  build_path:  str
    @rtype:  str
    @return:  absolute path to switchpp binaries if one exists or None if not
    @par  Example:
    @code
    get_absolute_build_path(build_path="/some/path/switchpp")
    @endcode
    """
    return_path = None
    build_path = os.path.expanduser(os.path.expandvars(build_path))
    abs_path = os.path.join(os.curdir, build_path)
    if os.path.isdir(abs_path):
        return_path = os.path.normpath(os.path.abspath(abs_path))
    return return_path
