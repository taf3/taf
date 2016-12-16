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

@file  snmphelpers.py

@summary  SNMP specific helpers functions.
"""

import sys
import os
import shutil
import tarfile
from subprocess import Popen, PIPE

import pytest
import paramiko as paramiko

from . import helpers
from . import loggers

# create logger for module


def is_mibs_folder_empty(path):
    """
    @brief  Checks is MIBs folder empty of not
    @param  path:  path to MIBs folder
    @type  path:  str
    @rtype:  bool
    @return:  True if empty and False if not
    @par  Example:
    @code
    is_mibs_folder_empty()
    @endcode
    """
    empty = True
    if os.path.exists(path):
        for file_n in os.listdir(path):
            if 'ONS' in file_n or "ons" in file_n:
                empty = False

    return empty


def clear_mibs_folder(path):
    """
    @brief  Removes all ONS mibs from MIBS folder
    @param  path:  path to MIBs folder
    @type  path:  str
    @par  Example:
    @code
    clear_mibs_folder()
    @endcode
    """
    if os.path.exists(path):
        shutil.rmtree(path)


def get_remote_file(hostname, port, username, password, remotepath, localpath):
    """
    @brief  Get remote file to local machine.
    @param  hostname:  Remote IP-address
    @type  hostname:  str
    @param  port:  Remote SSH port
    @type  port:  int
    @param  username:  Remote host username for authentication
    @type  username:  str
    @param  password:  Remote host password for authentication
    @type  password:  str
    @param  remotepath:  Remote file to download location path
    @type  remotepath:  str
    @param  localpath:  Local path to save remote file
    @type  localpath:  str
    @par  Example:
    @code
    get_remote_file(host, port, username, password, tar_remotepath, tar_localpath)
    @endcode
    """
    transport = paramiko.Transport((hostname, port))
    transport.connect(username=username, password=password)
    sftp = paramiko.SFTPClient.from_transport(transport)
    try:
        sftp.get(remotepath=remotepath, localpath=localpath)
    finally:
        sftp.close()
        transport.close()


def untar_file(tar_path, untar_path):
    """
    @brief  Unpack tar file.
    @param  tar_path:  Path to tar file
    @type  tar_path:  str
    @param  untar_path:  Path where to unpack
    @type  untar_path:  str
    @par  Example:
    @code
    untar_file(tar_localpath, mib_path_txt)
    @endcode
    """
    old_folder = os.path.join(untar_path, 'mibs')
    if os.path.isfile(old_folder):
        os.remove(old_folder)
    tar = tarfile.open(tar_path)
    tar.extractall(untar_path)
    tar.close()
    os.remove(tar_path)


def file_convert(mib_txt_path, mib_py_path):
    """
    @brief  Convert .txt MIB to .py
    @param  mib_txt_path:  Full path to .txt MIB.
    @type  mib_txt_path:  str
    @param  mib_py_path:  Full path to .py MIB
    @type  mib_py_path:  str
    @par  Example:
    @code
    file_convert(mib_txt_path, mib_py_path)
    @endcode
    """
    mod_logger_snmp = loggers.module_logger(name=__name__)

    # translate .txt mib into python format using 3rd party tools 'smidump'
    smidump = Popen(['smidump', '-k', '-f', 'python', mib_txt_path], stdout=PIPE)
    list_stdout = smidump.communicate()[0]
    if len(list_stdout) == 0:
        return "Fail"

    # create tmp directory for filling MIBs dictionary
    mib_path_tmp = os.path.join(mib_py_path, 'tmp')
    if not os.path.exists(mib_path_tmp):
        os.makedirs(mib_path_tmp)
    # added tmp path into sys.path for imports converted MIB's
    sys.path.append(mib_path_tmp)
    # get file without extension
    file_name = os.path.splitext(os.path.basename(mib_txt_path))[0]
    # create .py name
    temp_file_name = "{0}.py".format(file_name)
    # create .tmp file path for imports
    temp_file_path = os.path.join(mib_path_tmp, temp_file_name)

    # save and import converted MIB's
    with open(temp_file_path, "ab") as a:
        a.write(list_stdout)
    temp_module = __import__(os.path.splitext(os.path.basename(mib_txt_path))[0])
    # update helpers.MIBS_DICT with MIB data
    if "moduleName" in list(temp_module.MIB.keys()) and "nodes" in list(temp_module.MIB.keys()):
        helpers.MIBS_DICT.update({temp_module.MIB["moduleName"]: list(temp_module.MIB["nodes"].keys())})
    # clear tmp file path
    sys.path.remove(mib_path_tmp)
    os.remove(temp_file_path)

    # translate MIB from .py into pysnmp format using 3rd party tools 'libsmi2pysnmp'
    pipe = Popen(['libsmi2pysnmp', '--no-text'], stdout=PIPE, stdin=PIPE)
    stdout = pipe.communicate(input=list_stdout)
    # get MIB name from itself, add .py and save it.
    mib_name = "{0}.py".format(temp_module.MIB["moduleName"])
    mib_py_path = os.path.join(mib_py_path, mib_name)

    mod_logger_snmp.debug("Convert %s to %s" % (file_name, temp_file_name))

    with open(mib_py_path, 'a') as py_file:
        for string in stdout:
            if string is not None:
                str_dict = string.decode('utf-8').split('\n')
                for each_str in str_dict:
                    if "ModuleCompliance" in each_str:
                        if "ObjectGroup" in each_str:
                            py_file.write(each_str + '\n')
                    elif "Compliance)" in each_str:
                        pass
                    else:
                        py_file.write(each_str + '\n')

    return mib_name


def convert_to_py(txt_dir_path, py_dir_path):
    """
    @brief  Converts .txt MIB's to .py
    @param  txt_dir_path:  Path to dir with .txt MIB's.
    @type  txt_dir_path:  str
    @param  py_dir_path:  Path to dir with .py MIB's
    @type  py_dir_path:  str
    @par  Example:
    @code
    convert_to_py(mib_path_tmp, mib_path)
    @endcode
    """
    mod_logger_snmp = loggers.module_logger(name=__name__)
    txt_dir_path = os.path.join(txt_dir_path, "MIB")
    mod_logger_snmp.debug("Converts .txt MIB's to .py")
    os.environ['SMIPATH'] = txt_dir_path

    for mib in os.listdir(txt_dir_path):
        mib_txt_path = os.path.join(txt_dir_path, mib)
        retry_count = 3
        retry = 1
        while retry <= retry_count:
            mib_py = file_convert(mib_txt_path, py_dir_path)
            if mib_py not in os.listdir(py_dir_path):
                mod_logger_snmp.debug("Converted MIB %s is not present at %s" % (mib, py_dir_path))
                retry += 1
                if retry > retry_count:
                    mod_logger_snmp.debug("Can not convert %s" % (mib, ))
            else:
                mod_logger_snmp.debug("Converted MIB %s is present at %s" % (mib, py_dir_path))
                retry = retry_count + 1
    shutil.rmtree(txt_dir_path)
    shutil.rmtree(os.path.join(py_dir_path, "tmp"))


def create_mib_folder(config, path, env):
    """
    @brief  Creates MIB folder.
    @param  config:  Configuration dictionary.
    @type  config:  dict
    @param  path:  Path to MIB folder.
    @type  path:  str
    @param  env:  Environment object.
    @type  env:  Environment
    @par  Example:
    @code
    create_mib_folder()
    @endcode
    """
    if config is None:
        pytest.fail("UI settings not fount in environment configuration.")

    host = config['host']
    port = int(config['port'])
    username = config['username']
    password = config['password']
    tar_folder = config['tar_remotepath']
    tar_file = os.path.split(tar_folder)[1]
    branch = env.env_prop['switchppVersion']
    platform = getattr(getattr(env.switch[1], 'hw', None), 'snmp_path', None)

    tar_remotepath = tar_folder.format(**locals())

    if not os.path.exists(path):
        os.makedirs(path)

    tar_localpath = os.path.join(path, tar_file)

    mib_path_tmp = os.path.join(path, 'tmp')
    if not os.path.exists(mib_path_tmp):
        os.makedirs(mib_path_tmp)

    mib_path_txt = os.path.join(path, 'txt')
    if not os.path.exists(mib_path_txt):
        os.makedirs(mib_path_txt)

    get_remote_file(host, port, username, password, tar_remotepath, tar_localpath)
    untar_file(tar_localpath, mib_path_txt)

    convert_to_py(mib_path_txt, path)
