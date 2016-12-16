#!/usr/bin/env python
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

@file  XML.py

@summary  XML and HTML report classes.
"""
import json
import os
import sys
import tempfile
import traceback
from xml.sax.saxutils import unescape as xml_unescape
import unicodedata as ud
import ast

from py.xml import Namespace  # pylint: disable=no-name-in-module
from py import std as py_std  # pylint: disable=no-name-in-module

from pytest_helpers import get_failure_reason, get_skipped_reason, get_html_xml_path
import loggers


def str2dict(dictstr):
    """
    @brief  Convert string to dictionary
    """
    _dict = ast.literal_eval(dictstr)
    if not isinstance(_dict, dict):
        _dict = ast.literal_eval(dictstr.replace('"', ''))
    if not isinstance(_dict, dict):
        _dict = ast.literal_eval(dictstr.replace("'", ""))
    if not isinstance(_dict, dict):
        raise Exception("Cannot convert given string (%s) to dictionary." % (dictstr, ))
    return _dict

class ReportingServerConfig(object):
    """
    @description  Reporting Server configuration
    """
    class_logger = loggers.ClassLogger()

    @staticmethod
    def _additional_option(parser):
        """
        @brief  Plugin specific options.
        """
        group = parser.getgroup("XML report", "plugin: xml reporter")
        group.addoption("--xml_file", action="store", dest="xml_file",
                        metavar="path", default=None,
                        help="create junit-xml style report file at given path. Default = %default.")
        group.addoption("--xml_prefix", action="store", dest="xml_prefix",
                        metavar="str", default=None,
                        help="prepend prefix to classnames in junit-xml output. Default = %default.")
        group.addoption("--xml_cfg", action="store", dest="xml_cfg",
                        metavar="path", default=None,
                        help="Path to ini file with keys and regexps. Default = %default.")
        group.addoption("--xml_info", action="store", dest="xml_info",
                        metavar="str", default=None,
                        help="Dictionary with additional info to xml report." +
                             "(e.g. '{'Environment': 'Device 01', 'Version': '0.0.1.a'}') Default = %default.")
        group.addoption("--xml_html", action="store", dest="xml_html",
                        metavar="path", default=None,
                        help="create html report file at given path. Default = %default.")
        group.addoption("--xml_htmlcfg", action="store", dest="xml_htmlcfg",
                        metavar="path", default=None,
                        help="Path to htmlrepotr json config file. Default = %default.")

    @staticmethod
    def _configure(config):
        """
        @brief  Checking XML/HTML options.
        """
        if (config.option.xml_file is not None or config.option.xml_html is not None) and not config.option.collectonly:
            return True

    @staticmethod
    def _get_build_name(options):
        """
        @brief  Return specified buildname.
        """
        pass

    @staticmethod
    def _sessionstart(log_class, item, name, buildname):
        """
        @brief  Tell to XMLRPC Server that we are going to interact with it.
        @param  item:  test case item
        @type  item:  pytest.Item
        @param  name:  name for current session
        @type  name:  str
        @param  buildname:  buildname for current session
        @type  buildname:  str
        """
        commands = []
        try:
            update = item.config.option.tm_update
        except AttributeError:
            update = None

        if item.config.option.xml_file is not None or item.config.option.xml_html is not None:
            log_class.info("Enabling XML report creation ...")
            commands.append(["reportadd", [name, "xml"]])
            commands.append(["reportconfig",
                            [name, "xml", "options",
                            [["update", update]]
                            ]])
            # In case html selected but xml omitted create xml file with the same name as html.
            if item.config.option.xml_file is None:
                item.config.option.xml_file = os.path.splitext(item.config.option.xml_html)[0] + ".xml"
            commands.append(["reportconfig",
                            [name, "xml", "logfile", item.config.option.xml_file]])
            if item.config.option.xml_prefix is not None:
                commands.append(["reportconfig",
                                [name, "xml", "prefix", item.config.option.xml_prefix]])
            commands.append(["reportconfig",
                            [name, "xml", "cfgfile", item.config.option.xml_cfg]])
            if item.config.option.xml_info is not None:
                commands.extend(["reportconfig",
                                 [name, "xml", "info_dict", [key, value]]]
                                for key, value in str2dict(item.config.option.xml_info).items())
            env_prop = getattr(getattr(item.config, "env", None), "env_prop", {})
            commands.extend(["reportconfig",
                             [name, "xml", "info_dict", [key, value]]]
                            for key, value in item.config.env.env_prop.items())
            # Add buildname from cli option if it isn't equal to real buildname from switch properties
            if buildname is not None and env_prop['switchppVersion'] != buildname:
                commands.append(["reportconfig",
                                 [name, "xml", "info_dict", ["TM buildname", buildname]]])
            # Order and configure HTML report to server.
            if item.config.option.xml_html is not None:
                log_class.info("Enabling HTML report creation ...")
                commands.append(["reportconfig",
                                [name, "xml", "htmlfile", item.config.option.xml_html]])
                commands.append(["reportconfig",
                                [name, "xml", "htmlcfg", item.config.option.xml_htmlcfg]])
        return commands
