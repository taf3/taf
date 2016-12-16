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

@file  netconfcmd.py

@summary  Module for working with devices via Netconf over ssh connection
"""

from . import loggers


class NETCONF(object):
    """
    @description  Class for configure device using Netconf

    @param config:  Switch configuration dictionary.

    @code{.py}
    client=NETCONF(env.switch[1].config)
    @endcode
    """
    class_logger = loggers.ClassLogger()

    def __init__(self, config):
        """
        @brief  Initialize NETCONF class
        @param  config:  Switch configuration dictionary.
        @type  config:  dict
        """
        # TODO add necessary data into json when it will ready
        self.netconf_manager = None
        self.CAPABILITIES = None
        self.OPERATIONS = None
        self.session = None
        self.host = config["ip_host"]
        self.port = 830
        self.username = "telnet_user"
        self.password = "telnet_pass"

    def connect(self, host, port=830, username=None, password=None, timeout=None):
        """
        @brief  Establish netconf session
        @param  host:  Host name or IP address
        @type  host:  str
        @param  port:  Host port
        @type  port:  int
        @param  username:  Host user
        @type  username:  str
        @param  password:  Host password
        @type  password:  str
        @param  timeout:  Session timeout
        @type  timeout:  int
        @rtype:  ncclient.transport.Session
        @return:  NETCONF session
        """
        from ncclient import manager

        self.netconf_manager = manager
        self.CAPABILITIES = self.netconf_manager.CAPABILITIES
        self.OPERATIONS = self.netconf_manager.OPERATIONS

        self.session = self.netconf_manager.connect(host, port, timeout=timeout, username=username, password=password)
        return self.session

    def check_session(self):
        """
        @brief  Check if connection exist
        @rtype:  bool
        @return:  True if session connected
        """
        if self.session:
            return self.session.connected
        else:
            return False

    def close(self):
        """
        @brief  Close netconf connection.
        """
        self.session.close_session()

    def exec_operation(self, param, filtering=None):
        """
        @brief  Return result of the executed Netconf operation .
        @param  param:  Name of Netconf operation (Currently we use only "get" operation, but also can be used all other operation as well)
        @type  param:  str
        @param  filtering:  Consists of two elements Filter type ("xpath" or "subtree") and criteria
        @type  filtering:  tuple
        @return:  Netconf GetReply instance
        @note  This is wrapper for netconf calls.
        @par  Example:
        @code
        In [3]:  netconf.exec_operation("get", ("xpath", "//system/uname"))
        Out[3]:
        <?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"
          message-id="urn:uuid:1951ee4a-df07-11e2-9ddb-20cf3095bf10"
          last-modified="2013-06-27T08:33:02Z"
          xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
          <data>
            <system xmlns="http://netconfcentral.org/ns/yuma-system">
              <uname>
                <sysname>Linux</sysname>
                <release>3.2.0-48-generic</release>
                <version>#74-Ubuntu SMP Thu Jun 6 19:43:26 UTC 2013</version>
                <machine>x86_64</machine>
                <nodename><username></nodename>
              </uname>
            </system>
          </data>
        </rpc-reply>

        @endcode
        """
        self.class_logger.debug("check_session")
        if not self.check_session():
            self.class_logger.debug("session closed - reconnect")
            self.connect(self.host, self.port, self.username, self.password)
            self.class_logger.debug("reconected")
        self.class_logger.debug("performing %s operation" % param)
        return getattr(self.session, "%s" % param)(filtering)
