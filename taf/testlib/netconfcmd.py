# Copyright (c) 2011 - 2017, Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""``netconfcmd.py``

`Module for working with devices via Netconf over ssh connection`

"""

from . import loggers


class NETCONF(object):
    """Class for configure device using Netconf.

    Args:
        config:  Switch configuration dictionary.

    Examples::

        client=NETCONF(env.switch[1].config)

    """
    class_logger = loggers.ClassLogger()

    def __init__(self, config):
        """Initialize NETCONF class.

        Args:
            config(dict):  Switch configuration dictionary.

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
        """Establish netconf session.

        Args:
            host(str):  Host name or IP address
            port(int):  Host port
            username(str):  Host user
            password(str):  Host password
            timeout(int):  Session timeout

        Returns:
            ncclient.transport.Session:  NETCONF session

        """
        from ncclient import manager

        self.netconf_manager = manager
        self.CAPABILITIES = self.netconf_manager.CAPABILITIES
        self.OPERATIONS = self.netconf_manager.OPERATIONS

        self.session = self.netconf_manager.connect(host, port, timeout=timeout, username=username, password=password)
        return self.session

    def check_session(self):
        """Check if connection exist.

        Returns:
            bool:  True if session connected

        """
        if self.session:
            return self.session.connected
        else:
            return False

    def close(self):
        """Close netconf connection.

        """
        self.session.close_session()

    def exec_operation(self, param, filtering=None):
        """Return result of the executed Netconf operation.

        Args:
            param(str):  Name of Netconf operation (Currently we use only "get" operation, but also can be used all other operation as well)
            filtering(tuple):  Consists of two elements Filter type ("xpath" or "subtree") and criteria

        Returns:
            Netconf GetReply instance

        Notes:
            This is wrapper for netconf calls.

        Examples::

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

        """
        self.class_logger.debug("check_session")
        if not self.check_session():
            self.class_logger.debug("session closed - reconnect")
            self.connect(self.host, self.port, self.username, self.password)
            self.class_logger.debug("reconected")
        self.class_logger.debug("performing %s operation" % param)
        return getattr(self.session, "%s" % param)(filtering)
