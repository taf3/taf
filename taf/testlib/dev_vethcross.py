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

@file  dev_vethcross.py

@summary  Cross connection based on creating Virtual Ethernet devices.
"""

from subprocess import Popen, PIPE

from . import loggers

from .custom_exceptions import CrossException
from .dev_basecross import GenericXConnectMixin


class VethCross(GenericXConnectMixin):
    """
    @description  Xconnect based on creating virtual ethernet interfaces.

    @note  It is used for simulated environment.
    """

    class_logger = loggers.ClassLogger()

    def __init__(self, config, opts):
        """
        @brief  Initialize VethCross class
        @param  config:  Configuration information.
        @type  config:  dict
        @param  opts:  py.test config.option object which contains all py.test cli options.
        @type  opts:  OptionParser
        """
        self.class_logger.info("VethCross is selected.")
        self.id = config['id']
        self.type = config['instance_type']
        self.opts = opts
        # Connections info:
        self.connections = []
        # Do xconnect on create?
        self.autoconnect = config['autoconnect'] if "autoconnect" in config else True

        self.related_conf = {}
        if "related_conf" in list(config.keys()):
            self.related_conf = config['related_conf']

        # Set On/Off(True/False) status according to get_only option.
        self.status = self.opts.get_only

        # Aliases to support different connection types:
        # Remote TG connections
        self.netns_tg_nns = self.netns_netns
        self.nns_tg_nns = self.netns_netns
        self.generic_tg_nns = self.generic_netns
        self.tg_nns = self.generic_netns
        self.generic_tg = self.generic_generic
        self.tg = self.generic_generic

    def get_name_port(self, dev_id, port_id):
        """
        @brief  Get port name
        @param  dev_id:  Device ID
        @type  dev_id:  int
        @param  port_id:  Port ID
        @type  port_id:  int
        @rtype:  tuple
        @return:  Device name, Port name
        """
        dev_name = self.related_conf[dev_id]['name'].encode("ascii")
        dev_port = self.related_conf[dev_id]['ports'][port_id - 1].encode("ascii")
        return dev_name, dev_port

    def cross_connect(self, conn_list=None):
        """
        @brief  Create connections
        @param  conn_list:  List of connections
        @type  conn_list:  list[list]
        """
        self.class_logger.debug("Connection list: {0}".format(conn_list))
        for conn in conn_list:
            self.class_logger.info("Make connection {0}:{1}, and {2}:{3}.".
                                   format(conn[0], conn[1], conn[2], conn[3]))
            self.xconnect(conn)

    def cross_disconnect(self, disconn_list=None):
        """
        @brief  Destroy connections
        @param  disconn_list:  List of connections
        @type  disconn_list:  list[list]
        """
        self.class_logger.debug("Disconnection list: {0}".format(disconn_list))
        for conn in disconn_list:
            self.class_logger.info("Destroy connection {0}:{1}, and {2}:{3}.".
                                   format(conn[0], conn[1], conn[2], conn[3]))
            self.xdisconnect(conn)

    def netns_netns(self, connection, action):
        """
        @brief  Returns set of commands to create/destroy connection between 2 Linux Network Namespaces.
        @param  connection:  Connection info in format [sw1, port1, sw2, port2]
        @type  connection:  list
        @param  action:  Action for connection.
        @type  action:  str
        """
        commands = []
        src_name, src_port = self.get_name_port(connection[0], connection[1])
        dst_name, dst_port = self.get_name_port(connection[2], connection[3])
        if action == "Connecting":
            commands.append(["ip", "link", "add", "name", src_port,
                             "type", "veth", "peer", "name", dst_port,
                             "netns", dst_name])
            commands.append(["ip", "link", "set", src_port,
                             "netns", src_name])
            commands.append(["ip", "netns", "exec", src_name, "ifconfig", src_port, "up"])
            commands.append(["ip", "netns", "exec", dst_name, "ifconfig", dst_port, "up"])
        else:
            commands.append(["ip", "netns", src_name, "exec", "ip", "link", "delete", src_port])
        self.class_logger.debug("{0} {1}".format(action, [src_name, src_port, dst_name, dst_port], ))
        return commands

    def generic_netns(self, connection, action):
        """
        @brief  Returns set of commands to create/destroy connection between default NNS and custom NNS.
        @param  connection:  Connection info in format [sw1, port1, sw2, port2]
        @type  connection:  list
        @param  action:  Action for connection.
        @type  action:  str
        """
        commands = []
        con1 = self.get_name_port(connection[0], connection[1])
        con2 = self.get_name_port(connection[2], connection[3])
        src_name, src_port = con1
        dst_name, dst_port = con2
        generic_ip = self.related_obj[connection[0]].ipaddr
        if action == "Connecting":
            # Here we need to determine if generic is the same host or not.
            # Check if generic's IP is IP of the localhost.
            if generic_ip not in ["localhost", "127.0.0.1"]:
                commands.append(["ip", "link", "set", dst_port, "netns", dst_name])
            else:
                commands.append(["ip", "link", "add", "name", src_port,
                                 "type", "veth", "peer", "name", dst_port,
                                 "netns", dst_name])
                commands.append(["ifconfig", src_port, "up"])
            commands.append(["ip", "netns", "exec", dst_name, "ifconfig", dst_port, "up"])
        else:
            if generic_ip in ["localhost", "127.0.0.1"]:
                commands.append(["ip", "link", "delete", src_port])
            else:
                self.class_logger.debug("Skip following interface deleting as they weren't created by this cross.")
        self.class_logger.debug("{0} {1}".format(action, [src_name, src_port, dst_name, dst_port], ))
        return commands

    def generic_generic(self, connection, action):
        """
        @brief  Returns set of commands to create connection between 2 default NNS.
                This is used to create just veth interfaces without netns.
        @param  connection:  Connection info in format [sw1, port1, sw2, port2]
        @type  connection:  list
        @param  action:  Action for connection.
        @type  action:  str
        """
        commands = []
        src_name, src_port = self.get_name_port(connection[0], connection[1])
        dst_name, dst_port = self.get_name_port(connection[2], connection[3])
        if action == "Connecting":
            commands.append(["ip", "link", "add", "name", src_port,
                             "type", "veth", "peer", "name", dst_port])
            commands.append(["ifconfig", src_port, "up"])
            commands.append(["ifconfig", dst_port, "up"])
        else:
            commands.append(["ip", "link", "delete", src_port])
        self.class_logger.debug("{0} {1}".format(action, [src_name, src_port, dst_name, dst_port], ))
        return commands

    def xconnect(self, connection):
        """
        @brief  Create single connection.
        @param  connection:  Connection info in format [sw1, port1, sw2, port2]
        @type  connection:  list
        """
        self._exec_x_command(connection, "Connecting")

    def xdisconnect(self, connection):
        """
        @brief  Destroy single connection.
        @param  connection:  Connection info in format [sw1, port1, sw2, port2]
        @type  connection:  list
        """
        self._exec_x_command(connection, "Disconnecting")

    def _exec_x_command(self, connection, action):
        """
        @brief  Create single connection.
        @param  connection:  Connection info in format [sw1, port1, sw2, port2]
        @type  connection:  list
        @param  action:  Action for connection.
        @type  action:  str
        @raise  CrossException:  incorrect action type, error on connection
        """
        if action not in ["Connecting", "Disconnecting"]:
            message = "Incorrect action type {0}. action has to be in ['connect', 'disconnect']".format(action)
            self.class_logger.error(message)
            raise CrossException(message)

        type1 = self.related_obj[connection[0]].type
        type2 = self.related_obj[connection[2]].type
        try:
            # Connection order has to be the same as types order in method name
            if sorted([type1, type2]) != [type1, type2]:
                connection = connection[2:] + connection[:2]
            commands = getattr(self, "{0}_{1}".format(*sorted([type1, type2])))(connection, action)
        except AttributeError:
            message = "Connection type doesn't supported: {0} <-> {1}".format(type1, type2)
            self.class_logger.error(message)
            raise CrossException(message)

        for command in commands:
            self.class_logger.debug("{0} command: {1}".format(action, [command]))
            process = Popen(command, stdout=PIPE, stderr=PIPE)
            process.wait()
            # TODO: Investigate problem with rc == 1 in case of successful command execution
            if process.returncode != 0 and process.returncode != 1:
                self.class_logger.error("Cannot perform connection command.")
                out = process.stdout.read()
                if out:
                    self.class_logger.error("StdOut:\n{0}".format(out))
                out = process.stderr.read()
                if out:
                    self.class_logger.error("StdErr:\n{0}".format(out))
                self.class_logger.error("Cannot perform connection command.")
                message = ("{0} command {1} failed. Return code = {2}.".
                           format(action, command, process.returncode))
                self.class_logger.error(message)
                raise CrossException(message)


ENTRY_TYPE = "cross"
INSTANCES = {"veth": VethCross}
NAME = "cross"
