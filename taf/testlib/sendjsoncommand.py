# Copyright (c) 2016 - 2017, Intel Corporation.
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

"""``sendjsoncommand.py``

`JSON communication with OVS Nox Conroller functionality`

"""

import socket
import json


class SendJsonCommand(object):
    """Class for sending and receiving Json commands to/from OVS Nox Controller.

    Args:
        ip(str):  Controller IP address
        json_port(int):  Controller port to send to

    """

    def __init__(self, ip, json_port):
        """Initialize SendJsonCommand class.

        """
        self.controller_ip = ip
        self.controller_port = json_port
        self.reply = None
        self.sockets = []

    def probe(self, timeout=10):
        """Method for probing Nox Controller.

        Args:
            timeout(int):  timeout

        """
        cmd = {"type": "probe", "command": "probe"}
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.controller_ip, self.controller_port))
        sock.settimeout(timeout)
        sock.send(json.dumps(cmd))
        try:
            ans = json.dumps(json.loads(sock.recv(4096)))
            if len(ans) > 0:
                return True
            else:
                return False
        except Exception:
            return False
        finally:
            sock.shutdown(1)
            sock.close()

    def flow_add(self, command, command_string, reply=False, timeout=30):
        """Method for sending flow command to Ovs Controller (connect, send json command, disconnect).

        If reply is True - wait for reply from the Controller

        Args:
            command(str):  command, e.g "flow add"
            command_string(str):  command string, e.g. flow qualifiers and actions, delimited with space
            reply(bool):  specifies wait for reply or not
            timeout(int):  timeout

        """
        cmd = {}
        if not reply:
            reply = self.reply
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.controller_ip, self.controller_port))

        if command == "flow_add":
            cmd["type"] = "flow_mod"
            cmd["command"] = "flow_add"
            cmd["flow"] = command_string.split(" ")[0]
            cmd["action"] = command_string.split(" ")[1]

        sock.send(json.dumps(cmd))
        if reply:
            sock.settimeout(timeout)
            return json.dumps(json.loads(sock.recv(4096)))

        sock.send("{\"type\":\"disconnect\"}")
        sock.shutdown(1)
        sock.close()

    def flow_with_wildcards_add(self, command, command_string, reply=False, timeout=30):
        """Method for sending flow command to Ovs Controller (connect, send json command, disconnect).

        If reply is True - wait for reply from the Controller

        Args:
            command(str):  command, e.g "flow add"
            command_string(str):  command string, e.g. flow qualifiers and actions, delimited with space
            reply(bool):  specifies wait for reply or not
            timeout(int):  timeout

        """
        cmd = {}
        if not reply:
            reply = self.reply
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.controller_ip, self.controller_port))

        if command == "flow_with_wildcards_add":
            cmd["type"] = "flow_mod"
            cmd["command"] = "flow_with_wildcards_add"
            cmd["flow"] = command_string.split(" ")[0]
            cmd["action"] = command_string.split(" ")[1]
            cmd["flow_wildcards"] = int(command_string.split(" ")[2])

        sock.send(json.dumps(cmd))
        if reply:
            sock.settimeout(timeout)
            return json.dumps(json.loads(sock.recv(4096)))

        sock.send("{\"type\":\"disconnect\"}")
        sock.shutdown(1)
        sock.close()

    def flow_with_prio_add(self, command, command_string, reply=False, timeout=30):
        """Method for sending flow command to Ovs Controller (connect, send json command, disconnect).

        If reply is True - wait for reply from the Controller

        Args:
            command(str):  command, e.g "flow add"
            command_string(str):  command string, e.g. flow qualifiers and actions, delimited with space
            reply(bool):  specifies wait for reply or not
            timeout(int):  timeout

        """
        cmd = {}
        if not reply:
            reply = self.reply
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.controller_ip, self.controller_port))

        if command == "flow_with_prio_add":
            cmd["type"] = "flow_mod"
            cmd["command"] = "flow_with_prio_add"
            cmd["flow"] = command_string.split(" ")[0]
            cmd["action"] = command_string.split(" ")[1]
            cmd["flow_priority"] = int(command_string.split(" ")[2])

        sock.send(json.dumps(cmd))
        if reply:
            sock.settimeout(timeout)
            return json.dumps(json.loads(sock.recv(4096)))

        sock.send("{\"type\":\"disconnect\"}")
        sock.shutdown(1)
        sock.close()

    def flow_with_flags_add(self, command, command_string, reply=False, timeout=30):
        """Method for sending flow command to Ovs Controller (connect, send json command, disconnect).

        If reply is True - wait for reply from the Controller

        Args:
            command(str):  command, e.g "flow add"
            command_string(str):  command string, e.g. flow qualifiers and actions, delimited with space
            reply(bool):  specifies wait for reply or not
            timeout(int):  timeout

        """
        cmd = {}
        if not reply:
            reply = self.reply
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.controller_ip, self.controller_port))

        if command == "flow_with_flags_add":
            cmd["type"] = "flow_mod"
            cmd["command"] = "flow_with_flags_add"
            cmd_args = command_string.split(" ")
            cmd["flow"] = cmd_args[0]
            cmd["action"] = cmd_args[1]
            str_len = len(cmd_args)
            if str_len > 2:
                for i in range(2, str_len + 1):
                    if cmd_args[i][:cmd_args[i].find("=")] == "prio":
                        cmd["flow_priority"] = int(cmd_args[i][cmd_args[i].find("=") + 1:])
                    if cmd_args[i][:cmd_args[i].find("=")] == "wild":
                        cmd["flow_wildcards"] = int(cmd_args[i][cmd_args[i].find("=") + 1:])
                    if cmd_args[i][:cmd_args[i].find("=")] == "flags":
                        cmd["flow_flags"] = int(cmd_args[i][cmd_args[i].find("=") + 1:])

        sock.send(json.dumps(cmd))
        if reply:
            sock.settimeout(timeout)
            return json.dumps(json.loads(sock.recv(4096)))

        sock.send("{\"type\":\"disconnect\"}")
        sock.shutdown(1)
        sock.close()

    def flow_delete(self, command, command_string, reply=False, timeout=30):
        """Method for sending flow delete command to Ovs Controller (connect, send json command, disconnect).

        If reply is True - wait for reply from the Controller

        Args:
            command(str):  command, e.g "flow add"
            command_string(str):  command string, e.g. flow qualifiers and actions, delimited with space
            reply(bool):  specifies wait for reply or not
            timeout(int):  timeout

        """
        cmd = {}
        if not reply:
            reply = self.reply
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.controller_ip, self.controller_port))

        if command == "flow_delete":
            cmd["type"] = "flow_mod"
            cmd["command"] = "flow_delete"
            cmd["flow"] = command_string.split(" ")[0]
            # cmd["action"] = command_string.split(" ")[1]

        sock.send(json.dumps(cmd))
        if reply:
            sock.settimeout(timeout)
            return json.dumps(json.loads(sock.recv(4096)))

        sock.send("{\"type\":\"disconnect\"}")
        sock.shutdown(1)
        sock.close()

    def get_stats(self, command, reply=True, timeout=30):
        """Method for getting OVS statistics from Switch via Nox Controller.

        Args:
            command(str):  command, e.g "flow add"
            reply(bool):  specifies wait for reply or not
            timeout(int):  reply waiting timeout

        """
        cmd = {}
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.controller_ip, self.controller_port))

        if command == "portstats":
            cmd["type"] = "portstats"
            cmd["command"] = "portstats"

        elif command == "flowstats":
            cmd["type"] = "flowstats"
            cmd["command"] = "flowstats"

        elif command == "tablestats":
            cmd["type"] = "tablestats"
            cmd["command"] = "tablestats"

        elif command == "aggstats":
            cmd["type"] = "aggstats"
            cmd["command"] = "aggstats"

        elif command == "queuestats":
            cmd["type"] = "queuestats"
            cmd["command"] = "queuestats"

        sock.send(json.dumps(cmd))
        if reply:
            sock.settimeout(timeout)
            return json.dumps(json.loads(sock.recv(4096)))

        sock.send("{\"type\":\"disconnect\"}")
        sock.shutdown(1)
        sock.close()

    def get_features(self, command, reply=True, timeout=30):
        """Method for getting OVS Switch features via Nox Controller.

        Args:
            command(str):  command, e.g "flow add"
            reply(bool):  specifies wait for reply or not
            timeout(int):  reply waiting timeout

        """
        cmd = {}
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.controller_ip, self.controller_port))

        if command == "features_request":
            cmd["type"] = "features_request"
            cmd["command"] = "features_request"

        sock.send(json.dumps(cmd))
        if reply:
            sock.settimeout(timeout)
            return json.dumps(json.loads(sock.recv(4096)))

        sock.send("{\"type\":\"disconnect\"}")
        sock.shutdown(1)
        sock.close()

    def set_config(self, command, port_no, port_config, reply=False, timeout=30):
        """Method for setting OVS Switch port configuration via Nox Controller.

        Args:
            command(str):  command, e.g "flow add"
            port_no(int):  port number
            port_config(str):  port configuration
            reply(bool):  specifies wait for reply or not
            timeout(int):  reply waiting timeout

        """
        cmd = {}
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.controller_ip, self.controller_port))

        if command == "set_port_config":
            cmd["type"] = "set_config"
            cmd["command"] = "set_port_config"
            cmd["port_no"] = port_no
            cmd["config"] = port_config

        sock.send(json.dumps(cmd))
        if reply:
            sock.settimeout(timeout)
            return json.dumps(json.loads(sock.recv(4096)))

        sock.send("{\"type\":\"disconnect\"}")
        sock.shutdown(1)
        sock.close()

    def connect(self, controller_ip=None, controller_port=None):
        """Method for connecting to Ovs Controller socket.

        Args:
            controller_ip(str):  Controller IP address
            controller_port(int):  Controller port to send to

        """
        if not controller_ip:
            controller_ip = self.controller_ip
        if not controller_port:
            controller_port = self.controller_port

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((controller_ip, controller_port))
        self.sockets.append(sock)

    def send(self, command, command_string):
        """Method for sending json command to Ovs Controller.

        Args:
            command(str):  command, e.g "flow add"
            command_string(str):  command string, e.g. flow qualifiers and actions, delimited with space

        """
        cmd = {}
        if command == "flow_add":
            cmd["type"] = "flow_mod"
            cmd["command"] = "flow_add"
            cmd["flow"] = command_string.split(" ")[0]
            cmd["action"] = command_string.split(" ")[1]
        elif command == "flow_delete":
            cmd["type"] = "flow_mod"
            cmd["command"] = "flow_delete"
            cmd["flow"] = command_string
        elif command == "portstats":
            cmd["type"] = "portstats"
            cmd["command"] = "portstats"
        elif command == "flowstats":
            cmd["type"] = "flowstats"
            cmd["command"] = "flowstats"
        elif command == "tablestats":
            cmd["type"] = "tablestats"
            cmd["command"] = "tablestats"
        elif command == "aggstats":
            cmd["type"] = "aggstats"
            cmd["command"] = "aggstats"
        elif command == "queuestats":
            cmd["type"] = "queuestats"
            cmd["command"] = "queuestats"

        self.sockets[0].send(json.dumps(cmd))

    def disconnect(self):
        """Method for disconnecting from Ovs Controller socket.

        """
        self.sockets[0].send("{\"type\":\"disconnect\"}")
        self.sockets[0].shutdown(1)
        self.sockets[0].close()
        self.sockets.remove(0)
