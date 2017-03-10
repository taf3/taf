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

"""``restfloodlight.py``

`Functionality related to RestFloodlight OVS controller`

"""

import http.client
import json


class RestFloodlightController(object):
    """RestFloodlight OVS controller.

    """

    def __init__(self, ip, port):
        """Initialize RestFloodlightController class.

        Args:
            ip(str):  Controller IP address
            port(int):  Controller port

        """
        self.controller_ip = ip
        self.controller_port = port
        self.reply = True

    def probe(self, timeout=10):
        """Method for probing Floodlight Controller.

        Args:
            timeout(int):  timeout

        """
        path = '/wm/core/memory/json'
        ret = self.rest_call({}, 'GET', path, timeout)
        return json.loads(ret[2])

    def get_dpid(self, timeout=10):
        """Method for getting Switch dpid from Floodlight Controller.

        Args:
            timeout(int):  timeout

        Returns:
            str:  Switch dpid

        """
        path = '/wm/core/controller/switches/json'
        ret = self.rest_call({}, 'GET', path, timeout)
        return json.loads(ret[2])[0]['dpid']

    def get_multiple_dpids(self, timeout=10):
        """Method for getting Switches dpids in complex setup via Floodlight Controller.

        Args:
            timeout(int):  timeout

        Returns:
            list:  Switches dpids

        """
        path = '/wm/core/controller/switches/json'
        ret = self.rest_call({}, 'GET', path, timeout)
        return json.loads(ret[2])

    def get_stats(self, switch_id, stat_type, timeout=30):
        """Method for getting OVS statistics from Switch via Floodlight Controller.

        Args:
            switch_id(str):  Switch ID
            stat_type(str):  Statistics type
            timeout(int):  reply waiting timeout

        Returns:
            list:  Switch statistics

        """
        s_type = ''
        if stat_type == "aggstats":
            s_type = 'aggregate'
        elif stat_type == "portstats":
            s_type = 'port'
        elif stat_type == "flowstats":
            s_type = 'flow'
        elif stat_type == "tablestats":
            s_type = 'table'
        elif stat_type == "queuestats":
            s_type = 'queue'
        elif stat_type == "descstats":
            s_type = 'desc'
        else:
            s_type = stat_type
        path = '/wm/core/switch/%s/%s/json' % (switch_id, s_type, )
        ret = self.rest_call({}, 'GET', path, timeout)
        return json.loads(ret[2])

    def get_features(self, switch_id, command, reply=True, timeout=30):
        """Method for getting OVS Switch features via Floodlight Controller.

        Args:
            switch_id(str):  Switch ID
            command(str):  command: "features_request"
            reply(bool):  wait for reply
            timeout(int):  reply waiting timeout

        Returns:
            list:  Switch features statistics

        """
        features = self.get_stats(switch_id, "features")
        return features

    def flow_add(self, switch_id, command_string, name, wildcards=None, priority=32768, reply=False, timeout=30):
        """Method for adding flows via Floodlight Controller.

        Args:
            switch_id(str):  Switch ID
            command_string(str):  command string, e.g. flow qualifiers and actions, delimited with space
            name(str):  Flow name
            wildcards(str):  Flow wildcards
            priority(int):  Flow priority
            reply(bool):  specifies wait for reply or not
            timeout(int):  reply waiting timeout

        Returns:
            bool:  True if flow added

        """
        path = '/wm/staticflowentrypusher/json'
        cmd = dict()
        if not reply:
            reply = self.reply
        cmd["switch"] = switch_id
        cmd["name"] = name
        if wildcards:
            cmd["wildcards"] = wildcards
        for flow_field in command_string.split(" ")[0].split(","):
            if "in_port" in flow_field.split("=")[0]:
                cmd["ingress-port"] = flow_field.split("=")[1]
            elif "dl_src" in flow_field.split("=")[0]:
                cmd["src-mac"] = flow_field.split("=")[1]
            elif "dl_dst" in flow_field.split("=")[0]:
                cmd["dst-mac"] = flow_field.split("=")[1]
            elif "dl_vlan" in flow_field.split("=")[0] and "dl_vlan_pcp" not in flow_field.split("=")[0]:
                cmd["vlan-id"] = flow_field.split("=")[1]
            elif "dl_vlan_pcp" in flow_field.split("=")[0]:
                cmd["vlan-priority"] = flow_field.split("=")[1]
            elif "dl_type" in flow_field.split("=")[0]:
                cmd["ether-type"] = flow_field.split("=")[1]
            elif "nw_tos" in flow_field.split("=")[0]:
                cmd["tos-bits"] = flow_field.split("=")[1]
            elif "nw_proto" in flow_field.split("=")[0]:
                cmd["protocol"] = flow_field.split("=")[1]
            elif "nw_src" in flow_field.split("=")[0]:
                cmd["src-ip"] = flow_field.split("=")[1]
            elif "nw_dst" in flow_field.split("=")[0]:
                cmd["dst-ip"] = flow_field.split("=")[1]
            elif "tp_src" in flow_field.split("=")[0]:
                cmd["src-port"] = flow_field.split("=")[1]
            elif "tp_dst" in flow_field.split("=")[0]:
                cmd["dst-port"] = flow_field.split("=")[1]
            elif "ip" in flow_field.split("=")[0] and "ipv6" not in flow_field.split("=")[0]:
                cmd["ether-type"] = 2048
            elif "icmp" in flow_field.split("=")[0] and "icmp6" not in flow_field.split("=")[0]:
                cmd["ether-type"] = 2048
                cmd["protocol"] = 1
            elif "tcp" in flow_field.split("=")[0] and "tcp6" not in flow_field.split("=")[0]:
                cmd["ether-type"] = 2048
                cmd["protocol"] = 6
            elif "udp" in flow_field.split("=")[0] and "udp6" not in flow_field.split("=")[0]:
                cmd["ether-type"] = 2048
                cmd["protocol"] = 17
            elif "arp" in flow_field.split("=")[0]:
                cmd["ether-type"] = 0x0806
            elif "ipv6" in flow_field.split("=")[0]:
                cmd["ether-type"] = 0x86dd
            elif "tcp6" in flow_field.split("=")[0]:
                cmd["ether-type"] = 34525
                cmd["protocol"] = 6
            elif "udp6" in flow_field.split("=")[0]:
                cmd["ether-type"] = 34525
                cmd["protocol"] = 17
            elif "icmp6" in flow_field.split("=")[0]:
                cmd["ether-type"] = 34525
                cmd["protocol"] = 58
            cmd["active"] = "true"

            actions_list = []
            for action_item in command_string.split(" ")[1].split(','):
                if 'strip_vlan' in action_item:
                    actions_list.append('strip-vlan')
                elif 'mod_vlan_vid' in action_item:
                    actions_list.append('setvlan-id=%s' % (action_item.split(':')[1], ))
                elif 'mod_vlan_pcp' in action_item:
                    actions_list.append('set-vlan-priority=%s' % (action_item.split(':')[1], ))
                elif 'mod_dl_src' in action_item:
                    actions_list.append('set-src-mac=%s' % (action_item[action_item.find(':') + 1:], ))
                elif 'mod_dl_dst' in action_item:
                    actions_list.append('set-dst-mac=%s' % (action_item[action_item.find(':') + 1:], ))
                elif 'mod_nw_src' in action_item:
                    actions_list.append('set-src-ip=%s' % (action_item.split(':')[1], ))
                elif 'mod_nw_dst' in action_item:
                    actions_list.append('set-dst-ip=%s' % (action_item.split(':')[1], ))
                elif 'mod_nw_tos' in action_item:
                    actions_list.append('set-tos-bits=%s' % (action_item.split(':')[1], ))
                elif 'mod_tp_src' in action_item:
                    actions_list.append('set-src-port=%s' % (action_item.split(':')[1], ))
                elif 'mod_tp_dst' in action_item:
                    actions_list.append('set-dst-port=%s' % (action_item.split(':')[1], ))
                elif 'enqueue' in action_item:
                    actions_list.append('enqueue=%s:%s' % (action_item.split(':')[1], action_item.split(':')[2], ))
                elif 'DROP' in action_item:
                    actions_list = []
                elif 'IN_PORT' in action_item:
                    actions_list.append('output=ingress-port')
                elif 'ALL' in action_item:
                    actions_list.append('output=all')
                elif 'FLOOD' in action_item:
                    actions_list.append('output=flood')
                elif 'CONTROLLER' in action_item:
                    actions_list.append('output=controller')
                elif 'LOCAL' in action_item:
                    actions_list.append('output=local')
                elif 'NORMAL' in action_item:
                    actions_list.append('output=normal')
                else:
                    actions_list.append(action_item.replace(':', '=').lower())

            cmd["actions"] = ','.join(actions_list)
            cmd["priority"] = priority

        if reply:
            ret = self.rest_call(cmd, 'POST', path, timeout)
            return ret[0] == 200
        else:
            self.rest_call(cmd, 'POST', path, timeout)

    def flow_delete(self, command, name, timeout=30):
        """Method for deleting flows via Floodlight Controller.

        Args:
            command(str):  command, e.g "flow_delete"
            name(str):  Flow name
            timeout(int):  reply waiting timeout

        Returns:
            bool:  True if flow deleted

        """
        path = '/wm/staticflowentrypusher/json'
        if command == "flow_delete":
            ret = self.rest_call({'name': name}, 'DELETE', path, timeout)
            return ret[0] == 200

    def clear(self, switch_id, timeout=10):
        """Method for clearing all flows from switch.

        Args:
            switch_id(str):  Switch ID
            timeout(int):  reply waiting timeout

        Returns:
            bool:  True if flows cleared

        """
        path = '/wm/staticflowentrypusher/clear/%s/json' % (switch_id, )
        ret = self.rest_call({}, "GET", path, timeout)
        return ret[0] == 200

    def rest_call(self, data, action, path, timeout=10):
        """Method for executing call via Floodlight REST API.

        Args:
            data(dict):  Rest data
            action(str):  Action name
            path(str):  REST path
            timeout(int):  timeout

        Returns:
            tuple:  response.status, response.reason, response.read()

        """
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
        }
        body = json.dumps(data)
        conn = http.client.HTTPConnection(self.controller_ip, self.controller_port, timeout)
        conn.request(action, path, body, headers)
        response = conn.getresponse()
        ret = (response.status, response.reason, response.read())
        conn.close()
        return ret
