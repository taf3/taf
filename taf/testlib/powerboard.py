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


"""``powerboard.py``

`Functionality related to Power boards which support SNMP actions`

"""
import time

from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto import rfc1902

from testlib.custom_exceptions import CustomException


class SnmpPowerControl(object):
    def __init__(self, config):
        """Initialize SnmpPowerControl class.

        """
        super(SnmpPowerControl, self).__init__()
        self.pw_board = config.get("pwboard_host", "")
        self.pw_status_oid = config.get("pw_status_oid", "")
        self.pw_action_oid = config.get("pw_action_oid", "")
        self.pw_on_cmd = str(config.get("pw_on_cmd", "1"))
        self.pw_off_cmd = str(config.get("pw_off_cmd", "0"))
        self.pw_port = config.get("pwboard_port", "")
        self.powercycle_timeout = config.get('reboot_latency', 1)
        self.pwboard_snmp_rw_community_string = config.get('pwboard_snmp_rw_community_string', 'private')
        self.pw_snmp_service_port = config.get("pw_snmp_service_port", 161)

        self.power_status_map = {self.pw_on_cmd: 'On',
                                 self.pw_off_cmd: 'Off'}

    def power_off(self):
        """Perform power Off of device"""
        port_action_oid = tuple([int(x) for x in self.pw_action_oid.split('.') + [self.pw_port]])
        self.snmpset(port_action_oid, self.pw_off_cmd)

    def power_on(self):
        """Perform power On of device"""
        port_action_oid = tuple([int(x) for x in self.pw_action_oid.split('.') + [self.pw_port]])
        self.snmpset(port_action_oid, self.pw_on_cmd)

    def power_cycle(self):
        """Perform power cycle of device"""
        self.power_off()
        time.sleep(self.powercycle_timeout)
        self.power_on()

    def get_power_status(self):
        """Get Power status of device on power board

        Returns:
            (str):  'On'|'Off'

        """
        port_status_oid = tuple([int(x) for x in self.pw_status_oid.split('.') + [self.pw_port]])
        port_status = self.snmpget(port_status_oid)
        return self.power_status_map[port_status]

    def snmpget(self, snmp_get_oid):
        """Returns snmpget result connected to specified port on specified host via SNMP ()

        Args:
            snmp_get_oid(tuple):  SNMP OID

        Returns:
            (str):  SNMP get result

        """

        errorIndication, errorStatus, _, varBinds = \
            cmdgen.CommandGenerator().getCmd(
                cmdgen.CommunityData('my-agent', self.pwboard_snmp_rw_community_string, 0),
                cmdgen.UdpTransportTarget((self.pw_board, self.pw_snmp_service_port)),
                snmp_get_oid,
            )

        if errorIndication or errorStatus != 0 or not varBinds:
            raise CustomException("Error on SNMP get: OID: '{}'"
                                  "errorIndication: '{}', "
                                  "errorStatus: '{}', "
                                  "returned data: '{}'".format(snmp_get_oid, errorIndication, errorStatus, varBinds))
        data = varBinds[0][-1].prettyPrint()
        return data

    def snmpset(self, snmp_set_oid, snmp_set_value, snmp_set_type='INTEGER'):
        """Perform snmpset for specified OID to specified value

        Args:
            snmp_set_oid(tuple):  SNMP OID
            snmp_set_value(str):  SNMP OID
            snmp_set_type(str):  SNMP SET Data Type

        """

        if snmp_set_type.upper() == "INTEGER":
            def set_type(x):
                return rfc1902.Integer(int(x))
        else:
            set_type = rfc1902.OctetString

        errorIndication, errorStatus, _, _ = \
            cmdgen.CommandGenerator().setCmd(
                cmdgen.CommunityData('my-agent', self.pwboard_snmp_rw_community_string, 0),
                cmdgen.UdpTransportTarget((self.pw_board, self.pw_snmp_service_port)),
                (snmp_set_oid, set_type(snmp_set_value)),
            )
        if errorIndication or errorStatus != 0:
            raise CustomException("Error on SNMP set to value '{}': OID: '{}'"
                                  "errorIndication: '{}', "
                                  "errorStatus: '{}'".format(snmp_set_value, snmp_set_oid, errorIndication, errorStatus))
