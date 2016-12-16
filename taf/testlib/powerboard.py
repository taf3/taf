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

@file  powerboard.py

@summary  Functionality related to APC power boards.
"""

from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto import rfc1902

from . import loggers

mod_logger = loggers.module_logger(name=__name__)
commands = {}
actions = [{"PDU": "APC", "Reset": 3, "On": 1, "Off": 2, "Unknown": None},
           {"PDU": "PX2", "Reset": 2, "Off": 0, "On": 1, "Unknown": None}]

# system.sysDescr = 1.3.6.1.2.1.1.1.0
SNMP_SYSTEM_DESCRIPTION = (1, 3, 6, 1, 2, 1, 1, 1, 0)

SNMP_APC_PDU_OUTLET_CONTROL_NAME = \
    (1, 3, 6, 1, 4, 1, 318, 1, 1, 4, 4, 2, 1, 4)
SNMP_PX2_PDU_OUTLET_CONTROL_NAME = \
    (1, 3, 6, 1, 4, 1, 13742, 6, 3, 5, 3, 1, 3, 1)
SNMP_APC_PDU_OUTLET_CONTROL = \
    (1, 3, 6, 1, 4, 1, 318, 1, 1, 4, 4, 2, 1, 3)
SNMP_PX2_PDU_OUTLET_CONTROL = \
    (1, 3, 6, 1, 4, 1, 13742, 6, 4, 1, 2, 1, 2, 1)

# SNMP default service port
SNMP_DEFAULT_SERVICE_PORT = 161


def snmpget(snmp_host, snmp_community_string, snmp_get_oid,
            snmp_service_port=SNMP_DEFAULT_SERVICE_PORT):
    """
    @brief:  Returns snmpget result connected to specified port on
    specified host via SNMP ()

    @param  snmp_host:  PowerBoard hostname or IP (string).
    @type   snmp_host:  str
    @param  snmp_community_string:  PowerBoard SNMP community string to
    communicated with.
    @type   snmp_community_string:  str
    @param  snmp_get_oid:  SNMP OID
    @type   snmp_get_oid:  tuple
    @param  snmp_service_port:  SNMP service port.
    @type   snmp_service_port:  int

    @return:  device description name from SNMP system.sysDescr
    varBinds in a tuple of name, value
    @rtype:  (int, int, int, tuple(T, U))
    """

    errorIndication, errorStatus, errorIndex, varBinds = \
        cmdgen.CommandGenerator().getCmd(
            cmdgen.CommunityData('my-agent', snmp_community_string, 0),
            cmdgen.UdpTransportTarget((snmp_host, snmp_service_port)),
            snmp_get_oid
        )

    return errorIndication, errorStatus, errorIndex, varBinds


def snmpset(snmp_host, snmp_community_string, snmp_set_oid,
            snmp_set_type, snmp_set_value,
            snmp_service_port=SNMP_DEFAULT_SERVICE_PORT):
    """
    @brief:  Returns snmpget result connected to specified port on
    specified host via SNMP ()

    @param  snmp_host:  PowerBoard hostname or IP (string).
    @type   snmp_host:  str
    @param  snmp_community_string:  PowerBoard SNMP community string to
    communicated with.
    @type   snmp_community_string:  str
    @param  snmp_set_oid:  SNMP OID
    @type   snmp_set_oid:  tuple
    @param  snmp_set_type:  SNMP SET Data Type
    @type   snmp_set_type:  str
    @param  snmp_set_value:  SNMP OID
    @type   snmp_set_value:  str
    @param  snmp_service_port:  SNMP service port.
    @type   snmp_service_port:  int

    @return:  device description name from SNMP system.sysDescr.
    @rtype:  (int, int, int, int)
    """

    if snmp_set_type.upper() == "INTEGER":
        def set_type(x):
            return rfc1902.Integer(int(x))
    else:
        set_type = rfc1902.OctetString

    errorIndication, errorStatus, errorIndex, varBinds = \
        cmdgen.CommandGenerator().setCmd(
            cmdgen.CommunityData('my-agent', snmp_community_string, 0),
            cmdgen.UdpTransportTarget((snmp_host, snmp_service_port)),
            (snmp_set_oid, set_type(snmp_set_value))
        )

    return errorIndication, errorStatus, errorIndex, varBinds


def get_system_description(snmp_host, snmp_community_string):
    """
    @brief:  Returns device(PDU) name connected to specified port on
    specified host via SNMP (system.sysDescr = 1.3.6.1.2.1.1.1.0)

    @param  snmp_host:  PowerBoard hostname or IP.
    @type   snmp_host:  str
    @param  snmp_community_string:  PowerBoard SNMP community string to
    communicated with.
    @type   snmp_community_string:  str

    @return:  device description name from SNMP system.sysDescr.
    @rtype:  str
    """

    errorIndication, errorStatus, errorIndex, varBinds = \
        snmpget(snmp_host, snmp_community_string,
                SNMP_SYSTEM_DESCRIPTION,
                SNMP_DEFAULT_SERVICE_PORT)
    if isinstance(varBinds[0][1].asOctets(), bytes):
        return varBinds[0][1].asOctets().decode()
    return varBinds[0][1]


def _get_action_name(system_id, action_id):
    """
    @brief:  Returns action name based on provided ID.

    @param  system_id:  System ID which gets the first 3 characters
    from 'snmpget' command.
    @type   system_id:  str
    @param  action_id:  Action ID which has corresponding record in
    'commands' dictionary.
    @type   system_id: int

    @return:  action name
    @rtype:  str

    @par  Example:
    @code
    action_name = _get_action_name("APC", 1))
    action_name = _get_action_name("PX2", 2))
    @endcode
    """

    current_pdu = next(pdu for pdu in actions if pdu['PDU'] == system_id)
    return [k for k, v in current_pdu.items() if v == action_id][0]


def _get_action_id(system_id, action_name):
    """
    @brief:  Returns action ID based on provided names("On","Off","Reset").

    @param  system_id:  System ID which gets the first 3 characters
    from 'snmpget' command.
    @type   system_id:  str
    @param  action_name:  Action name which has corresponding record in
    'commands' dictionary
    @type   action_name: str

    @return:  action ID
    @rtype:  int

    @par  Example:
    @code
    action_name = _get_action_id("APC", "On")
    action_name = _get_action_id("PX2", "Off")
    @endcode
    """

    current_pdu = next(pdu for pdu in actions if pdu['PDU'] == system_id)
    return [v for k, v in current_pdu.items() if k == action_name][0]


def set_commands(snmp_host, snmp_community_string):
    """
    @brief:  Sets the 'commands' variable to call do_action() with human readable
    actions like "On", "Off", and "Reset". Based on PDUs, it might have different values
    for snmpset command.

    Raritan PDU status values: 0(OFF), 1(ON), 2(Recycle)
    APC PDU status values: 1 (ON), 2(OFF), 3(Recycle)

    @param  snmp_host:  PowerBoard hostname or IP.
    @type   snmp_host:  str
    @param  snmp_community_string:  PowerBoard SNMP community string to
    communicated with.
    @type   snmp_community_string:  str

    @return:  none

    @par  Example:
    @code
    initialize('192.168.1.1', 'private')
    initialize('192.168.1.1', 'private')
    @endcode
    """

    global commands

    system_id = get_system_description(snmp_host, snmp_community_string)[:3]

    current_pdu = next(pdu for pdu in actions if pdu['PDU'] == system_id)
    commands = current_pdu


def get_name(host, port, snmp_community_string):
    """
    @brief:  Returns configured device name connected to specified port on
    specified host.

    @param  host:  PowerBoard hostname or IP.
    @type   host:  str
    @param  port:  PowerBoard port to which device is connected (integer).
    @type   port:  int or [int]
    @param  snmp_community_string:  PowerBoard SNMP community string to
    communicated with.
    @type   snmp_community_string:  str

    @return:  device name
    @rtype:  str

    @par  Example:
    @code
    device_name = get_name('192.168.1.1', 2)
    @endcode
    """

    # WORKAROUND BEGIN: Ability to send commands on two ports simultaneously
    if isinstance(port, list):
        port = port[0]
    # WORKAROUND END

    system_id = get_system_description(host, snmp_community_string)[:3]

    if system_id == "APC":
        errorIndication, errorStatus, errorIndex, varBinds = \
            snmpget(host, snmp_community_string,
                    SNMP_APC_PDU_OUTLET_CONTROL_NAME + (int(port),),
                    SNMP_DEFAULT_SERVICE_PORT)

    else:  # if system_id == "PX2":
        errorIndication, errorStatus, errorIndex, varBinds = \
            snmpget(host, snmp_community_string,
                    SNMP_PX2_PDU_OUTLET_CONTROL_NAME + (int(port),),
                    SNMP_DEFAULT_SERVICE_PORT)

    return varBinds[0][1]


def get_status(host, port, snmp_community_string):
    """
    @brief:  Returns status of device connected to specified port on
    specified host.

    @param  host:  PowerBoard hostname or IP.
    @type   host:  str
    @param  port:  PowerBoard port to which device is connected.
    @type   port:  int
    @param  snmp_community_string:  PowerBoard SNMP community string to
    communicated with.
    @type   snmp_community_string:  str

    @return:  device status
    @rtype:  str

    @par  Example:
    @code
    device_status = get_status('192.168.1.1', 2, "private")
    device_status = get_status('192.168.1.1', '2', "private")
    device_status = get_status('192.168.1.1', [1,2], "private")
        will return the result of the first element's execution.
    @endcode
    """
    set_commands(host, snmp_community_string)

    system_id = get_system_description(host, snmp_community_string)[:3]

    mod_logger.log(loggers.levels['INFO'],
                   "Getting status of '%s' device..." %
                   (get_name(host, port, snmp_community_string), ))

    # WORKAROUND BEGIN: Ability to send commands on two ports simultaneously
    if isinstance(port, list):
        port = port[0]
    # WORKAROUND END

    if system_id == "APC":
        errorIndication, errorStatus, errorIndex, varBinds = \
            snmpget(host, snmp_community_string,
                    SNMP_APC_PDU_OUTLET_CONTROL + (int(port),),
                    SNMP_DEFAULT_SERVICE_PORT)

    else:  # if system_id == "PX2":
        errorIndication, errorStatus, errorIndex, varBinds = \
            snmpget(host, snmp_community_string,
                    SNMP_PX2_PDU_OUTLET_CONTROL + (int(port),),
                    SNMP_DEFAULT_SERVICE_PORT)

    return _get_action_name(system_id, int(varBinds[0][1]))


def do_action(host, port, snmp_community_string, action):
    """
    @brief:  Performs specified action for device connected to specified port
    on specified host. Before do_action(), get_status() should be ran in order to
    use 'action' parameter.

    @param  host:  PowerBoard  hostname or IP (string).
    @type   host:  string
    @param  port:  PowerBoard  port to which device is connected.
    @type   port:  integer, list of integer
    @param  snmp_community_string:  PowerBoard SNMP community string to
    communicated with.
    @type   snmp_community_string: string
    @param  action:  Action  to perform for device connected to specified port
    on specified host.
    @type   action:  int.

    @return:  none

    @par Example:
    @code
    do_action('192.168.1.1', 2, 'private', 1)
    do_action('192.168.1.1', '2', 'private', 2)
    do_action('192.168.1.1', [2, 3], 'private', 1)
    do_action('192.168.1.1', ['2', '3'], 'private', 1)
    @endcode
    """

    system_id = get_system_description(host, snmp_community_string)[:3]

    if isinstance(port, str) or \
            isinstance(port, str) or \
            isinstance(port, int):
        mod_logger.log(loggers.levels['INFO'],
                       "Performing '%s' action for '%s' device..." %
                       (_get_action_name(system_id, int(action)),
                        get_name(host, port, snmp_community_string)))

        if system_id == "APC":
            errorIndication, errorStatus, errorIndex, varBinds = \
                snmpset(host, snmp_community_string,
                        SNMP_APC_PDU_OUTLET_CONTROL + (int(port),),
                        "Integer", action,
                        SNMP_DEFAULT_SERVICE_PORT)
        else:  # if system_id == "PX2":
            errorIndication, errorStatus, errorIndex, varBinds = \
                snmpset(host, snmp_community_string,
                        SNMP_PX2_PDU_OUTLET_CONTROL + (int(port),),
                        "Integer", action,
                        SNMP_DEFAULT_SERVICE_PORT)

        assert errorStatus == 0

    # WORKAROUND BEGIN: Ability to send commands on two ports simultaneously
    elif isinstance(port, list):
        for _port in port:
            mod_logger.log(loggers.levels['INFO'],
                           "Performing '%s' action for '%s' device..." %
                           (_get_action_name(system_id, int(action)),
                            get_name(host, _port, snmp_community_string)))

            if system_id == "APC":
                errorIndication, errorStatus, errorIndex, varBinds = \
                    snmpset(host, snmp_community_string,
                            SNMP_APC_PDU_OUTLET_CONTROL + (int(_port),),
                            "Integer", action,
                            SNMP_DEFAULT_SERVICE_PORT)
            else:  # if system_id == "PX2":
                errorIndication, errorStatus, errorIndex, varBinds = \
                    snmpset(host, snmp_community_string,
                            SNMP_PX2_PDU_OUTLET_CONTROL + (int(_port),),
                            "Integer", action,
                            SNMP_DEFAULT_SERVICE_PORT)
            assert errorStatus == 0
    else:
        raise TypeError("Wrong 'port' variable type: %s. "
                        "Acceptable types - str/unicode, list"
                        % type(port))
    # WORKAROUND END
