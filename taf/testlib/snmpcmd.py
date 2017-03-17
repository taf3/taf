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

"""``snmpcmd.py``

`Module for SNMP specific functionality`

"""

import re
import time

from pyasn1.type import univ
from pysnmp.smi import builder, view
from pysnmp.entity.rfc3413.oneliner import cmdgen

from . import helpers
from . import loggers


class SNMPCmd(object):
    """`SNMP specific functionality class.

    Args:
        config(list[dict]):  environment config
        env_switches(dict):  switches dictionary in format {switch_id: switch_object}
        mib_dir(str):  MIB module name

    """
    suite_logger = loggers.ClassLogger()

    def __init__(self, config, env_switches, mib_dir):
        """Initialize SNMPCmd class

        Args:
            config(list[dict]):  environment config
            env_switches(dict):  switches dictionary in format {switch_id: switch_object}
            mib_dir(str):  MIB module name

        """
        self.switches = {}
        # get community info from config file:
        for conf in config:
            if 'get_community' in conf:
                self.get_community = conf['get_community']
                self.mib_dir = mib_dir
            if 'set_community' in conf:
                self.set_community = conf['set_community']
        # get switches ip addresses and ports
        for switch_id in list(env_switches.keys()):
            sw_ipaddr = env_switches[switch_id].ipaddr
            if 'sshtun_port' in env_switches[switch_id].config:
                sw_port = 161
                if env_switches[switch_id].config['sshtun_port'] != 22:
                    sw_ipaddr = "10.10.{0}.{1}".format(*str(env_switches[switch_id].config['sshtun_port']).split('0'))
            else:
                sw_port = int(env_switches[switch_id].port) - 8080 + 4700

            self.switches.update({switch_id: {'host': sw_ipaddr, 'port': sw_port}})

        self.mib_builder = builder.MibBuilder()
        mib_path = self.mib_builder.getMibPath() + (mib_dir, )
        self.mib_builder.setMibPath(*mib_path)
        # self.suite_logger.debug("mib_builder __modPathsSeen: %s" % (self.mib_builder._MibBuilder__modPathsSeen, ))
        # self.suite_logger.debug("mib_builder __modSeen: %s" % (self.mib_builder._MibBuilder__modSeen, ))

        self.mibViewController = view.MibViewController(self.mib_builder)

        # loading SNMP types as instances
        self.suite_logger.debug("Loading basic types from standard MIB modules")
        self.OctetString, Integer = self.mib_builder.importSymbols('ASN1', 'OctetString', 'Integer')[0:2]
        Counter32, Unsigned32, Counter64 = self.mib_builder.importSymbols('SNMPv2-SMI', 'Counter32', 'Unsigned32', 'Counter64')[0:3]
        InetAddressType, self.InetAddress, InetAddressIPv4, InetAddressIPv6, InetAddressIPv4z, InetAddressIPv6z, InetAddressDNS = \
            self.mib_builder.importSymbols('INET-ADDRESS-MIB', 'InetAddressType', 'InetAddress', 'InetAddressIPv4',
                                           'InetAddressIPv6', 'InetAddressIPv4z', 'InetAddressIPv6z', 'InetAddressDNS')[0:7]
        self.__integer = Integer()
        self.__counter32 = Counter32()
        self.__unsigned32 = Unsigned32()
        self.__counter64 = Counter64()
        self.__octetString = self.OctetString()

        # creating InetAddress types dict with keys corresponded to InetAddressType named values
        self.InetAddresses = {'ipv4': InetAddressIPv4(), 'ipv6': InetAddressIPv6(), 'ipv4z': InetAddressIPv4z(),
                              'ipv6z': InetAddressIPv6z(), 'dns': InetAddressDNS()}

    def _find_and_load_mib(self, mibs_dict, sym_name):
        """Find MIB name and load it to MibBuilder.

        Args:
            mibs_dict(dict):  dictionary that contains MIBs.
            sym_name(str):  MIB symbol name

        Returns:
            str:  Name of MIB in which symbol name is. 'None' if MIB's name wasn't found.

        Examples::

            self._find_and_load_mib(helpers.MIBS_DICT, 'onsSwitchppControlRouteInterfaceMtu')

        """

        # searching MIB name for specified symbol name in specified MIBs dictionary
        mod_name = next((name for name, values in mibs_dict.items() if sym_name in values), None)

        if not mod_name:
            # symbol name wasn't found in MIBs in MIBs dictionary
            self.suite_logger.debug("MIB name for << %s >> wasn't found" % (sym_name,))
        else:
            self.suite_logger.debug("MIB name for << %s >> found: << %s >>" % (sym_name, mod_name,))
            if mod_name not in self.mib_builder.mibSymbols:
                # loading found MIB
                try:
                    self.mib_builder.loadModules(mod_name)
                    self.suite_logger.debug("MIB << %s >> successful loaded" % (mod_name,))
                except Exception:
                    self.suite_logger.debug("MIB << %s >> is not loaded" % mod_name)
                    # self.suite_logger.debug("mib_builder __modPathsSeen: %s" % (self.mib_builder._MibBuilder__modPathsSeen, ))
                    # self.suite_logger.debug("mib_builder __modSeen: %s" % (self.mib_builder._MibBuilder__modSeen, ))
            else:
                self.suite_logger.debug("MIB << %s >> is already loaded" % (mod_name,))
        return mod_name

    def _get_oid(self, mod_name, sym_name):
        """Getting values from source by SNMP.

        Args:
            mod_name(dict):  MIB module name.
            sym_name(str):  MIB symbol name

        Returns:
            list:  List of MIBs oids.

        Examples::

            self._get_oid('ons_stat', 'onsSnmpAgentStatisticsPortId', 'tests/ui/mibs/')

        """

        mib_node, = self.mib_builder.importSymbols(mod_name, sym_name)[0:1]
        listed_oid = list(mib_node.getName())
        self.suite_logger.debug("Transleted OID: %s" % (listed_oid, ))

        return listed_oid

    def _get_previous(self, mod_name, sym_name):
        """Getting OID and NodeName of previous SNMP element of sequence.

        Args:
            mod_name(dict):  MIB module name.
            sym_name(str):  MIB symbol name

        Returns:
            list:  List with OID and symbol name of previous element.

        Examples::

            self._get_previous('ONS-SWITCH-MIB', 'onsSwitchppControlBridgeInfoInbandIpNetMaskInetAddress')

        """

        mib_node, = self.mib_builder.importSymbols(mod_name, sym_name)[0:1]
        type_oid = list(mib_node.getName())

        # decreasing last oid member for 1
        type_oid[-1] -= 1

        # getting information for previous element
        oid, prev_names, suffix = self.mibViewController.getNodeNameByOid(tuple(type_oid))

        return list(oid), prev_names[-1]

    def _normalize_result(self, mod_name, sym_name, result, to_oid=False):
        """Normalize SNMP GET result according syntax from MIB.

        Args:
            mod_name(dict):  MIB module name.
            sym_name(str):  MIB symbol name
            result(list):  List with one SNMP GET result for all types except InetAddress,
                           for InetAddress - list with two elements ['InetAddress', 'InetAddressType'].
            to_oid(bool):  indicator of formatting given result for OID.

        Returns:
            str, int:  Normalized result according to syntax.

        Examples::

            self._normalize_result('ONS-SWITCH-MIB', 'onsSwitchppControlBridgeInfoInbandIpNetMaskInetAddress',
                                   [OctetString(hexValue='ffffff00'), Integer(1)])

        """

        mib_node, = self.mib_builder.importSymbols(mod_name, sym_name)[0:1]
        syntax = mib_node.getSyntax()

        # branch for basic SNMP types
        if len(result) == 1 and result != 'None':
            result = result[0]

            # formatting digital types
            if result.isSuperTypeOf(self.__integer) or result.isSuperTypeOf(self.__counter32) \
                    or result.isSuperTypeOf(self.__unsigned32) or result.isSuperTypeOf(self.__counter64):
                self.suite_logger.debug("DIGITAL result type found.")
                if to_oid is False:
                    # if DIGITAL result normalizing not for OID
                    subtype_named_values = syntax.subtype().getNamedValues()
                    if len(subtype_named_values.namedValues) > 0:
                        result = subtype_named_values.getName(result)
                    elif hasattr(syntax, 'displayHint') and syntax.displayHint is not None:
                        self.suite_logger.debug("Formatting result according to DISPLAY-HINT: \"%s\"" % syntax.displayHint)
                        try:
                            result = int(syntax.prettyOut(result))
                        except ValueError:
                            result = syntax.prettyOut(result)
                    else:
                        result = int(result)
                elif to_oid is True:
                    # normalizing DIGITAL result for OID
                    self.suite_logger.debug("Formatting result to use in OID")
                    result = int(result)

            # formatting string types
            elif result.isSuperTypeOf(self.__octetString) or isinstance(result, self.OctetString):
                self.suite_logger.debug("OCTET STRING result type found.")
                if not to_oid:
                    # normalizing OCTET STRING result not for OID
                    if hasattr(syntax, 'displayHint') and syntax.displayHint is not None:
                        self.suite_logger.debug("Formatting result according to DISPLAY-HINT: \"%s\"" % syntax.displayHint)
                        result = syntax.prettyOut(result)
                    else:
                        self.suite_logger.debug("No DISPLAY-HINT found.")
                        result = result.prettyPrint()
                else:
                    # normalizing OCTET STRING result for OID
                    self.suite_logger.debug("Formatting result to use in OID")
                    res_len = "" if syntax.isFixedLength() else str(len(result)) + "."
                    result = res_len + ".".join(str(number) for number in result.asNumbers())
            else:
                self.suite_logger.debug("Unknown result type. Result \"%s\" didn't normalized." % (result, ))

        # branch for [InetAddress, InetAddressType] result
        elif len(result) == 2:
            if isinstance(syntax, self.InetAddress):
                self.suite_logger.debug("INET ADDRESS result type found.")
                addr_type_sym_name = self._get_previous(mod_name, sym_name)[1]
                addr_type = self._normalize_result(mod_name, addr_type_sym_name, [result[1]])
                self.suite_logger.debug("Formatting result according to INET ADDRESS TYPE value: \"%s\" = \"%s\"" % (addr_type_sym_name, addr_type))
                result = self.InetAddresses[addr_type].prettyOut(result[0])
                # normalizing InetAddress result for OID
                if to_oid is True:
                    self.suite_logger.debug("Formatting result to use in OID")
                    if addr_type == "dns":
                        result = str(len(result)) + "." + ".".join(str(number) for number in result.asNumbers())
                    else:
                        result = ".".join(re.findall(r"[\w]+", result))
        else:
            self.suite_logger.debug("Unknown result type. Result \"%s\" didn't normalized." % (result[0], ))

        return result

    def _snmp_get_call(self, switch_id, arguments, community, version, to_oid=False, poll_timeout=20):
        """Getting data from source via SNMP.

        Args:
            switch_id(int):  ID of switch to get SNMP call to.
            arguments(list):  SNMP call (SNMP symbol name, index). Index can have inserted calls.
            community(str):  SNMP community to read.
            version(str):  version of SNMP protocol to use.
            to_oid(bool):  indicator of returned result's OID format
            poll_timeout(int):  timeout to appearing SNMP data.

        Returns:
            str, int:  Normalized received SNMP data.

        Examples::

            self._snmp_get_call(1, ['onsSwitchppControlBridgeInfoInbandIpNetMaskInetAddress', "1"],
                                    "sppCommunity", "v2", False, 20)
            self._snmp_get_call(1, ['onsSwitchppControlBridgeInfoInbandIpNetMaskInetAddress', ["1.{}.1",
                                    ["PortId", "1.2.3"]]], "sppCommunity", "v2", False, 20)

        """

        sym_name = arguments[0]

        if isinstance(arguments[1], list):
            # Making calls inserted to index
            if "{}" in arguments[1][0]:
                # formation of OID by calling inserted calls and substitution received values to index
                values_list = []
                for call in arguments[1][1:]:
                    values_list.append(self._snmp_get_call(switch_id, call, community, version, to_oid=True))
                arguments[1] = arguments[1][0].format(*values_list)
            elif isinstance(arguments[1][0], str) and len(arguments[1]) == 2:
                arguments[1] = self._snmp_get_call(switch_id, arguments[1], community, version, to_oid=True)

        # finding MIB name by symbol parameter's name
        self.suite_logger.debug("Get parameter: << %s >>" % (sym_name,))
        mod_name = self._find_and_load_mib(helpers.MIBS_DICT, sym_name)
        # Return 'None' if MIB for parameter wasn't found
        if not mod_name:
            return 'None'

        # getting listed_oid(s):
        listed_oids = []
        listed_oid = self._get_oid(mod_name, sym_name)
        listed_oids.append(listed_oid)

        # adding oid of previous element (must be InetAddressType) to list if param type is InetAddress
        mib_node, = self.mib_builder.importSymbols(mod_name, sym_name)[0:1]
        if isinstance(mib_node.getSyntax(), self.InetAddress):
            listed_oids.append(self._get_previous(mod_name, sym_name)[0])

        if len(arguments) == 2 or len(arguments) == 5:
            oid_index = []
            for oid_element in str(arguments[1]).split('.'):
                oid_index.append(int(oid_element))
            listed_oids = [(oid + oid_index) for oid in listed_oids]
        else:
            self.suite_logger.debug("Wrong number of arguments in call: %s" % arguments)
            return 'None'

        # performing snmpget procedure:
        if version == 'v2':
            ip_addr = self.switches[switch_id]['host']
            port = "161"
            end_time = time.time() + poll_timeout
            final_res = [univ.Null()]
            self.suite_logger.debug("Get OID: %s" % (listed_oids[0], ))

            while True:
                if time.time() < end_time:
                    # do while at least one result list member is instance of univ.Null class
                    if any(isinstance(result, univ.Null) for result in final_res):
                        error_indication, error_status, error_index, var_binds = cmdgen.CommandGenerator().getCmd(
                            cmdgen.CommunityData('test-agent', community, 1),
                            cmdgen.UdpTransportTarget((ip_addr, port)),
                            *listed_oids)

                        if len(var_binds) > 0:
                            final_res = list(res[1] for res in var_binds)
                            self.suite_logger.debug("Returned SNMP Data:<<< %s >>>" % (final_res, ))
                        else:
                            self.suite_logger.debug("Returned SNMP response:<<< EMPTY >>>")
                    else:
                        self.suite_logger.debug("SNMP Data is not None:<<< %s >>>" % (final_res, ))
                        break
                else:
                    self.suite_logger.debug("Timeout exceeded and SNMP data is not appeared")
                    break

        elif version == 'v3':
            username = arguments[-3]
            authpass = arguments[-2][1]
            privpass = arguments[-1][1]
            auth = arguments[-2][0]
            priv = arguments[-1][0]

            authprtcl = {'MD5': cmdgen.usmHMACMD5AuthProtocol,
                         'SHA': cmdgen.usmHMACSHAAuthProtocol,
                         'no_auth': cmdgen.usmNoAuthProtocol}

            privprtcl = {'DES': cmdgen.usmDESPrivProtocol,
                         'AES': cmdgen.usmAesCfb128Protocol,
                         'no_priv': cmdgen.usmNoPrivProtocol}

            error_indication, error_status, error_index, var_binds = cmdgen.CommandGenerator().getCmd(
                cmdgen.UsmUserData(username, authKey=authpass, privKey=privpass, authProtocol=authprtcl[auth], privProtocol=privprtcl[priv]),
                cmdgen.UdpTransportTarget((self.switches[switch_id]['host'], self.switches[switch_id]['port'])),
                *listed_oids)
            final_res = list(res[1] for res in var_binds)

        if any(isinstance(result, univ.Null) for result in final_res):
            self.suite_logger.debug("Result is \'None\':<<< %s >>>" % (final_res[0].prettyPrint()))
            final_res = 'None'
        else:
            final_res = self._normalize_result(mod_name, sym_name, final_res, to_oid)
            self.suite_logger.debug("Normalized result:<<< %s >>>" % final_res)

        return final_res

    def snmp_get(self, elements_list, community, version, poll_timeout=20):
        """Walking through list of element to get and calling self._snmp_call() method.

        Args:
            elements_list(list):  List of (SNMP symbol name, index) pairs. Index can have inserted calls.
            community(str):  SNMP community to read.
            version(str):  version of SNMP protocol to use.
            poll_timeout(int):  timeout to appearing SNMP data.

        Returns:
            list:  List of SNMP-GET command results.

        Examples::

            self._snmp_get([{"1":[["onsSnmpAgentStatisticsPortId", "1"]]}])
            self._snmp_get([{"1":[["onsSnmpAgentStatisticsPortId", ["1.{}.3", ["onsSnmpAgentStatisticsPortKey", "2.4.5"]]]]}],
                           "sppCommunity", "v2")

        """

        if not community:
            community = self.get_community

        result = []
        result_dict = {}
        result_list = []
        for elements_dict in elements_list:
            for key in list(elements_dict.keys()):
                if elements_dict[key] != [["readOnly"]]:
                    for arguments in elements_dict[key]:
                        result.append([self._snmp_get_call(int(key), arguments, community, version, False, poll_timeout)])
                else:
                    result = [["readOnly"]]
                result_dict[key] = result
        result_list.append(result_dict)
        return result_list

    def snmp_set(self, elements_list, community, mib_dir=None):
        """Setting values by SNMP.

        Args:
            elements_list(list):  List of (SNMP symbol name, index) pairs. Index can have inserted calls.
            community(str):  SNMP community to read.
            mib_dir(str):  MIB module name.

        Returns:
            list:  List of SNMP-SET command results.

        Examples::

            self._snmp_get(conf[test]['snmp_set'])

        """
        if not mib_dir:
            mib_dir = self.mib_dir
        if not community:
            community = self.set_community

        result = []
        result_dict = {}
        result_list = []
        # try:
        for elements_dict in elements_list:
            for key in list(elements_dict.keys()):
                if elements_dict[key] != [["readOnly"]]:
                    for arguments in elements_dict[key]:
                        sym_name = str(arguments[0])

                        if len(arguments) == 4:
                            arg_type = 3
                            arg_value = 2
                        else:
                            arg_type = 2
                            arg_value = 1

                        if arguments[arg_type] == 'INTEGER':
                            try:
                                set_value = univ.Integer(int(arguments[arg_value]))
                            except Exception:
                                result_dict[key] = [["None"]]
                                return result_list.append(result_dict)
                        else:
                            try:
                                set_value = univ.OctetString(arg_value)
                            except Exception:
                                result_dict[key] = [["None"]]
                                return result_list.append(result_dict)

                        # getting mib-number:
                        listed_oid = self._get_oid(mib_dir, sym_name)
                        if len(arguments) == 4:
                            for oid_element in str(arguments[1]).split('.'):
                                listed_oid.append(int(oid_element))
                        mib_number = tuple(listed_oid)

                        error_indication, error_status, error_index, var_binds = cmdgen.CommandGenerator().setCmd(
                            cmdgen.CommunityData('test-agent', 'private', 1),
                            cmdgen.UdpTransportTarget((self.switches[int(key)]['host'], self.switches[int(key)]['port'])),
                            (mib_number, set_value))

                        if error_index != 0:
                            final_res = error_status
                        else:
                            final_res = 0
                        result.append(final_res)
                else:
                    result = ["readOnly"]
                result_dict[key] = [result]
        result_list.append(result_dict)
        return result_list

    @staticmethod
    def snmp_walk(community, host, port, oid):
        """Perform SNMP walk for submitted oid.

        Args:
            community(str):  SNMP community to read.
            host(str):  SNMP host.
            port(int):  SNMP host port.
            oid(str):  SNMP OID.

        Raises:
            CustomException

        """
        from testlib.custom_exceptions import CustomException

        cmd_gen = cmdgen.CommandGenerator()
        error_indication, error_status, error_index, var_binds = cmd_gen.nextCmd(cmdgen.CommunityData('test-agent', community, 1),
                                                                                 cmdgen.UdpTransportTarget((host, port)), oid)

        # Check for errors and print out results
        if error_indication:
            raise CustomException(error_indication)
        else:
            if error_status:
                messages = ('%s at %s' % (error_status.prettyPrint(),  # pylint: disable=no-member
                                          error_index and var_binds[int(error_index) - 1] or '?'))
                raise CustomException(messages)
            else:
                if var_binds:
                    for name, val in var_binds[0]:
                        messages = '%s = %s' % (name.prettyPrint(), val.prettyPrint())
                else:
                    messages = 'Empty Replay'

        return messages
