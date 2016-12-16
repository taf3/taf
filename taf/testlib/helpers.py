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

@file  helpers.py

@summary  Helpers functions.
"""
import json
import os
import time
import random
import itertools
from xmlrpc.client import Fault as XMLRPCFault
from collections import OrderedDict

import py.code  # pylint: disable=no-name-in-module
import pytest
from _pytest.mark import MarkDecorator

from .custom_exceptions import CustomException, CLIException
from . import loggers


ERRORS = None
PLATFORM_INFO_DICT = None

MIBS_DICT = {}
# Wait timeout between state checking in wait_until_stp_state and wait_until_ops_state
DEFAULT_TIMEOUT = 2

# create logger for module
mod_logger = loggers.module_logger(name=__name__)

# Predefined test skippers


def simswitch_only(x="SimSwitch only test case."):
    return run_on_platforms(["lxc", ], x)


def realswitch_only(x="Real switch only test case."):
    return skip_on_platforms(["lxc", ], x)


def skiptest(x):
    return pytest.mark.skipif("True", reason=x or "Test case skipped by 'skiptest' marker.")


skip_reason = "This test is skipped on current platform."


def skip_on_platforms(x, y=skip_reason):
    return pytest.mark.skipif(
        "any(p in {0} for p in set([x.type for x in config.env.switch.values()]))".format(x),
        reason=y)


def run_on_platforms(x, y=skip_reason):
    return pytest.mark.skipif(
        "any(p not in {0} for p in set([x.type for x in config.env.switch.values()]))".format(x),
        reason=y)


def skip_on_ui(x, y="Skip with current UI"):
    return pytest.mark.skipif("config.option.ui in %s" % (x, ), reason=y)


def run_on_ui(x, y="Skip with current UI"):
    return pytest.mark.skipif("config.option.ui not in %s" % (x, ), reason=y)


def skip_on_tg(x, y=skip_reason):
    return pytest.mark.skipif(
        "any(t in {0} for t in set([x.type for x in config.env.tg.values()]))".format(x), reason=y)


def run_on_tg(x, y=skip_reason):
    return pytest.mark.skipif(
        "any(t not in {0} for t in set([x.type for x in config.env.tg.values()]))".format(x), reason=y)


def run_on_ixnetwork(y="Run on IxNetwork setup only"):
    return pytest.mark.skipif(
            "all(not x.is_protocol_emulation_present for x in config.env.tg.values())",
            reason=y)


def get_attribute_from_argvalue(argvalue, item):
    """
    @brief:  Gets an attribute from argvalues
    @param  item: This can be an int (it will attempt to retrieve an index or a
    str (it will attempt to retrieve a NamedTuple's field name)
    @type  item: int | str
    @raise  AttributeError: when attribute not found
    @raise  IndexError: when index not found
    @rtype:  str
    """
    # This is a MarkDectorator where the argvalue is the last element in args.
    while isinstance(argvalue, MarkDecorator):
        # getattr will raise natural Attribute error if args is not present
        mark_argvalue = getattr(argvalue, 'args')
        argvalue = mark_argvalue[-1]
    if isinstance(item, int):
        # integers can't be attributes so it must be an index
        name = argvalue[item]
    else:
        # this will raise TypeError is item is not a valid attribute
        name = getattr(argvalue, item)
    return name


def get_json(path, filename):
    """
    @brief  Get json file
    """
    file_path = os.path.join(path, 'resources', filename)
    with open(file_path) as _f:
        # we used to do unicode decode, but I don't know why.
        _json = json.load(_f)
    return _json


def get_stepped_value(value, step, step_type='Down'):
    """
    @brief:  Returns the rounded value, given an initial input value.
    @param  value: The input value
    @param  step:  The step value
    @param  step_up:  Whether the value is incremented to the next step
    @type  value:  int
    @type  step:  int | OrderedDict
    @type  step_up: bool
    @raise:  ValueError
    @rtype: int
    """
    if isinstance(step, OrderedDict):
        attribute_step = step.copy()
        threshold_value, threshold_step = attribute_step.popitem(last=False)
        while value >= threshold_value:
            try:
                threshold_value, threshold_step = attribute_step.popitem(last=False)
            except KeyError:
                break
        step = threshold_step
    if not isinstance(step, int):
        raise KeyError("Unexpected argument for step.")

    if step_type in {'Up', 'Down'}:
        added_step = (step if value % step > 0 and step_type == 'Up' else 0)
    elif step_type == 'Round':
        added_step = (step if float(value % step) / step >= 0.5 else 0)
    else:
        raise TypeError

    return value // step * step + added_step


def ri_find_wrapper(switch_instance, vlan=None, ip_address=None, bandwith=100, mtu=1500, vrf=0):
    """
    @brief  Wrapper of "find" function for RouteInterface table.

    @note this is temporary function.

    @param  switch_instance:  Switch instance
    @param vlan:  Vlan on which route interface is implemented.
    @param ip_address:  IP address of route interface.
    @param mtu:  MTU of route interface.
    @param bandwith:  Bandwith of route interface
    @param vrf:  Virtual route Id

    @return  row

    @par  Example:
    @code
    _ri_find_wrapper(env.switch[1], vlan=10, ip_address="10.0.10.1/24", mtu=100, bandwith=1500, vrf=0)
    @endcode
    """
    try:
        result = switch_instance.nb.RouteInterface.find(vlan, ip_address, bandwith, mtu, vrf)
    except XMLRPCFault:
        result = switch_instance.nb.RouteInterface.find(ip_address)
    return result


def wait_for_route_iface_status(switch, iface_id, timeout, status):
    """
    @brief  Wait for RouteInterface changed its oper status to expected value or raise exception if it is not after 'interval' seconds elapsed

    @param switch:  switch for checking RouteInterface oper state value
    @param iface_id:  interface id for checking oper state value
    @param timeout:   seconds for checking RouteInterface oper state value
    @param status:  RouteInterface oper state value (lower)

    @return  None

    @par  Example:
    @code
    _wait_for_route_iface_status(env.switch[1], 2, 120, 'down')
    @endcode
    """
    end_time = time.time() + timeout
    while True:
        time.sleep(0.33)
        if switch.nb.RouteInterface.get.operationalStatus(iface_id).lower() == status.lower():
            break
        else:
            if time.time() > end_time:
                raise CustomException("Route Interface %s did not change its status to  %s after %s seconds elapsed" % (iface_id, status, timeout))


def wait_for_route_iface_deleted(switch, iface_id, ip_address, bandwidth, mtu, vrf, timeout):
    """
    @brief  Wait for RouteInterface deleted if it is not after 'timeout' seconds elapsed

    @param switch:  switch for checking RouteInterface being deleted
    @param iface_id:  interface id for checking RouteInterface being deleted
    @param ip_address:  ip address for checking RouteInterface being deleted
    @param bandwidth:  bandwidth for checking RouteInterface being deleted
    @param mtu:   mtu for checking RouteInterface being deleted
    @param vrf:  vrf for checking RouteInterface being deleted
    @param timeout:  seconds for checking RouteInterface being deleted

    @return  None

    @par  Example:
    @code
    _wait_for_route_iface_deleted(env.switch[1], 3210, '2001:db8:85a3::8a3e:370:7377/96', 1000, 1280, 0, 120)
    @endcode
    """
    end_time = time.time() + timeout
    while True:
        time.sleep(0.33)
        if switch.nb.RouteInterface.find(iface_id, ip_address, bandwidth, mtu, vrf) == -1:
            break
        else:
            if time.time() > end_time:
                raise CustomException("Route Interface %s was not deleted after %s seconds elapsed" % (iface_id, timeout))


def set_all_ports_admin_disabled(switches, wait_status=True):
    """
    @brief  Sets all ports of all switches provided as an argument to admin state Down.

    @param  switches:  Switches configuration (dictionary)
    @param  wait_status:  Wait for ports desire necessary state (bool)

    @return  none

    @par  Example:
    @code
    set_all_ports_admin_disabled(env.switch)
    @endcode
    """

    mod_logger.debug("Set adminMode = Disabled for all ports...")
    if isinstance(switches, dict):
        switch_instances = [x for x in list(switches.values()) if not hasattr(x, "rag") or x.rag.role == "master"]

        for switch_instance in switch_instances:
            switch_instance.ui.set_all_ports_admin_disabled()

        if wait_status:
            for switch_instance in switch_instances:
                switch_instance.ui.wait_all_ports_admin_disabled()


def set_ports_admin_enabled(switches, ports, wait_status=True, fail_func=None):
    """
    @brief  Sets provided in arguments ports to admin state Up.

    @param  switches:  Switches configuration (dictionary)
    @param  ports:  List of ports to enable. Each element is a dictionary like {('sw1', 'sw2'): {link_id: port_id})} (dictionary of dictionaries)
    @param  wait_status:  Wait for ports desire necessary state (bool)
    @param  fail_func:  function with params that will be executed in case of failure (tuple)

    @return  none

    @par  Example:
    @code
    ports = {('sw1', 'sw2'): {1: 2, 2: 4}}
    set_ports_admin_enabled(env.switch, ports)
    set_ports_admin_enabled(env.switch, ports, fail_func=(pytest.softexit, [mesasge, env]))
    @endcode
    """

    def wait_for_port_status(switch, port, status, timeout=30):
        """
        @brief  Wait for port status during specified time.
        """
        mod_logger.debug("Function wait_for_port_status started.")
        end_time = time.time() + timeout
        iter_counter = 1
        while True:
            if time.time() < end_time:
                _port_row = switch.ui.get_table_ports([port])
                _status = _port_row[0]['operationalStatus']
                if _status == status:
                    mod_logger.debug("Function wait_for_port_status finished.")
                    break
                iter_counter += 1
                time.sleep(0.3)
            else:
                mod_logger.debug("Function wait_for_port_status finished.")
                raise CustomException(("Timeout exceeded: Parameter operationalStatus wasn't changed in Ports table " +
                                       "during timeout 30 into %s value") % (status, ))

    # WORKAROUND: Verify that port is up and retry if not
    def check_n_retry(xmlproxy, port, op_xmlproxy, op_port, timeout=30):
        """
        @brief  Check that port change status to Up and retry Down/Up cycle if not.
        """
        # Convert port number to port Id in switch table.
        try:
            wait_for_port_status(xmlproxy, port, "Up", timeout=timeout)
        except CustomException:
            mod_logger.warning("Port %s on switch %s does not pass to Up state. Retry..." % (port, xmlproxy.ipaddr))
            xmlproxy.ui.modify_ports([port, ], adminMode='Down')
            if op_xmlproxy is not None:
                op_xmlproxy.ui.modify_ports([op_port, ], adminMode='Down')
            time.sleep(0.3)
            xmlproxy.ui.modify_ports([port, ], adminMode='Up')
            if op_xmlproxy is not None:
                op_xmlproxy.ui.modify_ports([op_port, ], adminMode='Up')
            try:
                wait_for_port_status(xmlproxy, port, "Up")
            except CustomException:
                mod_logger.error("Port %s on switch %s does not pass to Up state after retry." %
                                 (port, xmlproxy.ipaddr))
                if fail_func is None:
                    raise
                else:
                    _args = []
                    _kwargs = {}
                    for _param in fail_func[1:]:
                        if isinstance(_param, list):
                            _args = _param
                        if isinstance(_param, dict):
                            _kwargs = _param
                    fail_func[0](*_args, **_kwargs)

    # WORKAROUND END

    mod_logger.debug("Setting admin mode up for ports: %s." % (ports, ))
    # TAFv2
    if isinstance(ports, dict):
        for link_key in list(ports.keys()):
            # Check if the first component of ports key is switch acroname
            if link_key[0][:2] == "sw":
                sw_id = int(link_key[0][2:])
                for port_id in list(ports[link_key].keys()):
                    mod_logger.debug("Setting admin mode up for port %s of %s device." %
                                     (ports[link_key][port_id], switches[sw_id].ipaddr))
                    # Additional check for LAGs
                    port_info = switches[sw_id].ui.get_table_ports([ports[link_key][port_id]])[0]
                    if port_info['type'] == 'LAG':
                        check_n_retry_timeout = 70  # ONS requires 70 seconds to wait for LAG become Up
                    else:
                        check_n_retry_timeout = 30
                    switches[sw_id].ui.modify_ports([ports[link_key][port_id]], adminMode='Up')

        if wait_status:
            for link_key in list(ports.keys()):
                if link_key[0][:2] == "sw":
                    sw_id = int(link_key[0][2:])
                    # Check for opposite switch
                    if link_key[1][:2] == "sw":
                        op_sw_id = int(link_key[1][2:])

                        _link_key_left = (link_key[1], link_key[0])
                        op_switch = switches[op_sw_id]
                    else:
                        op_switch = None
                    for port_id in list(ports[link_key].keys()):
                        mod_logger.debug("Verify operational status of port %s of %s device." %
                                         (ports[link_key][port_id], switches[sw_id].ipaddr))
                        if op_switch is not None:
                            op_port = ports[_link_key_left][port_id]
                        else:
                            op_port = None

                        check_n_retry(switches[sw_id], ports[link_key][port_id], op_switch, op_port, check_n_retry_timeout)

    else:
        raise CustomException("Unknown ports list type.")


def wait_until_fdb_entry_is_added(mac_address=None, port_id=1, timeout=5, vlan_id=1, switch_instance=None):
    """
    @brief  Wait some time for adding dynamic entry to FDB

    @param switch_instance:  Switch instance to work with (xmlrpclib.ServerProxy object)
    @param mac_address:  MAC address for check
    @param port_id:  Port ID corresponding to MAC address
    @param vlan_id:  VLAN ID corresponding to MAC address
    @param  timeout:  seconds for checking Fdb entry being added

    @return  none

    @par  Example:
    @code
    wait_time_for_adding_entry_to_fdb(mac_address=source_mac, port_id=port_id_2, timeout=10, vlan_id=vlan_id, switch_instance=env.switch[1])
    @endcode
    """
    if type(switch_instance).__name__.find("Switch") >= 0:
        switch_instance = switch_instance.xmlproxy
    end_time = time.time() + timeout
    break_flag = False
    while True:
        if time.time() < end_time:
            table = switch_instance.nb.Fdb.getTable()
            table_length = len(table)
            if mac_address is not None:
                for row in table:
                    if row['macAddress'] == mac_address and row['portId'] == port_id and row['vlanId'] == vlan_id:
                        break_flag = True
                        break
                if break_flag:
                    break
            else:
                table_length = len(table)
                if table_length != 0:
                    break
        else:
            raise Exception("Timeout exceeded: Entry with %s MAC-address, %s Port Id and %s Vlan Id is not added during timeout" %
                                (mac_address, port_id, vlan_id))


def is_entry_added_to_fdb(mac_address=None, port_id=1, vlan_id=1, switch_instance=None):
    """
    @brief  Check dynamic entry in FDB

    @param switch_instance:  Switch instance to work with (xmlrpclib.ServerProxy object)
    @param mac_address:  Source mac-address to check entry in FDB
    @param port_id:  Port number from where packet was sent (integer)
    @param vlan_id:  Vlan number from where packet was sent (integer)
    @return  True or False

    @par  Example:
    @code
    is_entry_added_to_fdb(mac_address=source_mac, port_id=1, vlan_id=vlab_id, switch_instance=env.switch[1].xmlproxy)
    @endcode
    """
    if type(switch_instance).__name__.find("Switch") >= 0:
        switch_instance = switch_instance.xmlproxy
    table = switch_instance.nb.Fdb.getTable()
    row_count = 0
    for row in table:
        if row['macAddress'] == mac_address and row['portId'] == port_id and row['vlanId'] == vlan_id:
            row_count += 1
    if row_count == 1:
        return True
    return False


def is_static_entry_added(mac_address=None, vlan_id=1, port_id=1, switch_instance=None):
    """
    @brief  Check static entry in StaticMAC table

    @param switch_instance:  Switch instance to work with (xmlrpclib.ServerProxy object)
    @param mac_address:  Source mac-address to check entry in FDB
    @param port_id:  port number from where packet was sent (integer)
    @param vlan_id:  vlan number from where packet was sent (integer)
    @return  True or False

    @par  Example:
    @code
    is_static_entry_added(mac_address=source_mac, port_id=1, vlan_id=vlab_id, switch_instance=env.switch[1].xmlproxy)
    @endcode
    """
    table = switch_instance.nb.StaticMAC.getTable()
    row_count = 0
    for row in table:
        if row['macAddress'] == mac_address and row['vlanId'] == vlan_id and row['portId'] == port_id:
            row_count += 1
    if row_count == 1:
        return True
    return False


def is_entry_added_to_acl_expressions_table(field=None, mask=None, data=None, switch_instance=None):
    """
    @brief  Check entry in ACL Expressions Table

    @param switch_instance:  Switch instance to work with (xmlrpclib.ServerProxy object)
    @param field:  The field to operate on
    @param mask:  The bitwise mask to AND with the field
    @param data:  The expected result
    @return  True or False

    @par  Example:
    @code
    is_entry_added_to_acl_expressions_table(field=field, mask=mask_acl, data=data_acl, switch_instance=env.switch[1].xmlproxy)
    @endcode
    """
    table = switch_instance.nb.ACLExpressions.getTable()
    row_count = 0
    for row in table:
        if row['field'] == field and row['mask'] == mask and row['data'] == data:
            row_count += 1
    if row_count == 1:
        return True
    return False


def is_entry_added_to_acl_actions_table(action=None, param=None, switch_instance=None):
    """
    @brief  Check entry in ACL Actions Table

    @param switch_instance:  Switch instance to work with (xmlrpclib.ServerProxy object)
    @param action:  The actual action
    @param param:  Parameters required for the action
    @return  True or False

    @par  Example:
    @code
    is_entry_added_to_acl_actions_table(action=action_acl, param=param_acl, switch_instance=env.switch[1].xmlproxy)
    @endcode
    """
    table = switch_instance.nb.ACLActions.getTable()
    row_count = 0
    for row in table:
        if row['action'] == action and row['param'] == param:
            row_count += 1
    if row_count == 1:
        return True
    return False


def is_entry_added_to_rules_table(rule_id=1, expression_id=1, action_id=1, stage=None, enabled="Disabled", priority=1, switch_instance=None):
    """
    @brief  Check entry in ACL Rules Table

    @param switch_instance:  Switch instance to work with (xmlrpclib.ServerProxy object)
    @param  rule_id:  Given ruleId from the ACLRules table
    @param expression_id:  Given expressionId from the ACLExpressions table
    @param action_id:  Given actionId from the ACLActions table
    @param stage:  "Ingress", "Egress", "Lookup"
    @param enabled:  Enable or disable rule
    @param priority:  Rules priority
    @return  True or False

    @par  Example:
    @code
    is_entry_added_to_rules_table(rule_id=rule_id, expression_id=expression_id, action_id=action_id,
                                  stage=rules_stage_ingress, enabled=rules_disabled,
                                  priority=priority_zero, switch_instance=env.switch[1].xmlproxy)
    @endcode
    """
    table = switch_instance.nb.ACLRules.getTable()
    row_count = 0
    for row in table:
        if row['ruleId'] == rule_id and row['expressionId'] == expression_id and \
           row['actionId'] == action_id and row['stage'] == stage and \
           row['enabled'] == enabled and row['priority'] == priority:
            row_count += 1
    if row_count == 1:
        return True
    return False


def set_invalid_value(switch_instance=None, method=None, params=None):
    """
    @brief  Exception handler for negative testcases

    @param switch_instance:  Switch instance to work with (xmlrpclib.ServerProxy object)
    @param method:  XML RPC method to invoke (string)
    @param params:  Arguments to pass to XML RPC method (list of mixed types values)

    @return  none

    @par  Example:
    @code
    set_invalid_value(switch_instance=env.switch[1].xmlproxy, method="nb.Table.set.field", params=[param1, param2,param3])
    @endcode
    """
    try:
        return_code = getattr(switch_instance, method)(*params)
        if return_code == -1:
            raise Exception("Cannot set invalid parameter: %s(%s)" % (method, str(params)[1:][:-1]))
        if return_code == 0:
            bad_value_set_successfully = True
            mod_logger.debug("Invalid parameter was set: %s(%s)" % (method, str(params)[1:][:-1]))
    except Exception as err:
        bad_value_set_successfully = False
        mod_logger.debug("Error: %s" % err)
    finally:
        assert not bad_value_set_successfully


def clear_table(switch_instance=None, table_name=None):
    """
    @brief  Clear table for correct test cases work

    @param switch_instance:  Switch instance to work with (xmlrpclib.ServerProxy object)
    @param table_name:  Specific table name (string)

    @return  none

    @par  Example:
    @code
    clear_table(switch_instance=env.switch[1], table_name="ACLRules")
    @endcode
    """
    if switch_instance.opts.ui == "onpss_shell":
        # Note: This needs to be fixed. It assumes clear_table is clearing static FDB table where it should be taking in a table_name
        if table_name == "StaticMAC":
            switch_instance.ui.clear_table_fdb()
    else:
        param_names = switch_instance.getprop_method_help("nb.%s.find" % (table_name, ))
        param_names = param_names.split(table_name)[1]
        param_names = param_names[1: param_names.index(")")]
        param_names_list = param_names.split(',')
        table = switch_instance.getprop_table(table_name)
        for row in table:
            find_params_list = []
            for _key in param_names_list:
                find_params_list.append(row[_key.strip()])
            assert switch_instance.delprop_row(table_name, switch_instance.findprop(table_name, find_params_list)) == 0


def set_stp_mode(switch_instance=None, mode="STP"):
    """
    @brief  Set SpanningTree mode to STP|RSTP|MSTP

    @param  switch_instance:  Switch class instance to work with
    @param  mode:  SpanningTree mode

    @return  none

    @par  Example:
    @code
    set_stp_mode(env.switch[1], "MSTP")
    @endcode
    """
    # if not switch_instance.getprop("SpanningTree", "mode", 1) == mode:
    #         switch_instance.setprop("SpanningTree", "globalEnable", [1, "Disabled"])
    #         switch_instance.setprop("SpanningTree", "mode", [1, mode])
    #         switch_instance.setprop("SpanningTree", "globalEnable", [1, "Enabled"])
    # WORKAROUND for compatibility with TAFv1
    if type(switch_instance).__name__.find("Switch") >= 0:
        switch_instance = switch_instance.xmlproxy
    if not switch_instance.nb.SpanningTree.get.mode(1) == mode:
        switch_instance.nb.SpanningTree.set.globalEnable(1, "Disabled")
        switch_instance.nb.SpanningTree.set.mode(1, mode)
        switch_instance.nb.SpanningTree.set.globalEnable(1, "Enabled")


def change_stp_state(switche_instance, state):
    """
    @brief  Disables/Enables STP state on per-port basis.

    @note  Very useful to prevent packet storm caused by global STP disabling.

    @param switche_instance:  Switche xmlrpc.ServerProxy object (object)
    @param state:  Desired STP state change action ('Enabled' or 'Disabled')

    @return  none
    """
    # define ports directly from the switch
    ports_table = switche_instance.nb.Ports.getTable()
    for port in ports_table:
        if state == "Enabled":
            switche_instance.nb.RSTPPorts.set.adminState(int(port['portId']), "Enabled")
        elif state == "Disabled":
            switche_instance.nb.RSTPPorts.set.adminState(int(port['portId']), "Disabled")
        else:
            raise ValueError("Unknown state (%s) specified. Acceptable values are 'Enabled' and 'Disabled'." % (state, ))


def set_lldp_ports_admin_status(switch_instance, port_list, status="Disabled"):
    """
    @brief  Set LLDP port admin status on ports.

    @param switch_instance:  the switch instance.
    @param port_list:  the list of ports.
    @param status:  the LLDP port admin status.

    @return  True or False

    @end
    """
    # check if LLDP feature is enabled
    if 'nb.LldpPorts.set.adminStatus' in switch_instance.system.listMethods():
        for port in port_list:
            if switch_instance.nb.LldpPorts.set.adminStatus(port, status) != 0:
                return False
    return True


def wait_until_value_is_changed(switch_instance=None, table_name=None, parameter_name=None, value=None, row_id=1, timeout=30, findlist=None):
    """
    @brief  Wait until value is changed in table

    @param switch_instance:  Switch class instance to work with
    @param table_name:  Specific getTable method (string)
    @param parameter_name:  Parameter in table (string)
    @param value:  Checking value
    @param row_id:  Row id in table
    @param timeout:  time to wait until value is changed
    @param findlist:  list of parameters to find a row in the given table

    @return  True or False

    @par  Example:
    @code
    wait_until_value_is_changed(env.switch[1], "Ports2LagRemote", "partnerOperSystemPriority", 0, 1)
    wait_until_value_is_changed(switch_instance=env.switch[1], table_name="Ports2LagRemote", parameter_name="partnerOperSystemPriority",
                                value=0, row_id=1, timeout=30, [1, 1])
    @endcode
    """
    mod_logger.debug("Function wait_until_value_is_changed started.")
    end_time = time.time() + timeout
    iter_counter = 1
    while True:
        if time.time() < end_time:
            if findlist is not None:
                row_id = switch_instance.findprop(table_name, findlist)
                while (row_id == -1) and (time.time() < end_time):
                    time.sleep(0.3)
                    waiting_table_is_loaded(switch_instance=switch_instance, table_name=table_name, expected_table_length=1, timeout=60, deviation=1,
                                            direction="+")
                    row_id = switch_instance.findprop(table_name, findlist)
            if type(switch_instance).__name__.find("Switch") >= 0:
                parameter = switch_instance.getprop(table_name, parameter_name, row_id)
            else:
                parameter = getattr(switch_instance, "nb.%s.get.%s" % (table_name, parameter_name))(row_id)
            mod_logger.debug("table_name %s row_id %s parameter_name %s = %s; iterated %s times, time to leave = %s" %
                             (table_name, row_id, parameter_name, parameter, iter_counter, (end_time - time.time())))
            if parameter == value:
                mod_logger.debug("Function wait_until_value_is_changed finished.")
                break
            iter_counter += 1
            time.sleep(0.3)
        else:
            mod_logger.debug("Function wait_until_value_is_changed finished.")
            raise CustomException(("Timeout exceeded: Parameter %s wasn't changed in %s table " +
                                   "during timeout %s into %s value") %
                                  (parameter_name, table_name, timeout, value))


def send_receive_packets(packet_definition=None, count=5, src_port=None, dst_port=None,
                         sniff_time=5, sniff_filter="", tg=None, expect_rcv=True):
    """
    @brief  Send and verify receiving of packets
    """

    def _compare_packets(packet_definition=None, packet=None, tg=None):
        """
        @brief  Comparing packets.
        """
        for i, v in enumerate(packet_definition):
            for layer in list(packet_definition[i].keys()):
                if tg.get_packet_layer(packet=packet, layer=layer, output_format="pypacker"):
                    for field in list(packet_definition[i][layer].keys()):
                        if not tg.check_packet_field(packet=packet, layer=layer, field=field,
                                                     value=packet_definition[i][layer][field]):
                            return False
                else:
                    return False
        return True

    def _count_packets_by_definition(packets, packet_definition=None, tg=None):
        """
        @brief  Counting specific packets.
        """
        count = 0
        for packet in packets:
            if _compare_packets(packet_definition, packet, tg):
                count += 1
        return count

    mod_logger.debug("Verify packets forwarding. %s -> %s" % (src_port, dst_port, ))
    stream_id = tg.set_stream(packet_definition, count=count, iface=src_port)
    tg.start_sniff([dst_port, ], sniffing_time=sniff_time, filter_layer=sniff_filter,
                   packets_count=count)
    tg.send_stream(stream_id)

    data = tg.stop_sniff([dst_port, ])
    mod_logger.debug("Got data %s" % data)

    all_rcvd = _count_packets_by_definition(data[dst_port], packet_definition, tg) == count

    if expect_rcv:
        assert all_rcvd, ("Comparison of packets sent from {0} and received "
                          "on {1} failed".format(src_port, dst_port))
    else:
        assert not all_rcvd, ("Unexpected packets from {0}"
                              "received on {1}".format(src_port, dst_port))


def waiting_table_is_loaded(switch_instance, table_name, expected_table_length, watch_interval=1, timeout=120, deviation=None, direction=None, verbose=False):
    """
    @brief  Wait until any table become necessary size, for example it can ba Dynamic ARP table or Route table.
            Use deviation parameter if expected_table_length is not strict and can be larger ("+") then expected on deviation value
            or smaller ("-") then expected on deviation value or near (None=+/-) expected on deviation value

    @param switch_instance:  switch instance from env (object)
    @param table_name:  table name under test, example: "ARP" (string)
    @param expected_table_length:  value table length should increase to (int)
    @param watch_interval:  interval in seconds between re-reading table from switch instance (int)
    @param timeout:  120 - timeout in seconds for function execution (int)
    @param deviation:  if expected_table_length is not strict value and some deviation in entries is acceptable (int)
    @param direction:  "+", "-" or None. In case None then assuming that deviation is bidirectional, both "+" and "-" (string)
    @param verbose:  can be True or False. In case True then monitoring table content will be displayed in debug log (bool)

    @return  True/False

    @par  Example:
    @code
    helpers.waiting_table_is_loaded(env.switch[1], "Route", 21, watch_interval = 1, timeout = 120, deviation = 2, direction = "+")

    @endcode
    """
    mod_logger.debug("Starting 'waiting_table_is_loaded' function.")

    if deviation is None:
        left_margin = expected_table_length
        right_margin = expected_table_length + 1
        direction = None
    else:
        if direction is None:
            left_margin = expected_table_length - deviation
            right_margin = expected_table_length + deviation + 1
        elif direction == "+":
            left_margin = expected_table_length
            right_margin = expected_table_length + deviation + 1
        elif direction == "-":
            left_margin = expected_table_length - deviation
            right_margin = expected_table_length + 1

    mod_logger.debug("waiting_table_is_loaded - received parameters: table_name: %s, expected table length range: %s, watch_interval: %s, timeout: %s,\
                      deviation: %s, direction: %s" % (table_name, list(range(left_margin, right_margin)), watch_interval, timeout, deviation, direction))

    end_time = time.time() + timeout

    table_length = switch_instance.getprop_size(table_name)

    while table_length not in list(range(left_margin, right_margin)):
        if time.time() >= end_time:
            mod_logger.error("Timeout exceeded: %s table length %s wasn't changed to %s during %s" %
                             (table_name, table_length, list(range(left_margin, right_margin)), timeout))
            mod_logger.debug("Function 'waiting_table_is_loaded' is finished.")
            return False
        table_length = switch_instance.getprop_size(table_name)
        mod_logger.debug("%s table length = %s, time left %s" % (table_name, table_length, end_time - time.time()))
        if verbose:
            table = switch_instance.getprop_table(table_name)
            mod_logger.debug("%s table content: %s" % (table_name, table))
        mod_logger.debug("Waiting for %s seconds for next iteration" % watch_interval)
        time.sleep(watch_interval)
    mod_logger.debug("Exit parameters: table_name: %s, expected table length range: %s, current table length: %s" %
                     (table_name, list(range(left_margin, right_margin)), table_length))
    mod_logger.debug("Function 'waiting_table_is_loaded' is finished.")
    return True


def generate_random_mac(mac_exclusions=None, quantity=1):
    """
    @brief  Generate list that contains randomly generated MAC addresses that starts from 00

    @param mac_exclusions:  list if MAC addresses that should be excluded from generated list (list)
    @param quantity:  quantity of mac addresses that should be generated (int)

    @return  mac_pool  list of generated MAC addresses

    @par  Example: mac_exclusions = ["01:00:02:00:00:01", ], quantity = 10
    @code
    source_macs = helpers.generate_random_mac(mac_exclusions = ["01:00:02:00:00:01", ], quantity = 10)
    @endcode
    """
    mod_logger.debug("Starting 'generate_random_mac' function.")
    if mac_exclusions is None:
        mac_exclusions = []
    forbidden_macs = ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", ]
    mac_exclusions.extend(forbidden_macs)
    mac_pool = []
    count = 1
    while count <= quantity:
        mac = [0x00,
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff), ]
        mac_addr = ":".join(["%02x" % x for x in mac])
        if mac_addr not in mac_exclusions:
            mac_pool.append(mac_addr)
            mac_exclusions.append(mac_addr)
            count += 1
    mod_logger.debug("Generated MAC addresses list %s" % mac_pool)
    mod_logger.debug("Function 'generate_random_mac' is finished.")
    return mac_pool


def generate_random_ip(ip_exclusions=None, prefix=None, quantity=1):
    """
    @brief  Generate list that contains randomly generated IP addresses that starts from prefix.

    @param ip_exclusions:  list if IP addresses that should be excluded from generated list, for example Route Interface address used on device (list)
    @param prefix:  Network part of IP address (string)
    @param quantity:  quantity of ip addresses that should be generated (int)

    @return  ip_pool  list of generated MAC addresses

    @par  Example: ip_exclusions = ["10.0.1.1", ], quantity = 10
    @code
    source_ips = helpers.generate_random_ip(ip_exclusions = router_ips, prefix = "10.0.1", quantity = streams_quantity)
    @endcode
    """
    mod_logger.debug("Starting 'generate_random_ip' function.")
    if ip_exclusions is None:
        ip_exclusions = []
    forbidden_ips = ["127.0.0.1", ]
    ip_exclusions.extend(forbidden_ips)
    prefix_part = list(int(part) for part in prefix.split('.'))
    suffix_length = 4 - len(prefix_part)
    ip_pool = []
    count = 1
    while count <= quantity:
        suffix_count = 1
        suffix_part = []
        while suffix_count <= suffix_length:
            suffix_part.append(str(random.randrange(1, 255)))
            suffix_count += 1
        ip_part = [str(prefix), ]
        ip_part.extend(suffix_part)
        ip = ".".join(ip_part)
        if ip not in ip_exclusions:
            ip_pool.append(ip)
            ip_exclusions.append(ip)
            count += 1
    mod_logger.debug("Generated IP addresses list %s" % ip_pool)
    mod_logger.debug("Function 'generate_random_ip' is finished.")
    return ip_pool


def stat_counters_clear(switch_instances=None, ports=None, counter_name="EtherStatsPkts"):
    """
    @brief  Clear all statistic counters on defined port.

    @note  DO NOT USE ON CONTINUOUSLY RUNNING TRAFFIC - FUNCTION IS WAITING THAT COUNTER BECOME 0

    @param switch_instances:  list of switch instances from env
    @param ports:  list of ports where statistic should be cleared
    @param counter_name:  counter that checked to become 0 after clear action. "EtherStatsPkts" used by default.

    @return  nothing

    @par  Example: switch_instances=[env.switch[2], ], ports=ports["sw2", "sw1"].values(), counter_name="EtherStatsPkts256to511Octets"
    @code
    helpers.stat_counters_clear(switch_instances=[env.switch[2], ], ports=ports["sw2", "sw1"].values(), counter_name="EtherStatsPkts256to511Octets")
    @endcode
    """
    mod_logger.debug("Starting 'stat_counters_clear' function.")
    if switch_instances is None:
        mod_logger.debug("'switch_instances' is not defined.")
        return False
    if ports is None:
        mod_logger.debug("'ports' is not defined.")
        return False
    for switch in switch_instances:
        for port in ports:
            mod_logger.debug("clear statistics on port %s" % port)
            switch.xmlproxy.nb.Methods.clearPortStats(port)
            wait_until_value_is_changed(switch, table_name="Statistics", parameter_name=counter_name,
                                        value=0, row_id=port, timeout=90)
    mod_logger.debug("Function 'stat_counters_clear' is finished.")


def stat_counters_read(switch_instances=None, ports=None, counter_name="EtherStatsPkts", previous_results=None, expected_results=None, timeout=30):
    """
    @brief  read statistic counter on defined port on defined switch.
            In addition if previous_results defined then sum of read results compared with sum of previous results.
            If expected results defined then sum of current results compared with sum of expected results and if match occurred then return results
            In case expected results is not defined then sum of currently read results == sum of previous results counters read again until timeout
            But,

    @param switch_instances:  list of switch instances from env
    @param ports:  list of ports where statistic should be read
    @param counter_name:  counter that should be read
    @param previous_results:  list with previous statistics results.
    @param expected_results:  list with expected counters values from ports
    @param timeout:  timeout for re-reading counters in case sum of previous results matchedwith current results, default = 30

    @return  list with read counters from ports

    @par  Example:
    @code
    sw2_statistics = helpers.stat_counters_read(switch_instances=[env.switch[2], ], ports=ports["sw2","sw1"].values(),
                                                counter_name="EtherStatsPkts256to511Octets", previous_results=previous_sw2_stats, timeout=30)
    @endcode
    """

    def reading_counters(switch_instances, ports, counter_name):
        """
        @brief  Once read defined counter for defined port and return results
        """
        current_results = []
        for switch in switch_instances:
            for port in ports:
                current_result = switch.getprop("Statistics", counter_name, port)
                current_results.append(current_result)
                mod_logger.debug("Port %s counter %s = %s" % (port, counter_name, current_result))
        return current_results

    mod_logger.debug("Starting stat_counters_read function.")
    if switch_instances is None:
        mod_logger.debug("'switch_instances' is not defined.")
        return False
    if ports is None:
        mod_logger.debug("'ports' is not defined.")
        return False
    if previous_results is None:
        previous_results = []
    if expected_results is None:
        expected_results = []
    current_results = reading_counters(switch_instances, ports, counter_name)
    end_time = time.time() + timeout
    iteration = 1

    if not expected_results:
        mod_logger.debug("Checking for any updated counters")
        while (sum(current_results) - sum(previous_results)) == 0:
            current_results = reading_counters(switch_instances, ports, counter_name)
            mod_logger.debug("Reading counters again and compare with previous. previous =%s, current =%s" %
                             (previous_results, current_results))
            mod_logger.debug("Iteration =%s, time left =%s" % (iteration, (end_time - time.time())))
            time.sleep(0.99)
            if time.time() >= end_time:
                mod_logger.debug("Break re-reading counters on timeout")
                break
            iteration += 1
        return current_results
    else:
        mod_logger.debug("Checking according to Expected results")
        while (sum(current_results) - sum(expected_results)) != 0:
            current_results = reading_counters(switch_instances, ports, counter_name)
            mod_logger.debug("Reading counters again and compare with expected. expected =%s, current =%s" %
                             (expected_results, current_results))
            mod_logger.debug("Iteration =%s, time left =%s" % (iteration, (end_time - time.time())))
            time.sleep(0.99)
            if time.time() >= end_time:
                mod_logger.debug("Break re-reading counters on timeout")
                break
            iteration += 1
    return current_results


def get_packet_from_the_port(sniff_port=None, params=None, sniff_data=None, tg=None):
    """
    @brief  Return packet from the sniffer data according to search criteria

    @param sniff_port:  port where packet was sniffed
    @param params:  params list for packet search
    @param sniff_data:  sniffed data
    @param tg:  traffic generator

    @return  packet or None

    @par  Example:
    @code
    helpers.get_packet_from_the_port('vlab0', ({'layer': "Ether", 'field': "src", 'value': "00:00:00:01:02:03".lower()},), data, env.tg[1])
    @endcode
    """
    packets = []
    if sniff_port in list(sniff_data.keys()):
        for packet in sniff_data[sniff_port]:
            _packet_error = True
            for param in params:
                if not tg.check_packet_field(packet=packet, layer=param["layer"], field=param["field"], value=param["value"]):
                    _packet_error = False
                    break
            if _packet_error:
                packets.append(packet)
    return packets


def print_sniffed_data_brief(sniffer_data):
    """
    @brief  Print sniffed packets with sniffed count

    @param sniffer_data:  sniffed data

    @par  Example:
    @code
    helpers.print_sniffed_data_brief(data)
    @endcode
    """
    for _port in list(sniffer_data.keys()):
        _packets_sniffed = {"packets": [], "count": []}
        mod_logger.debug("Sniffer port: %s" % (_port, ))
        for _pack in sniffer_data[_port]:
            if _pack not in _packets_sniffed["packets"]:
                _packets_sniffed["packets"].append(_pack)
                _packets_sniffed["count"].append(1)
            else:
                pack_index = _packets_sniffed["packets"].index(_pack)
                _packets_sniffed["count"][pack_index] += 1
        for _pack in _packets_sniffed["packets"]:
            pack_index = _packets_sniffed["packets"].index(_pack)
            mod_logger.debug(_pack.__str__)
            mod_logger.debug("count %s" % _packets_sniffed["count"][pack_index])


def is_packet_received(data=None, iface_1=None, iface_2=None, layer_1="Ether", field_1="dst", value_1=None,
                       layer_2="IP", field_2="dst", value_2=None,
                       tg_instance=None, result=True, lag_available=False, f_result=False):
    """
    @brief  Checking if packet is received.

    @param data:  Captured data (string)
    @param iface_1:  Interface (string)
    @param iface_2:  Interface (string)
    @param layer_1:  Layer to analyze (string)
    @param field_1:  Field to look for (string)
    @param value_1:  Comparing value (can be different)
    @param layer_2:  Layer to analyze (string)
    @param field_2:  Field to look for (string)
    @param value_2:  Comparing value (can be different)
    @param tg_instance:  TG instance (string)
    @param result:  Expected result: true or false (boolean)
    @param lag_available:  is ports are in LAG: true or false (boolean)
    @param f_result:  Flag to

    @return  True or raise exception

    @par  Example:
    @code
    helpers.is_packet_received(data=data, iface_1=sniff_ports[1], iface_2=sniff_ports[0], value_1="ff:ff:ff:ff:ff:ff",
                               layer_2="ARP", field_2="pdst", value_2="10.0.31.2",
                               tg_instance=env.tg[1], lag_available=True)
    @endcode
    """
    packet_received = False
    if iface_1 in data:
        for row in data[iface_1]:
            if row.get_lfield(layer_1, field_1) == value_1.lower():
                if row.get_lfield(layer_2, field_2) == value_2:
                    packet_received = True
    if lag_available:
        if iface_2 in data:
            for row in data[iface_2]:
                if row.get_lfield(layer_1, field_1) == value_1.lower():
                    if row.get_lfield(layer_2, field_2) == value_2:
                        packet_received = True
    if packet_received == result:
        return True
    else:
        if packet_received is False:
            if f_result:
                return False
            else:
                pytest.fail("Packet is not received!")
        if packet_received is True:
            if f_result:
                return False
            else:
                pytest.fail("Packet is received (should not be)!")


def is_double_tag_packet_received(iface=None, destination_mac=None, eth_type=0x9100, prio_1=6, prio_2=None, vlan_1=None, vlan_2=None,
                                  result=True, type_1=None, type_2=None, tg_instance=None):
    """
    @brief  Check if proper packet is received

    @param  iface:  Interface (string)
    @param  destination_mac:  Destination MAC address (string)
    @param  eth_type:  Ether.type (hex)
    @param  prio_1:  Dot1Q.prio of outer layer (int)
    @param  prio_2:  Dot1Q.prio of inner layer (int)
    @param  vlan_1:  Dot1Q.vlan of outer layer (int)
    @param  vlan_2:  Dot1Q.vlan of inner layer (int)
    @param  type_1:  Dot1Q.type of outer layer (int)
    @param  type_2:  Dot1Q.type of inner layer (int)
    @param  result:  Expected result: true or false (boolean)
    @param  tg_instance:  TG instancestring

    @return  True or raise exception

    @par  Example:
    @code
    self._check_if_double_tag_packet_received(iface=data[sniff_ports[3]],destination_mac=self.destination_mac, vlan_1=self.vlan_id_20,
                                              vlan_2=self.vlan_id_10, type_1=0x8100, type_2=0x800, tg_instance=env.tg[1])
    @endcode
    """
    packet_received = False
    for packet in iface:
        if packet.get_lfield("Ether", "dst") == destination_mac:
            if packet.get_lfield("Ether", "type") == eth_type:
                if packet.get_lfield("Dot1Q", "vlan") == vlan_1:
                    assert packet.get_lfield("Dot1Q", "prio") == prio_1
                    assert packet.get_lfield("Dot1Q", "type") == type_1
                if vlan_2:
                    if packet.get_lfield("Dot1Q", "vlan") == vlan_2:
                        assert packet.get_lfield("Dot1Q", "prio") == prio_2
                        assert packet.get_lfield("Dot1Q", "type") == type_2
                packet_received = True
    if packet_received == result:
        return True
    else:
        if packet_received is False:
            pytest.fail("Packet is not received!")
        if packet_received is True:
            pytest.fail("Packet is received (should not be)!")


def is_row_added_to_arp_table(timeout=60, switch_instance=None, net_address=None, if_id=None, result=True):
    """
    @brief  Wait until proper row will be added to ARP table.
    """
    end_time = time.time() + timeout
    is_entry_added_to_arp_table = False
    while True:
        if time.time() < end_time:
            table = switch_instance.getprop_table("ARP")
            mod_logger.debug("ARP table for switch is :%s" % table)
            for row in table:
                if row['netAddress'] == net_address and row["ifId"] == if_id:
                    is_entry_added_to_arp_table = True
                    mod_logger.debug("ARP table for switch is :%s" % table)
                    return True
            # Need to wait until proper row will be added to ARP table.
            time.sleep(1)
        elif is_entry_added_to_arp_table == result:
            break
        else:
            mod_logger.debug("ARP table for switch is :%s" % table)
            pytest.fail("Timeout exceeded: Row with netAddress %s wasn't added to ARP table during timeout" % net_address)


def is_row_added_to_l2multicast_table(mac_address=None, port_id=None, vlan_id=1, switch_instance=None, result=True):
    """
    @brief  Check if row with specified parameters added to L2Multicast table.
    """
    # Need to wait until entry will be added to L2Multicast table.
    time.sleep(1)
    table = switch_instance.getprop_table("L2Multicast")
    is_entry_added = False
    if table:
        for row in table:
            if (row['macAddress'] == mac_address) and (row['portId'] == port_id) and (row['vlanId'] == vlan_id):
                is_entry_added = True
    if is_entry_added == result:
        return True
    else:
        if is_entry_added is False:
            pytest.fail("Entry is not added to L2Multicast table!")
        if is_entry_added is True:
            pytest.fail("Entry is added to L2Multicast table (should not be)!")


def wait_until_row_is_added_to_routes_table(timeout=60, switch_instance=None, network_ip="10.0.2.0/24", nexthop=None):
    """
    @brief  Wait until proper row will be added to Route table.

    @param switch_instance:  Switch class instance to work with (string)
    @param timeout:  Time to wait (integer)
    @param network_ip:  Network IP address (string)
    @param nexthop:  Network IP (string)

    @return  Raise exception

    @par  Example:
    @code
    helpers._wait_until_row_is_added_to_routes_table(switch_instance=env.switch[1], nexthop="10.0.31.2")
    @endcode
    """
    end_time = time.time() + timeout
    result = False
    while True:
        if time.time() < end_time:
            table = switch_instance.getprop_table("Route")
            mod_logger.debug("Route table: %s" % table)
            for row in table:
                if row['network'] == network_ip and row['nexthop'] == nexthop:
                    result = True
                    break
            # Need to wait until entry will be added to proper table.
            time.sleep(1)
        else:
            pytest.fail("Timeout exceeded: Row with network %s and nexthop %s wasn't added to Route table during timeout" % (network_ip, nexthop))
        if result:
            break


def wait_until_entry_is_expired(expected_timeout=1, switch_instance=None, table_name="L2Multicast"):
    """
    @brief  wait until entry is expired from table

    @param  switch_instance:  Switch class instance to work with
    @param  expected_timeout:  Time to wait (integer)
    @param  table_name:  XML-RPC table name (string)

    @return  True or raise exception

    @par  Example:
    @code
    assert self.wait_until_entry_is_expired(timeout=10, switch_instance=env.switch[2])
    @endcode
    """
    default_interval = switch_instance.getprop("IGMPSnoopingGlobalAdmin", "queryInterval", 1)
    default_robustness = switch_instance.getprop("IGMPSnoopingGlobalAdmin", "querierRobustness", 1)
    min_querier_robustness = 1
    max_response_time = 10
    assert switch_instance.setprop("IGMPSnoopingGlobalAdmin", "querierRobustness", [1, min_querier_robustness]) == 0
    if expected_timeout <= 10:
        assert switch_instance.setprop("IGMPSnoopingGlobalAdmin", "queryInterval", [1, 1]) == 0
    else:
        assert switch_instance.setprop("IGMPSnoopingGlobalAdmin", "queryInterval", [1, expected_timeout - max_response_time]) == 0
    # aging timeout is determined by the formula (queryInterval * querierRobustness) + (maxResponseTime) (+1 it is acceptable error)
    timeout = (switch_instance.getprop("IGMPSnoopingGlobalAdmin", "queryInterval", 1) +
               switch_instance.getprop("IGMPSnoopingGlobalAdmin", "querierRobustness", 1) + max_response_time)
    end_time = time.time() + timeout
    table = switch_instance.getprop_table("L2Multicast")
    mod_logger.debug("%s table for switch is :%s" % (table_name, table))
    if not table:
        assert switch_instance.setprop("IGMPSnoopingGlobalAdmin", "queryInterval", [1, default_interval]) == 0
        assert switch_instance.setprop("IGMPSnoopingGlobalAdmin", "querierRobustness", [1, default_robustness]) == 0
        return True
    else:
        while True:
            # Verify that entry is removed.
            if time.time() > end_time:
                # Need to wait untill entry will be expired from table.
                time.sleep(1)
                table = switch_instance.getprop_table("L2Multicast")
                mod_logger.debug("%s table for switch is :%s" % (table_name, table))
                if table:
                    assert switch_instance.setprop("IGMPSnoopingGlobalAdmin", "queryInterval", [1, default_interval]) == 0
                    assert switch_instance.setprop("IGMPSnoopingGlobalAdmin", "querierRobustness", [1, default_robustness]) == 0
                    pytest.fail("Table %s is not empty." % table_name)
                else:
                    assert switch_instance.setprop("IGMPSnoopingGlobalAdmin", "queryInterval", [1, default_interval]) == 0
                    assert switch_instance.setprop("IGMPSnoopingGlobalAdmin", "querierRobustness", [1, default_robustness]) == 0
                    return True


def set_admin_mode_for_slave_ports(switch_instance=None, admin_mode="Down"):
    """
    @brief  Set adminMode for logical ports.

    @param switch_instance:  Switch class instance to work with
    @param admin_mode:  Ports adminMode(string)

    @return  True or raise exception
    @par  Example:
    @code
    assert helpers.set_admin_mode_for_slave_ports(switch_instance=env.switch[1])
    @endcode
    """
    timeout = 10
    end_time = time.time() + timeout
    # Temporary workaround according to ONS-28780.
    if switch_instance.type != "simulated" and switch_instance.type != "lxc":
        master_ports_list = [49, 53, 57, 61]
        slave_ports_count = 4
        for port in master_ports_list:
            if switch_instance.getprop("Ports", "speed", switch_instance.findprop("Ports", [port, ])) == 10000:
                while True:
                    if time.time() < end_time:
                        # Need to wait untill entry is appeared in Ports table.
                        time.sleep(1)
                        for i in range(1, slave_ports_count):
                            slave_port_result = switch_instance.findprop("Ports", [port + i, ])
                            if slave_port_result > 0:
                                break
                        if slave_port_result > 0:
                            break
                    else:
                        pytest.fail("Slave ports are not appeared in Ports table during timeout %s seconds" % timeout)
                for i in range(1, slave_ports_count):
                    assert switch_instance.setprop("Ports", "adminMode", [switch_instance.findprop("Ports", [port + i, ]), "Down"]) == 0
    return True


def raises(expected_exception, fail_message, *args, **kwargs):
    """
    @brief  Assert that a code block/function call raises ExpectedException and raise a failure exception otherwise.

    @note  You can specify a callable by passing a to-be-called lambda or an arbitrary callable with arguments.

    @param expected_exception:  Expected exception type (Exception)
    @param fail_message:  Fail message in case exception doesn't raise (string)
    @param  args, kwargs  function to test as first argument and it's parameters

    @return  Exception info or pytest.fail

    @par  Example:
    @code
    helpers.raises(ZeroDivisionError, "Expected ZeroDevision didn't raise.", lambda: 1/0)

    def f(x): return 1/x
    ...
    helpers.raises(ZeroDivisionError, "Expected exception didn't raise.", f, 0)
    helpers.raises(ZeroDivisionError, "Did not raise", f, x=0)
    @endcode
    """
    # __tracebackhide__ = True
    if expected_exception is AssertionError:
        # we want to catch a AssertionError
        # replace our subclass with the builtin one
        # see https://bitbucket.org/hpk42/pytest/issue/176/pytestraises
        from _pytest.assertion.util import BuiltinAssertionError
        # assign instead of import as, so sys.modules is not changed
        expected_exception = BuiltinAssertionError

    rc = None
    func = args[0]
    try:
        rc = func(*args[1:], **kwargs)
    except expected_exception:
        return py.code.ExceptionInfo()  # pylint: disable=no-member
    # k = ", ".join(["%s=%r" % x for x in kwargs.items()])
    # if k:
    #     k = ', ' + k
    # expr = '%s(%r%s)' % (getattr(func, '__name__', func), args, k)
    # a = ", ".join(["%s" % x for x in args[1:]])
    # expr = '%s(%s%s)' % (getattr(func, '__name__', func), a, k)
    # print "\nFunction call: %s\n" % expr
    pytest.fail(fail_message + " Return Code: " + str(rc))


def pass_xmlrpc_fault(func):
    """
    @brief  Decorator to create raises functions with predefined xmlrpclib. Fault exception.
    """
    def wrapper(*args, **kwargs):
        """
        @brief  Decorator to create raises functions with predefined xmlrpclib.
        """
        return func(XMLRPCFault, *args, **kwargs)

    return wrapper


def is_error_in_expected(exception):
    """
    @brief  Check if exception is in list of expected errors
    """
    if not ERRORS:
        raise CustomException("ERRORS variable id not present.")

    is_exception_in_error = False

    if not isinstance(exception, str):
        return is_exception_in_error

    for error in list(ERRORS.values()):
        if "%" in error:
            error_split = error.split("%")
            parts_in_exception = []
            for error_part in error_split:
                if error_split.index(error_part) % 2 == 0:
                    if error_part:
                        parts_in_exception.append(error_part in exception)
            if parts_in_exception:
                is_exception_in_error = all(parts_in_exception)
        else:
            is_exception_in_error = exception in error
        if is_exception_in_error:
            break
    return is_exception_in_error


@pass_xmlrpc_fault
def xmlrpc_raises(expected_exception, fail_message, *args, **kwargs):
    """
    @brief  Temporary replacement for original xmlrpc_raises.
    """
    if expected_exception is AssertionError:
        from _pytest.assertion.util import BuiltinAssertionError
        # assign instead of import as, so sys.modules is not changed
        expected_exception = BuiltinAssertionError

    rc = None
    func = args[0]
    try:
        rc = func(*args[1:], **kwargs)
    except expected_exception:
        _exception = py.code.ExceptionInfo().exconly().split("Fault: ")[-1]  # pylint: disable=no-member
        # Check if exception is in list of expected values
        if is_error_in_expected(_exception):
            return py.code.ExceptionInfo()  # pylint: disable=no-member
        else:
            pytest.fail(py.code.ExceptionInfo())  # pylint: disable=no-member
    else:
        if rc == -1:
            mod_logger.warning("Unexpected xmlrpc returncode -1: %s, %s, %s" % (args[0].__name__, args[1:], kwargs))
            return rc
    pytest.fail(fail_message + " Return Code: " + str(rc))


def set_equal_ports_costs(ports, switch, switch_id, table, cost=2000):
    """
    @brief  Sets equal port costs for switch ports.

    @param ports:  ports dictionary (dict of dict)
    @param switch:  switch instance (SwitchX object)
    @param switch_id:  id of switch in environment (int)
    @param table:  table name (e.g. "MSTPPorts") (str)
    @param cost:  port cost value (int)

    @return  None
    """
    for key in ports:
        if 'sw%d' % (switch_id, ) in key[0] and "tg1" not in key[0]:
            for link_id in list(ports[key].keys()):
                if table != "MSTPPorts":
                    ports_table_id = switch.findprop(table, [ports[key][link_id], ])
                    if switch.getprop(table, "cost", ports_table_id) != cost:
                        assert switch.setprop(table, "cost", [ports_table_id, cost]) == 0, "Cost is not set."
                elif table == "MSTPPorts":
                    mstis = len(switch.getprop_table("STPInstances"))
                    for msti_id in range(mstis):
                        ports_table_id = switch.findprop(table, [msti_id, ports[key][link_id], ])
                        if msti_id == 0:
                            assert switch.setprop(table, "externalCost", [ports_table_id, cost]) == 0, "Cost is not set"
                        assert switch.setprop(table, "internalCost", [ports_table_id, cost]) == 0, "Cost is not set"


def set_equal_ports_speed(ports, switch, switch_id, speed=10000):
    """
    @brief  Sets equal port costs for switch ports

    @param ports:  ports dictionary
    @param switch:  switch instance
    @param switch_id:  id of switch in environment
    @param speed:  port speed value, integer

    @return  none
    """
    if switch.type != 'lxc':
        for key in list(ports.keys()):
            if 'sw%d' % (switch_id, ) in key[0] and "tg1" not in key[0]:
                for link_id in list(ports[key].keys()):
                    ports_table_id = switch.findprop("Ports", [ports[key][link_id], ])
                    assert switch.setprop("Ports", "speed", [ports_table_id, speed]) == 0, "Port speed is not set"


def set_equal_port_speed_and_cost(ports, switch, table, switch_id=None, cost=2000, speed=10000):
    """
    @brief  Sets equal ports cost and speed for switch ports, and disables slave 40G ports

    @param ports:  ports dictionary
    @param switch:  switch instance
    @param switch_id:  id of switch in environment
    @param table:  table name or list of table names (f.e. "MSTPPorts" or ["RSTPPorts", "MSTPPorts"])
    @param cost:  port cost value, integer
    @param speed:  port speed value, integer

    @return  none

    @par  Example:
    @code
    helpers.set_equal_port_speed_and_cost(ports, env.switch, ["MSTPPorts", "RSTPPorts", "RSTPPorts"])
    helpers.set_equal_port_speed_and_cost(ports, env.switch, "RSTPPorts")
    helpers.set_equal_port_speed_and_cost(ports, env.switch[1], "RSTPPorts", switch_id=1]
    @endcode
    """
    if isinstance(switch, dict) and not switch_id:
        for switch_id in list(switch.keys()):
            if isinstance(table, list):
                set_equal_ports_costs(ports, switch[switch_id], switch_id, table[switch_id - 1], cost=cost)
            else:
                set_equal_ports_costs(ports, switch[switch_id], switch_id, table, cost=cost)
            set_equal_ports_speed(ports, switch[switch_id], switch_id, speed=speed)
            time.sleep(3)
            set_admin_mode_for_slave_ports(switch_instance=switch[switch_id], admin_mode="Down")
    elif isinstance(switch, dict) and switch_id:
        for switch_id in list(switch.keys()):
            set_equal_ports_costs(ports, switch[switch_id], switch_id, table, cost=cost)
            set_equal_ports_speed(ports, switch[switch_id], switch_id, speed=speed)
            time.sleep(3)
            set_admin_mode_for_slave_ports(switch_instance=switch[switch_id], admin_mode="Down")
    else:
        set_equal_ports_costs(ports, switch, switch_id, table, cost=cost)
        set_equal_ports_speed(ports, switch, switch_id, speed=speed)
        time.sleep(3)
        set_admin_mode_for_slave_ports(switch_instance=switch, admin_mode="Down")


def designated_port(priority, port_id):
    """
    @brief  Function for return hex string value that is sum of bridgePriority and port_id in hex format.

    @param priority:  Port bridgePriority
    @param port_id:  Port ID

    @return  Hex Value without 0x prefix

    @par  Example:
    @code
    helpers.designated_port(32768, 28)
    @endcode
    """
    return hex(priority)[2:].zfill(2).upper() + hex(port_id)[2:].zfill(2).upper()


def set_rstp_mode(switch_instance=None):
    """
    @brief  Obsoleted function. Use set_stp_mode with proper option instead.
    """
    return set_stp_mode(switch_instance=switch_instance, mode="RSTP")


def set_mstp_mode(switch_instance=None):
    """
    @brief  Obsoleted function. Use set_stp_mode with proper option instead.
    """
    return set_stp_mode(switch_instance=switch_instance, mode="MSTP")


def wait_until_stp_state(switch_instance=None, table="STPPorts", port=1, state="Disabled", timeout=30):
    """
    @brief  Obsoleted function. Use wait_until_value_is_changed with proper option instead.
    """
    return wait_until_value_is_changed(switch_instance=switch_instance, table_name=table, parameter_name="state",
                                       value=state, row_id=port, timeout=timeout)


def wait_until_ops_state(switch_instance=None, port=1, state="Up", timeout=30):
    """
    @brief  Obsoleted function. Use wait_until_value_is_changed with proper option instead.
    """
    return wait_until_value_is_changed(switch_instance=switch_instance, table_name="Ports", parameter_name="operationalStatus",
                                       value=state, row_id=port, timeout=timeout)


def process_multicall(return_list):
    """
    @brief  Returns list of methods with errors
    """
    mod_logger.debug("Multicall results processing starts")
    results = []
    for row in return_list:
        if row['result'] == "-1" or "faultCode" in row["result"]:
            results.append(row)
            results[-1]["error"] = "Method %s with params %s returns error %s" % (row["methodName"], row["params"], row["result"])

    return results


def is_entry_added_to_table(switch_inst, table_name, srch_params, timeout=1, expect_count=1, exist=True):
    """
    @brief  Check if entry with specified fields values is added to table

    @param switch_inst:  Switch instance to work with
    @param table_name:  The name of table to perform search in (string)
    @param srch_params:  Parameters for entry search (dictionary)
    @param timeout:  Time to wait (integer)
    @param expect_count:  Number of entries in the table that correspond to search parameters (integer)
    @param exist:  Decided if entry exists in table or not (boolean)

    @return  True/False

    @par  Example:
    @code
    srch_params = {'macAddress': '00:00:00:BB:00:AA', 'portId': 24, 'valid': 'Enabled'}
    assert helpers.is_entry_added_to_table(env.switch[1], "DcbxRemotes", srch_params, timeout=5)
    assert helpers.is_entry_added_to_table(env.switch[1], "DcbxRemotes", srch_params, timeout=5, exist=False)
    @endcode
    """
    end_time = time.time() + timeout
    while True:
        # Calculate number of entry occurrences in table
        table = switch_inst.getprop_table(table_name)
        occur_count = 0
        for row in table:
            if all([row[field] == value for field, value in srch_params.items()]):
                occur_count += 1

        return_value = False
        if exist:
            if occur_count == expect_count:
                return_value = True
        else:
            if not occur_count:
                return_value = True

        # Exit while loop if entry is added to table or due to timeout expiration
        if return_value or time.time() > end_time:
            break
        else:
            time.sleep(0.5)

    return return_value


def verify_port_params_in_table(switch_inst, table_name, params, find_params=None, row_id=None, timeout=0, interval=0.25):
    """
    @brief  Verify that row has correct parameters' values in table

    @param switch_inst:  Switch instance to work with
    @param table_name:  The name of table to validate the row parameters (string)
    @param params:  Parameters and values the row in table should match (dictionary)
    @param find_params:  List of parameters to find a row in table (list)
    @param row_id:  Row ID in table (integer)
    @param timeout:  Time to wait (integer)
    @param interval:  interval in seconds between re-reading the table (integer)

    @return  None (Raises error if values are incorrect)

    @par  Example:
    @code
    helpers.verify_port_params_in_table(env.switch[1], "DcbxPfcPortsLocal", {"willing": "Enabled", "enabled": "0,0,0,0,0,0,0,1"}, [port_id, ], timeout=1)
    helpers.verify_port_params_in_table(env.switch[1], "DcbxPorts", {"multiplePeers": 'Enabled'}, row_id=24, timeout=1)
    @endcode
    """
    end_time = time.time() + timeout
    while True:
        try:
            # find row_id in table
            if (row_id is None or row_id == -1) and find_params is not None:
                row_id = switch_inst.findprop(table_name, find_params)
            elif row_id is None and find_params is None:
                raise ValueError("Find_params or row_id should be specified to check parameter value in table")

            assert row_id != -1, "Can't find row in table '%s' with find params %s" % (table_name, find_params)

            # verify that values are correct
            row = switch_inst.getprop_row(table_name, row_id)
            for field, value in params.items():
                assert row[field] == value, "Incorrect value is set for %s field: %s" % (field, row[field])
            break
        except ValueError as err:
            pytest.fail("%s" % err)
        except AssertionError as err:
            if time.time() < end_time:
                time.sleep(interval)
            else:
                if row_id == -1:
                    mod_logger.debug("Content of '%s' table:\n%s" % (table_name, switch_inst.getprop_table(table_name)))
                pytest.fail("%s" % err)


def update_table_params(switch_inst, table_name, params, find_params=None, row_id=None, validate_updates=True):
    """
    @brief  Configure port parameters in table

    @param switch_inst:  Switch instance to work with
    @param table_name:  The name of table to work with (string)
    @param params:  Parameters and values that should be configured for port (dictionary)
    @param find_params:  List of parameters to find a row in table (list)
    @param row_id:  Row ID in table (integer)
    @param validate_updates:  Verify if updates were set (bool)

    @return  None

    @par  Example:
    @code
    helpers.update_table_params(env.switch[1], "DcbxPfcPortsAdmin", {"willing": "Enabled", "enabled": "0,0,0,1,0,0,0,0"}, [port_id, ])
    helpers.update_table_params(env.switch[1], "DcbxPorts", {"adminStatus": 'Disabled'}, row_id=24)
    @endcode
    """
    if row_id is None and find_params is not None:
        row_id = switch_inst.findprop(table_name, find_params)
    elif row_id is None and find_params is None:
        raise ValueError("Find_params or row_id should be specified to update parameter value in table")

    assert row_id != -1, "Can't find row in table '%s' with find params %s" % (table_name, find_params)

    for field, value in params.items():
        assert switch_inst.setprop(table_name, field, [row_id, value]) == 0, "%s values is not set for field %s" % (field, value)

    if validate_updates:
        verify_port_params_in_table(switch_inst, table_name, params, row_id=row_id)


def disable_lldp_for_all_ports(switch_instance):
    """
    @brief  Disable Lldp on all device ports

    @param switch_instance:  Switch instance to work with

    @return  None

    @par  Example:
    @code
    helpers.disable_lldp_for_all_ports(env.switch[1])
    @endcode
    """
    mod_logger.debug("Set LLDP adminStatus to Disabled for all ports")
    switch_instance.ui.disable_lldp_on_device_ports()

    mod_logger.debug("LLDP Remotes table should be empty")
    assert not switch_instance.ui.get_table_lldp_remotes(), "Llldp Remotes table is not empty"


def validate_frame_against_multiple_layers(packet, src_mac=None, unexpected_layers=None, expected_layers=None):
    """
    @brief  Verify that frame doesn't contain specific set of Layers and contains correct values for other expected Layers

    @param packet:  Packet that should be validated (pypacker packet)
    @param src_mac:  Expected src mac address of packet (None or MacAddress)
    @param unexpected_layers:  List of layers that should not be present is the frame (list of strings)
    @param expected_layers:  List or Dictionary of layers with expected values that should be present in frame. If the frame contains multiple number
                             of specific layer than value in expected_layer dictionary should be a list (list or dictionary)

    @return  None (Raises error if packet is incorrect)

    @par  Example:
    @code
    expected_layers = {"DCBXApplicationPriority": {"type": 127L, "length": 5L, "oui": 0x80c2, "subtype": 12L, "reserved": 0},
                       "DCBXApplicationPriorityTable": [{'priority': 7, 'protocolid': 125, 'sel': 2, 'reserved': 0L},
                                                        {'priority': 6, 'protocolid': 555, 'sel': 4, 'reserved': 0L}],
                       "LLDPDUEnd": {"type": 0, "length": 0}}
    unexpected_layers = ["DCBXCongestionNotification", "DCBXConfiguration"]
    helpers.validate_frame_against_multiple_layers(packet, dut_mac, unexpected_layers=unexpected_layers, expected_layers=expected_layers)
    @endcode
    """
    failures = []
    if src_mac is not None:
        assert packet.get_lfield(layer="Ether", field="src").lower() == src_mac.lower(), "Src mac address in Ether layer is not equal to expected"

    if unexpected_layers is None:
        unexpected_layers = ()

    if expected_layers is None:
        expected_layers = ()

    mod_logger.debug("Verify that frame doesn't contain specific set of Layers")
    for layer in unexpected_layers:
        try:
            assert not packet.haslayer(layer), "%s layer was received in the frame, but shouldn't" % layer
        except AssertionError as err:
            failures.append(str(err))

    mod_logger.debug("Verify that frame contains specific set of Layers with correct values")
    for layer in expected_layers:
        try:
            assert packet.haslayer(layer), "%s layer was not received in the frame" % layer

            if isinstance(expected_layers, dict):
                # Verify that packet contain correct number of multiple layers
                layer_count = packet.get_lcount(layer)
                if isinstance(expected_layers[layer], list):
                    assert len(expected_layers[layer]) == layer_count, "Not all '%s' layers present in frame" % layer
                    multilayer_params = expected_layers[layer]
                else:
                    assert layer_count == 1, "More than one '%s' layer present in frame" % layer
                    multilayer_params = [expected_layers[layer], ]

                # Verify that Layer have correct fields' values
                for layer_params in multilayer_params:
                    layer_exist = False
                    for layer_id in range(1, layer_count + 1):
                        if all([packet.get_lfield(layer, field, layer_id) == expected_value for field, expected_value in layer_params.items()]):
                            layer_exist = True
                            break
                    try:
                        assert layer_exist, "Can't find layer '%s' with params %s" % (layer, layer_params)
                    except AssertionError as err:
                        failures.append(str(err))
        except AssertionError as err:
            failures.append(str(err))

    if failures:
        pytest.fail("\n".join(failures))


def process_cli_results(return_list):
    """
    @brief  Returns list of errors in CLI set results
    """
    if return_list:
        mod_logger.debug("Multicall results processing starts")
        for row in return_list:
            if 'Error' in row:
                raise CLIException(row)


def grouper(iterable, n):
    """
    Collect data into fixed-length chunks or blocks

    grouper('ABCDEFG', 3) --> ABC DEF G

    Modified from http://stackoverflow.com/users/1052325/reclosedev 's modification
    of http://stackoverflow.com/users/279627/sven-marnach 's answer

    http://stackoverflow.com/a/8998040

    @param iterable: iterable to group into chunks
    @type iterable: iter()
    @param n: chunk size
    @type n: int
    @return: itererable of chunks of size n
    @rtype: iter(list)
    """
    it = iter(iterable)
    while True:
        chunk_it = itertools.islice(it, n)
        # look ahead to check for StopIteration
        try:
            first_el = next(chunk_it)
        except StopIteration:
            return
        yield tuple(itertools.chain((first_el,), chunk_it))


def grouper_it(iterable, n):
    """
    Collect data into iterables of fixed-length chunks or blocks

    grouper_it('ABCDEFG', 3) --> iter(ABC) iter(DEF) iter(G)

    Copyied from http://stackoverflow.com/users/1052325/reclosedev 's modification
    of http://stackoverflow.com/users/279627/sven-marnach 's answer

    http://stackoverflow.com/a/8998040

    @param iterable: iterable to group into chunks
    @type iterable: iter()
    @param n: chunk size
    @type n: int
    @return: return an iterable of iterables of chunk size n
    @rtype:  iter(iter())
    """
    it = iter(iterable)
    while True:
        chunk_it = itertools.islice(it, n)
        # look ahead to check for StopIteration
        try:
            first_el = next(chunk_it)
        except StopIteration:
            return
        yield itertools.chain((first_el,), chunk_it)


def group_get(match, *args, **kwargs):
    """

    @type match: _sre.SRE_Match
    @param default: default value, kwargs only
    """
    try:
        return match.group(*args)
    except (IndexError, AttributeError):
        return kwargs.get('default')


def merge_dicts(*dict_args):
    """Merge dictionaries from dict_args.

    When same keys present the last dictionary in args list has the highest priority.

    :@aram tuple(dict) dict_args:
    @return dict: merged dictionary
    """
    result = {}
    for d in dict_args:
        result.update(d)
    return result
