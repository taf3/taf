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

"""``helpers.py``

`Helpers functions`

"""

import json
import os
import time
import random
import itertools
from xmlrpc.client import Fault as XMLRPCFault
from collections import OrderedDict
import functools

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
    """Gets an attribute from argvalues.

    Args:
        item(int | str): This can be an int (it will attempt to retrieve an index or a
                         str (it will attempt to retrieve a NamedTuple's field name)

    Raises:
        AttributeError: when attribute not found
        IndexError: when index not found

    Returns:
        str

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
    """Get json file.

    """
    file_path = os.path.join(path, 'resources', filename)
    with open(file_path) as _f:
        # we used to do unicode decode, but I don't know why.
        _json = json.load(_f)
    return _json


def get_stepped_value(value, step, step_type='Down'):
    """Returns the rounded value, given an initial input value.

    Args:
        value(int): The input value
        step(int | OrderedDict):  The step value
        step_type(str):  Whether the value is incremented to the next step

    Raises:
        ValueError

    Returns:
        int

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
    """Wrapper of "find" function for RouteInterface table.

    Notes:
        This is temporary function.

    Args:
        switch_instance(object):  Switch instance
        vlan(str):  Vlan on which route interface is implemented.
        ip_address(str):  IP address of route interface.
        mtu(int):  MTU of route interface.
        bandwith(int):  Bandwith of route interface
        vrf(int):  Virtual route Id

    Returns:
        row

    Examples::

        _ri_find_wrapper(env.switch[1], vlan=10, ip_address="10.0.10.1/24", mtu=100, bandwith=1500, vrf=0)

    """
    try:
        result = switch_instance.nb.RouteInterface.find(vlan, ip_address, bandwith, mtu, vrf)
    except XMLRPCFault:
        result = switch_instance.nb.RouteInterface.find(ip_address)
    return result


def wait_for_route_iface_status(switch, iface_id, timeout, status):
    """Wait for RouteInterface changed its oper status to expected value or raise exception if it is not after 'interval' seconds elapsed

    Args:
        switch(SwitchX object):  switch for checking RouteInterface oper state value
        iface_id(str):  interface id for checking oper state value
        timeout(int):   seconds for checking RouteInterface oper state value
        status(str):  RouteInterface oper state value (lower)

    Returns:
        None

    Examples::

        _wait_for_route_iface_status(env.switch[1], 2, 120, 'down')

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
    """Wait for RouteInterface deleted if it is not after 'timeout' seconds elapsed

    Args:
        switch(SwitchX object):  switch for checking RouteInterface being deleted
        iface_id(str):  interface id for checking RouteInterface being deleted
        ip_address(str):  ip address for checking RouteInterface being deleted
        bandwidth(int):  bandwidth for checking RouteInterface being deleted
        mtu(int):   mtu for checking RouteInterface being deleted
        vrf(int):  vrf for checking RouteInterface being deleted
        timeout(int):  seconds for checking RouteInterface being deleted

    Returns:
        None

    Examples::

        _wait_for_route_iface_deleted(env.switch[1], 3210, '2001:db8:85a3::8a3e:370:7377/96', 1000, 1280, 0, 120)

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
    """Sets all ports of all switches provided as an argument to admin state Down.

    Args:
        switches(dict):  Switches configuration
        wait_status(bool):  Wait for ports desire necessary state

    Returns:
        none

    Examples::

        set_all_ports_admin_disabled(env.switch)

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
    """Sets provided in arguments ports to admin state Up.

    Args:
        switches(dict):  Switches configuration
        ports(dict(dict)):  List of ports to enable. Each element is a dictionary like {('sw1', 'sw2'): {link_id: port_id})}
        wait_status(bool):  Wait for ports desire necessary state
        fail_func(tuple):  function with params that will be executed in case of failure

    Returns:
        none

    Examples::

        ports = {('sw1', 'sw2'): {1: 2, 2: 4}}
        set_ports_admin_enabled(env.switch, ports)
        set_ports_admin_enabled(env.switch, ports, fail_func=(pytest.softexit, [mesasge, env]))

    """

    def wait_for_port_status(switch, port, status, timeout=30):
        """Wait for port status during specified time.

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
        """Check that port change status to Up and retry Down/Up cycle if not.

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
    """Wait some time for adding dynamic entry to FDB.

    Args:
        switch_instance(xmlrpclib.ServerProxy object):  Switch instance to work with
        mac_address(str):  MAC address for check
        port_id(int):  Port ID corresponding to MAC address
        vlan_id(int):  VLAN ID corresponding to MAC address
        timeout(int):  seconds for checking Fdb entry being added

    Returns:
        None

    Examples::

        wait_time_for_adding_entry_to_fdb(mac_address=source_mac, port_id=port_id_2, timeout=10, vlan_id=vlan_id, switch_instance=env.switch[1])

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
    """Check dynamic entry in FDB.

    Args:
        switch_instance(xmlrpclib.ServerProxy object):  Switch instance to work with
        mac_address(str):  Source mac-address to check entry in FDB
        port_id(int):  Port number from where packet was sent
        vlan_id(int):  Vlan number from where packet was sent

    Returns:
        bool: True or False

    Examples::

        is_entry_added_to_fdb(mac_address=source_mac, port_id=1, vlan_id=vlab_id, switch_instance=env.switch[1].xmlproxy)

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
    """Check static entry in StaticMAC table

    Args:
        switch_instance(xmlrpclib.ServerProxy object):  Switch instance to work with
        mac_address(str):  Source mac-address to check entry in FDB
        port_id(int):  Port number from where packet was sent
        vlan_id(int):  Vlan number from where packet was sent

    Returns:
        bool: True or False

    Examples::

        is_static_entry_added(mac_address=source_mac, port_id=1, vlan_id=vlab_id, switch_instance=env.switch[1].xmlproxy)

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
    """Check entry in ACL Expressions Table.

    Args:
        switch_instance(xmlrpclib.ServerProxy object):  Switch instance to work with (xmlrpclib.ServerProxy object)
        field(str):  The field to operate on
        mask(str):  The bitwise mask to AND with the field
        data(str):  The expected result

    Returns:
        bool: True or False

    Examples::

        is_entry_added_to_acl_expressions_table(field=field, mask=mask_acl, data=data_acl, switch_instance=env.switch[1].xmlproxy)

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
    """Check entry in ACL Actions Table.

    Args:
        switch_instance(xmlrpclib.ServerProxy object):  Switch instance to work with
        action(str):  The actual action
        param(str):  Parameters required for the action

    Returns:
        bool: True or False

    Examples::

        is_entry_added_to_acl_actions_table(action=action_acl, param=param_acl, switch_instance=env.switch[1].xmlproxy)

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
    """Check entry in ACL Rules Table.

    Args:
        switch_instance(xmlrpclib.ServerProxy object):  Switch instance to work with
        rule_id(int):  Given ruleId from the ACLRules table
        expression_id(int):  Given expressionId from the ACLExpressions table
        action_id(int):  Given actionId from the ACLActions table
        stage(str):  "Ingress", "Egress", "Lookup"
        enabled(str):  Enable or disable rule
        priority(int):  Rules priority

    Returns:
        bool: True or False

    Examples::

        is_entry_added_to_rules_table(rule_id=rule_id, expression_id=expression_id, action_id=action_id,
                                      stage=rules_stage_ingress, enabled=rules_disabled,
                                      priority=priority_zero, switch_instance=env.switch[1].xmlproxy)

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
    """Exception handler for negative testcases.

    Args:
        switch_instance(xmlrpclib.ServerProxy object):  Switch instance to work with
        method(str):  XML RPC method to invoke
        params(list of mixed types values):  Arguments to pass to XML RPC method

    Returns:
        None

    Examples::

        set_invalid_value(switch_instance=env.switch[1].xmlproxy, method="nb.Table.set.field", params=[param1, param2,param3])

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
    """Clear table for correct test cases work.

    Args:
        switch_instance(xmlrpclib.ServerProxy object):  Switch instance to work with
        table_name(str):  Specific table name

    Returns:
        None

    Examples::

        clear_table(switch_instance=env.switch[1], table_name="ACLRules")

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
    """Set SpanningTree mode to STP|RSTP|MSTP.

    Args:
        switch_instance(xmlrpclib.ServerProxy object):  Switch class instance to work with
        mode(str):  SpanningTree mode

    Returns:
        None

    Examples::

        set_stp_mode(env.switch[1], "MSTP")

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
    """Disables/Enables STP state on per-port basis.

    Notes:
        Very useful to prevent packet storm caused by global STP disabling.

    Args:
        switche_instance(object):  Switche xmlrpc.ServerProxy object (object)
        state(str):  Desired STP state change action ('Enabled' or 'Disabled')

    Returns:
        None

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
    """Set LLDP port admin status on ports.

    Args
        switch_instance(object):  the switch instance.
        port_list(list):  the list of ports.
        status(str):  the LLDP port admin status.

    Returns:
        bool: True or False

    """
    # check if LLDP feature is enabled
    if 'nb.LldpPorts.set.adminStatus' in switch_instance.system.listMethods():
        for port in port_list:
            if switch_instance.nb.LldpPorts.set.adminStatus(port, status) != 0:
                return False
    return True


def wait_until_value_is_changed(switch_instance=None, table_name=None, parameter_name=None, value=None, row_id=1, timeout=30, findlist=None):
    """Wait until value is changed in table

    Args:
        switch_instance(object):  Switch class instance to work with
        table_name(str):  Specific getTable method
        parameter_name(str):  Parameter in table
        value(int):  Checking value
        row_id(int):  Row id in table
        timeout(int):  time to wait until value is changed
        findlist(list):  list of parameters to find a row in the given table

    Returns:
        bool: True or False

    Examples::

        wait_until_value_is_changed(env.switch[1], "Ports2LagRemote", "partnerOperSystemPriority", 0, 1)
        wait_until_value_is_changed(switch_instance=env.switch[1], table_name="Ports2LagRemote", parameter_name="partnerOperSystemPriority",
                                    value=0, row_id=1, timeout=30, [1, 1])

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
    """Send and verify receiving of packets.

    """

    def _compare_packets(packet_definition=None, packet=None, tg=None):
        """Comparing packets.

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
        """Counting specific packets.

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
    """Wait until any table become necessary size, for example it can ba Dynamic ARP table or Route table.

    Use deviation parameter if expected_table_length is not strict and can be larger ("+") then expected on deviation value
    or smaller ("-") then expected on deviation value or near (None=+/-) expected on deviation value

    Args:
        switch_instance(object):  switch instance from env
        table_name(str):  table name under test, example: "ARP"
        expected_table_length(int):  value table length should increase to
        watch_interval(int):  interval in seconds between re-reading table from switch instance
        timeout(int):  120 - timeout in seconds for function execution
        deviation(int):  if expected_table_length is not strict value and some deviation in entries is acceptable
        direction(str):  "+", "-" or None. In case None then assuming that deviation is bidirectional, both "+" and "-"
        verbose(bool):  can be True or False. In case True then monitoring table content will be displayed in debug log

    Returns:
        bool: True/False

    Examples::

        helpers.waiting_table_is_loaded(env.switch[1], "Route", 21, watch_interval = 1, timeout = 120, deviation = 2, direction = "+")

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
    """Generate list that contains randomly generated MAC addresses that starts from 00.

    Args:
        mac_exclusions(list):  list if MAC addresses that should be excluded from generated list
        quantity(int):  quantity of mac addresses that should be generated (int)

    Returns:
        list: mac_pool  list of generated MAC addresses

    Examples::

        source_macs = helpers.generate_random_mac(mac_exclusions = ["01:00:02:00:00:01", ], quantity = 10)

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
    """Generate list that contains randomly generated IP addresses that starts from prefix.

    Args:
        ip_exclusions(list):  list if IP addresses that should be excluded from generated list, for example Route Interface address used on device
        prefix(str):  Network part of IP address
        quantity(int):  quantity of ip addresses that should be generated

    Returns:
        list: ip_pool  list of generated MAC addresses

    Examples::

        source_ips = helpers.generate_random_ip(ip_exclusions = router_ips, prefix = "10.0.1", quantity = streams_quantity)

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
    """Clear all statistic counters on defined port.

    Notes:
        DO NOT USE ON CONTINUOUSLY RUNNING TRAFFIC - FUNCTION IS WAITING THAT COUNTER BECOME 0

    Args:
        switch_instances(list):  list of switch instances from env
        ports(list):  list of ports where statistic should be cleared
        counter_name(str):  counter that checked to become 0 after clear action. "EtherStatsPkts" used by default.

    Returns:
        None

    Examples::

        helpers.stat_counters_clear(switch_instances=[env.switch[2], ], ports=ports["sw2", "sw1"].values(), counter_name="EtherStatsPkts256to511Octets")

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
    """Read statistic counter on defined port on defined switch.

    In addition if previous_results defined then sum of read results compared with sum of previous results.
    If expected results defined then sum of current results compared with sum of expected results and if match occurred then return results
    In case expected results is not defined then sum of currently read results == sum of previous results counters read again until timeout

    Args:
        switch_instances(list):  list of switch instances from env
        ports(list):  list of ports where statistic should be read
        counter_name(str):  counter that should be read
        previous_results(list):  list with previous statistics results.
        expected_results(list):  list with expected counters values from ports
        timeout(int):  timeout for re-reading counters in case sum of previous results matchedwith current results, default = 30

    Returns:
        list: list with read counters from ports

    Examples::

        sw2_statistics = helpers.stat_counters_read(switch_instances=[env.switch[2], ], ports=ports["sw2","sw1"].values(),
                                                    counter_name="EtherStatsPkts256to511Octets", previous_results=previous_sw2_stats, timeout=30)

    """

    def reading_counters(switch_instances, ports, counter_name):
        """Once read defined counter for defined port and return results.

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
    """Return packet from the sniffer data according to search criteria.

    Args:
        sniff_port(list):  port where packet was sniffed
        params(list):  params list for packet search
        sniff_data:  sniffed data
        tg(object):  traffic generator

    Returns:
        packet or None

    Examples::

        helpers.get_packet_from_the_port('vlab0', ({'layer': "Ether", 'field': "src", 'value': "00:00:00:01:02:03".lower()},), data, env.tg[1])

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
    """Print sniffed packets with sniffed count.

    Args:
        sniffer_data:  sniffed data

    Examples::

        helpers.print_sniffed_data_brief(data)

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
    """Checking if packet is received.

    Args:
        data(str):  Captured data
        iface_1(str):  Interface
        iface_2(str):  Interface
        layer_1(str):  Layer to analyze
        field_1(str):  Field to look for
        value_1(can be different):  Comparing value
        layer_2(str):  Layer to analyze
        field_2(str):  Field to look for
        value_2(can be different):  Comparing value
        tg_instance(str):  TG instance
        result(bool):  Expected result: true or false
        lag_available(bool):  is ports are in LAG: true or false
        f_result(bool):  Flag to

    Returns:
        True or raise exception

    Examples::

        helpers.is_packet_received(data=data, iface_1=sniff_ports[1], iface_2=sniff_ports[0], value_1="ff:ff:ff:ff:ff:ff",
                                   layer_2="ARP", field_2="pdst", value_2="10.0.31.2",
                                   tg_instance=env.tg[1], lag_available=True)

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
    """Check if proper packet is received.

    Args:
        iface(str):  Interface
        destination_mac(str):  Destination MAC address
        eth_type(hex):  Ether.type
        prio_1(int):  Dot1Q.prio of outer layer
        prio_2(int):  Dot1Q.prio of inner layer
        vlan_1(int):  Dot1Q.vlan of outer layer
        vlan_2(int):  Dot1Q.vlan of inner layer
        type_1(int):  Dot1Q.type of outer layer
        type_2(int):  Dot1Q.type of inner layer
        result(bool):  Expected result: true or false
        tg_instance(str):  TG instance

    Returns:
        True or raise exception

    Examples::

        self._check_if_double_tag_packet_received(iface=data[sniff_ports[3]],destination_mac=self.destination_mac, vlan_1=self.vlan_id_20,
                                                  vlan_2=self.vlan_id_10, type_1=0x8100, type_2=0x800, tg_instance=env.tg[1])

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
    """Wait until proper row will be added to ARP table.

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
    """Check if row with specified parameters added to L2Multicast table.

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
    """Wait until proper row will be added to Route table.

    Args:
        switch_instance(str):  Switch class instance to work with
        timeout(int):  Time to wait
        network_ip(str):  Network IP address
        nexthop(str):  Network IP

    Returns:
        Raise exception

    Examples::

        helpers._wait_until_row_is_added_to_routes_table(switch_instance=env.switch[1], nexthop="10.0.31.2")

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
    """Wait until entry is expired from table

    Args:
        switch_instance(object):  Switch class instance to work with
        expected_timeout(int):  Time to wait
        table_name(str):  XML-RPC table name

    Returns:
        True or raise exception

    Examples::

        assert self.wait_until_entry_is_expired(timeout=10, switch_instance=env.switch[2])

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
    """Set adminMode for logical ports.

    Args:
        switch_instance(object):  Switch class instance to work with
        admin_mode(str):  Ports adminMode

    Returns:
        True or raise exception

    Examples::

        assert helpers.set_admin_mode_for_slave_ports(switch_instance=env.switch[1])

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
    """Assert that a code block/function call raises ExpectedException and raise a failure exception otherwise.

    Notes:
        You can specify a callable by passing a to-be-called lambda or an arbitrary callable with arguments.

    Args:
        expected_exception(Exception):  Expected exception type
        fail_message(str):  Fail message in case exception doesn't raise (string)
        args, kwargs:  function to test as first argument and it's parameters

    Returns:
        Exception info or pytest.fail

    Examples::

        helpers.raises(ZeroDivisionError, "Expected ZeroDevision didn't raise.", lambda: 1/0)

        def f(x): return 1/x
        ...
        helpers.raises(ZeroDivisionError, "Expected exception didn't raise.", f, 0)
        helpers.raises(ZeroDivisionError, "Did not raise", f, x=0)

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
    """Decorator to create raises functions with predefined xmlrpclib. Fault exception.

    """
    def wrapper(*args, **kwargs):
        """Decorator to create raises functions with predefined xmlrpclib.

        """
        return func(XMLRPCFault, *args, **kwargs)

    return wrapper


def is_error_in_expected(exception):
    """Check if exception is in list of expected errors.

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
    """Temporary replacement for original xmlrpc_raises.

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
    """Sets equal port costs for switch ports.

    Args:
        ports(dict of dict):  ports dictionary
        switch(SwitchX object):  switch instance
        switch_id(int):  id of switch in environment
        table(str):  table name (e.g. "MSTPPorts")
        cost(int):  port cost value

    Returns:
        None

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
    """Sets equal port costs for switch ports.

    Args:
        ports(dict):  ports dictionary
        switch(object):  switch instance
        switch_id(int):  id of switch in environment
        speed(int):  port speed value, integer

    Returns:
        None

    """
    if switch.type != 'lxc':
        for key in list(ports.keys()):
            if 'sw%d' % (switch_id, ) in key[0] and "tg1" not in key[0]:
                for link_id in list(ports[key].keys()):
                    ports_table_id = switch.findprop("Ports", [ports[key][link_id], ])
                    assert switch.setprop("Ports", "speed", [ports_table_id, speed]) == 0, "Port speed is not set"


def set_equal_port_speed_and_cost(ports, switch, table, switch_id=None, cost=2000, speed=10000):
    """Sets equal ports cost and speed for switch ports, and disables slave 40G ports

    Args:
        ports(dict):  ports dictionary
        switch(object):  switch instance
        switch_id(int):  id of switch in environment
        speed(int):  port speed value, integer
        table:  table name or list of table names (f.e. "MSTPPorts" or ["RSTPPorts", "MSTPPorts"])
        cost(int):  port cost value, integer

    Returns:
        None

    Examples::

        helpers.set_equal_port_speed_and_cost(ports, env.switch, ["MSTPPorts", "RSTPPorts", "RSTPPorts"])
        helpers.set_equal_port_speed_and_cost(ports, env.switch, "RSTPPorts")
        helpers.set_equal_port_speed_and_cost(ports, env.switch[1], "RSTPPorts", switch_id=1]

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
    """Function for return hex string value that is sum of bridgePriority and port_id in hex format.

    Args:
        priority(int):  Port bridgePriority
        port_id(int):  Port ID

    Returns:
        Hex Value without 0x prefix

    Examples::

        helpers.designated_port(32768, 28)

    """
    return hex(priority)[2:].zfill(2).upper() + hex(port_id)[2:].zfill(2).upper()


def set_rstp_mode(switch_instance=None):
    """Obsoleted function. Use set_stp_mode with proper option instead.

    """
    return set_stp_mode(switch_instance=switch_instance, mode="RSTP")


def set_mstp_mode(switch_instance=None):
    """Obsoleted function. Use set_stp_mode with proper option instead.

    """
    return set_stp_mode(switch_instance=switch_instance, mode="MSTP")


def wait_until_stp_state(switch_instance=None, table="STPPorts", port=1, state="Disabled", timeout=30):
    """Obsoleted function. Use wait_until_value_is_changed with proper option instead.

    """
    return wait_until_value_is_changed(switch_instance=switch_instance, table_name=table, parameter_name="state",
                                       value=state, row_id=port, timeout=timeout)


def wait_until_ops_state(switch_instance=None, port=1, state="Up", timeout=30):
    """Obsoleted function. Use wait_until_value_is_changed with proper option instead.

    """
    return wait_until_value_is_changed(switch_instance=switch_instance, table_name="Ports", parameter_name="operationalStatus",
                                       value=state, row_id=port, timeout=timeout)


def process_multicall(return_list):
    """Returns list of methods with errors.

    """
    mod_logger.debug("Multicall results processing starts")
    results = []
    for row in return_list:
        if row['result'] == "-1" or "faultCode" in row["result"]:
            results.append(row)
            results[-1]["error"] = "Method %s with params %s returns error %s" % (row["methodName"], row["params"], row["result"])

    return results


def is_entry_added_to_table(switch_inst, table_name, srch_params, timeout=1, expect_count=1, exist=True):
    """Check if entry with specified fields values is added to table

    Args:
        switch_inst(object):  Switch instance to work with
        table_name(str):  The name of table to perform search in
        srch_params(dict):  Parameters for entry search
        timeout(int):  Time to wait
        expect_count(int):  Number of entries in the table that correspond to search parameters (integer)
        exist(bool):  Decided if entry exists in table or not (boolean)

    Returns:
        bool: True/False

    Examples::

        srch_params = {'macAddress': '00:00:00:BB:00:AA', 'portId': 24, 'valid': 'Enabled'}
        assert helpers.is_entry_added_to_table(env.switch[1], "DcbxRemotes", srch_params, timeout=5)
        assert helpers.is_entry_added_to_table(env.switch[1], "DcbxRemotes", srch_params, timeout=5, exist=False)

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
    """Verify that row has correct parameters' values in table.

    Args:
        switch_inst(object):  Switch instance to work with
        table_name(str):  The name of table to validate the row parameters
        params(dict):  Parameters and values the row in table should match
        find_params(list):  List of parameters to find a row in table
        row_id(int):  Row ID in table
        timeout(int):  Time to wait
        interval(int):  interval in seconds between re-reading the table

    Returns:
        None (Raises error if values are incorrect)

    Examples::

        helpers.verify_port_params_in_table(env.switch[1], "DcbxPfcPortsLocal", {"willing": "Enabled", "enabled": "0,0,0,0,0,0,0,1"}, [port_id, ], timeout=1)
        helpers.verify_port_params_in_table(env.switch[1], "DcbxPorts", {"multiplePeers": 'Enabled'}, row_id=24, timeout=1)

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
    """Configure port parameters in table.

    Args:
        switch_inst(object):  Switch instance to work with
        table_name(str):  The name of table to work with
        params(dict):  Parameters and values that should be configured for port
        find_params(list):  List of parameters to find a row in table
        row_id(int):  Row ID in table
        validate_updates(bool):  Verify if updates were set

    Returns:
        None

    Examples::

        helpers.update_table_params(env.switch[1], "DcbxPfcPortsAdmin", {"willing": "Enabled", "enabled": "0,0,0,1,0,0,0,0"}, [port_id, ])
        helpers.update_table_params(env.switch[1], "DcbxPorts", {"adminStatus": 'Disabled'}, row_id=24)

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
    """Disable Lldp on all device ports.

    Args:
        switch_instance(object):  Switch instance to work with

    Returns:
        None

    Examples::

        helpers.disable_lldp_for_all_ports(env.switch[1])

    """
    mod_logger.debug("Set LLDP adminStatus to Disabled for all ports")
    switch_instance.ui.disable_lldp_on_device_ports()

    mod_logger.debug("LLDP Remotes table should be empty")
    assert not switch_instance.ui.get_table_lldp_remotes(), "Llldp Remotes table is not empty"


def validate_frame_against_multiple_layers(packet, src_mac=None, unexpected_layers=None, expected_layers=None):
    """Verify that frame doesn't contain specific set of Layers and contains correct values for other expected Layers.

    Args:
        packet(pypacker packet):  Packet that should be validated
        src_mac(None or MacAddress):  Expected src mac address of packet
        unexpected_layers(list of strings):  List of layers that should not be present is the frame
        expected_layers(list or dict):  List or Dictionary of layers with expected values that should be present in frame. If the frame contains multiple number
                                        of specific layer than value in expected_layer dictionary should be a list (list or dictionary)

    Returns:
        None (Raises error if packet is incorrect)

    Examples::

        expected_layers = {"DCBXApplicationPriority": {"type": 127L, "length": 5L, "oui": 0x80c2, "subtype": 12L, "reserved": 0},
                           "DCBXApplicationPriorityTable": [{'priority': 7, 'protocolid': 125, 'sel': 2, 'reserved': 0L},
                                                            {'priority': 6, 'protocolid': 555, 'sel': 4, 'reserved': 0L}],
                           "LLDPDUEnd": {"type": 0, "length": 0}}
        unexpected_layers = ["DCBXCongestionNotification", "DCBXConfiguration"]
        helpers.validate_frame_against_multiple_layers(packet, dut_mac, unexpected_layers=unexpected_layers, expected_layers=expected_layers)

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
    """Returns list of errors in CLI set results.

    """
    if return_list:
        mod_logger.debug("Multicall results processing starts")
        for row in return_list:
            if 'Error' in row:
                raise CLIException(row)


def grouper(iterable, n):
    """Collect data into fixed-length chunks or blocks

    grouper('ABCDEFG', 3) --> ABC DEF G

    Modified from http://stackoverflow.com/users/1052325/reclosedev 's modification
    of http://stackoverflow.com/users/279627/sven-marnach 's answer

    http://stackoverflow.com/a/8998040

    Args:
        iterable(iter()): iterable to group into chunks
        n(int): chunk size

    Returns:
        iter(list): itererable of chunks of size n

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
    """Collect data into iterables of fixed-length chunks or blocks

    grouper_it('ABCDEFG', 3) --> iter(ABC) iter(DEF) iter(G)

    Copyied from http://stackoverflow.com/users/1052325/reclosedev 's modification
    of http://stackoverflow.com/users/279627/sven-marnach 's answer

    http://stackoverflow.com/a/8998040

    Args:
        iterable(iter()): iterable to group into chunks
        n(int): chunk size

    Returns:
        iter(iter()): return an iterable of iterables of chunk size n

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

    Args:
        match(_sre.SRE_Match)

    """
    try:
        return match.group(*args)
    except (IndexError, AttributeError):
        return kwargs.get('default')


def merge_dicts(*dict_args):
    """Merge dictionaries from dict_args.

    When same keys present the last dictionary in args list has the highest priority.

    Args:
        dict_args(tuple(dict))

    Returns:
        dict: merged dictionary

    """
    result = {}
    for d in dict_args:
        result.update(d)
    return result


def apply_action_and_add_finalizer(request, targets, action, reaction):
    for a_target in targets:
        action(a_target)
        request.addfinalizer(functools.partial(reaction, a_target))
