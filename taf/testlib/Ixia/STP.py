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

@file  STP.py

@summary  IxNetwork xSTP protocol emulation functionality.

@note
TCL procedures:
::ixia::emulation_stp_bridge_config
::ixia::emulation_stp_control
::ixia::emulation_stp_info
::ixia::emulation_stp_lan_config
::ixia::emulation_stp_msti_config
::ixia::emulation_stp_vlan_config
"""


class STP(object):
    """
    @description  IxNet STP configuration wrapper
    """

    def __init__(self, ixia):
        """
        @brief  STP class initialization
        @param ixia:  Ixia traffic generator
        @type  ixia:  IxiaHLTMixin
        """
        self.ixia = ixia
        self.stp_dictionary = {}

    def configure_bridges(self, port, ifaces=None, bridge_handler_id=None, br_iface_handler_id=None, vlan_msti_handler_id=None, **kwargs):
        """
        @brief  Configure/Modify STP bridges on port
        @param port:  TG port in format tuple(chassisID, cardId, portId)
        @type  port:  tuple(int)
        @param ifaces:  STP interface handler name
        @type  ifaces:  str
        @param bridge_handler_id:  STP bridge handler name
        @type  bridge_handler_id:  str
        @param br_iface_handler_id:  STP bridge interface handler name
        @type  br_iface_handler_id:  str
        @param vlan_msti_handler_id:  STP bridge_msti_vlan handler name
        @type  vlan_msti_handler_id:  str
        @raise  Exception:  non-existent STP bridge or
                            not defined STP bridge handler name to modify VLAN MSTI
        @raise  AssertionError:  error in executing tcl code
        @rtype:  tuple(dict,dict,dict)
        @return:  stp bridges handler names, stp bridge interface handler names,
                  protocol interface handler names for a specific STP bridge
        @note:  See description of keyword arguments in ixia_stp_api.tcl
                Full path: /opt/ixos/lib/hltapi/library/ixia_stp_api.tcl
        """
        if port not in list(self.stp_dictionary.keys()):
            self.stp_dictionary[port] = {}
        if "br_handler" not in list(self.stp_dictionary[port].keys()):
            self.stp_dictionary[port]['br_handler'] = {}
        if "br_intf_handler" not in list(self.stp_dictionary[port].keys()):
            self.stp_dictionary[port]['br_intf_handler'] = {}
        if "stp_intf_handler" not in list(self.stp_dictionary[port].keys()):
            self.stp_dictionary[port]['stp_intf_handler'] = {}
        _port = "_".join(map(str, port))
        cfg_name = "stp_bridge_config_{0}".format(_port)
        if "mode" not in list(kwargs.keys()):
            kwargs["mode"] = "create"
        if kwargs["mode"] != "create":
            if "stp_bridge_cfg_name" not in self.stp_dictionary[port] or self.stp_dictionary[port]["stp_bridge_cfg_name"] is None:
                raise Exception("Could not modify stp bridge because it wasn't created. Use mode='create' first.")
            if vlan_msti_handler_id is not None and bridge_handler_id is None and br_iface_handler_id is None:
                raise Exception("User should provide bridge_handler_id or br_iface_handler_id to modify vlan_msti_handler_id")
        if kwargs["mode"] == "create":
            if ifaces is not None:
                kwargs["interface_handle"] = ifaces
            else:
                kwargs["port_handle"] = "/".join(map(str, port))
        else:
            if bridge_handler_id is not None:
                kwargs["handle"] = "$" + self.stp_dictionary[port]['br_handler'][bridge_handler_id]
            if br_iface_handler_id is not None:
                kwargs["handle"] = "$" + self.stp_dictionary[port]['br_intf_handler'][br_iface_handler_id]
            if vlan_msti_handler_id is not None:
                kwargs["bridge_msti_vlan"] = "$" + self.stp_dictionary[port]['msti_handler'][vlan_msti_handler_id]
        self.ixia.ixia_emulation_stp_bridge_config(**kwargs)
        assert self.ixia.check_return_code() == ""
        if kwargs["mode"] == "create":
            self.ixia.set_var(**{cfg_name: "$return_code"})
        self.stp_dictionary[port]['stp_bridge_cfg_name'] = cfg_name

        # Create stp bridge handles list
        _rlist = self.ixia.tcl("keylget {0} bridge_handles".format(cfg_name))
        _rlist = _rlist.split(" ")
        for item in _rlist:
            # item example: '::ixNet::OBJ-/vport:1/protocols/stp/bridge:1'
            pos = item.rfind(":")
            _id = item[pos + 1:]
            _index = _rlist.index(item)
            self.stp_dictionary[port]['br_handler'][_id] = "bridge_{0}_{1}".format(_port, _id)
            self.ixia.set_var(**{self.stp_dictionary[port]['br_handler'][_id]: "[lindex [keylget {0} bridge_handles] {1}]".format(cfg_name, _index)})

        # Create stp bridge interface handles list
        for br_index in list(self.stp_dictionary[port]['br_handler'].keys()):
            br_name = self.stp_dictionary[port]['br_handler'][br_index]
            _rlist = self.ixia.tcl("keylget {0} bridge_interface_handles.${1}".format(cfg_name, br_name))
            _rlist = _rlist.split(" ")
            for item in _rlist:
                # item example: '::ixNet::OBJ-/vport:1/protocols/stp/bridge:1/interface:1'
                pos = item.rfind(":")
                _id = item[pos + 1:]
                _index = _rlist.index(item)
                self.stp_dictionary[port]['br_intf_handler'][(br_index, _id)] = "bridge_interface_{0}_br{1}_{2}".format(_port, br_index, _id)
                self.ixia.set_var(**{self.stp_dictionary[port]['br_intf_handler'][(br_index, _id)]:
                                     "[lindex [keylget {0} bridge_interface_handles.${1}] {2}]".format(cfg_name, br_name, _index)})

        # Create stp interface handles list
        for br_index in list(self.stp_dictionary[port]['br_handler'].keys()):
            br_name = self.stp_dictionary[port]['br_handler'][br_index]
            _rlist = self.ixia.tcl("keylget {0} interface_handles.${1}".format(cfg_name, br_name))
            _rlist = _rlist.split(" ")
            for item in _rlist:
                # item example: '::ixNet::OBJ-/vport:1/interface:1'
                pos = item.rfind(":")
                _id = item[pos + 1:]
                _index = _rlist.index(item)
                self.stp_dictionary[port]['stp_intf_handler'][_id] = "stp_interface_{0}_{1}".format(_port, _id)
                self.ixia.set_var(**{self.stp_dictionary[port]['stp_intf_handler'][_id]:
                                     "[lindex [keylget {0} interface_handles.${1}] {2}]".format(cfg_name, br_name, _index)})

        return self.stp_dictionary[port]['br_handler'].copy(), self.stp_dictionary[port]['br_intf_handler'].copy(), \
            self.stp_dictionary[port]['stp_intf_handler'].copy()

    def control(self, port, bridge_handler_id=None, **kwargs):
        """
        @brief  Start STP protocol on specified port/bridge
        @param port:  TG port in format tuple(chassisID, cardId, portId)
        @type  port:  tuple(int)
        @param bridge_handler_id:  STP bridge handler name
        @type  bridge_handler_id:  str
        @raise  AssertionError:  error in executing tcl code
        @return:  None
        @note:  See description of keyword arguments in ixia_stp_api.tcl
                Full path: /opt/ixos/lib/hltapi/library/ixia_stp_api.tcl
        """
        if port not in list(self.stp_dictionary.keys()):
            self.stp_dictionary[port] = {}
        _port = "_".join(map(str, port))
        cfg_name = "stp_control_{0}".format(_port)
        if "mode" not in list(kwargs.keys()):
            kwargs["mode"] = "start"
        if bridge_handler_id is not None:
            kwargs["handle"] = "$" + self.stp_dictionary[port]['br_handler'][bridge_handler_id]
        else:
            kwargs["port_handle"] = "/".join(map(str, port))
        self.ixia.ixia_emulation_stp_control(**kwargs)
        assert self.ixia.check_return_code() == ""
        self.ixia.set_var(**{cfg_name: "$return_code"})
        self.stp_dictionary[port]['stp_control'] = cfg_name

    def info(self, port, bridge_handler_id=None, **kwargs):
        """
        @brief  Command to retrieve STP statistics
        @param port:  TG port in format tuple(chassisID, cardId, portId)
        @type  port:  tuple(int)
        @param bridge_handler_id:  STP bridge handler name
        @type  bridge_handler_id:  str
        @raise  AssertionError:  error in executing tcl code
        @rtype:  dict
        @return:  STP statistics
        @note:  See description of keyword arguments in ixia_stp_api.tcl
                Full path: /opt/ixos/lib/hltapi/library/ixia_stp_api.tcl
        """
        if port not in list(self.stp_dictionary.keys()):
            self.stp_dictionary[port] = {}
        _port = "_".join(map(str, port))
        cfg_name = "stp_info_{0}".format(_port)
        if "mode" not in list(kwargs.keys()):
            kwargs["mode"] = "aggregate_stats"
        if bridge_handler_id is not None:
            kwargs["handle"] = "$" + self.stp_dictionary[port]['br_handler'][bridge_handler_id]
        else:
            kwargs["port_handle"] = "/".join(map(str, port))
        self.ixia.ixia_emulation_stp_info(**kwargs)
        assert self.ixia.check_return_code() == ""
        self.ixia.set_var(**{cfg_name: "$return_code"})
        self.stp_dictionary[port]["stp_info"] = cfg_name

        # Create stp info dictionary
        self.stp_dictionary[port]["info"] = {}
        if not isinstance(port[0], tuple):
            port_list = (port,)
        else:
            port_list = port
        for port_item in port_list:
            _port_item = "/".join(map(str, port_item))
            self.stp_dictionary[port]["info"][port_item] = {}
            _rlist = self.ixia.tcl("keylkeys {0} {1}".format(cfg_name, _port_item))
            _rlist = _rlist.split(" ")
            for key_item in _rlist:
                # item example: '::ixNet::OBJ-/vport:1/protocols/stp/bridge:1'
                self.stp_dictionary[port]['info'][port_item][key_item] = {}
                _slist = self.ixia.tcl("keylkeys {0} {1}.{2}".format(cfg_name, _port_item, key_item))
                _slist = _slist.split(" ")
                for s_key_item in _slist:
                    self.stp_dictionary[port]['info'][port_item][key_item][s_key_item] = {}
                    if key_item == 'aggregate':
                        self.stp_dictionary[port]['info'][port_item][key_item][s_key_item] = \
                            self.ixia.tcl("keylget {0} {1}.{2}.{3}".format(cfg_name, _port_item, key_item, s_key_item))
                    else:
                        _tlist = self.ixia.tcl("keylkeys {0} {1}.{2}.{3}".format(cfg_name, _port_item, key_item, s_key_item))
                        _tlist = _tlist.split(" ")
                        for t_key_item in _tlist:
                            self.stp_dictionary[port]['info'][port_item][key_item][s_key_item][t_key_item] = {}
                            if s_key_item == "stp" or s_key_item == "cist":
                                self.stp_dictionary[port]['info'][port_item][key_item][s_key_item][t_key_item] = \
                                    self.ixia.tcl("keylget {0} {1}.{2}.{3}.{4}".format(cfg_name, _port_item, key_item, s_key_item, t_key_item))
                            else:
                                _ulist = self.ixia.tcl("keylkeys {0} {1}.{2}.{3}.{4}".format(cfg_name, _port_item, key_item, s_key_item, t_key_item))
                                _ulist = _ulist.split(" ")
                                for u_key_item in _ulist:
                                    self.stp_dictionary[port]['info'][port_item][key_item][s_key_item][t_key_item][u_key_item] = {}
                                    if s_key_item == "msti_intf":
                                        _vlist = self.ixia.tcl("keylkeys {0} {1}.{2}.{3}.{4}.{5}".format(cfg_name, _port_item, key_item,
                                                                                                         s_key_item, t_key_item, u_key_item))
                                        _vlist = _vlist.split(" ")
                                        for v_key_item in _vlist:
                                            self.stp_dictionary[port]['info'][port_item][key_item][s_key_item][t_key_item][u_key_item][v_key_item] = {}
                                            self.stp_dictionary[port]['info'][port_item][key_item][s_key_item][t_key_item][u_key_item][v_key_item] = \
                                                self.ixia.tcl("keylget {0} {1}.{2}.{3}.{4}.{5}.{6}".format(cfg_name, _port_item, key_item,
                                                                                                           s_key_item, t_key_item, u_key_item, v_key_item))
                                    else:
                                        self.stp_dictionary[port]['info'][port_item][key_item][s_key_item][t_key_item][u_key_item] = \
                                            self.ixia.tcl("keylget {0} {1}.{2}.{3}.{4}.{5}".format(cfg_name, _port_item, key_item,
                                                                                                   s_key_item, t_key_item, u_key_item))

        import copy
        return copy.deepcopy(self.stp_dictionary[port]['info'])

    def configure_lans(self, port, lan_bridge_handler_id=None, **kwargs):
        """
        @brief  Create/modify/delete/enable/disable an emulated LAN for STP protocol
        @param port:  TG port in format tuple(chassisID, cardId, portId)
        @type  port:  tuple(int)
        @param lan_bridge_handler_id:  STP bridge handler name
        @type  lan_bridge_handler_id:  str
        @raise  AssertionError:  error in executing tcl code
        @rtype:  dict
        @return:  STP control bridges handler names
        @note:  See description of keyword arguments in ixia_stp_api.tcl
                Full path: /opt/ixos/lib/hltapi/library/ixia_stp_api.tcl
        """
        if port not in list(self.stp_dictionary.keys()):
            self.stp_dictionary[port] = {}
        if "lan_bridge_handler" not in list(self.stp_dictionary[port].keys()):
            self.stp_dictionary[port]['lan_bridge_handler'] = {}
        _port = "_".join(map(str, port))
        cfg_name = "stp_lan_config_{0}".format(_port)
        if "mode" not in list(kwargs.keys()):
            kwargs["mode"] = "create"
        if kwargs["mode"] != "create":
            if "stp_lan_config" not in list(self.stp_dictionary[_port].keys()) or self.stp_dictionary[_port]["stp_lan_config"] is None:
                raise Exception("Could not modify stp lan bridge because it wasn't created. Use mode='create' first.")
        if lan_bridge_handler_id is not None:
            kwargs["handle"] = "$" + self.stp_dictionary[port]['lan_bridge_handler'][lan_bridge_handler_id]
        else:
            kwargs["port_handle"] = "/".join(map(str, port))
        self.ixia.ixia_emulation_stp_lan_config(**kwargs)
        assert self.ixia.check_return_code() == ""
        if kwargs["mode"] == "create":
            self.ixia.set_var(**{cfg_name: "$return_code"})
        self.stp_dictionary[port]["stp_lan_config"] = cfg_name

        # Create stp lan bridge handles list
        _rlist = self.ixia.tcl("keylget {0} handle".format(cfg_name))
        _rlist = _rlist.split(" ")
        for item in _rlist:
            # item example: '::ixNet::OBJ-/vport:1/protocols/stp/lan:1'
            pos = item.rfind(":")
            _id = item[pos + 1:]
            _index = _rlist.index(item)
            self.stp_dictionary[port]['lan_bridge_handler'][_id] = "stp_lan_bridge_{0}_{1}".format(_port, _id)
            self.ixia.set_var(**{self.stp_dictionary[port]['lan_bridge_handler'][_id]: "[lindex [keylget {0} handle] {1}]".format(cfg_name, _index)})

        return self.stp_dictionary[port]['lan_bridge_handler'].copy()

    def configure_msti(self, port, bridge_handler_id=None, msti_handler_id=None, **kwargs):
        """
        @brief  Create/modify/delete/enable/disable a STP MSTI object
        @param port:  TG port in format tuple(chassisID, cardId, portId)
        @type  port:  tuple(int)
        @param bridge_handler_id:  STP bridge handler name
        @type  bridge_handler_id:  str
        @param msti_handler_id:  STP MSTI handler name
        @type  msti_handler_id:  str
        @raise  AssertionError:  error in executing tcl code
        @rtype:  dict
        @return:  STP MSTI bridges handler names
        @note:  See description of keyword arguments in ixia_stp_api.tcl
                Full path: /opt/ixos/lib/hltapi/library/ixia_stp_api.tcl
        """
        if port not in list(self.stp_dictionary.keys()):
            self.stp_dictionary[port] = {}
        if "msti_handler" not in list(self.stp_dictionary[port].keys()):
            self.stp_dictionary[port]['msti_handler'] = {}
        _port = "_".join(map(str, port))
        cfg_name = "stp_msti_config_{0}".format(_port)
        if "mode" not in list(kwargs.keys()):
            kwargs["mode"] = "create"
        if kwargs["mode"] != "create":
            if "stp_msti_config" not in self.stp_dictionary[port] or self.stp_dictionary[port]["stp_msti_config"] is None:
                raise Exception("Could not modify stp msti because it wasn't created. Use mode='create' first.")
        if msti_handler_id is not None:
            kwargs["handle"] = "$" + self.stp_dictionary[port]['msti_handler'][msti_handler_id]
        elif bridge_handler_id is not None:
            kwargs["bridge_handle"] = "$" + self.stp_dictionary[port]['br_handler'][bridge_handler_id]
        else:
            raise Exception("bridge_handler_id or msti_handler_id should be defined")
        self.ixia.ixia_emulation_stp_msti_config(**kwargs)
        assert self.ixia.check_return_code() == ""
        if kwargs["mode"] == "create":
            self.ixia.set_var(**{cfg_name: "$return_code"})
        self.stp_dictionary[port]["stp_msti_config"] = cfg_name

        # Create stp msti bridge handles list
        _rlist = self.ixia.tcl("keylget {0} handle".format(cfg_name))
        _rlist = _rlist.split(" ")
        for item in _rlist:
            # item example: '::ixNet::OBJ-/vport:1/protocols/stp/bridge:1/msti:1'
            pos = item.rfind(":")
            _id = item[pos + 1:]
            _index = _rlist.index(item)
            self.stp_dictionary[port]['msti_handler'][_id] = "stp_msti_bridge_{0}_{1}".format(_port, _id)
            self.ixia.set_var(**{self.stp_dictionary[port]['msti_handler'][_id]: "[lindex [keylget {0} handle] {1}]".format(cfg_name, _index)})

        return self.stp_dictionary[port]['msti_handler'].copy()

    def configure_vlans(self, port, bridge_handler_id=None, vlan_handler_id=None, **kwargs):
        """
        @brief Create/modify/delete/enable/disable a STP VLAN object.
        @param port:  TG port in format tuple(chassisID, cardId, portId)
        @type  port:  tuple(int)
        @param bridge_handler_id:  STP bridge handler name
        @type  bridge_handler_id:  str
        @param vlan_handler_id:  VLAN handler name
        @type  vlan_handler_id:  str
        @raise  AssertionError:  error in executing tcl code
        @rtype:  dict
        @return:  STP VLAN bridges handler names
        @note:  See description of keyword arguments in ixia_stp_api.tcl
                Full path: /opt/ixos/lib/hltapi/library/ixia_stp_api.tcl
        """
        if port not in list(self.stp_dictionary.keys()):
            self.stp_dictionary[port] = {}
        if "vlan_handler" not in list(self.stp_dictionary[port].keys()):
            self.stp_dictionary[port]['vlan_handler'] = {}
        _port = "_".join(map(str, port))
        cfg_name = "stp_vlan_config_{0}".format(_port)
        if "mode" not in list(kwargs.keys()):
            kwargs["mode"] = "create"
        if kwargs["mode"] != "create":
            if "stp_vlan_config" not in self.stp_dictionary[_port] or self.stp_dictionary[_port]["stp_vlan_config"] is None:
                raise Exception("Could not modify stp vlan because it wasn't created. Use mode='create' first.")
        if vlan_handler_id is not None:
            kwargs["handle"] = "$" + self.stp_dictionary[port]['vlan_handler'][vlan_handler_id]
        elif bridge_handler_id is not None:
            kwargs["bridge_handle"] = "$" + self.stp_dictionary[port]['br_handler'][bridge_handler_id]
        else:
            raise Exception("bridge_handler_id or vlan_handler_id should be defined")
        self.ixia.ixia_emulation_stp_vlan_config(**kwargs)
        assert self.ixia.check_return_code() == ""
        if kwargs["mode"] == "create":
            self.ixia.set_var(**{cfg_name: "$return_code"})
        self.stp_dictionary[port]["stp_vlan_config"] = cfg_name

        # Create stp vlan bridge handles list
        _rlist = self.ixia.tcl("keylget {0} handle".format(cfg_name))
        _rlist = _rlist.split(" ")
        for item in _rlist:
            # item example: 'ixNet::OBJ-/vport:1/protocols/bgp/neighborRange:1'
            pos = item.rfind(":")
            _id = item[pos + 1:]
            _index = _rlist.index(item)
            self.stp_dictionary[port]['vlan_handler'][_id] = "stp_vlan_bridge_{0}_{1}".format(_port, _id)
            self.ixia.set_var(**{self.stp_dictionary[port]['vlan_handler'][_id]: "[lindex [keylget {0} handle] {1}]".format(cfg_name, _index)})

        return self.stp_dictionary[port]['vlan_handler'].copy()

    def cleanup(self):
        """
        @brief  Clean all TCL variables and stp_dictionary
        @return:  None
        """
        for port_values in list(self.stp_dictionary.values()):
            for key in list(port_values.keys()):
                if key != 'info':
                    value = port_values[key]
                    if isinstance(value, dict):
                        for inner_value in list(value.values()):
                            self.ixia.tcl("unset {0}".format(inner_value))
                    else:
                        self.ixia.tcl("unset {0}".format(value))
        self.stp_dictionary = {}
