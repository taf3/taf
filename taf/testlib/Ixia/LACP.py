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

@file  LACP.py

@summary  IxNetwork LACP protocol emulation functionality.

@note
TCL procedures:
::ixia::emulation_lacp_control
::ixia::emulation_lacp_info
::ixia::emulation_lacp_link_config
"""

import copy


class LACP(object):
    """
    @description  IxNet LACP configuration wrapper
    """

    def __init__(self, ixia):
        """
        @brief  LACP class initialization
        @param ixia:  Ixia traffic generator
        @type  ixia:  IxiaHLTMixin
        """
        self.ixia = ixia
        self.lacp_dict = {}

    def control(self, port, link_handler_id=None, **kwargs):
        """
        @brief  Start/stop/restart protocol, start/stop sending PDU, send Marker Request,
                update link parameters after the link has been modified.
        @param port:  TG port in format tuple(chassisID, cardId, portId)
        @type  port:  tuple(int)
        @param link_handler_id:  LACP link name
        @type  link_handler_id:  str
        @raise  AssertionError:  error in executing tcl code
        @return:  None
        @note:  See description of keyword arguments in ixia_lacp_api.tcl
                Full path: /opt/ixos/lib/hltapi/library/ixia_lacp_api.tcl
        """
        if port not in list(self.lacp_dict.keys()):
            self.lacp_dict[port] = {}
        if 'port_handle' not in self.lacp_dict[port]:
            if isinstance(port[0], tuple):
                _ports = []
                for port_item in port:
                    _ports.append("_".join(map(str, port_item)))
                _port = "_".join(_ports)
                port_handler_name = "port_handler_{0}".format(_port)
                self.ixia.set_var(**{port_handler_name: "[list]"})
                for port_item in port:
                    self.ixia.tcl("lappend {0} {1}".format(port_handler_name, "/".join(map(str, port_item))))
            else:
                _port = "_".join(port.split("/"))
                port_handler_name = "port_handler_{0}".format(_port)
                self.ixia.set_var(**{port_handler_name: "/".join(map(str, port))})
            self.lacp_dict[port]['port_handle'] = port_handler_name
        cfg_name = "lacp_control_{0}".format(self.lacp_dict[port]['port_handle'].replace("port_handler_", ""))
        if "mode" not in list(kwargs.keys()):
            kwargs["mode"] = "start"
        if link_handler_id is not None:
            kwargs["handle"] = "${0}".format(self.lacp_dict[port]['link_handler'][link_handler_id])
        else:
            kwargs["port_handle"] = "${0}".format(self.lacp_dict[port]['port_handle'])
        self.ixia.ixia_emulation_lacp_control(**kwargs)
        assert self.ixia.check_return_code() == ""
        self.ixia.set_var(**{cfg_name: "$return_code"})
        self.lacp_dict[port]['lacp_control'] = cfg_name

    def info(self, port, link_handler_id=None, **kwargs):
        """
        @brief  Command to retrieve LACP statistics
        @param port:  TG port in format tuple(chassisID, cardId, portId)
        @type  port:  tuple(int)
        @param link_handler_id:  LACP link name
        @type  link_handler_id:  str
        @raise  AssertionError:  error in executing tcl code
        @rtype:  dict
        @return:  LACP statistics
        @note:  See description of keyword arguments in ixia_lacp_api.tcl
                Full path: /opt/ixos/lib/hltapi/library/ixia_lacp_api.tcl
        """
        if port not in list(self.lacp_dict.keys()):
            self.lacp_dict[port] = {}
        if 'port_handle' not in self.lacp_dict[port]:
            if isinstance(port[0], tuple):
                _ports = []
                for port_item in port:
                    _ports.append("_".join(map(str, port_item)))
                _port = "_".join(_ports)
                port_handler_name = "port_handler_{0}".format(_port)
                self.ixia.set_var(**{port_handler_name: "[list]"})
                for port_item in port:
                    self.ixia.tcl("lappend {0} {1}".format(port_handler_name, "/".join(map(str, port_item))))
            else:
                _port = "_".join(port.split("/"))
                port_handler_name = "port_handler_{0}".format(_port)
                self.ixia.set_var(**{port_handler_name: "/".join(map(str, port))})
            self.lacp_dict[port]['port_handle'] = port_handler_name
        cfg_name = "lacp_info_{0}".format(self.lacp_dict[port]['port_handle'].replace("port_handler_", ""))
        if "mode" not in list(kwargs.keys()):
            kwargs["mode"] = "aggregate_stats"
        if link_handler_id is not None:
            kwargs["handle"] = "${0}".format(self.lacp_dict[port]['link_handler'][link_handler_id])
        else:
            kwargs["port_handle"] = "${0}".format(self.lacp_dict[port]['port_handle'])
        self.ixia.ixia_emulation_lacp_info(**kwargs)
        assert self.ixia.check_return_code() == ""
        self.ixia.set_var(**{cfg_name: "$return_code"})
        self.ixia.puts("$return_code")
        self.lacp_dict[port]["lacp_info"] = cfg_name

        # Create lacp info dictionary
        self.lacp_dict[port]["info"] = {}
        if not isinstance(port[0], tuple):
            port_list = (port, )
        else:
            port_list = port

        for port_item in port_list:
            p_item = str(port_item[0]) + "/" + str(port_item[1]) + "/" + str(port_item[2])
            self.lacp_dict[port]["info"][p_item] = {}
            _rlist = self.ixia.tcl("keylkeys {0} {1}".format(cfg_name, p_item))
            _rlist = _rlist.split(" ")

            for key_item in _rlist:
                # item example: '::ixNet::OBJ-/vport:1/protocols/stp/bridge:1'
                self.lacp_dict[port]['info'][p_item][key_item] = self.ixia.tcl("lindex [keylget {0} {1}.{2}] 0".format(cfg_name, p_item, key_item))

        return copy.deepcopy(self.lacp_dict[port]['info'])

    def configure_links(self, port, link_handler_id=None, **kwargs):
        """
        @brief  Create/modify/delete/enable/disable a LACP link
        @param port:  TG port in format tuple(chassisID, cardId, portId)
        @type  port:  tuple(int)
        @param link_handler_id:  LACP link name
        @type  link_handler_id:  str
        @raise  AssertionError:  error in executing tcl code
        @rtype:  dict
        @return:  LACP links handler names
        @note:  See description of keyword arguments in ixia_lacp_api.tcl
                Full path: /opt/ixos/lib/hltapi/library/ixia_lacp_api.tcl
        """

        if port not in list(self.lacp_dict.keys()):
            self.lacp_dict[port] = {}

        if "link_handler" not in list(self.lacp_dict[port].keys()):
            self.lacp_dict[port]['link_handler'] = {}

        if 'port_handle' not in self.lacp_dict[port]:
            if isinstance(port[0], tuple):
                _ports = []
                for port_item in port:
                    _ports.append("_".join(map(str, port_item)))
                _port = "_".join(_ports)
                port_handler_name = "port_handler_{0}".format(_port)
                self.ixia.set_var(**{port_handler_name: "[list]"})
                for port_item in port:
                    self.ixia.tcl("lappend {0} {1}".format(port_handler_name, "/".join(map(str, port_item))))
            else:
                _port = "_".join(port.split("/"))
                port_handler_name = "port_handler_{0}".format(_port)
                self.ixia.set_var(**{port_handler_name: "/".join(map(str, port))})
            self.lacp_dict[port]['port_handle'] = port_handler_name

        cfg_name = "lacp_link_config_{0}".format(self.lacp_dict[port]['port_handle'].replace("port_handler_", ""))
        if "mode" not in list(kwargs.keys()):
            kwargs["mode"] = "create"

        if kwargs["mode"] != "create":
            if "lacp_link_cfg_name" not in self.lacp_dict[port] or self.lacp_dict[port]["lacp_link_cfg_name"] is None:
                raise Exception("Could not modify lacp link because it wasn't created. Use mode='create' first.")

        if kwargs["mode"] == "create":
            kwargs["port_handle"] = "${0}".format(self.lacp_dict[port]['port_handle'])
        else:
            kwargs["handle"] = "$" + self.lacp_dict[port]['link_handler'][link_handler_id]

        self.ixia.ixia_emulation_lacp_link_config(**kwargs)
        assert self.ixia.check_return_code() == ""
        if kwargs["mode"] == "create":
            self.ixia.set_var(**{cfg_name: "$return_code"})
        self.lacp_dict[port]['lacp_link_cfg_name'] = cfg_name

        # Create lacp link handles list
        _rlist = self.ixia.tcl("keylget {0} handle".format(cfg_name))
        _rlist = _rlist.split(" ")
        for item in _rlist:
            # item example: '::ixNet::OBJ-/vport:1/protocols/stp/bridge:1'
            pos = item.rfind("vport")
            _id = item[pos + 6:][0]
            _index = _rlist.index(item)
            self.lacp_dict[port]['link_handler'][_id] = "lacp_link_{0}_{1}".format(self.lacp_dict[port]['port_handle'], _id)
            self.ixia.set_var(**{self.lacp_dict[port]['link_handler'][_id]: "[lindex [keylget {0} handle] {1}]".format(cfg_name, _index)})

        return self.lacp_dict[port]['link_handler'].copy()

    def cleanup(self):
        """
        @brief  Clean all TCL variables and lacp_dict
        @return:  None
        """
        for port_values in list(self.lacp_dict.values()):
            for value in list(port_values.values()):
                if isinstance(value, dict):
                    for inner_value in list(value.values()):
                        self.ixia.tcl("unset {0}".format(inner_value))
                else:
                    self.ixia.tcl("unset {0}".format(value))
        self.lacp_dict = {}
