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

"""``OSPF.py``

`IxNetwork OSPF protocol emulation functionality`

Note:
    TCL procedures::

        ::ixia::emulation_ospf_config
        ::ixia::emulation_ospf_topology_route_config
        ::ixia::emulation_ospf_control
        ::ixia::emulation_ospf_lsa_config
        ::ixia::emulation_ospf_info

"""

import copy
import re


class OSPF(object):
    """IxNet OSPF configuration wrapper.

    """

    def __init__(self, ixia):
        """OSPF class initialization.

        Args:
            ixia(IxiaHLTMixin):  Ixia traffic generator

        """
        self.ixia = ixia
        self.ospf_dict = {}

    def config(self, port, *args, **kwargs):
        """Configure OSPF routers.

        Args:
            port(tuple(int)):  TG port in format tuple(chassisID, cardId, portId)

        Raises:
            AssertionError:  error in executing tcl code

        Returns:
            str:  OSPF session handler name

        Note:
            See description of keyword arguments in ixia_ospf_api.tcl

            Full path: /opt/ixos/lib/hltapi/library/ixia_ospf_api.tcl

        """
        # kwargs['port_handle'] = "/".join(map(str, port))
        if "mode" not in list(kwargs.keys()):
            kwargs["mode"] = "create"
        kwargs['port_handle'] = "/".join(map(str, port))

        if kwargs["mode"] == "modify":
            kwargs['handle'] = "$" + args[0]

        _port = "_".join(map(str, port))
        cfg_name = "ospf_session_config_{0}".format(_port)
        if port not in self.ospf_dict:
            self.ospf_dict[port] = {}

        self.ospf_dict[port]['cfg_name'] = cfg_name
        # if not "session_handler" in self.ospf_dict:
        #    self.ospf_dict[port]['session_handler'] = {}

        self.ixia.ixia_emulation_ospf_config(**kwargs)
        assert self.ixia.check_return_code() == ""
        self.ixia.puts("$return_code")

        self.ixia.set_var(**{cfg_name: "$return_code"})

        # Create ospf router handles list:
        self.ospf_dict[port]['session_handle'] = "ospf_session_{0}".format(_port)
        self.ixia.set_var(**{self.ospf_dict[port]['session_handle']: "[keylget {0} handle]".format(cfg_name)})

        _neighbours = self.ixia.tcl("return ${0}".format(self.ospf_dict[port]['session_handle']))
        self.ospf_dict[port]['neighbours'] = []

        for index in range(len(_neighbours.split(' '))):
            self.ospf_dict[port]['neighbours'].append("neighbour_{0}_{1}".format(_port, index))
            self.ixia.set_var(**{self.ospf_dict[port]['neighbours'][index]: "[lindex ${0} {1}]".format(self.ospf_dict[port]['session_handle'], index)})

        return self.ospf_dict[port]['session_handle']

    def topology_route_config(self, handle, *args, **kwargs):
        """Configure OSPF routes topology.

        Args:
            handle(str):  OSPF session handler name

        Raises:
            AssertionError:  error in executing tcl code

        Returns:
            str:  OSPF route handler name

        Note:
            See description of keyword arguments in ixia_ospf_api.tcl

            Full path: /opt/ixos/lib/hltapi/library/ixia_ospf_api.tcl

        """
        kwargs['handle'] = "$" + handle
        if "mode" not in list(kwargs.keys()):
            kwargs["mode"] = "create"

        _port = re.search(r"(\d)_(\d)_(\d*)", handle).group()
        port = tuple([int(x) for x in _port.split("_")])

        # if not "handler" in self.ospf_dict:
        #    self.ospf_dict[port]['handler'] = {}

        cfg_name = "ospf_router_config_{0}".format(_port)
        self.ixia.ixia_emulation_ospf_topology_route_config(*args, **kwargs)
        assert self.ixia.check_return_code() == ""

        self.ixia.puts("$return_code")
        self.ixia.set_var(**{cfg_name: "$return_code"})

        self.ospf_dict[port]['router_handle'] = "ospf_router_{0}".format(_port)
        if kwargs["mode"] == "create":
            self.ixia.set_var(**{self.ospf_dict[port]['router_handle']: "[keylget {0} elem_handle]".format(cfg_name)})

        return self.ospf_dict[port]['router_handle']

    def ospf_control(self, handle, *args, **kwargs):
        """Turning OSPF on\off.

        Args:
            handle(str):  OSPF session handler name

        Raises:
            AssertionError:  error in executing tcl code

        Returns:
            None

        Note:
            See description of keyword arguments in ixia_ospf_api.tcl

            Full path: /opt/ixos/lib/hltapi/library/ixia_ospf_api.tcl

        """
        kwargs['handle'] = "$" + handle
        if "mode" not in list(kwargs.keys()):
            kwargs["mode"] = "start"

        port = tuple([int(x) for x in handle.split("_")[2:]])
        _port = "_".join(handle.split("_")[2:])

        cfg_name = "ospf_control_{0}".format(_port)
        self.ixia.ixia_emulation_ospf_control(*args, **kwargs)
        assert self.ixia.check_return_code() == ""
        self.ixia.puts("$return_code")

    def ospf_lsa_config(self, handle, *args, **kwargs):
        """Configure OSPF LSA.

        Args:
            handle(str):  OSPF session handler name

        Raises:
            AssertionError:  error in executing tcl code

        Returns:
            str:  OSPF LSA handler name

        Note:
            See description of keyword arguments in ixia_ospf_api.tcl

            Full path: /opt/ixos/lib/hltapi/library/ixia_ospf_api.tcl

        """
        kwargs['handle'] = "$" + handle
        if "mode" not in list(kwargs.keys()):
            kwargs["mode"] = "create"

        port = tuple([int(x) for x in handle.split("_")[2:]])
        _port = "_".join(handle.split("_")[2:])

        # if not "lsa_handle" in self.ospf_dict:
        #    self.ospf_dict[port]['lsa_handle'] = {}

        cfg_name = "ospf_lsa_config_{0}".format(_port)
        self.ixia.ixia_emulation_ospf_lsa_config(*args, **kwargs)
        assert self.ixia.check_return_code() == ""

        self.ixia.puts("$return_code")
        self.ixia.set_var(**{cfg_name: "$return_code"})

        self.ospf_dict[port]['lsa_handle'] = "ospf_lsa_{0}".format(_port)
        self.ixia.set_var(**{self.ospf_dict[port]['lsa_handle']: "[keylget {0} lsa_handle]".format(cfg_name)})

        return self.ospf_dict[port]['lsa_handle']

    def ospf_info(self, handle, **kwargs):
        """Command to retrieve OSPF statistics.

        Args:
            handle(str):  OSPF session handler name

        Raises:
            AssertionError:  error in executing tcl code

        Returns:
            dict: OSPF statistics

        Note:
            See description of keyword arguments in ixia_ospf_api.tcl

            Full path: /opt/ixos/lib/hltapi/library/ixia_ospf_api.tcl

        """
        # define what the type of handle:
        if isinstance(handle, tuple):
            obj_type = "port_handle"
            if handle not in list(self.ospf_dict.keys()):
                self.ospf_dict[handle] = {}
        else:
            obj_type = "handle"

        # make port variables and arguments:
        if obj_type == "port_handle":
            port = handle
            _port = "_".join(map(str, port))
            kwargs["port_handle"] = "/".join(map(str, handle))
        elif obj_type == "handle":
            port = tuple([int(x) for x in handle.split("_")[2:]])
            _port = "_".join(handle.split("_")[2:])
            kwargs["handle"] = handle

        self.ospf_dict[port]["info"] = {}

        if "mode" not in list(kwargs.keys()):
            kwargs["mode"] = "aggregate_stats"

        # use tcl function for wrapper:
        cfg_name = "ospf_info_{0}".format(_port)
        self.ixia.ixia_emulation_ospf_info(**kwargs)
        assert self.ixia.check_return_code() == ""

        self.ixia.puts("$return_code")
        self.ixia.set_var(**{cfg_name: "$return_code"})

        # create list of info objects keys:
        mode = self.ixia.tcl("keylkeys {0} {1}".format(cfg_name, "/".join(map(str, port))))
        _rlist = self.ixia.tcl("keylkeys {0} {1}.{2}".format(cfg_name, "/".join(map(str, port)), mode))
        _rlist = _rlist.split(" ")

        for key_item in _rlist:
            self.ospf_dict[port]["info"][key_item] = self.ixia.tcl("keylget {0} {1}.{2}.{3}".format(cfg_name, "/".join(map(str, port)), mode, key_item))

        return copy.deepcopy(self.ospf_dict[port]['info'])
