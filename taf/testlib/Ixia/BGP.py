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

"""``BGP.py``

``IxNetwork BGP protocol emulation functionality``

Note:
    TCL procedures::

        ::ixia::emulation_bgp_config
        ::ixia::emulation_bgp_control
        ::ixia::emulation_bgp_info
        ::ixia::emulation_bgp_route_config


"""

import copy


class BGP(object):
    """IxNet BGP configuration wrapper.

    """

    def __init__(self, ixia):
        """BGP class initialization.

        Args:
            ixia(IxiaHLTMixin):  Ixia traffic generator

        """
        self.ixia = ixia
        self.bgp_dict = {}

    def configure_neighbour(self, port, *args, **kwargs):
        """Configure BGP neighbors.

        Args:
            port(tuple(int)):  TG port in format tuple(chassisID, cardId, portId)

        Raises:
            AssertionError:  error in executing tcl code

        Returns:
            dict: Neighbour handler names

        Note:
            See description of keyword arguments in ixia_bgp_api.tcl

            Full path: /opt/ixos/lib/hltapi/library/ixia_bgp_api.tcl

        """
        kwargs['port_handle'] = "/".join(map(str, port))
        self.ixia.ixia_emulation_bgp_config(*args, **kwargs)
        assert self.ixia.check_return_code() == ""

        _port = "_".join(map(str, port))
        cfg_name = "bgp_routers_status_{0}".format(_port)
        if port not in self.bgp_dict:
            self.bgp_dict[port] = {}
        self.bgp_dict[port]['cfg_name'] = cfg_name
        if "n_handler" not in self.bgp_dict:
            self.bgp_dict[port]['n_handler'] = {}

        self.ixia.set_var(**{cfg_name: "$return_code"})

        # Create bgp neighbors handles list
        _rlist = self.ixia.tcl("keylget {0} handles".format(cfg_name))
        _rlist = _rlist.split(" ")
        for item in _rlist:
            # item example: 'ixNet::OBJ-/vport:1/protocols/bgp/neighborRange:1'
            pos = item.rfind(":")
            _id = item[pos + 1:]
            _index = _rlist.index(item)
            self.bgp_dict[port]['n_handler'][_id] = "bgp_neighbour_{0}_{1}".format(_port, _id)
            self.ixia.set_var(**{self.bgp_dict[port]['n_handler'][_id]: "[lindex [keylget {0} handles] {1}]".format(cfg_name, _index)})

        return self.bgp_dict[port]['n_handler'].copy()

    def control(self, *args, **kwargs):
        """Turning BGP on/off, enabling statistics.

        Raises:
            AssertionError:  error in executing tcl code

        Returns:
            None

        Note:
            See description of keyword arguments in ixia_bgp_api.tcl

            Full path: /opt/ixos/lib/hltapi/library/ixia_bgp_api.tcl

        """
        if "port" in kwargs:
            kwargs['port_handle'] = "/".join(map(str, kwargs.pop("port")))
        if "router" in kwargs:
            kwargs['handle'] = "$" + kwargs.pop("router")
        self.ixia.ixia_emulation_bgp_control(*args, **kwargs)
        assert self.ixia.check_return_code() == ""

    def emulation_bgp_info(self, *args, **kwargs):
        """Command to retrieve BGP statistics.

        Raises:
            AssertionError:  error in executing tcl code

        Returns:
            dict: BGP statistics

        Note:
            See description of keyword arguments in ixia_bgp_api.tcl

            Full path: /opt/ixos/lib/hltapi/library/ixia_bgp_api.tcl

        """
        if 'neighbour_keys' in kwargs:
            is_neighbour_handler = True
            neighbour_key_list = kwargs.pop('neighbour_keys')

        the_port = None
        for port in args:
            self.bgp_dict[port]["info"] = {}
            self.bgp_dict[port]["bgp_info"] = {}
            if is_neighbour_handler:
                key_list = neighbour_key_list[args.index(port)]
            else:
                key_list = list(self.bgp_dict[port]["n_handler"].keys())

            # create bgp info dictionary:
            for key in key_list:
                n_handle = self.bgp_dict[port]['n_handler'][key]
                self.bgp_dict[port]["info"][n_handle] = {}
                cfg_name = "bgp_info_{0}".format(n_handle.replace("bgp_neighbour_", ""))
                self.ixia.puts("${0}".format(n_handle))
                kwargs["handle"] = "${0}".format(n_handle)

                self.ixia.ixia_emulation_bgp_info(**kwargs)
                assert self.ixia.check_return_code() == ""
                self.ixia.set_var(**{cfg_name: "$return_code"})
                self.bgp_dict[port]["bgp_info"][key] = cfg_name
                self.ixia.puts("$return_code")

                # create list of info objects keys:
                _rlist = self.ixia.tcl("keylkeys {0}".format(cfg_name))
                _rlist = _rlist.split(" ")
                for key_item in _rlist:
                    self.bgp_dict[port]["info"][n_handle][key_item] = self.ixia.tcl("keylget {0} {1}".format(cfg_name, key_item))

            the_port = self.bgp_dict[port]['info']

        if the_port is not None:
            return copy.deepcopy(the_port)

    def configure_route(self, *args, **kwargs):
        """Create a route range associated with neighbor.

        Raises:
            AssertionError:  error in executing tcl code

        Returns:
            dict: Route handler names

        Note:
            See description of keyword arguments in ixia_bgp_api.tcl

            Full path: /opt/ixos/lib/hltapi/library/ixia_bgp_api.tcl

        """
        if "neighbor" in kwargs:
            kwargs['handle'] = "$" + kwargs.pop("neighbor")
        self.ixia.ixia_emulation_bgp_route_config(*args, **kwargs)
        assert self.ixia.check_return_code() == ""

        # Get IxNet port name and neighbor id from handler name
        port = tuple([int(x) for x in kwargs['handle'].split("_")[-4:-1]])
        _port = "_".join(map(str, port))
        neighbor_id = kwargs['handle'].split("_")[-1]

        if "r_handler" not in self.bgp_dict:
            self.bgp_dict[port]['r_handler'] = {}

        # Create bgp routers handles list
        # return_code example:
        # {bgp_routes {::ixNet::OBJ-/vport:1/protocols/bgp/neighborRange:2/routeRange:3
        #              ::ixNet::OBJ-/vport:1/protocols/bgp/neighborRange:2/routeRange:4} }
        # {status 1}
        _rlist = self.ixia.tcl("keylget return_code bgp_routes")
        _rlist = _rlist.split(" ")
        for item in _rlist:
            _id = item.split(":")[-1]
            _index = _rlist.index(item)
            self.bgp_dict[port]['r_handler'][_id] = "bgp_routes_{0}_n{1}_{2}".format(_port, neighbor_id, _id)
            self.ixia.set_var(**{self.bgp_dict[port]['r_handler'][_id]: "[lindex [keylget return_code bgp_routes] {0}]".format(_index)})

        return self.bgp_dict[port]['r_handler'].copy()
