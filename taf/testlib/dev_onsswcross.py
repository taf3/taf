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

@file  dev_onsswcross.py

@summary  Cross Connection device based on ONS switches.
"""

from . import loggers
from . import dev_basecross

from .xmlrpc_proxy import TimeoutServerProxy as xmlrpcProxy


class ONSSwitchCross(dev_basecross.GenericXConnectMixin):
    """
    @description  Cross connection device based on ONS switch.

    Configuration dictionary example:
    @code
    {"id": "ONS_switch_cross_ID", "entry_type": "cross", "instance_type": "onssw",
     "ipaddr": "10.0.5.101", "port": "8081",
     "portmap":[[10, 1, 3], [10, 2, 4], [11, 1, 5], [11, 2, 6]]}
    Where portmap: [[<device ID>, <device port ID>, <self ONS switch port number>], ]
    @endcode
    """

    class_logger = loggers.ClassLogger()

    def __init__(self, config, opts):
        """
        @brief  Initialize ONSSwitchCross class
        @param  config:  Configuration information.
        @type  config:  dict
        @param  opts:  py.test config.option object which contains all py.test cli options.
        @type  opts:  OptionParser
        """
        self.class_logger.info("Init ONS Switch Cross object.")
        self.id = config['id']
        self.type = config['instance_type']
        self.name = config['name'] if "name" in config else "noname"
        self.config = config
        self.opts = opts
        # Connections info:
        self.connections = []
        # Do xconnect on create?
        self.autoconnect = config['autoconnect'] if "autoconnect" in config else True

        self.ipaddr = config['ipaddr']
        self.port = config['port']
        self.xmlproxy = xmlrpcProxy("http://{0}:{1}/RPC2".format(self.ipaddr, self.port))

        self.portmap = config['portmap']
        self.related_conf = config['related_conf'] if "related_conf" in config else []

    def _get_free_vlan(self):
        """
        @brief  Return free vlan id.
        @raise  Exception:  no free vlans
        @rtype:  int
        @return:  Free vlan id
        """
        vt = self.xmlproxy.nb.Vlans.getTable()
        # Actual VLAN ID list
        vids = [i['vlanId'] for i in vt]
        # All possible VLAN IDs
        avids = list(range(1, 4095))
        # Free VLAN IDs
        fvids = set(avids).difference(set(vids))
        if len(fvids) > 0:
            fvid = list(fvids)[0]
            return fvid
        else:
            raise Exception("VLANs number has reached max = 4094.")

    def _add_vlan_tube(self, port1, port2):
        """
        @brief  Create connection between 2 ports with VLANs.
        @param  port1:  Port ID
        @type  port1:  int
        @param  port2:  Port ID
        @type  port2:  int
        """
        vid = self._get_free_vlan()
        vname = "{0}_cross".format(vid)
        self.xmlproxy.nb.Vlans.addRow(vid, vname)
        self.xmlproxy.nb.Ports2Vlans.addRow(port1, vid, "Untagged")
        self.xmlproxy.nb.Ports.set.pvid(port1, vid)
        self.xmlproxy.nb.Ports2Vlans.addRow(port2, vid, "Untagged")
        self.xmlproxy.nb.Ports.set.pvid(port2, vid)

    def _del_vlan_tube(self, port1, port2):
        """
        @brief  Remove VLAN connection betwen 2 ports.
        @param  port1:  Port ID
        @type  port1:  int
        @param  port2:  Port ID
        @type  port2:  int
        """
        self._clear_port_vlan_cfg(port1)
        self._clear_port_vlan_cfg(port2)

    def _clear_port_vlan_cfg(self, port):
        """
        @brief  Remove port from VLAN if such configuration exists.
        @param  port:  Port ID
        @type  port:  int
        """
        rid = self.xmlproxy.nb.Ports.find(port)
        prow = self.xmlproxy.nb.Ports.getRow(rid)
        if prow['pvid'] != 1:
            # Set default pvid and try to remove VLAN
            self.xmlproxy.nb.Ports.set.pvid(port, 1)
            # Try to remove VLAN if it is unused.
            vrid = self.xmlproxy.nb.Vlans.find(prow['pvid'])
            if vrid > 0:
                self.xmlproxy.nb.Vlans.delRow(vrid)

    def _get_self_port(self, dev_id, dev_port):
        """
        @brief  Return self port id by connected device id and port.
        @param  dev_id:  Device ID
        @type  dev_id:  int
        @param  dev_port:  Device's port ID
        @type  dev_port:  int
        @raise  Exception:  no device/port in port map
        @rtype:  int
        @return:  self port id
        """
        self_pid = None
        for pmap in self.portmap:
            if pmap[0] == dev_id and pmap[1] == dev_port:
                self_pid = pmap[2]
                break
        if self_pid is None:
            raise Exception("Cannot find DeviceID:{0} PortID:{1} in port map.".format(dev_id, dev_port))
        return self_pid

    def xconnect(self, conn):
        """
        @brief  Peform single connection.
        @param  conn:  Connection info in format [sw1, port1, sw2, port2]
        @type  conn:  list
        """
        self.class_logger.debug("Create connection: {0}".format(conn))
        port1 = self._get_self_port(conn[0], conn[1])
        port2 = self._get_self_port(conn[2], conn[3])
        self._clear_port_vlan_cfg(port1)
        self._clear_port_vlan_cfg(port2)
        self._add_vlan_tube(port1, port2)

    def xdisconnect(self, conn):
        """
        @brief  Destroy single connection.
        @param  conn:  Connection info in format [sw1, port1, sw2, port2]
        @type  conn:  list
        """
        self.class_logger.debug("Destroy connection: {0}".format(conn))
        port1 = self._get_self_port(conn[0], conn[1])
        port2 = self._get_self_port(conn[2], conn[3])
        self._clear_port_vlan_cfg(port1)
        self._clear_port_vlan_cfg(port2)

    def cross_connect(self, conn_list=None):
        """
        @brief  Peform all connections from conn_list.
        @param  conn_list:  List of connections
        @type  conn_list:  list[list]
        """
        for conn in conn_list:
            self.xconnect(conn=conn)

    def cross_disconnect(self, disconn_list=None):
        """
        @brief  Destroy all connections from conn_list.
        @param  disconn_list:  List of connections
        @type  disconn_list:  list[list]
        """
        for conn in disconn_list:
            self.xdisconnect(conn=conn)


ENTRY_TYPE = "cross"
INSTANCES = {"onssw": ONSSwitchCross}
NAME = "cross"
