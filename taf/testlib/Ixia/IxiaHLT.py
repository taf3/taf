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

@file  IxiaHLT.py

@summary  Python wrapper to IxNetworkTcl and HLTAPI Ixia modules.
"""
import time
import os

from tkinter import Tcl, TclError

from ..custom_exceptions import IxiaException
from ..loggers import ClassLogger
from ..loggers import LOG_DIR
from . import ixia_helpers

PROTOCOLS_LIST = ["STP", "BGP", "LACP", "OSPF"]


class IxiaMapper(object):
    """
    @description  Tcl to Python functions mapper
    """

    class_logger = None

    def __init__(self, config, opts):
        """
        @brief  Initialize IxiaMapper class
        @param config:  Configuration information
        @type  config:  dict
        @param opts:  py.test config.option object which contains all py.test cli options
        @type  opts:  OptionParser
        """

        self.class_logger.info("Init Ixia HLTAPI class.")

        self._init_tcl()

        home = os.path.dirname(__file__)

        self.__config = config

        self.tcl("package req Ixia")
        self.tcl("source " + home + "/library/ixia_lacp_api.tcl")
        self.tcl("source " + home + "/library/ixnetwork_lacp_api.tcl")
        self.__register_methods()

        self.id = config['id']
        self.type = config['instance_type']

        self.chassis_ip = config['ip_host']
        self.tcl_server = config['tcl_server']

    def _init_tcl(self):
        """
        @brief  Initialize Tcl interpreter
        @return:  None
        """
        try:
            self.Tcl is None
        except AttributeError:
            self.Tcl = Tcl()

            # Define logger
            def tcl_puts(*args):
                """
                @brief  Enables logging for tcl output
                @return:  None
                """
                if len(args) >= 2:
                    stream = args[0]
                    if stream == "stdout":
                        self.class_logger.debug(" ".join(args[1:]))
                    elif stream == "stderr":
                        self.class_logger.error(" ".join(args[1:]))
                    else:
                        self.class_logger.debug("stream <%s>: %s" % (args[0], " ".join(args[1:])))
                elif len(args) == 1:
                    self.class_logger.debug(args[0])
                else:
                    self.class_logger.error("Called puts without arguments.")
                return None

            self.Tcl.createcommand("tcl_puts", tcl_puts)
            self.class_logger.debug("Insert tcl script to catch puts output.")
            ixia_helpers.tcl_puts_replace(self.Tcl)

            ixia_helpers.ixtclhal_import(self.Tcl)

    def tcl(self, code):
        """
        @brief  Log end execute tcl code
        @param code:  Tcl command
        @type  code:  str
        @rtype:  str
        @return:  Result of execution
        """
        self.class_logger.debug("Exec tcl: {0}".format(code))
        return self.Tcl.eval(code)

    def __register_methods(self):
        """
        @brief  Register all Ixia.tcl methods
        @return:  None
        """

        def wrap(func, method):
            return lambda *args, **kwargs: self.__ixia_tcl_wrapper(method, *args, **kwargs)

        methods = self.tcl("info commands ::ixia::*")
        m_list = methods.split(" ")

        for _m in m_list:
            f_name = _m.replace("::ixia::", "")
            setattr(self,
                    "ixia_" + f_name,
                    wrap(self.__ixia_tcl_wrapper, f_name))

    def __ixia_tcl_wrapper(self, method, *args, **kwargs):
        """
        @brief  Execute tcl ::ixia::method
        @param method:  Method name
        @type  method:  str
        @rtype:  str
        @return:  Result of execution
        """
        _tcl_code = "set return_code [::ixia::" + method
        if args:
            _tcl_code += " " + " ".join(args)
        for name, value in list(kwargs.items()):
            if isinstance(value, bool):
                if value:
                    _tcl_code += " -" + name
            else:
                _tcl_code += " -" + name + " " + str(value)
        _tcl_code += " ]"
        return self.tcl(_tcl_code)

    def check_return_code(self):
        """
        @brief  Check if ERROR is in return_code
        @rtype:  str
        @return:  Error message or empty string
        """
        return self.tcl('if {[keylget return_code status] != $::SUCCESS} ' +
                        '{return "Last tcl operation FAIL -  [keylget return_code log]"}')

    def set_var(self, **kwargs):
        """
        @brief  Set variable in tcl namespace
        @return:  None
        """
        for name, value in list(kwargs.items()):
            self.tcl("set {0} {1}".format(name, value))

    def get_var(self, var_name):
        """
        @brief  Get variable value string representation from tcl namespace
        @param var_name:  Variable name
        @type  var_name:  str
        @rtype:  str
        @return:  Value of variable
        """
        return self.tcl("return ${0}".format(var_name))

    def puts(self, expr):
        """
        @brief  Call tcl puts method
        @param expr:  Expression
        @type  expr:  str
        @return:  None
        """
        self.tcl("puts {0}".format(expr))


class IxiaHLTMixin(IxiaMapper):
    """
    @description  IxNetwork interaction base class
    """

    def __init__(self, *args, **kwargs):
        """
        @brief  Initialize IxiaHLTMixin class
        """
        super(IxiaHLTMixin, self).__init__(*args, **kwargs)
        self.__init_protos()

        if "config" in kwargs:
            self.__config = kwargs['config']
        else:
            self.__config = args[0]
        if "opts" in kwargs:
            self.__opts = kwargs['opts']
        else:
            self.__opts = args[1]
        self.qt = None
        self.ixncfg_file = None
        self.traffic_dictionary = {}
        self.traffic_item_dictionary = {}
        self.protocol_interface_handles = {}
        self.last_traffic_item = None
        self.last_protocol_interface = None

    def __init_protos(self):
        """
        @brief  Load protocol modules
        @return:  None
        """
        for proto in PROTOCOLS_LIST:
            _import = __import__("testlib.Ixia.%s" % (proto, ), fromlist=["testlib.Ixia"])
            setattr(self, proto, getattr(_import, proto)(self))

    def check(self):
        """
        @copydoc testlib::tg_template::GenericTG::check()
        """
        pass

    def create(self):
        """
        @copydoc testlib::tg_template::GenericTG::create()
        """
        # Perform connection.
        self.__connect()
        # Load ixncfg file if one is set.
        if "ixncfg" in self.__config:
            self.load_ixncfg(self.__config['ixncfg'])
        else:
            # Create list of quick tests.
            self.qt = QuickTests(self.tcl)

    def destroy(self):
        """
        @copydoc testlib::tg_template::GenericTG::destroy()
        """
        if not self.__opts.leave_on and not self.__opts.get_only:
            self.__disconnect(mode="fast")

    def cleanup(self, mode="fast"):
        """
        @copydoc testlib::tg_template::GenericTG::cleanup()
        """
        self.tcl("ixNet exec newConfig")
        self.__connect()

    def sanitize(self):
        """
        @copydoc testlib::tg_template::GenericTG::sanitize()
        """
        pass

    def set_port_list(self, port_list=None):
        """
        @brief  Set port_list variable in tcl namespace
        @param port_list:  List of TG ports
        @type  port_list:  list
        @return:  None
        """
        port_list = port_list or self.ports
        # Convert python ixia ports list to tcl representation for Ixia module
        _pl = " ".join(["{1}/{2}".format(*x) for x in port_list])
        _pl = "[list {0}]".format(_pl)
        self.set_var(port_list=_pl)

    def connect(self):
        """
        @brief  Perform connection to IxTcl and IxTclNetwork servers
        @raise  IxiaException:  Connection error
        @return:  None
        """
        self.class_logger.info("Performing connection to IxTcl and IxTclNetwork servers.")
        _t = time.time()
        self.set_var(chassis_ip=self.chassis_ip,
                     ixnet_tcl_server=self.tcl_server)
        self.set_port_list()
        self.ixia_connect(reset=True, device="$chassis_ip", port_list="$port_list",
                          # tcl_server="$chassis_ip",
                          ixnetwork_tcl_server="$ixnet_tcl_server", guard_rail="statistics")
        rc = self.check_return_code()
        if rc:
            raise IxiaException(rc)
        self.set_var(connect_status="$return_code")
        self.class_logger.debug("Connection time: {0:10.4f}".format(time.time() - _t))
        self.tcl("puts $connect_status")
        _pl = self.tcl("lsearch [keylkeys connect_status] port_handle")
        if "-" not in _pl:
            self.set_var(port_array="[keylget connect_status port_handle.$chassis_ip]")
        else:
            self.set_var(port_array="[list ]")
        self.tcl("puts $port_array")
        # self.tcl("[keylget port_array [lindex $port_list 0]]")

    __connect = connect

    def disconnect(self, mode="fast"):
        """
        @brief  Perform session cleanup
        @param mode:  Type of mode to execute
        @type  mode:  str
        @raise  IxiaException:  Cleanup error
        @return:  None
        """
        _t = time.time()
        _params = {}
        # port_handle_list is removed because it causes an exception. Confirmed with Ixia support.
        # rc = self.ixia_get_port_list_from_connect("$connect_status", "$chassis_ip", "$port_list")
        # self.class_logger.info("port_handle_list: {0}".format(rc))
        # _params = {'port_handle_list': "$return_code"}
        if mode == "full":
            _params['reset'] = True
        self.set_var(**_params)
        # self.ixia_cleanup_session(port_handle="$port_handle_list")
        self.ixia_cleanup_session()
        rc = self.check_return_code()
        if rc:
            raise IxiaException(rc)
        self.class_logger.debug("Close connection time: {0:10.4f}".format(time.time() - _t))

    __disconnect = disconnect

    def load_ixncfg(self, ixncfg_file):
        """
        @brief  Load IxNetwork configuration
        @param ixncfg_file:  Path to ixia configuration file
        @type  ixncfg_file:  str
        @raise  IxiaException:  Load error
        @return:  None
        """
        _ixncfg_file = os.path.normpath(os.path.realpath(os.path.expandvars(os.path.expanduser(ixncfg_file))))
        if not os.path.exists(_ixncfg_file):
            message = "Cannot find IxNetworkconfiguration file: {0}".format(_ixncfg_file)
            self.class_logger.error(message)
            raise IxiaException(message)
        rc = self.tcl(("if {[catch {ixNet exec loadConfig [ixNet readFrom %(ixncfg)s]} err]} {" +
                       "    keylset returnList status $::FAILURE;" +
                       "    keylset returnList log \"Failed to load IxNetwork configuration from '%(ixncfg)s'. $err\";" +
                       "    return $returnList}") % {'ixncfg': _ixncfg_file})
        if rc != "":
            message = "Load IxNetwork configuration is failed with the following message:\n{0}".format(rc)
            self.class_logger.error(message)
            raise IxiaException(message)
        # TODO: Replace timesleep with check_config_load_status method
        # Wait until config fully loaded.
        time.sleep(5)
        # Update port_list if one
        if self.ports:
            self.iface_update()
        # Store ixncfg file name.
        self.ixncfg_file = ixncfg_file
        # Create list of quick tests.
        self.qt = QuickTests(self.tcl)

    def iface_update(self):
        """
        @brief  Dynamically update list of assigned ports
        @return:  None
        """
        self.class_logger.info("Updating ports ownership.")
        self.tcl("ixNet setMultiAttribute [ixNet getRoot]/availableHardware -offChassisHwM {}; ixNet commit;")
        self.tcl("set chassis [ixNet add [ixNet getRoot]/availableHardware \"chassis\"];")
        self.tcl("ixNet setMultiAttribute $chassis -hostname $chassis_ip  -cableLength 0 -masterChassis {} -sequenceId 1; ixNet commit;")
        self.tcl("foreach port $port_list vport [ixNet getList [ixNet getRoot] vport] " +
                 "{regexp {(\d+)/(\d+)} $port - slot pn;" +
                 "ixNet setA $vport -connectedTo $chassis/card:$slot/port:$pn };" +
                 "ixNet commit")

    def iface_config(self, port, *args, **kwargs):
        """
        @brief  Wrapper to Ixia ::ixia::interface_config function
        @param port:  TG port in format tuple(chassisID, cardId, portId)
        @type  port:  tuple(int)
        @raise  AssertionError:  error in executing tcl code
        @return:  None
        """

        # kwargs['port_handle'] = "{0}/{1}/{2}".format(*port)
        # self._IxiaMapper__ixia_tcl_wrapper("interface_config", *args, **kwargs)
        # assert self.check_return_code() == ""

        kwargs['port_handle'] = "{0}/{1}/{2}".format(*port)
        cfg_name = "iface_config_info"
        self._IxiaMapper__ixia_tcl_wrapper("interface_config", *args, **kwargs)
        self.set_var(**{cfg_name: "$return_code"})
        try:
            _iface_handle = self.tcl("keylget {0} {1}".format(cfg_name, "interface_handle"))

            # extracting vport:x port number below
            self.last_protocol_interface = _iface_handle
            l_index = _iface_handle.find("/")
            r_index = _iface_handle.find("/", l_index + 1)
            _vport = _iface_handle[l_index + 1:r_index]

            if _vport not in self.protocol_interface_handles:
                self.protocol_interface_handles[_vport] = []
                self.protocol_interface_handles[_vport].append(_iface_handle)
            else:
                self.protocol_interface_handles[_vport].append(_iface_handle)
        except TclError:
            pass
        assert self.check_return_code() == ""

    def traffic_config(self, *args, **kwargs):
        """
        @brief  Wrapper to Ixia ::ixia::traffic_config function
        @raise  AssertionError:  error in executing tcl code
        @return:  None
        """
        # before modifications:
        # self.ixia_traffic_config(**kwargs)
        # assert self.check_return_code() == ""

        cfg_name = "traffic_config_info"
        self.ixia_traffic_config(**kwargs)
        assert self.check_return_code() == ""
        self.set_var(**{cfg_name: "$return_code"})
        _slist = self.tcl("keylkeys {0}".format(cfg_name))
        _slist = _slist.split(" ")
        try:
            _stream_id = self.tcl("keylget {0} {1}".format(cfg_name, "stream_id"))
            self.traffic_item_dictionary[_stream_id] = {}
            self.last_traffic_item = _stream_id
        except TclError:
            pass

        def copyFromTclList(tcl_list, dict_ref, tcl_command_string_args=None, level=0):
            tcl_command_base = tcl_command_string_args
            for key_item in tcl_list:
                if "log" in key_item:
                    continue
                dict_ref[key_item] = {}
                if level == 0:
                    tcl_command_string_args = "{0} {1}".format(cfg_name, key_item)
                else:
                    tcl_command_string_args = tcl_command_base + ".{0}".format(key_item)

                try:
                    newList = self.tcl("keylkeys {0}".format(tcl_command_string_args))
                    newList = newList.split(" ")
                    copyFromTclList(newList, dict_ref[key_item], tcl_command_string_args, level + 1)
                except TclError:
                    _val = self.tcl("keylget {0}".format(tcl_command_string_args))
                    dict_ref[key_item] = _val
                    index = tcl_command_string_args.rfind(".")
                    tcl_command_string_args = tcl_command_string_args[:index]

        copyFromTclList(_slist, self.traffic_item_dictionary[_stream_id])

    def traffic_control(self, *args, **kwargs):
        """
        @brief  Wrapper to Ixia ::ixia::traffic_control function
        @raise  AssertionError:  error in executing tcl code
        @return:  None
        """
        self.ixia_traffic_control(**kwargs)
        assert self.check_return_code() == ""

    def traffic_stats(self, port, *args, **kwargs):
        """
        @brief  Wrapper to Ixia ::ixia::traffic_stats function
        @param port:  TG port in format tuple(chassisID, cardId, portId)
        @type  port:  tuple(int)
        @raise  AssertionError:  error in executing tcl code
        @return:  None
        """
        port_name = "%s/%s/%s" % port
        # Set empty 'port' item in case it has not been already defined
        self.traffic_dictionary.setdefault(port, {})
        _port = "_".join(map(str, port))
        cfg_name = "traffic_info_{0}".format(_port)
        kwargs['port_handle'] = port_name
        # If mode has not been defined, use default value
        kwargs.setdefault("mode", "aggregate")
        self.ixia_traffic_stats(**kwargs)
        assert self.check_return_code() == ""
        self.set_var(**{cfg_name: "$return_code"})
        self.traffic_dictionary[port]["traffic_info_name"] = cfg_name
        self.traffic_dictionary[port]['stats'] = {}
        try:
            _slist = self.tcl("keylkeys {0} {1}".format(cfg_name, port_name))
            _slist = _slist.split(" ")
            for s_key_item in _slist:
                self.traffic_dictionary[port]['stats'][s_key_item] = {}
                _klist = self.tcl("keylkeys {0} {1}.{2}".format(cfg_name, port_name, s_key_item))
                _klist = _klist.split(" ")
                for k_key_item in _klist:
                    try:
                        self.traffic_dictionary[port]['stats'][s_key_item][k_key_item] = {}
                        _vlist = self.tcl("keylkeys {0} {1}.{2}.{3}".format(cfg_name, port_name, s_key_item, k_key_item))
                        _vlist = _vlist.split(" ")
                        for v_key_item in _vlist:
                            try:
                                self.traffic_dictionary[port]['stats'][s_key_item][k_key_item][v_key_item] = {}
                                _v1list = self.tcl("keylkeys {0} {1}.{2}.{3}.{4}".format(cfg_name, port_name, s_key_item, k_key_item, v_key_item))
                                _v1list = _v1list.split(" ")
                                for v1_key_item in _v1list:
                                    self.traffic_dictionary[port]['stats'][s_key_item][k_key_item][v_key_item][v1_key_item] = \
                                        self.tcl("keylget {0} {1}.{2}.{3}.{4}.{5}".format(cfg_name, port_name, s_key_item, k_key_item, v_key_item, v1_key_item))
                            except TclError:
                                self.traffic_dictionary[port]['stats'][s_key_item][k_key_item][v_key_item] = \
                                    self.tcl("keylget {0} {1}.{2}.{3}.{4}".format(cfg_name, port_name, s_key_item, k_key_item, v_key_item))
                    except TclError:
                        self.traffic_dictionary[port]['stats'][s_key_item][k_key_item] = \
                            self.tcl("keylget {0} {1}.{2}.{3}".format(cfg_name, port_name, s_key_item, k_key_item))
        except TclError:
            pass

    def traffic_stats_traffic_items(self, ti, *args, **kwargs):
        """
        @brief  Wrapper to Ixia ::ixia::traffic_stats function
        @param ti:  Traffic item
        @type  ti:  str
        @raise  AssertionError:  error in executing tcl code
        @return:  None
        @note:  This version is for traffic item stats
        """
        ti_name = "%s" % ti
        self.traffic_dictionary.setdefault(ti_name, {})
        cfg_name = "traffic_item"
        kwargs.setdefault("mode", "traffic_item")
        self.ixia_traffic_stats(**kwargs)
        assert self.check_return_code() == ""
        self.set_var(**{cfg_name: "$return_code"})
        _tiList = self.tcl("keylkeys {0} {1}".format(cfg_name, "traffic_item"))
        if ti_name in _tiList:
            self.traffic_dictionary[ti_name]['stats'] = {}
        _diList = self.tcl("keylkeys {0} {1}.{2}".format(cfg_name, "traffic_item", ti_name))  # traffic direction list
        _diList = _diList.split(" ")

        for di_key_item in _diList:
            self.traffic_dictionary[ti_name]['stats'][di_key_item] = {}
            # statistics keys for direction
            _sList = self.tcl("keylkeys {0} {1}.{2}.{3}".format(cfg_name, "traffic_item", ti_name, di_key_item))
            _sList = _sList.split(" ")
            for s_key_item in _sList:
                _value = self.tcl("keylget {0} {1}.{2}.{3}.{4}".format(cfg_name, "traffic_item", ti_name, di_key_item, s_key_item))  # get value
                self.traffic_dictionary[ti_name]['stats'][di_key_item][s_key_item] = _value

    def vlan_traffic_stats(self, ports):
        """
        @brief  Gets per-port stats and returns per-vlan flow stats
        Params: ports = dict({id:(chassis, card, port)})
        Returns: dict({ flow_name:{ vlan_id: , ti_name: , port_rx|tx: , pgid_value_rx|tx: , all other stats... }  })
        """
        # Generate stats dictionary for Ixia ports
        for key, port in ports.items():
            self.traffic_stats(port, mode='all', return_method='keyed_list')
        # Loop around per-port stats dictionary
        # to generate per-vlan flow data combined of stats of tx and rx ports
        # flow_data_combined - dictionary of combined rx and tx statistics for the same flow_name
        # flow_data_combined = { flow_name:{ vlan_id: , ti_name: , port_rx|tx: , all other stats rx|tx... }  }
        flow_data_combined = {}
        for port, port_data in self.traffic_dictionary.items():
            # If ...'flow' statistics exist for a port, parse them
            try:
                for flow_item, flow_item_data in port_data['stats']['flow'].items():
                    # Parse rx and tx stats for a port/flow
                    for direction, direction_data in flow_item_data.items():
                        try:
                            # 'flow_name' parameter exists only in flows which have vlan_id set,
                            # so it can be usd to identify vlan-related statistics
                            # 'flow_name' consists of space-separated: destination port ID, traffic item name, vlan ID.
                            #     These parameters are extracted from flow_name as separate variables.
                            # Data from tx and rx flows are joined in a single dictionary in flow_data_combined.
                            #     Keys are appended with flow direction and stored in direction_data_modified
                            flow_name = direction_data['flow_name']
                            flow_dst_port, flow_ti_name, flow_vlan_id = flow_name.split(' ')
                            flow_dst_port = '({})'.format(flow_dst_port.replace('/', ','))
                            local_port = str(port)
                            # Append direction (rx/tx) suffix to key names and write keys:values in direction_data_modified dictionary
                            direction_data_modified = {'_'.join([key, direction]): val for key, val
                                                       in direction_data.items()
                                                       if key not in {'flow_name', }}
                            # ... except flow name - this parameter is identical for both directions
                            direction_data_modified['flow_name'] = flow_name
                            # Store appropriate port names
                            if direction in {'rx', 'tx'}:
                                direction_data_modified['port_{}'.format(direction)] = local_port
                            # Store the the flow/direction data in the combined dictionary
                            flow_data_combined.setdefault(flow_name, {}).update(
                                direction_data_modified,
                                vlan_id=flow_vlan_id,
                                ti_name=flow_ti_name,
                                dst_port=flow_dst_port)
                        except(KeyError, IndexError):
                            pass
            except(KeyError, IndexError):
                pass
        return flow_data_combined

    def copy_remote_file(self, remote_path, local_path):
        """
        @brief  Copy file from IxNetwork host to local host
        @param remote_path:  Remote path to file
        @type  remote_path:  str
        @param local_path:  Local path to file
        @type  local_path:  str
        @rtype:  str
        @return:  Result of execution
        """
        remote_path = remote_path.replace("\\", "\\\\")
        return self.tcl("ixNet exec copyFile [ixNet readFrom \"{0}\" -ixNetRelative] [ixNet writeTo {1}]".
                        format(remote_path, local_path))

    def copy_local_file(self, local_path, remote_path):
        """
        @brief  Copy file from local host to IxNetwork host
        @param local_path:  Local path to file
        @type  local_path:  str
        @param remote_path:  Remote path to file
        @type  remote_path:  str
        @rtype:  str
        @return:  Result of execution
        """
        return self.tcl("ixNet exec copyFile [ixNet readFrom \"{0}\"] [ixNet writeTo {1} -ixNetRelative]".
                        format(local_path, remote_path))


class QuickTests(object):
    """
    @description  Class to represent IxNetwork QuickTests
    """

    class_logger = ClassLogger()

    # Get copy file methods.
    copy_remote_file = IxiaHLTMixin.__dict__['copy_remote_file']
    copy_local_file = IxiaHLTMixin.__dict__['copy_local_file']

    def __init__(self, tcl):
        """
        @brief  Initialize QuickTests class
        @param tcl: Tcl interpreter
        @type  tcl:  Tkinter.Tcl
        """
        self.tcl = tcl
        self.tc_list = []
        self.load_tclist()

    def load_tclist(self):
        """
        @brief  Loading list of QuickTests
        @return:  None
        """
        def store_tc(qt):
            """
            @brief  Store quick test in tc_list
            @return:  None
            """
            qt_name, qt_id = qt.split(":")
            self.tc_list.append((qt_name, qt_id))

        _qtlist = self.tcl("ixNet getAttr [ixNet getRoot]/quickTest -testIds")
        if _qtlist:
            _qtlist = _qtlist.split(" ")
            _qtlist = [x.lstrip("::ixNet::OBJ-/quickTest/") for x in _qtlist]
        else:
            _qtlist = []
        # QT list is read. Cleanup previous one and store new list.
        self.tc_list = []
        if _qtlist:
            list(map(store_tc, _qtlist))

    def start(self, qt_name, qt_id):
        """
        @brief  Start QuickTest without waiting for result
        @param qt_name:  QuickTest name
        @type  qt_name:  str
        @param qt_id:  QuickTest id
        @type  qt_id:  int
        @rtype:  str
        @return:  Result of execution
        """
        self.class_logger.info("Launching QT (w/o result waiting): {0}:{1}".format(qt_name, qt_id))
        rc = self.tcl("ixNet exec start [ixNet getRoot]/quickTest/{0}:{1}".format(qt_name, qt_id))
        return rc

    def wait(self, qt_name, qt_id, tc_name=None):
        """
        @brief  Wait for QuickTest to complete
        @param qt_name:  QuickTest name
        @type  qt_name:  str
        @param qt_id:  QuickTest id
        @type  qt_id:  int
        @param tc_name:  test case name
        @type  tc_name:  str
        @rtype:  dict
        @return:  Result of execution
        """
        rc = self.tcl("ixNet exec waitForTest [ixNet getRoot]/quickTest/{0}:{1}".format(qt_name, qt_id))
        self.class_logger.debug("QT Wait return: {0}".format(rc))
        return self.analyze_result(qt_name, qt_id, tc_name)

    def run(self, qt_name, qt_id, tc_name=None):
        """
        @brief  Run QuickTest until completion
        @param qt_name:  QuickTest name
        @type qt_name:  str
        @param qt_id:  QuickTest id
        @type  qt_id:  int
        @param tc_name:  test case name
        @type  tc_name:  str
        @rtype:  dict
        @return:  Result of execution
        """
        self.class_logger.info("Launching QT: {0}:{1}".format(qt_name, qt_id))
        rc = self.tcl("ixNet exec run [ixNet getRoot]/quickTest/{0}:{1}".format(qt_name, qt_id))
        self.class_logger.debug("QT Run return: {0}".format(rc))
        return self.analyze_result(qt_name, qt_id, tc_name)

    def report(self, pdf=False):
        """
        @brief  Enable/Disable report options
        @param  pdf:  Enable/Disable PDF report
        @type  pdf:  bool
        @return:  None
        """
        self.tcl("ixNet setAttribute [ixNet getRoot]/testConfiguration -enableGenerateReportAfterRun {0}".format(pdf))

    def analyze_result(self, qt_name, qt_id, tc_name):
        """
        @brief  Analyze QuickTest run status
        @param qt_name:  QuickTest name
        @type  qt_name:  str
        @param qt_id:  QuickTest id
        @type  qt_id:  int
        @param tc_name:  test case name
        @type  tc_name:  str
        @raise  AssertionError:  QuickTest is failed/Report is not generated
        @rtype:  dict
        @return:  Result of execution
        """
        def get_attr(attr):
            return self.tcl("ixNet getAttr [ixNet getRoot]/quickTest/{0}:{1}/results -{2}".format(qt_name, qt_id, attr))

        attrs = ["status", "progress", "result", "resultPath", "startTime", "duration"]
        result = dict([k, None] for k in attrs)

        if tc_name is None and LOG_DIR:
            tc_name = "{0}_{1}".format(qt_name, qt_id)

        for attr in result:
            result[attr] = get_attr(attr)

        if result['resultPath'] and LOG_DIR:
            self.download_logs(result['resultPath'], tc_name)

        errmsg = result['status']
        if result['resultPath']:
            errmsg += " Result path: " + result['resultPath']
        else:
            errmsg += " Report was not created."
        assert result['resultPath'] and result['result'] != "fail", errmsg

        self.class_logger.debug("QT status: {0}".format(result))
        return result

    def download_logs(self, r_path, l_path):
        """
        @brief  Download QuickTest run logs
        @param r_path:  Path to report
        @type  r_path:  str
        @param l_path:  Name of logs directory to be written
        @type  l_path:  str
        @raise  OSError:  Error on folder creation
        @return:  None
        """
        file_list = ["AgregateResults.csv",
                     "AgregateResults.csv.idx",
                     "info.csv",
                     "iteration.csv",
                     "iteration.csv.idx",
                     "PortMap.csv",
                     "results.csv",
                     "results.csvdx,",
                     "logFile.txt",
                     "ixNetwork.xmd",
                     "ITSnapshots\\AggSource.csv",
                     "ITSnapshots\\AggSource.csv.idx",
                     "ITSnapshots\\Flow View.csv",
                     "ITSnapshots\\Flow View.csv.columns",
                     "ITSnapshots\\Flow View.csv.kyes",
                     "ITSnapshots\\Flow View.csv.txlabels",
                     "AesResults\\PassFailStats.csv",
                     "AesResults\\PassFailStats.xml",
                     ]

        # Set and create folder for ixnet logs.
        ixn_log_dir = os.path.join(LOG_DIR, l_path)
        try:
            os.mkdir(ixn_log_dir)
        except OSError as err:
            # Skip "file exist error"
            if err.errno == 17:
                pass
            else:
                raise

        for fn in file_list:
            try:
                rc = self.copy_remote_file("{0}\\{1}".format(r_path, fn),
                                           "{0}/{1}".format(ixn_log_dir, fn.replace("\\", "/")))
                if "::ixNet::OK" in rc:
                    self.class_logger.debug("IxNetwork log file {0} copied.".format(fn))
                else:
                    self.class_logger.warning("Cannot copy log file {0}: {1}".format(fn, rc))
            except TclError:
                pass
