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

@file  TrexHLT.py

@summary  Python wrapper to TRex HLT API.
"""

import trex_stl_lib.trex_stl_hltapi as THltApi

from testlib.custom_exceptions import TrexException


class TrexHLTMixin(object):
    """
    @description  TRex HLT API interaction base class
    """

    def __init__(self, *args, **kwargs):
        """
        @brief  Initialize TRexHLTMixin class
        """
        super(TrexHLTMixin, self).__init__(*args, **kwargs)

        self.traffic_dictionary = {}
        self.traffic_item_dictionary = {}

        self.hltapi = THltApi.CTRexHltApi()

    def check_res(self, result):
        if result['status'] == 0:
            self.class_logger.error('Encountered error: {0}'.format(result['log']))
            raise TrexException(result['log'])
        return result

    def check(self):
        """
        @copydoc testlib::tg_template::GenericTG::check()
        """
        pass

    def create(self):
        """
        @copydoc testlib::tg_template::GenericTG::create()
        """
        self.__connect()

    def destroy(self):
        """
        @copydoc testlib::tg_template::GenericTG::destroy()
        """
        self.__disconnect(mode="fast")

    def cleanup(self, mode="fast"):
        """
        @copydoc testlib::tg_template::GenericTG::cleanup()
        """
        self._cleanup_session()
        self.__connect()

    def _cleanup_session(self):
        self.check_res(self.hltapi.cleanup_session(port_handle='all'))

    def sanitize(self):
        """
        @copydoc testlib::tg_template::GenericTG::sanitize()
        """
        pass

    def connect(self):
        """
        @brief  Perform connection to TRex server
        @raise  TrexException:  Connection error
        @return:  None
        """
        self.class_logger.info("Performing connection to TRex server via HLT API")
        self.check_res(self.hltapi.connect(device=self.host, port_list=self.ports, reset=True, break_locks=True))

    __connect = connect

    def disconnect(self, mode="fast"):
        """
        @brief  Perform session cleanup
        @param mode:  Type of mode to execute
        @type  mode:  str
        @raise  TrexException:  Cleanup error
        @return:  None
        """
        self._cleanup_session()

    __disconnect = disconnect

    def iface_config(self, port, *args, **kwargs):
        """
        @brief  Wrapper to TRex HLT API interface_config function
        @param port:  TG port
        @type  port:  int
        @raise  TrexException:  Incorrect mode
        @return:  None

        @note Allowed modes are 'config', 'modify', 'destroy'
        @note TRex HLT API interface_config function is not implemented yet.
              For more info see $TREX_PATH/trex_stl_lib/trex_stl_hltapi.py
        """
        kwargs['port_handle'] = port
        self.check_res(self.hltapi.interface_config(*args, **kwargs))

    def traffic_config(self, *args, **kwargs):
        """
        @brief  Wrapper to TRex HLT API traffic_config function
        @raise  TrexException:  command execution error
        @return:  None
        """
        self.check_res(self.hltapi.traffic_config(**kwargs))

    def traffic_control(self, *args, **kwargs):
        """
        @brief  Wrapper to TRex HLT API traffic_control function
        @raise  TrexException:  command execution error
        @return:  None
        """
        self.check_res(self.hltapi.traffic_control(**kwargs))

    def traffic_stats(self, *args, **kwargs):
        """
        @brief  Wrapper to TRex HLT API  traffic_stats function
        @param port:  TG port
        @type  port:  int
        @raise  TrexException:  command execution error
        @rtype:  list(dict)
        @return:  Port statistics
        """
        if 'port_handle' not in kwargs:
            kwargs.setdefault('port_handle', self.ports)
        # If mode has not been defined, use default value
        kwargs.setdefault("mode", "aggregate")
        res = self.hltapi.traffic_stats(**kwargs)
        self.check_res(res)
        return {x: res[x] for x in kwargs['port_handle']}
