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

"""``TrexHLT.py``

`Python wrapper to TRex HLT API`

"""

import trex_stl_lib.trex_stl_hltapi as THltApi

from testlib.custom_exceptions import TrexException


class TrexHLTMixin(object):
    """TRex HLT API interaction base class.

    """

    def __init__(self, *args, **kwargs):
        """Initialize TRexHLTMixin class.

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
        """Check if TG object is alive and ready for processing.

        Returns:
            None or raise and exception.

        """
        pass

    def create(self):
        """Perform all necessary procedures to initialize TG device and prepare it for interaction.

        Returns:
            None or raise and exception.

        Notes:
            Method has to check --get_only option.

            Set of steps to configure TG device is related to particular TG type.

        """
        self.__connect()

    def destroy(self):
        """Perform all necessary procedures to uninitialize TG device.

        Returns:
            None or raise and exception.

        Notes:
            Method has to check --get_only and --leave_on options.
            Set of steps to unconfigure TG device is related to particular TG type.
            Method has to clear all connections and stop all captures and data streams.

        """
        self.__disconnect(mode="fast")

    def cleanup(self, mode="fast"):
        """This method should do Ixia ports cleanup (remove streams etc).

        Args:
            mode(str): "fast" or "complete". If mode == "fast", method does not clear streams on the port, but stops them (str).

        Returns:
            None or raise and exception.

        """
        self._cleanup_session()
        self.__connect()

    def _cleanup_session(self):
        self.check_res(self.hltapi.cleanup_session(port_handle='all'))

    def sanitize(self):
        """This method has to clear all stuff which can cause device inconsistent state after exit or unexpected exception.

        Notes:
            E.g. clear connections, stop threads. This method is called from pytest.softexit

        """
        pass

    def connect(self):
        """Perform connection to TRex server.

        Raises:
            TrexException:  Connection error

        Returns:
            None

        """
        self.class_logger.info("Performing connection to TRex server via HLT API")
        self.check_res(self.hltapi.connect(device=self.host, port_list=self.ports, reset=True, break_locks=True))

    __connect = connect

    def disconnect(self, mode="fast"):
        """Perform session cleanup.

        Args:
            mode(str):  Type of mode to execute

        Raises:
            TrexException:  Cleanup error

        Returns:
            None

        """
        self._cleanup_session()

    __disconnect = disconnect

    def iface_config(self, port, *args, **kwargs):
        """Wrapper to TRex HLT API interface_config function.

        Args:
            port(int):  TG port

        Raises:
            TrexException:  Incorrect mode

        Returns:
            None

        Notes:
            Allowed modes are 'config', 'modify', 'destroy'

        Notes:
            TRex HLT API interface_config function is not implemented yet.

            For more info see $TREX_PATH/trex_stl_lib/trex_stl_hltapi.py

        """
        kwargs['port_handle'] = port
        self.check_res(self.hltapi.interface_config(*args, **kwargs))

    def traffic_config(self, *args, **kwargs):
        """Wrapper to TRex HLT API traffic_config function.

        Raises:
            TrexException:  command execution error

        Returns:
            None

        """
        self.check_res(self.hltapi.traffic_config(**kwargs))

    def traffic_control(self, *args, **kwargs):
        """Wrapper to TRex HLT API traffic_control function.

        Raises:
            TrexException:  command execution error

        Returns:
            None

        """
        self.check_res(self.hltapi.traffic_control(**kwargs))

    def traffic_stats(self, *args, **kwargs):
        """Wrapper to TRex HLT API  traffic_stats function.

        Args:
            port(int):  TG port

        Raises:
            TrexException:  command execution error

        Returns:
            list(dict): Port statistics

        """
        if 'port_handle' not in kwargs:
            kwargs.setdefault('port_handle', self.ports)
        # If mode has not been defined, use default value
        kwargs.setdefault("mode", "aggregate")
        res = self.hltapi.traffic_stats(**kwargs)
        self.check_res(res)
        return {x: res[x] for x in kwargs['port_handle']}
