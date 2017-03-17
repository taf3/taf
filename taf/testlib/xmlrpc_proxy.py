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

"""``xmlrpc_proxy.py``

`Implementation of xmlrpclib.ServerProxy class with timeout option`

"""

import sys
import http.client
import gc
import xmlrpc.client

from . import loggers


class CliMarshaller(xmlrpc.client.Marshaller):
    """Convert INT-64 value to XML-RPC chunk.

    Notes:
        No direct calls supposed.

    """

    dispatch = xmlrpc.client.Marshaller.dispatch.copy()
    # Make references to original dump methods.
    dump_int_orig = xmlrpc.client.Marshaller.dump_int
    dump_long_orig = xmlrpc.client.Marshaller.dump_long

    def dump_i8(self, value, write):
        """Override base class method.

        Notes:
            Allow processing INT-64 values in CLI.If passed value could not be converted by original method, try to convert it using 'dump_i8' method.

        """
        write("<value><i8>")
        write(str(value))
        write("</i8></value>\n")

    def dump_int(self, value, write):
        """Override base class method.

        Notes:
            Allow processing INT-64 values in CLI.If passed value could not be converted by original method, try to convert it using 'dump_i8' method.

        """
        try:
            return self.dump_int_orig(value, write)
        except OverflowError:
            return self.dump_i8(value, write)

    def dump_long(self, value, write):
        """Override base class method.

        Notes:
            Allow processing INT-64 values in CLI.If passed value could not be converted by original method, try to convert it using 'dump_i8' method.

        """
        try:
            return self.dump_long_orig(value, write)
        except OverflowError:
            return self.dump_i8(value, write)

    dispatch[int] = dump_int
#    dispatch[long] = dump_long

# TODO: Investidate unexpectd behaviour on Python 3.4
# Replace XML-RPC marshaller with CLI marshaller.
# To allow processing INT-64 values
# xmlrpc.client.Marshaller = CliMarshaller


class TimeoutHTTPConnection(http.client.HTTPConnection):
    """Timeout HTTP connection class definition.

    """

    def __init__(self, host, timeout=10):
        """Initialize TimeoutHTTPConnection class.

        """
        super(TimeoutHTTPConnection, self).__init__(host, timeout=timeout)
        # self.set_debuglevel(99)


class TimeoutTransport(xmlrpc.client.Transport):
    """Timeout Transport class definition.

    """

    def __init__(self, timeout=10, *args, **kwargs):
        """Initialize TimeoutTransport class.

        """
        super(TimeoutTransport, self).__init__(*args, **kwargs)
        self.timeout = timeout

    def make_connection(self, host):
        """Configure connection.

        """
        return TimeoutHTTPConnection(host, self.timeout)


class _Method(xmlrpc.client._Method):  # pylint: disable=protected-access
    """_Method class definition.

    """
    class_logger = loggers.ClassLogger()

    def __call__(self, *args):
        """Configuring calls.

        """
        try:
            call_info = str(gc.get_referents(self))
            subst1 = "ServerProxy for "
            subst2 = ">>"
            proxy = call_info[call_info.find(subst1) + len(subst1):call_info.find(subst2)]
            if len(args) == 0:
                meth = "%s()" % self.__name
            elif len(args) == 1:
                if args[0] == "":
                    meth = "%s('')" % self.__name
                else:
                    meth = "%s(%s)" % (self.__name, ",".join(map(str, args)))
            else:
                meth = "%s%s" % (self.__name, args)
            if "__repr__" not in meth:
                self.class_logger.debug("%s.%s" % (proxy, meth))
        except Exception:
            pass

        return self.__send(self.__name, args)


xmlrpc.client._Method = _Method  # pylint: disable=protected-access


class TimeoutServerProxy(xmlrpc.client.ServerProxy):
    """xmlrpclib.ServerProxy class with additional timeout option

    """

    def __init__(self, uri, timeout=180, *args, **kwargs):
        """Initialize TimeoutServerProxy class.

        """
        kwargs['transport'] = TimeoutTransport(timeout=timeout, use_datetime=kwargs.get('use_datetime', 0))
        xmlrpc.client.ServerProxy.__init__(self, uri, *args, **kwargs)
