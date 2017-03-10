#!/usr/bin/env python

# Copyright (c) 2017, Intel Corporation.
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

"""``pypacker_server.py``

`Remote Pypacker traffic generator with XMLRPC API.`

"""

import os
import sys
import time
import pickle
import signal
import socket
import traceback
import argparse
from contextlib import closing
from collections import defaultdict
from collections.abc import Sequence, Mapping

from twisted.web import xmlrpc, server
from twisted.internet import reactor

from . import loggers
from .dev_pypacker import PypackerTG


class XMLPypackerServer(xmlrpc.XMLRPC):
    """Pypacker server handler.

    """

    class_logger = loggers.ClassLogger()

    @classmethod
    def _get_server_name(cls):
        return cls.__name__

    def xmlrpc_ping(self):
        """Return server name.

        Returns:
            str:  Server name

        """
        return self._get_server_name()

    def xmlrpc_setup(self, config, opts):
        """Create TCMS proxy instance and set necessary attributes.

        Args:
            config(dict):  Configuration information.
            opts(ArgumentParser):  cli options (ArgumentParser( parsed options).

        Returns:
            None

        """
        self.pypacker = PypackerTG(config, pickle.loads(opts.data))
        self.__register_methods()

    def __register_methods(self):
        """Register all Pypacker TG methods.

        """
        def xmlrpc_wrap(func, *args, **kwargs):
            """Register all Pypacker TG methods.

            """
            try:
                return func(*args, **kwargs)
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback_message = traceback.format_exception(exc_type, exc_value, exc_traceback)
                raise xmlrpc.Fault(500, traceback_message)

        def wrap_method(method):
            """Register all Pypacker TG methods.

            """
            return lambda args, kwargs: xmlrpc_wrap(getattr(self.pypacker, method),
                                                    *pickle.loads(args.data), **pickle.loads(kwargs.data))

        def wrap_attibute(attr):
            """Register all Pypacker TG attributes.

            """
            return lambda: getattr(self.pypacker, attr)

        # Get full list of pypacker attrs
        pypacker_attrs = (fn for fn in dir(self.pypacker) if not fn.startswith("_"))
        # Register attributes and methods
        for attr in pypacker_attrs:
            attr_instance = getattr(self.pypacker, attr)
            if isinstance(attr_instance, (str, int, Sequence, Mapping)):
                setattr(self, "xmlrpc_{0}".format(attr), wrap_attibute(attr))
                self.class_logger.debug("Registered Pypacker TG attribute %s", attr)
            elif callable(attr_instance):
                setattr(self, "xmlrpc_{0}".format(attr), wrap_method(attr))
                self.class_logger.debug("Registered Pypacker TG method %s", attr)

        # Need to wrap stop_sniff separately
        # because we have to perform additional procedures with sniffed data before sending.
        self.xmlrpc_stop_sniff = self.stop_sniff

    def stop_sniff(self, args, kwargs):
        """Stops sniffing on specified interfaces and returns captured data.

        Notes:
            Redefine standard method because we need convert packet data string before sending over xml.

        """
        try:
            self.class_logger.debug("Stop sniffing")
            data_orig = self.pypacker.stop_sniff(*args, **kwargs)
            data_str = defaultdict(list)
            for iface in data_orig:
                for packet in data_orig[iface]:
                    # Store original packet timestamps, to restore them on remote side
                    _time = packet.time
                    data_str[iface].append((_time, packet.bin()))
            return pickle.dumps(data_str)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback_message = traceback.format_exception(exc_type, exc_value, exc_traceback)
            message = "Error while stop_sniff:\n{0}".format("".join(traceback_message))
            self.class_logger.error(message)
            raise xmlrpc.Fault(500, message)

    def xmlrpc_tgcmd(self, method, args=None, kwargs=None):
        """Store shutdown server command.

        """
        args = args if args is not None else []
        kwargs = kwargs if kwargs is not None else {}
        str_args = ", ".join(map(str, args))
        str_kwargs = " ".join(("{0}={1}".format(k, v) for k, v in kwargs.items()))
        self.class_logger.info("Command: %s(%s, %s)", method, str_args, str_kwargs)
        try:
            rc = getattr(self.pypacker, method)(*args, **kwargs)
            return rc
        except Exception as err:
            self.class_logger.error(str(err))
            raise xmlrpc.Fault(500, str(err))

    def xmlrpc_shutdown(self, trycount=0, lasttry=0):
        """Store shutdown server command.

        """
        self.class_logger.info("Shutdown command received.")
        self.shutdown()
        return "Shutdown command is added to queue."

    def shutdown(self):
        """Shutdown xmlrpc server.

        """
        pid = os.getpid()
        os.kill(pid, signal.SIGTERM)
        return "Server {0} ready to shut down.".format(self._get_server_name())


def parse_options():
    """Parsing options.

    """
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--port", action="store", default=None,
                        help="Local port to listen. Use random if not set.")
    parser.add_argument("--loglevel", action="store", default="DEBUG",
                        help="Logging level.")
    parser.add_argument("--logdir", action="store", default=os.curdir, dest="logdir",
                        help="Path to dir for log files.")
    parser.add_argument("--logprefix", dest="logprefix", default="main",
                        help="Log files prefix.")
    parser.add_argument("--ppfile", dest="ppfile", default=None,
                        help="Port/PID file path.")
    options = parser.parse_args()
    return options


def main(ppid):
    """Start standalone server.

    """

    def get_local_port():
        """Return free local port.

        """
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(("", 0))
            return s.getsockname()[1]

    def signal_handler(signum, frame):
        """Process termination signals.

        """
        mod_logger.info("Caught a signal=%s", signum)
        time.sleep(3)
        reactor.stop()  # pylint: disable=no-member

    mod_logger = loggers.module_logger(__name__)
    mod_logger.info("Log filename: %s", loggers.LOG_FILENAME)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGABRT, signal_handler)
    signal.signal(signal.SIGILL, signal_handler)

    xmlrpcsrv = XMLPypackerServer(allowNone=True)
    opts = parse_options()
    port = opts.port
    if port is None:
        port = get_local_port()

    # Create pid file with port inside
    # Reason: we need to launch server with random port and need to get this number.
    # We cannot catch server stdout (because if we do so, we break stdout logger)
    # So we use file for this.
    vr_path = opts.ppfile
    if vr_path is None:
        vr_path = os.path.join("/run/taf-reporting-server" if os.path.isdir("/run/taf-reporting-server") else "/var/run/taf-reporting-server",
                               "{0}.pid".format(ppid))

    try:
        with open(vr_path, "w") as f:
            f.write(str(port))
    except OSError as err:
        mod_logger.warning("Failed to create pid/port file %s. Error:\n%s", vr_path, err)
        if not opts.port:
            # Raise exception in case Remote TG should be started with random port.
            # Client cannot determinate Remote TG port without file.
            raise

    reactor.listenTCP(int(port), server.Site(xmlrpcsrv))  # pylint: disable=no-member
    mod_logger.info("Listen on localhost:%s", port)
    reactor.run()  # pylint: disable=no-member


if __name__ == "__main__":

    # Set parent process pid
    ppid = os.getpid()
    # Launch server.
    try:
        os.fork()
        main(ppid)
    except OSError:
        sys.exit(0)
