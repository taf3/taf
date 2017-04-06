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

"""``reporting_server.py``

`Standalone loggingserver for pytest plugin`

"""

import os
import signal
import socket
import sys
import time
import argparse
import contextlib
import traceback
from functools import wraps
from threading import RLock
from threading import Thread
from collections import OrderedDict

from twisted.web import xmlrpc, server
from twisted.internet import reactor

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../taf')))
from testlib import loggers


MODULES = {}
FIRST_ITEM_IN_QUEUE = 0


def imp_plugins(dest):
    """Import all py modules from <dest> subfolder.

    """
    _list = []
    try:
        _list = [os.path.splitext(_m)[0] for _m in os.listdir(os.path.join(os.path.dirname(__file__), dest))
                 if not _m.startswith("_") and _m.endswith(".py")]
    except OSError:
        pass
    else:
        for _m in _list:
            _module = "{0}.{1}".format(dest, _m)
            MODULES[_module] = __import__(_module)


def log_exception(msg, exc_type=(Exception,)):
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except exc_type as err:
                log_message = "Function '{0}' {1}. Error: {2}".format(func.__name__, msg, err)
                self.class_logger.error(log_message)
        return wrapper
    return decorator


class CommandCollector(object):
    """Thread safe collector for server command queue.

    """

    class_logger = loggers.ClassLogger()

    def __init__(self):
        """Initialize CommandCollector class.

        """
        self._lock = RLock()
        self.queue = []

    @log_exception(msg="failed to add command")
    def add(self, cmd):
        """Add command to collector.

        Args:
            cmd(dict):  Command

        Returns:
            bool:  Status

        Examples::

            command = {'client': "client-name-with-pid-1111", 'build': 'cool-software-v.0.0.0.1-pre-alfa', 'close': True, 'duration': 15}
            command_collector.add(command)

        """
        with self._lock:
            self.queue.append(cmd)
            self.class_logger.info("Command added successfully. CMD keys: %s", list(cmd.keys()))
            return True

    def pop(self):
        """Pop the first item.

        Returns:
            dict: command

        Note:
            See also get() method.

        """
        with self._lock:
            try:
                return self.queue.pop(FIRST_ITEM_IN_QUEUE)
            except IndexError:
                return None

    def get(self):
        """Same as pop but does not remove item.

        Returns:
            dict: command

        Note:
            See pop() method description.

        """
        with self._lock:
            try:
                return self.queue[FIRST_ITEM_IN_QUEUE]
            except IndexError:
                return None

    def drop(self, index):
        """Remove item by index.

        Args:
            index(int):  Index of item in queue list.

        Returns:
            dict|str: Command or Error message.

        """
        with self._lock:
            try:
                return self.queue.pop(index)
            except IndexError:
                message = "ERROR: No item with such index: {0}".format(index)
                self.class_logger.error(message)
                return message
            except Exception as err:
                message = "ERROR: {0}".format(err)
                self.class_logger.error(message)
                return message

    def len(self):
        """Return command queue length.

        Returns:
            int: command queue length.

        """
        with self._lock:
            return len(self.queue)

    def list(self):
        """Return list of all items.

        Returns:
            list[dict]: All commands list.

        """
        with self._lock:
            return self.queue


class ClientCollector(object):
    """Thread safe object for collecting clients dictionaries.

    """

    # Allowed client statuses.
    STATUSES = ["Active", "Inactive"]

    class_logger = loggers.ClassLogger()

    def __init__(self):
        """Initialize ClientCollector class.

        """
        self._lock = RLock()
        self.clients = {}

    def update(self, client, status):
        """Update status of the client.

        Args:
            client(tuple(str)): Tuple of ClientID and build.
            status(str): Available values are listed in STATUSES constant.

        Raises:
            ValueError:  status not in self.STATUSES

        Returns:
            None

        Examples::

            client_id = "py.test-user-1234"
            build = "0.0.0.0.pre-alfa"
            client_collector.update((client_id, build), ClientCollector.STATUSES[0])

        """
        with self._lock:
            if status not in self.STATUSES:
                raise ValueError("Invalid status - {0}. Acceptable values: {1}.".format(status, self.STATUSES))
            if client not in self.clients:
                self.clients[client] = {}
            self.clients[client]['status'] = status
            self.clients[client]['connect_time'] = time.time()
            if "reports" not in self.clients[client]:
                self.clients[client]['reports'] = {}

    def addreport(self, client, report_type):
        """Add and open report type.

        Args:
            client(tuple(str)): Tuple of ClientID and build.
            report_type(str): "html", "xml" or "wrtm".

        Raises:
            KeyError: client not in self.clients

        Returns:
            None

        Examples::

            client = ("py.test-user-1234", "v.0.0.0.0.0.1")
            report_type = "html"
            client_collector.addreport(client, report_type)

        """
        with self._lock:
            if client not in self.clients:
                raise KeyError("Unknown client: {0}.".format(client))
            self.clients[client]['reports'][report_type] = True
            self.clients[client]['reports'] = OrderedDict(sorted(list(self.clients[client]['reports'].items()), key=lambda t: t[0]))

    def closereport(self, client, report_type):
        """Close report type (set False for existing opened report).

        Args:
            client( tuple(str)):  Tuple of ClientID and build
            report_type(str):  "html", "xml" or "wrtm".

        Raises:
            KeyError:  client not in self.clients

        Returns:
            None

        """
        with self._lock:
            if client not in self.clients:
                raise KeyError("Unknown client: {0}.".format(client))
            self.clients[client]['reports'][report_type] = False
            self.class_logger.info("Report type - %s of client - %s closed", report_type, client)

    def delreport(self, client, report_type):
        """Remove report type (disabling collecting info for report).

        Args:
            client(tuple(str)):  Tuple of ClientID and build.
            report_type(str):  "html", "xml" or "wrtm".

        Raises:
            KeyError:  client not in self.clients

        Returns:
            None

        """
        with self._lock:
            if client not in self.clients:
                raise KeyError("Unknown client: {0}.".format(client))
            try:
                del self.clients[client]['reports'][report_type.lower()]
            except KeyError:
                pass

    @log_exception(msg="failed to get client's attribute")
    def get(self, client, attr):
        """Return client's attribute.

        Args:
            client(tuple(str)):  Tuple of ClientID and build.
            attr(str):  Client attribute - key of client dict.

        Returns:
            Client's attribute (return type depends on attribute type).

        Examples::

            client = ("py.test-user-1234", "v.0.0.0.0.0.1")
            client_collector.get(client, "connect_time")
            client_collector.get(client, "reports")

        """
        with self._lock:
            if client in self.clients and attr in self.clients[client]:
                return self.clients[client][attr]
            else:
                return None

    def getall(self, client):
        """Return all client attributes.

        Args:
            client(str):  Tuple of ClientID and build.

        Returns:
            dict: client dict.

        """
        with self._lock:
            if client in self.clients:
                return self.clients[client]
            else:
                return None

    def active(self):
        """List of active clients.

        Returns:
            list[dict]: list of clients.

        Note:
            There are can be commands from client in queue when client is disconnected (see inprocess() method).

        """
        with self._lock:
            active = [_x for _x in list(self.clients.keys()) if self.clients[_x]['status'] == self.STATUSES[0]]
            return active

    def inprocess(self):
        """List of clients with unprocessed close command.

        Returns:
            list[dict]: list of clients.

        Note:
            On close command server should close (and dump) client's reports.

        """
        with self._lock:
            active = [_x for _x in list(self.clients.keys()) if True in list(self.clients[_x]['reports'].values())]
            return active

    def all(self):
        """All connected/disconnected client.

        Returns:
            list[dict]: @return:  list of clients.

        """
        with self._lock:
            try:
                return list(self.clients.keys())
            except IndexError:
                return None


def update_timestamp(function):
    """Decorator: update last operation timestamp.

    """
    def wrapper(*args, **kwargs):
        """Function wrapper.

        """
        args[0].last_operation_time = time.time()
        return function(*args, **kwargs)
    return wrapper


class XMLReportingServer(xmlrpc.XMLRPC):
    """Root reporting server handler.

    Note:
        This handler receive all test execution information and with command_processor process it to reports.

    """

    NAME = "XMLReportingServer"

    class_logger = loggers.ClassLogger()

    # Last operation timestamp
    last_operation_time = None
    last_cmdprocess_time = None
    last_cmdprocess_status = None
    # Client collector
    clients = None
    # commands queue
    queue = None

    watchdog = None
    watchdog_thr = None

    # list of reports. {'type1': {<dict of instances>}, }
    _reports = {}

    # list of connectors. {'name': {<dict of instance>}, }
    _connectors = {}

    # To avoid process termination by buildbot we have to send keepalive messages to console
    keep_alive_interval = 3600
    keep_alive_last = time.time()

    def xmlrpc_ping(self):
        """Return self.NAME.

        """
        return self.NAME

    def setup(self, opts):
        """Create WRTM proxy instance and set necessary attributes.

        Args:
            opts(OptionParse):  cli options (OptionParse parsed options).

        Returns:
            None

        """
        self.last_operation_time = time.time()
        self.clients = ClientCollector()
        self.queue = CommandCollector()
        self._reports = {}
        self._connectors = {}
        self.init_connectors()

        # Start queue processing
        self.watchdog = True
        self.start_queue_watchdog()

        # Multiuser
        self.multiuser = opts.multiuser  # pylint: disable=attribute-defined-outside-init

    def xmlrpc_shutdown(self, trycount=0, lasttry=0):
        """Store shutdown server command.

        Args:
            trycount(int): attempts count.
            lasttry(int): time of last attempt.

        """
        if self.multiuser:
            message = "Multiuser mode On. Shutdown command canceled."
            self.class_logger.info(message)
            return message
        self.class_logger.info("Shutdown command received.")
        cmd = {'shutdown': trycount, 'lasttry': lasttry}
        self.queue.add(cmd)
        return "Shutdown command is added to queue."

    # TODO: Implement correct reactor stop
    def shutdown(self):
        """Shutdown xmlrpc server.

        """
        qlen = self.queue.len()
        cinprocess = self.clients.inprocess()
        idle = False
        # Check if qlen == 1 because 1 command is shutdown itself.
        if qlen == 1 and len(cinprocess) == 0:
            idle = True

        if idle:
            self.watchdog = False
            self.watchdog_thr.join()
            pid = os.getpid()
            os.kill(pid, signal.SIGTERM)
            return "Server {0} ready to shut down.".format(self.NAME)
        else:
            return "Server {0} still processing queries... Cancel operation...".format(self.NAME)

    @update_timestamp
    def xmlrpc_open(self, client_id):
        """Store connected client information.

        Args:
            client_id(str): Unique client name.

        Returns:
            bool: True if command successfully processed.

        Examples::

            xs = xmlrpclib.ServerProxy("http://localhost:18080")
            xs.reports.open("py.test-user-1234", "CoolSoftware-0.0.0.1234-1")

        """
        self.class_logger.info("New client %s has connected to %s.", client_id, self.NAME)
        self.clients.update(client_id, ClientCollector.STATUSES[0])
        return True

    @update_timestamp
    def xmlrpc_close(self, client_id):
        """Free client information.

        Args:
            client_id(str):  Unique client name.

        Returns:
            bool: True if command successfully processed.

        Note:
            Set Inactive status to client and set session duration.

        Examples::

            xs = xmlrpclib.ServerProxy("http://localhost:18080")
            xs.reports.close("py.test-user-1234", "CoolSoftware-0.0.0.1234-1")

        """
        self.class_logger.info("Client %s has disconnected from %s.", client_id, self.NAME)
        connect_time = self.clients.get(client_id, "connect_time")
        if connect_time is not None:
            duration = time.time() - connect_time
        else:
            duration = 0
        self.class_logger.info("Client %s session duration = %s.", client_id, duration)
        cmd = {'client': client_id, 'close': True, 'duration': duration}
        self.queue.add(cmd)
        self.clients.update(client_id, ClientCollector.STATUSES[1])
        return True

    @update_timestamp
    def xmlrpc_reportadd(self, client_id, report_type):
        """Append client report attribute with report_type.

        Args:
            client_id(str):  Unique client name.
            report_type(str):  Report typr. E.g. "xml", "html" or "wrtm".

        Returns:
            bool True if command successfully processed.

        Examples::

            xs = xmlrpclib.ServerProxy("http://localhost:18080")
            xs.reports.reportadd("py.test-user-1234", "CoolSoftware-0.0.0.1234-1", "xml")

        """
        self.class_logger.info("Add %s report type for client %s.", report_type, client_id)
        self.clients.addreport(client_id, report_type)
        self.check_report_instance(report_type, client_id)
        return True

    @update_timestamp
    def xmlrpc_reportdel(self, client_id, report_type):
        """Remove report type from client report attribute.

        Args:
            client_id(str):  Unique client name.
            report_type(str):  Report typr. E.g. "xml", "html" or "wrtm".

        Returns:
            bool: True if command successfully processed.

        Examples::

            xs = xmlrpclib.ServerProxy("http://localhost:18080")
            xs.reports.delreport("py.test-user-1234", "CoolSoftware-0.0.0.1234-1", "xml")

        """
        self.class_logger.info("Remove %s report type from client %s.", report_type, client_id)
        self.clients.delreport(client_id, report_type)
        return True

    @update_timestamp
    def xmlrpc_reportconfig(self, client_id, report_type, cfgname, value):
        """Config XML RPC reports.

        Args:
            client_id(str):  Unique client name.
            report_type(str):  Report typr. E.g. "xml", "html" or "wrtm".
            cfgname(str):  Report attribute.
            value(Depends on attribute):  Attribute value.

        Returns:
            Depends on report.

        Note:
            Set report attributes.

        Examples::

            xs = xmlrpclib.ServerProxy("http://localhost:18080")
            xs.reports.reportconfig("py.test-user-1234", "CoolSoftware-0.0.0.1234-1", "xml", "logfile", "/path/where/to/store/log")

        """
        # if not hasattr(self, "{0}_report_cfg".format(report_type)):
        #    return "WARNING: There is no method to configure report of the {0} type.".format(report_type)
        # return getattr(self, "{0}_report_cfg".format(report_type))(client_id, build, cfgname, value)

        self.check_report_instance(report_type, client_id)
        if cfgname == "options" and value:
            for i in value:
                setattr(self._reports[report_type.upper()][client_id], i[0], i[1])

            setattr(self._reports[report_type.upper()][client_id], cfgname, value)
        if cfgname in ["", None]:
            return "ERROR: cfgname must be defined."
        try:
            setattr(self._reports[report_type.upper()][client_id], cfgname, value)
        except Exception as err:
            self.class_logger.error("Setattr %s = %s failed for report '%s'. Exception occurred: %s",
                                    cfgname, value, report_type, err)
            return err
        else:
            self.class_logger.info("Setattr %s = %s is OK for report %s.", cfgname, value, report_type)
            return True

    def xmlrpc_idletime(self):
        """Return idle time.

        Returns:
            int: time elapsed from last processed xmlrpc query (int).

        """
        return int(time.time() - self.last_operation_time)

    def xmlrpc_queueidletime(self):
        """Return queue idle time.

        Returns:
            int: time elapsed from last processed command (int).

        """
        return int(time.time() - self.last_cmdprocess_time)

    def xmlrpc_queuelastcmdstatus(self):
        """Get last queue command process status.

        Returns:
            bool: last queue command process status

        """
        return self.last_cmdprocess_status

    def xmlrpc_queuelen(self):
        """Get command queue length.

        Returns:
            int: command queue length

        """
        return self.queue.len()

    def xmlrpc_queuelist(self):
        """Get command queue list.

        Returns:
            list[dict]: command queue list

        """
        return self.queue.list()

    def xmlrpc_queuedropcmd(self, index):
        """Remove command from queue by index.

        Args:
            index(int): Index of command in queue.

        Returns:
            dict: Command.

        Note:
            It's recommended to stop queue processing first
            (see cmdprocdisable method) and check queuelist.

        """
        return self.queue.drop(index)

    def xmlrpc_clientlist(self, ltype="active"):
        """Get list of active clients.

        Args:
            ltype(str):  'all'|'active'

        Returns:
            list: list of active clients

        """
        if ltype == "all":
            return self.clients.all()
        elif ltype == "active":
            return self.clients.active()
        else:
            return "Unknown ltype option."

    def xmlrpc_clientfullinfo(self, client):
        """Return full client info.

        Args:
            client(tuple(str)):  Tuple of ClientID and build.

        Returns:
            dict: Full client dictionary with all attributes.

        """
        return str(self.clients.getall(client))

    def xmlrpc_reportslist(self, r_type=None):
        """List of all report instances.

        Args:
            r_type(str):  Report type to list.

        Returns:
            dict: dict of dict {<type>: {<build>: {<client>: <value>}}}
            Values are dicts of report specific values. (dict of dict)

        """
        r_dict = {}

        if r_type is None:
            report_type_list = list(self._reports.keys())
        else:
            report_type_list = [_rt for _rt in self._reports if r_type.upper() in _rt]

        for t_key in report_type_list:
            r_dict[t_key] = {}
            for b_key in self._reports[t_key]:
                r_dict[t_key][b_key] = self._reports[t_key][b_key].info()
        return r_dict

    def xmlrpc_reportmethod(self, report_type, client, method, params=None):
        """Call report class method.

        Args:
            report_type(str):  Report type.
            client(tuple(str)):  Tuple of ClientID and build.
            method(str):  method name.
            params(list):  method params.

        Returns:
            Query execution status if one.

        """
        # ctime = self.clients.get((client, build), "connect_time")
        # if ctime is None:
        #   ctime = 0
        # duration = time.time() - ctime
        params = [] if params is None else params
        return getattr(self._reports[report_type.upper()][client],
                       method)(*params)

    def xmlrpc_cmdprocdisable(self):
        """Disabling and stopping queue command processing.

        Returns:
            bool: Query execution status.

        """
        self.watchdog = False
        self.class_logger.debug("cmdproc is disable")
        return not self.watchdog

    def xmlrpc_cmdprocenable(self):
        """Enabling queue command processing.

        Returns:
            bool: Query execution status.

        """
        self.watchdog = True
        self.class_logger.debug("cmdproc is enable")
        return self.watchdog

    def xmlrpc_cmdprocstart(self):
        """Starting queue command processing.

        Returns:
            bool: Query execution status.

        """
        return self.start_queue_watchdog()

    def xmlrpc_cmdproccheck(self):
        """Return queue command processing status.

        Returns:
            str: Query execution status.

        """
        return "Watchdog is %s and cmdproc is %s" % (self.watchdog, self.watchdog_thr.is_alive())

    def xmlrpc_checklocks(self):
        """Get CommandCollector and ClientCollector lock statuses.

        Returns:
            dict{bool}: CommandCollector and ClientCollector lock statuses.

        """
        return {"ClientCollector": self.clients._lock._is_owned(),  # pylint: disable=protected-access
                "CommandCollector": self.queue._lock._is_owned()}  # pylint: disable=protected-access

    @update_timestamp
    def xmlrpc_post(self, client, build, suite, tc, status, report=None, info=None, build_info=None, **kwargs):
        """Post TC run result.

        Args:
            client(tuple(str)):  Tuple of ClientID and build.
            build(str):  Build name.
            suite(str):  Suite class name).
            tc(str):  TC function name.
            status(str):  TC status string ('Run', 'Passed', 'Failed').
            report(dict):  TC run duration, longreport, retval.

        Returns:
            bool: Query execution status.

        Examples::

            xs = xmlrpclib.ServerProxy("http://localhost:18080")
            xs.reports.post("py.test-user-1234", "0.0.0.1234-1/CoolSoftware", "feature_tests.Feature1Test", "test_same_behaviour", "Run")

        """
        self.class_logger.debug("Kwargs: %s", kwargs)
        if info is None:
            info = {}
        cmd = {'client': client, 'build': build, 'suite': suite, 'tc': tc, 'status': status, 'report': report, 'info': info, 'build_info': build_info}
        with contextlib.suppress(Exception):
            self.queue.add(cmd)
            return True
        return False

    def queue_watchdog(self):
        """Send commands from queue to command processor in loop.

        Raises:
            Exception:  exception while processing command.

        """
        while self.watchdog:
            # Send keep_alive message
            _cur_time = time.time()
            if (self.keep_alive_last + self.keep_alive_interval) <= _cur_time:
                sys.stdout.write("Keep alive message. Time stamp: %s\n" % (_cur_time, ))
                sys.stdout.flush()
                self.keep_alive_last = _cur_time
            cmd = self.queue.get()
            if cmd is not None:
                try:
                    self.last_cmdprocess_time = time.time()
                    self.command_processor(cmd)
                    self.class_logger.debug("Command processed.")
                    self.queue.pop()
                    self.class_logger.debug("Command removed from queue.")
                    self.last_cmdprocess_status = True
                except Exception:
                    self.last_cmdprocess_status = False
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    traceback_message = traceback.format_exception(exc_type, exc_value,
                                                                   exc_traceback)
                    self.class_logger.error("Exception while processing command: %s", cmd)
                    self.class_logger.error("Traceback:\n%s", "".join(traceback_message))
                    raise
            else:
                time.sleep(0.5)
        self.class_logger.info("Exiting command processor.")
        return False

    def start_queue_watchdog(self):
        """Start watchdog in thread.

        """
        def start_thr():
            """Launching queue_watchdog in thread.

            """
            self.watchdog_thr = Thread(target=self.queue_watchdog)
            self.watchdog_thr.daemon = True
            self.watchdog_thr.start()

        self.class_logger.info("Starting queue processing.")
        if not self.watchdog:
            self.class_logger.info("Queue processing start canceled. Reason - it is disabled.")
            return False
        if self.watchdog_thr is None:
            # First start
            self.class_logger.info("Command processor first start.")
            start_thr()
        elif self.watchdog_thr.is_alive():
            self.class_logger.info("Command processor is already running.")
        else:
            # Thread is dead
            # Try to stop current thread
            self.class_logger.info("Command processor has been started but dead.")
            self.class_logger.info("Try to wait while thread terminates.")
            self.watchdog_thr.join(10)
            if self.watchdog_thr.is_alive():
                self.class_logger.warning("watchdog_thr didn't terminate after 10 sec.")
                self.class_logger.warning("Thread object will be deleted and new one created.")
            # Try to restart
            self.class_logger.info("Command processor has been started but dead.")
            start_thr()
        return True

    def command_processor(self, cmd):
        """Processing command from queue.

        Args:
            cmd(dict):  Command.

        Returns:
            None

        """
        # Truncating command for log message
        cmd1 = {k: v for k, v in cmd.items() if k not in ['report']}
        self.class_logger.info("Start processing command: %s.", cmd1)

        # Processing shutdown command.
        if "shutdown" in cmd:
            # Perform shutdown only if 30s have passed after previous try.
            if time.time() - cmd['lasttry'] >= 30:
                reactor.callFromThread(self.shutdown)  # pylint: disable=no-member
            # Wait until shutdown
            time.sleep(1)
            # Put command again to queue if shutdown is canceled.
            # Cancel shutdown if 3 attempts are failed.
            if cmd['shutdown'] < 3:
                self.class_logger.info("Shutdown command is postponed.")
                self.queue.add({'shutdown': cmd['shutdown'] + 1,
                                'lasttry': time.time()})
            else:
                self.class_logger.error("Shutdown command is canceled after 3 failed attempts.")
            return

        for r_type in self.clients.get(cmd['client'], "reports"):
            self.class_logger.debug("Processing %s command.", r_type)
            try:
                self._reports[r_type.upper()][cmd['client']].process_cmd(cmd)
                if "close" in cmd:
                    self.class_logger.info("Closing %s report.", r_type)
                    self.clients.closereport(cmd['client'], r_type)

            except Exception as err:
                self.class_logger.error("Error while processing command: %s. ERROR: %s", cmd, err)

                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback_message = traceback.format_exception(exc_type, exc_value,
                                                               exc_traceback)
                self.class_logger.error("Traceback:\n%s", "".join(traceback_message))

    def is_idle(self):
        """Command processor idle status.

        Returns:
            bool: True if command queue is empty and all clients are in closed state

        """
        self.class_logger.info("Last operation time: %s", self.last_operation_time)
        qlen = self.queue.len()
        self.class_logger.info("Command queue length: %s", qlen)
        cinprocess = self.clients.inprocess()
        self.class_logger.info("Clients in process: %s", cinprocess)
        return qlen == 0 and len(cinprocess) == 0

    def check_report_instance(self, r_type, client_id):
        """Create report instance if any for given client_id and build.

        Args:
            r_type(str):  report type.
            client_id(str):  Unique client name.

        Returns:
            None

        """
        r_type = r_type.upper()
        if r_type not in self._reports:
            self._reports[r_type] = {}
#        if not build in self._reports[r_type]:
#            self._reports[r_type][build] = {}
        if client_id not in self._reports[r_type]:
            self._reports[r_type][client_id] = getattr(getattr(MODULES['reports.{0}'.format(r_type)], r_type), r_type)(connectors=self._connectors)

    def init_connectors(self):
        """Initializing connectors.

        """
        for mod in MODULES:
            if mod.startswith('connectors.'):
                arr = mod.split('.')
                self._connectors[arr[1]] = getattr(getattr(MODULES[mod], arr[1].upper()), arr[1].upper())()


def parse_options():
    """Parsing options.

    """

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--port", action="store", default=None,
                        help="Local port to listen. Use random if not set.")
    parser.add_argument("--multiuser", action="store_true",
                        help="Ignore shutdown command from clients.")
    parser.add_argument("--loglevel", action="store", default="DEBUG",
                        help="Logging level.")
    parser.add_argument("--logdir", action="store", default=os.curdir, dest="logdir",
                        help="Path to dir for log files.")
    parser.add_argument("--logprefix", dest="logprefix", default="main",
                        help="Log files prefix.")
    parser.add_argument("--silent", action="store_true", dest="silent",
                        help="Do not print logging to console.")

    options = parser.parse_args()
    return options


def get_local_port():
    """Return free local port.

    """
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("", 0))
        return sock.getsockname()[1]


def main(ppid):
    """Start standalone server.

    """
    def signal_handler(signum, frame):
        """Process termination signals.

        """
        mod_logger.info("Caught a signal=%s", signum)
        time.sleep(3)
        # 2 is signal of SysExit or Ctrl+C KeyboardInterupt
        if signum != 2:
            reactor.stop()  # pylint: disable=no-member

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGABRT, signal_handler)
    signal.signal(signal.SIGILL, signal_handler)

    opts = parse_options()

    mod_logger = loggers.module_logger(__name__)
    mod_logger.info("Log filename: %s", loggers.LOG_FILENAME)

    xmlrpcsrv = XMLReportingServer()
    xmlrpcsrv.setup(opts)

    port = opts.port if opts.port is not None else get_local_port()

    # Create pid file with port inside
    # Reason: we need to launch server with variable port and need to get it's number.
    # We cannot catch server stdout (because if we do so, we break stdout logger)
    # So we use file for this.
    _vr_path = os.path.join("/tmp", "{0}.pid".format(ppid))
    try:
        with open(_vr_path, "w") as _vr:
            _vr.write(str(port))
    except OSError as err:
        mod_logger.warning("Failed to create pid/port file %s. Error:\n%s", _vr_path, err)
        if not opts.port:
            # Raise exception in case RS should be started with random port.
            # Client cannot determinate RS port without file.
            raise

    reactor.listenTCP(int(port), server.Site(xmlrpcsrv))  # pylint: disable=no-member
    mod_logger.info("Listen on localhost: %s", port)
    reactor.run()  # pylint: disable=no-member


if __name__ == "__main__":

    # Import reports and connectors plugins.
    imp_plugins("reports")
    imp_plugins("connectors")
    # Set parent process pid
    ppid = os.getpid()

    # Launch server.
    if os.fork() == 0:
        main(ppid)
    else:
        sys.exit(0)
