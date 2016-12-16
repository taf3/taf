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

@file  reporting_server.py

@summary  Standalone loggingserver for pytest plugin.
"""

import os
import signal
import socket
import sys
import time
import argparse
from threading import RLock
from threading import Thread
import traceback
from collections import OrderedDict

from twisted.web import xmlrpc, server
from twisted.internet import reactor

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../taf')))
from testlib import loggers


MODULES = {}
def imp_plugins(dest):
    """
    @brief  Import all py modules from <dest> subfolder.
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


class CommandCollector(object):
    """
    @description  Thread safe collector for server command queue.
    """

    class_logger = loggers.ClassLogger()

    def __init__(self):
        """
        @brief  Initialize CommandCollector class.
        """
        self._lock = RLock()
        self.queue = []

    def add(self, cmd):
        """
        @brief  Add command to collector.
        @param  cmd:  Command
        @type  cmd:  dict
        @rtype:  bool
        @return:  Status
        @par Example:
        @code
        command = {'client': "client-name-with-pid-1111", 'build': 'cool-software-v.0.0.0.1-pre-alfa', 'close': True, 'duration': 15}
        command_collector.add(command)
        @endcode
        """
        _ok = False
        self._lock.acquire()
        try:
            self.queue.append(cmd)
            self.class_logger.info("Command added successfully. CMD keys: {0}".format(list(cmd.keys())))
            _ok = True
        except Exception as err:
            self.class_logger.error("Command addition failed. CMD keys: {0}. Error: {1}".format(list(cmd.keys()), err))
        finally:
            self._lock.release()
        return _ok

    def pop(self):
        """
        @brief  Pop the first item.
        @rtype:  dict
        @return:  command
        @note  See also get() method.
        """
        self._lock.acquire()
        try:
            if len(self.queue) > 0:
                return self.queue.pop(0)
            else:
                return None
        finally:
            self._lock.release()

    def get(self):
        """
        @brief  Same as pop but does not remove item.
        @rtype:  dict
        @return:  command
        @note  See pop() method description.
        """
        self._lock.acquire()
        try:
            if len(self.queue) > 0:
                return self.queue[0]
            else:
                return None
        finally:
            self._lock.release()

    def drop(self, index):
        """
        @brief  Remove item by index.
        @param  index:  Index of item in queue list.
        @type  index:  int
        @rtype:  dict|str
        @return:  Command or Error message.
        """
        self._lock.acquire()
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
        finally:
            self._lock.release()

    def len(self):
        """
        @brief  Return command queue length.
        @rtype:  int
        @return:  command queue length.
        """
        self._lock.acquire()
        try:
            return len(self.queue)
        finally:
            self._lock.release()

    def list(self):
        """
        @brief  Return list of all items.
        @rtype:  list[dict]
        @return:  All commands list.
        """
        self._lock.acquire()
        try:
            return self.queue
        finally:
            self._lock.release()


class ClientCollector(object):
    """
    @description  Thread safe object for collecting clients dictionaries.
    """

    # Allowed client statuses.
    STATUSES = ["Active", "Inactive"]

    class_logger = loggers.ClassLogger()

    def __init__(self):
        """
        @brief  Initialize ClientCollector class.
        """
        self._lock = RLock()
        self.clients = {}

    def update(self, client, status):
        """
        @brief  Update status of the client.
        @param  client:  Tuple of ClientID and build.
        @type  client:  tuple(str)
        @param  status:  Available values are listed in STATUSES constant.
        @type  status:  str
        @raise  ValueError:  status not in self.STATUSES
        @return:  None
        @par Example:
        @code
        client_id = "py.test-user-1234"
        build = "0.0.0.0.pre-alfa"
        client_collector.update((client_id, build), ClientCollector.STATUSES[0])
        @endcode
        """
        self._lock.acquire()
        try:
            if status not in self.STATUSES:
                raise ValueError("Invalid status - {0}. Acceptable values: {1}.".format(status, self.STATUSES))
            if client not in self.clients:
                self.clients[client] = {}
            self.clients[client]['status'] = status
            self.clients[client]['connect_time'] = time.time()
            if "reports" not in self.clients[client]:
                self.clients[client]['reports'] = {}
        finally:
            self._lock.release()

    def addreport(self, client, report_type):
        """
        @brief  Add and open report type.
        @param  client:  Tuple of ClientID and build.
        @type  client:  tuple(str)
        @param  report_type:  "html", "xml" or "wrtm".
        @type  report_type:  str
        @raise  KeyError:  client not in self.clients
        @return:  None
        @par Example:
        @code
        client = ("py.test-user-1234", "v.0.0.0.0.0.1")
        report_type = "html"
        client_collector.addreport(client, report_type)
        @endcode
        """
        self._lock.acquire()
        try:
            if client not in self.clients:
                raise KeyError("Unknown client: {0}.".format(client))
            self.clients[client]['reports'][report_type] = True
            self.clients[client]['reports'] = OrderedDict(sorted(list(self.clients[client]['reports'].items()), key=lambda t: t[0]))
        finally:
            self._lock.release()

    def closereport(self, client, report_type):
        """
        @brief  Close report type (set False for existing opened report).

        @param  client:  Tuple of ClientID and build
        @type  client:  tuple(str)
        @param  report_type:  "html", "xml" or "wrtm".
        @type  report_type:  str
        @raise  KeyError:  client not in self.clients
        @return:  None
        """
        self._lock.acquire()
        try:
            if client not in self.clients:
                raise KeyError("Unknown client: {0}.".format(client))
            self.clients[client]['reports'][report_type] = False
            self.class_logger.info("Report type - {0} of client - {1} closed".format(report_type, client))
        finally:
            self._lock.release()

    def delreport(self, client, report_type):
        """
        @brief  Remove report type (disabling collecting info for report).

        @param  client:  Tuple of ClientID and build.
        @type  client:  tuple(str)
        @param  report_type:  "html", "xml" or "wrtm".
        @type  report_type:  str
        @raise  KeyError:  client not in self.clients
        @return:  None
        """
        self._lock.acquire()
        try:
            if client not in self.clients:
                raise KeyError("Unknown client: {0}.".format(client))
            try:
                del self.clients[client]['reports'][report_type.lower()]
            except KeyError:
                pass
        finally:
            self._lock.release()

    def get(self, client, attr):
        """
        @brief  Return client's attribute.
        @param  client:  Tuple of ClientID and build.
        @type  client:  tuple(str)
        @param  attr:  Client attribute - key of client dict.
        @type  attr:  str
        @return:  client's attribute (return type depends on attribute type).
        @par Example:
        @code
        client = ("py.test-user-1234", "v.0.0.0.0.0.1")
        client_collector.get(client, "connect_time")
        client_collector.get(client, "reports")
        @endcode
        """
        self._lock.acquire()
        try:
            if client in self.clients and attr in self.clients[client]:
                return self.clients[client][attr]
            else:
                return None
        except Exception as err:
            self.class_logger.debug("Error occurred: {0}".format(err))
        finally:
            self._lock.release()

    def getall(self, client):
        """
        @brief  Return all client attributes.
        @param  client:  Tuple of ClientID and build.
        @type  client:  tuple(str)
        @rtype:  dict
        @return:  client dict.
        """
        self._lock.acquire()
        try:
            if client in self.clients:
                return self.clients[client]
            else:
                return None
        finally:
            self._lock.release()

    def active(self):
        """
        @brief  List of active clients.
        @rtype:  list[dict]
        @return:  list of clients.
        @note  There are can be commands from client in queue when client is disconnected. (See inprocess() method.)
        """
        self._lock.acquire()
        try:
            active = [_x for _x in list(self.clients.keys()) if self.clients[_x]['status'] == self.STATUSES[0]]
            return active
        finally:
            self._lock.release()

    def inprocess(self):
        """
        @brief  List of clients with unprocessed close command.
        @rtype:  list[dict]
        @return:  list of clients.
        @note  On close command server should close (and dump) client's reports.
        """
        self._lock.acquire()
        try:
            active = [_x for _x in list(self.clients.keys()) if True in list(self.clients[_x]['reports'].values())]
            return active
        finally:
            self._lock.release()

    def all(self):
        """
        @brief  All connected/disconnected client.
        @rtype:  list[dict]
        @return:  list of clients.
        """
        self._lock.acquire()
        try:
            return list(self.clients.keys())
        finally:
            self._lock.release()


def update_timestamp(function):
    """
    @brief  Decorator: update last operation timestamp.
    """
    def wrapper(*args, **kwargs):
        """
        @brief  Function wrapper.
        """
        args[0].last_operation_time = time.time()
        return function(*args, **kwargs)
    return wrapper


class XMLReportingServer(xmlrpc.XMLRPC):
    """
    @description  Root reporting server handler.

    @note  This handler receive all test execution information and with command_processor process it to reports.
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
        """
        @brief  Return self.NAME.
        """
        return self.NAME

    def setup(self, opts):
        """
        @brief  Create WRTM proxy instance and set necessary attributes.
        @param  opts:  cli options (OptionParse parsed options).
        @type  opts:  OptionParse
        @return:  None
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
        self.multiuser = opts.multiuser

    def xmlrpc_shutdown(self, trycount=0, lasttry=0):
        """
        @brief  Store shutdown server command.
        @param  trycount:  attempts count.
        @type  trycount:  int
        @param  lasttry:  time of last attempt.
        @type  lasttry:  int
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
        """
        @brief  Shutdown xmlrpc server.
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
        """
        @brief  Store connected client information.
        @param  client_id:  Unique client name.
        @type  client_id:  str
        @rtype:  bool
        @return:  True if command successfully processed.
        @par Example:
        @code
        xs = xmlrpclib.ServerProxy("http://localhost:18080")
        xs.reports.open("py.test-user-1234", "CoolSoftware-0.0.0.1234-1")
        @endcode
        """
        self.class_logger.info("New client {0} has connected to {1}.".format(client_id, self.NAME))
        self.clients.update(client_id, ClientCollector.STATUSES[0])
        return True

    @update_timestamp
    def xmlrpc_close(self, client_id):
        """
        @brief  Free client information.
        @param  client_id:  Unique client name.
        @type  client_id:  str
        @rtype:  bool
        @return  True if command successfully processed.
        @note  Set Inactive status to client and set session duration.
        @par Example:
        @code
        xs = xmlrpclib.ServerProxy("http://localhost:18080")
        xs.reports.close("py.test-user-1234", "CoolSoftware-0.0.0.1234-1")
        @endcode
        """
        self.class_logger.info("Client {0} has disconnected from {1}.".format(client_id, self.NAME))
        connect_time = self.clients.get(client_id, "connect_time")
        if connect_time is not None:
            duration = time.time() - connect_time
        else:
            duration = 0
        self.class_logger.info("Client {0} session duration = {1}.".format(client_id, duration))
        cmd = {'client': client_id, 'close': True, 'duration': duration}
        self.queue.add(cmd)
        self.clients.update(client_id, ClientCollector.STATUSES[1])
        return True

    @update_timestamp
    def xmlrpc_reportadd(self, client_id, report_type):
        """
        @brief  Append client report attribute with report_type.
        @param  client_id:  Unique client name.
        @type  client_id:  str
        @param  report_type:  Report typr. E.g. "xml", "html" or "wrtm".
        @type  report_type:  str
        @rtype:  bool
        @return:  True if command successfully processed.
        @par Example:
        @code
        xs = xmlrpclib.ServerProxy("http://localhost:18080")
        xs.reports.reportadd("py.test-user-1234", "CoolSoftware-0.0.0.1234-1", "xml")
        @endcode
        """
        self.class_logger.info("Add {1} report type for client {0}.".format(client_id, report_type))
        self.clients.addreport(client_id, report_type)
        self.check_report_instance(report_type, client_id)
        return True

    @update_timestamp
    def xmlrpc_reportdel(self, client_id, report_type):
        """
        @brief  Remove report type from client report attribute.
        @param  client_id:  Unique client name.
        @type  client_id:  str
        @param  report_type:  Report typr. E.g. "xml", "html" or "wrtm".
        @type  report_type:  str
        @rtype:  bool
        @return:  True if command successfully processed.
        @par Example:
        @code
        xs = xmlrpclib.ServerProxy("http://localhost:18080")
        xs.reports.delreport("py.test-user-1234", "CoolSoftware-0.0.0.1234-1", "xml")
        @endcode
        """
        self.class_logger.info("Remove {1} report type from client {0}.".
                               format(client_id, report_type))
        self.clients.delreport(client_id, report_type)
        return True

    @update_timestamp
    def xmlrpc_reportconfig(self, client_id, report_type, cfgname, value):
        """
        @brief  Config XML RPC reports.
        @param  client_id:  Unique client name.
        @type  client_id:  str
        @param  report_type:  Report typr. E.g. "xml", "html" or "wrtm".
        @type  report_type:  str
        @param  cfgname:  Report attribute.
        @type  cfgname:  str
        @param  value:  Attribute value.
        @type  value:  Depends on attribute
        @return:  Depends on report.
        @note  Set report attributes.
        @par Example:
        @code
        xs = xmlrpclib.ServerProxy("http://localhost:18080")
        xs.reports.reportconfig("py.test-user-1234", "CoolSoftware-0.0.0.1234-1", "xml", "logfile", "/path/where/to/store/log")
        @endcode
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
            self.class_logger.error("Setattr {0} = {1} failed for report '{2}'. Exception occurred: {3}".
                                    format(cfgname, value, report_type, err))
            return err
        else:
            self.class_logger.info("Setattr {0} = {1} is OK for report {2}.".
                                   format(cfgname, value, report_type))
            return True

    def xmlrpc_idletime(self):
        """
        @brief  Return idle time.
        @rtype:  int
        @return:  time elapsed from last processed xmlrpc query (int).
        """
        return int(time.time() - self.last_operation_time)

    def xmlrpc_queueidletime(self):
        """
        @brief  Return queue idle time.
        @rtype:  int
        @return:  time elapsed from last processed command (int).
        """
        return int(time.time() - self.last_cmdprocess_time)

    def xmlrpc_queuelastcmdstatus(self):
        """
        @brief  Get last queue command process status.
        @rtype:  bool
        @return:  last queue command process status
        """
        return self.last_cmdprocess_status

    def xmlrpc_queuelen(self):
        """
        @brief  Get command queue length.
        @rtype:  int
        @return:  command queue length
        """
        return self.queue.len()

    def xmlrpc_queuelist(self):
        """
        @brief  Get command queue list.
        @rtype: list[dict]
        @return:  command queue list
        """
        return self.queue.list()

    def xmlrpc_queuedropcmd(self, index):
        """
        @brief  Remove command from queue by index.
        @param  index:  Index of command in queue.
        @type  index:  int
        @rtype: dict
        @return:  Command.
        @note  It's recommended to stop queue processing first
               (see cmdprocdisable method) and check queuelist.
        """
        return self.queue.drop(index)

    def xmlrpc_clientlist(self, ltype="active"):
        """
        @brief  Get list of active clients.
        @param  ltype:  'all'|'active'
        @type  ltype:  str
        @rtype:  list
        @return: list of active clients
        """
        if ltype == "all":
            return self.clients.all()
        elif ltype == "active":
            return self.clients.active()
        else:
            return "Unknown ltype option."

    def xmlrpc_clientfullinfo(self, client):
        """
        @brief  Return full client info.
        @param  client:  Tuple of ClientID and build.
        @type  client:  tuple(str)
        @rtype:  dict
        @return:  Full client dictionary with all attributes.
        """
        return str(self.clients.getall(client))

    def xmlrpc_reportslist(self, r_type=None):
        """
        @brief  List of all report instances.
        @param   r_type:  Report type to list.
        @param   r_type:  str
        @rtype:  dict
        @return:  dict of dict {<type>: {<build>: {<client>: <value>}}}
                 Values are dicts of report specific values.
                 (dict of dict)
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
        """
        @brief  Call report class method.
        @param  report_type:  Report type.
        @type  report_type:  str
        @param  client:  Tuple of ClientID and build.
        @type  client:  tuple(str)
        @param  method:  method name.
        @type  method:  str
        @param  params:  method params.
        @type  params:  list
        @return:  Query execution status if one.
        """
        # ctime = self.clients.get((client, build), "connect_time")
        # if ctime is None:
        #   ctime = 0
        # duration = time.time() - ctime
        params = [] if params is None else params
        return getattr(self._reports[report_type.upper()][client],
                       method)(*params)

    def xmlrpc_cmdprocdisable(self):
        """
        @brief  Disabling and stopping queue command processing.
        @rtype:  bool
        @return:  Query execution status.
        """
        self.watchdog = False
        self.class_logger.debug("cmdproc is disable")
        return not self.watchdog

    def xmlrpc_cmdprocenable(self):
        """
        @brief  Enabling queue command processing.
        @rtype:  bool
        @return:  Query execution status.
        """
        self.watchdog = True
        self.class_logger.debug("cmdproc is enable")
        return self.watchdog

    def xmlrpc_cmdprocstart(self):
        """
        @brief  Starting queue command processing.
        @rtype:  bool
        @return:  Query execution status.
        """
        return self.start_queue_watchdog()

    def xmlrpc_cmdproccheck(self):
        """
        @brief  Return queue command processing status.
        @rtype:  str
        @return:  Query execution status.
        """
        return "Watchdog is %s and cmdproc is %s" % (self.watchdog, self.watchdog_thr.is_alive())

    def xmlrpc_checklocks(self):
        """
        @brief  Get CommandCollector and ClientCollector lock statuses.
        @rtype:  dict{bool}
        @return:  CommandCollector and ClientCollector lock statuses
        """
        return {"ClientCollector": self.clients._lock._is_owned(),
                "CommandCollector": self.queue._lock._is_owned()}

    @update_timestamp
    def xmlrpc_post(self, client, build, suite, tc, status, report=None, info=None, build_info=None, **kwargs):
        """
        @brief  Post TC run result.
        @param  client:  Tuple of ClientID and build.
        @type  client:  tuple(str)
        @param  build:  Build name.
        @type  build:  str
        @param  suite:  Suite class name).
        @type  suite:  str
        @param  tc:  TC function name.
        @type  tc:  str
        @param  status:  TC status string ('Run', 'Passed', 'Failed').
        @type  status:  str
        @param  report:  TC run duration, longreport, retval.
        @type  report:  dict
        @rtype:  bool
        @return:  Query execution status.
        @par Example:
        @code
        xs = xmlrpclib.ServerProxy("http://localhost:18080")
        xs.reports.post("py.test-user-1234", "0.0.0.1234-1/CoolSoftware", "feature_tests.Feature1Test", "test_same_behaviour", "Run")
        @endcode
        """
        self.class_logger.debug("Kwargs: %s" % (str(kwargs), ))
        try:
            if info is None:
                info = {}

            cmd = {'client': client, 'build': build, 'suite': suite, 'tc': tc, 'status': status, 'report': report, 'info': info, 'build_info': build_info}
            self.queue.add(cmd)
            return True
        except Exception:
            return False

    def queue_watchdog(self):
        """
        @brief  Send commands from queue to command processor in loop.
        @raise  Exception:  exception while processing command.
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
                    self.class_logger.error("Exception while processing command: {0}".format(cmd))
                    self.class_logger.error("Traceback:\n{0}".format("".join(traceback_message)))
                    raise
            else:
                time.sleep(0.5)
        self.class_logger.info("Exiting command processor.")
        return False

    def start_queue_watchdog(self):
        """
        @brief  Start watchdog in thread.
        """
        def start_thr():
            """
            @brief  Launching queue_watchdog in thread.
            """
            self.watchdog_thr = Thread(target=self.queue_watchdog)
            self.watchdog_thr.daemon = True
            self.watchdog_thr.start()

        self.class_logger.info("Starting queue processing.")
        if self.watchdog:
            if self.watchdog_thr is None:
                # First start
                self.class_logger.info("Command processor first start.")
                start_thr()
            else:
                if self.watchdog_thr.is_alive() is False:
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
                else:
                    self.class_logger.info("Command processor is already running.")
            return True
        else:
            self.class_logger.info("Queue processing start canceled. Reason - it is disabled.")
            return False

    def command_processor(self, cmd):
        """
        @brief  Processing command from queue.
        @param  cmd:  Command.
        @type  cmd:  dict
        @return:  None
        """
        # Truncating command for log message
        cmd1 = cmd.copy()
        try:
            cmd1.pop("report")
        except KeyError:
            pass
        self.class_logger.info("Start processing command: {0}.".format(cmd1))

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
            self.class_logger.debug("Processing {0} command.".format(r_type))
            try:
                self._reports[r_type.upper()][cmd['client']].process_cmd(cmd)
                if "close" in cmd:
                    self.class_logger.info("Closing {0} report.".format(r_type))
                    self.clients.closereport(cmd['client'], r_type)

            except Exception as err:
                self.class_logger.error("Error while processing command: {0}. ERROR: {1}".format(cmd, err))

                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback_message = traceback.format_exception(exc_type, exc_value,
                                                               exc_traceback)
                self.class_logger.error("Traceback:\n{0}".format("".join(traceback_message)))

    def is_idle(self):
        """
        @brief  Command processor idle status.
        @rtype:  bool
        @return:  True if command queue is empty and all clients are in closed state
        """
        self.class_logger.info("Last operation time: {0}".format(self.last_operation_time))
        qlen = self.queue.len()
        self.class_logger.info("Command queue length: {0}".format(qlen))
        cinprocess = self.clients.inprocess()
        self.class_logger.info("Clients in process: {0}".format(cinprocess))
        if qlen == 0 and len(cinprocess) == 0:
            return True
        else:
            return False

    def check_report_instance(self, r_type, client_id):
        """
        @brief  Create report instance if any for given client_id and build.
        @param  r_type:  report type.
        @type  r_type:  str
        @param  client_id:  Unique client name.
        @type  client_id:  str
        @return:  None
        """
        r_type = r_type.upper()
        if r_type not in self._reports:
            self._reports[r_type] = {}
#        if not build in self._reports[r_type]:
#            self._reports[r_type][build] = {}
        if client_id not in self._reports[r_type]:
            self._reports[r_type][client_id] = getattr(getattr(MODULES['reports.{0}'.format(r_type)], r_type), r_type)(connectors=self._connectors)

    def init_connectors(self):
        """
        @brief  Initializing connectors.
        """
        for mod in MODULES:
            if mod.startswith('connectors.'):
                arr = mod.split('.')
                self._connectors[arr[1]] = getattr(getattr(MODULES[mod], arr[1].upper()), arr[1].upper())()


def parse_options():
    """
    @brief  Parsing options.
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
    """
    @brief  Return free local port.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("", 0))
    _port = sock.getsockname()[1]
    sock.close()
    del sock
    return _port


def main(ppid):
    """
    @brief  Start standalone server.
    """
    def signal_handler(signum, frame):
        """
        @brief  Process termination signals.
        """
        mod_logger.info("Caught a signal={0}".format(signum))
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
    mod_logger.info("Log filename: {0}".format(loggers.LOG_FILENAME))

    xmlrpcsrv = XMLReportingServer()
    xmlrpcsrv.setup(opts)

    port = opts.port if opts.port is not None else get_local_port()

    # Create pid file with port inside
    # Reason: we need to launch server with variable port and need to get it's number.
    # We cannot catch server stdout (because if we do so, we break stdout logger)
    # So we use file for this.
    _vr_path = os.path.join("/tmp", "{0}.pid".format(ppid))
    _vr = None
    try:
        _vr = open(_vr_path, "w")
        _vr.write(str(port))
    except Exception as err:
        mod_logger.warning("Failed to create pid/port file {0}. Error:\n{1}".format(_vr_path, err))
        if not opts.port:
            # Raise exception in case RS should be started with random port.
            # Client cannot determinate RS port without file.
            raise
    finally:
        if _vr:
            _vr.close()

    reactor.listenTCP(int(port), server.Site(xmlrpcsrv))  # pylint: disable=no-member
    mod_logger.info("Listen on localhost:{0}".format(port))
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
