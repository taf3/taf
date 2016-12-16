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

@file  pytest_reportingserver.py

@summary  XML-RPC reporting server plugin
"""
import os
from re import sub as re_sub
from socket import error as socket_error
from subprocess import Popen
import sys
import time
from xml.sax.saxutils import escape as xml_escape
from xmlrpc.client import ProtocolError as XmlrpcProtocolError
import errno
from abc import ABCMeta, abstractmethod

import pytest

from .pytest_helpers import get_tcname, get_suite_name, get_steps, get_brief
from testlib import loggers
from testlib.xmlrpc_proxy import TimeoutServerProxy as XMLRPCProxy


MODULES = {}
def imp_plugins(dest):
    """
    @brief  Import all py modules from <dest> subfolder.
    """
    _list = [os.path.splitext(_m)[0] for _m in os.listdir(os.path.join(os.path.dirname(__file__), dest))
             if not _m.startswith("_") and _m.endswith(".py")]
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), dest))
    sys.path.insert(0, os.path.dirname(__file__))
    for _m in _list:
        _module = "{0}.{1}".format(dest, _m)
        MODULES[_module] = __import__(_m)

imp_plugins("reports_conf")


class ReportingServerConfigBase(object, metaclass=ABCMeta):
    """
    @description  Reporting Server configuration
    """

    @abstractmethod
    def _additional_option(self):
        """
        @brief  Defining options for Reporting Server.
        """
        pass


def pytest_addoption(parser):
    """
    @brief  Plugin specific options.
    """
    [MODULES[_var].ReportingServerConfig._additional_option(parser) for _var in MODULES if "reports_conf." in _var]

    group = parser.getgroup("Reporting server", "plugin: reporting server")
    group.addoption("--tc_duration", action="store_true",
                    help="Use to show only duration only Test Case execution. Default = %default")

    group.addoption("--rs_port", action="store", default=None,
                    help="Bind to the already launched instance of reporting server listenning on port. %default by default.")


def pytest_configure(config):
    """
    @brief  Registering plugin
    @raise  Exception:  not able to connect to the reporting server
    """
    if_start_server = any([MODULES[_var].ReportingServerConfig._configure(config) for _var in MODULES if "reports_conf." in _var])
    if if_start_server:
        config.reportingserver = ReportingServer(config.option)
        config.pluginmanager.register(config.reportingserver, "reportingserver")

        if config.option.rs_port is None:
            config.reportingserver.launch_server()
        else:
            if not config.reportingserver.check_server(3):
                raise Exception("Cannot connect to reporting server on given port localhost:{0}".
                                format(config.option.rs_port))


def pytest_unconfigure(config):
    """
    @brief  Unregistering plugin
    """
    reportingserver = getattr(config, "reportingserver", None)
    if reportingserver:
        # Time sleep for assurance that server add close command to queue and going to dump xml report
        time.sleep(1)
        reportingserver.shutdown_server()
        del config.reportingserver
        config.pluginmanager.unregister(reportingserver)


class ReportingServer(object):
    """
    @description  Logging xmlrpc server class
    """
    REPORTINGSRV_PATH = "reporting_server.py"
    class_logger = loggers.ClassLogger()

    def __init__(self, opts):
        """
        @brief  Initialize ReportingServer class
        """

        self._opts = opts
        self.rs_port = opts.rs_port

        self._tc2id_map = {}
        self.xmlproxy = XMLRPCProxy("http://localhost:{0}".format(self.rs_port), allow_none=True)

        # _sessionstart launch status flag
        # _sessionstart should be launched only ones at the first runtest_call
        self._init_session = False

        # Setting build name : This is a test.
        # Setting build name
        self._buildname = None
        self.post_queue = []
        # duration of Test Case since pytest_setup to longrepr
        self.detailed_duration = dict()

        self.platform = 'undetermined'
        self.build = 'undetermined'

        # Get os username
        try:
            self.os_username = os.environ['SUDO_USER']
        except KeyError:
            self.os_username = os.environ['USER']

        self.self_name = "py.test-{0}-{1}".format(self.os_username, os.getpid())

    def buildname(self, env_prop=None):
        """
        @brief  Return buildname for current session
        @param  env_prop:  environment information e.g. build, name, etc.
        @type  env_prop:  dict
        @rtype:  str
        @return:  buildname
        """
        if self._buildname is not None:
            return self._buildname
        # Check cli options first
        get_build_name = [MODULES[_var].ReportingServerConfig._get_build_name(self._opts) for _var in MODULES if "reports_conf." in _var
                          if MODULES[_var].ReportingServerConfig._get_build_name(self._opts) is not None]
        if env_prop:
            self._buildname = "{0}-{1}".format(env_prop['switchppVersion'], env_prop['chipName'])
            self.platform = env_prop["chipName"]
            self.build = env_prop["switchppVersion"]
        else:
            message = "Cannot determinate buildname."
            self.class_logger.warning(message)
            # raise Exception(message)
#            return None

        if get_build_name and env_prop:
            self._buildname = "{0}-{1}".format(get_build_name[0], env_prop['chipName'])

        # WORKAROUND to add 'sanity' suffix to buildname
        if 'sanity' in self._opts.markexpr and self._buildname is not None:
            self._buildname += "-sanity"
        # WORKAROUND END
        return self._buildname

    def shutdown_server(self):
        """
        @brief  Send xmlrpc request to shutdown xmlrpc server
        """
        try:
            ans = self.xmlproxy.shutdown()
        except socket_error as err:
            self.class_logger.info("xmlrpc shutdown complete. (DEBUG: {0})".format(err))
        except XmlrpcProtocolError as err:
            self.class_logger.info("xmlrpc shutdown complete. (DEBUG: {0})".format(err))
        except Exception as err:
            self.class_logger.info("xmlrpc shutdown expected error: {0} - {1}".format(type(err), err))
        else:
            self.class_logger.info("xmlrpc shutdown query answer: %s" % (ans, ))
        # except socket.error, err:
        #   if err[0] == 111:
        #         print "!"*100
        #         print "ERR '{0}' handled".format(err)
        #   else:
        #         raise

    REPORTINGSRV_TIMEOUT = 30

    def launch_server(self, port=None):
        """
        @brief  Launch xmlrpc server
        @param  port:  port to launch xmlrpc server
        @type  port:  int
        """
        def wait_rc(popen, timeout=30):
            """
            @brief  Wait until popen finish execution
            """
            stop = False
            end_time = time.time() + timeout
            rc = None
            while not stop:
                rc = popen.poll()
                if time.time() > end_time:
                    stop = True
                    return rc
                if rc is not None:
                    stop = True
                    return rc
                else:
                    time.sleep(0.5)

        logdir = self._opts.logdir if self._opts.logdir is not None else os.curdir
        # server_path = os.path.join(os.path.dirname(__file__), self.REPORTINGSRV_PATH)
        server_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../reporting', self.REPORTINGSRV_PATH))
        cmd = [
            sys.executable,
            server_path,
            "--logdir={0}".format(logdir),
            "--loglevel={0}".format(self._opts.loglevel),
            "--silent",
            "--logprefix={0}".format(os.path.splitext(self.REPORTINGSRV_PATH)[0]),
        ]
        if port:
            cmd.append("--port={0}".format(port))

        popen = Popen(cmd)
        self.class_logger.debug("reporting server parent process PID - {0}".format(popen.pid))
        rc = wait_rc(popen)
        if rc != 0:
            message = "Failed to start XMLRPC server with command: {0}. Return code: {1}".format(" ".join(cmd), rc)
            self.class_logger.error(message)
            raise Exception(message)

        retry = 0
        _vr_path = os.path.join("/tmp", "{0}.pid".format(popen.pid))
        while port is None and retry < self.REPORTINGSRV_TIMEOUT:
            try:
                with open(_vr_path, "r") as _vr:
                    # Read server port number from file
                    port = int(_vr.read())
            except IOError as err:
                if err.errno == errno.ENOENT:
                    self.class_logger.warning("Sleeping until %s exists",
                                              _vr_path)
                    retry += 1
                    time.sleep(1)
            except Exception as err:
                self.class_logger.error("Cannot determinate reporting server port.")
                self.class_logger.error("Failed to open pid/port file {0}. Error:\n{1}".format(_vr_path, err))
                raise
        self.class_logger.info("Reporting server is listening on port {0}".format(port))

        self.rs_port = port
        self.xmlproxy = XMLRPCProxy("http://localhost:{0}".format(self.rs_port), allow_none=True)
        # Wait until xmlrpc server starts processing requests
        if not self.check_server(timeout=60):
            message = "XMLRPC Server does not respond."
            self.class_logger.error(message)
            raise Exception(message)

    def check_server(self, timeout=1):
        """
        @brief  Check if xmlrpc server is alive
        @param  timeout:  timeout for server verification
        @type  timeout:  int
        """
        ans = None
        end_time = time.time() + timeout
        while time.time() <= end_time:
            try:
                ans = self.xmlproxy.ping()
            except socket_error:
                time.sleep(1)
            except Exception as err:
                self.class_logger.warning("Unexpected type of error while checking xmlrpc server - {0} - {1}".format(type(err), err))
                time.sleep(1)
            else:
                if ans == "XMLReportingServer":
                    return True
                else:
                    message = "Unknown xmlrpc server is running on localhost:18080"
                    self.class_logger.error(message)
                    raise Exception(message)
        return False

    def server_cmd(self, cmd, args, retry=3):
        """
        @brief Send XML query to server with retry and exception handling
        @param  cmd:  command name
        @type  cmd:  str
        @param  args:  command arguments
        @type  args:  list
        @param  retry:  retry count
        @type  retry:  int
        """
        success = False
        _i = 1
        try:
            while not success and _i <= retry:
                _i += 1
                try:
                    getattr(self.xmlproxy, cmd)(*args)
                except socket_error:
                    self.class_logger.info("XMLRPC query {0}({1}) failed on {2} retry.".format(cmd, str(args), _i))
                    time.sleep(2 * _i)
                except KeyboardInterrupt:
                    self.class_logger.debug("Caught KeyboardInterrupt on server_cmd.")
                    self.pytest_sessionfinish(session=self)
                else:
                    success = True
        except Exception as err:
            self.class_logger.error("XMLRPC query {0}({1}) failed on {2} retry. Unexpected error type {3}: {4}".
                                    format(cmd, str(args), _i, type(err), err))
        if not success:
            self.class_logger.warning("XMLRPC query {0}({1}) failed.".format(cmd, str(args)))

    def _send_post_request(self, item):
        """
        @brief Send post request to reporting server or add it to queue
        @param  item:  test case item
        @type  item:  pytest.Item
        """
        tc_name = get_tcname(item)
        try:
            env_prop = item.config.env.env_prop
        except AttributeError:
            buildname = 'unspecified'
        else:
            buildname = self.buildname(env_prop)
        suite_name = get_suite_name(item.nodeid)
        info = {"brief": get_brief(item, tc_name), "description": get_steps(item, tc_name)}

        if self.post_queue:
            self._send_post_queue(item, buildname)
        self.server_cmd("post", [self.self_name, buildname, suite_name, tc_name, "Run", "", info, self._get_build_info(item)])

    def pytest_runtest_setup(self, item):
        """
        @brief Add info about test case start time
        @param  item:  test case item
        @type  item:  pytest.Item
        """
        if not item.config.option.tc_duration:
            self.detailed_duration[item.nodeid] = dict()
            self.detailed_duration[item.nodeid]['setup'] = time.time()

        if self._buildname is not None:
            self._send_post_request(item)

    @pytest.mark.tryfirst
    def pytest_runtest_call(self, item):
        """
        @brief  Create TC instance and send it to the Reporting Server
        @param  item:  test case item
        @type  item:  pytest.Item
        """
        if not item.config.option.tc_duration:
            self.detailed_duration[item.nodeid]['call'] = time.time()

        if self._buildname is None:
            self.buildname(item.config.env.env_prop)
            if self._buildname is not None and not self._init_session:
                self._sessionstart(item)
                self._init_session = True
            self._send_post_request(item)

    def _send_post_queue(self, item=None, buildname=None, sanity=False):
        """
        @brief  Send info about test execution to the Reporting Server
        @param  item:  test case item
        @type  item:  pytest.Item
        @param  buildname:  buildname
        @type  buildname:  str
        @param  sanity:  True if sanity test
        @type  sanity:  bool
        """

        if buildname is None:
            buildname = 'undetermined'
            if sanity:
                buildname += "-sanity"

            self.server_cmd("post", [self.self_name, buildname, "", "", "Run", "", "", self._get_build_info(item)])

        for post_req in self.post_queue:
            post_req[1] = buildname
            # Add empty description and brief. In synapsert new TC won't create
            post_req.append(('', ''))
            post_req.append(self._get_build_info(item))
            self.server_cmd("post", post_req)
        self.post_queue[:] = []

    def _get_build_info(self, item=None):
        """
        @brief  Get info about build
        @param  item:  test case item
        @type  item:  pytest.Item
        @rtype:  dict{"platform": str, "build": str}
        @return build info
        """

        if item is not None and item.config and hasattr(item.config, 'env')\
                and item.config.env and "chipName" in item.config.env.env_prop \
                and "switchppVersion" in item.config.env.env_prop and self.platform == 'undetermined':
            self.platform = item.config.env.env_prop["chipName"]
            self.build = item.config.env.env_prop["switchppVersion"]
        return {'platform': self.platform, 'build': self.build}

    def pytest_runtest_logreport(self, report):
        """
        @brief  Send update TC run status to the Reporting Server
        @param  report:  pytets report
        @type  report:  pytest.BaseReport
        """
        status = None
        if report.passed:
            # ignore setup/teardown
            if report.when == "call":
                status = "Passed"
        elif report.failed:
            if report.when in ["setup", "teardown"]:
                status = "Error"
            else:
                status = "Failed"
        elif report.skipped:
            status = "Skipped"
            # status = "Blocked"
        if not status and hasattr(report, 'monitor'):
            status = "Monitor"
        if status is not None:
            _report = {}
            _report['longrepr'] = ""
            _report['when'] = report.when
            if hasattr(report, "longrepr"):
                # Remove all bash escape sequences
                _report['longrepr'] = xml_escape(re_sub(r"\x1b.*?m", "", str(report.longrepr)))
                # longrepr = xml_unescape(re_sub(r"\x1b.*?m", "", report['longrepr']))
            if hasattr(report, "keywords") and "xfail" in report.keywords:
                _report['keywords'] = {}
                # TODO: check xfail in keywords because now it's number
                _report['keywords']['xfail'] = report.keywords['xfail']
            if hasattr(report, "sections"):
                _report['sections'] = []
                for i in range(len(report.sections)):
                    if isinstance(report.sections[i], str):
                        _report['sections'].append(xml_escape(report.sections[i]))
                # _report['sections'] = report.sections
            if hasattr(report, "duration"):
                if not self._opts.tc_duration and self.detailed_duration.get(report.nodeid) and self.detailed_duration.get(report.nodeid).get('call'):
                    _report['detailed_duration'] = dict()
                    _report['detailed_duration']['setup'] = \
                        self.detailed_duration.get(report.nodeid).get('call') - self.detailed_duration.get(report.nodeid).get('setup')
                    _report['detailed_duration']['longrepr'] = time.time() - self.detailed_duration.get(report.nodeid).get('call') - report.duration
                _report['duration'] = report.duration
            if hasattr(report, "retval"):
                _report['retval'] = report.retval
            if hasattr(report, "monitor"):
                _report['monitor'] = report.monitor
            tc_name = get_tcname(report)
            suite_name = get_suite_name(report.nodeid)
            if self.buildname() is not None:
                self.server_cmd("post", [self.self_name, self.buildname(), suite_name, tc_name, status, _report, "", self._get_build_info()])
            else:
                self.post_queue.append([self.self_name, self.buildname(), suite_name, tc_name, status, _report])

    def _sessionstart(self, item):
        """
        @brief  Tell to XMLRPC Server that we are going to interact with it
        @param  item:  test case item
        @type  item:  pytest.Item
        """
        self.class_logger.info("Configuring reporting server...")
        self.server_cmd("open", [self.self_name])
        for _var in MODULES:
            if "reports_conf." in _var:
                commands = MODULES[_var].ReportingServerConfig._sessionstart(self.class_logger, item, self.self_name,
                                                                               self.buildname(item.config.env.env_prop))
                for comm in commands:
                    self.server_cmd(*comm)
        # Order TM reporting to server.

        # Order and configure XML report to server.

    def pytest_sessionfinish(self, session):
        """
        @brief  Tell to XMLRPC Server that we have finished interaction
        @param  session:  test session
        @type  session:  pytest.Session
        """
        _buildname = self.buildname()
        if _buildname is None:
            if not self._init_session:
                self._sessionstart(session)

            if self.post_queue:
                if 'sanity' in self._opts.markexpr:
                    self._send_post_queue(session, sanity=True)
                else:
                    self._send_post_queue(session)
            self.class_logger.warning("Cannot determinate buildname. Probably test setup is failed. Skipping report.close step.")
        self.server_cmd("close", [self.self_name])

    def pytest_keyboard_interrupt(self, excinfo):
        """
        @brief  Handle KeyboardInterrupt
        @param  excinfo:  exception info
        @type  excinfo:  py.code.ExceptionInfo
        """
        self.class_logger.debug("Caught KeyboardInterrupt on pytest_hook.")
        self.pytest_sessionfinish(session=self)
