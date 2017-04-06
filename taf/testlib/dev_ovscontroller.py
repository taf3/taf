# Copyright (c) 2016 - 2017, Intel Corporation.
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

"""``dev_ovscontroller.py``

`OVS Nox controller specific functionality`

"""
# TODO track creation of separate module to work with external processes and use it's functionality.

import os
import sys
import time
import socket
import traceback
import subprocess as subprocess
import json
import signal
# from types import NoneType

import pytest

from . import entry_template
from . import loggers
from .sendjsoncommand import SendJsonCommand as JsonCommand
from .restfloodlight import RestFloodlightController as FloodlightCommand
from .xmlrpc_proxy import TimeoutServerProxy as xmlrpcProxy
from .custom_exceptions import OvsControllerException
from .sshtun import get_local_port


NoneType = type(None)


class OvsControllerGeneralMixin(entry_template.GenericEntry):
    """General pattern class for OVS Controller objects.

    """
    class_logger = loggers.ClassLogger()

    def __init__(self, config):
        """Initialize OvsControllerGeneralMixin class.

        Args:
            config(dict):  Configuration information.

        """
        self.val = config['related_id'][0]
        self.sw_type = config['related_conf'][self.val]['instance_type']
        if 'ip_host' in list(config.keys()):
            self.ipaddr = config['ip_host']
        else:
            self.ipaddr = self.__get_ovs_controller_iface(self.sw_type)
        self.json_ipaddr = config['json_iphost']
        self.port = config['json_ipport']
        self.cport = config['ip_port']
        self.id = config['id']
        self.type = config['instance_type']
        self.path = config['path']
        self.adcomponent = config['ad_component']
        self.name = config['name']
        # This variable indicates if devices is On(True) or Off(False)
        self.status = False

    def __get_ovs_controller_iface(self, switchtype):
        """Get OVS controller interface.

        Args:
            switchtype(str):  Switch type.

        Returns:
            str:  OVS controller interface

        """
        ifaces_list = []
        cmd = "ifconfig"
        if_cmd = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE)
        ifaces_list = if_cmd.stdout.read().strip().split('\n')
        ifaces_list.append(" ")
        if_cmd.terminate()

        i = 0
        raw_ifaces_dict = {}
        table_lines_list = []
        for line in ifaces_list:
            if line.strip():
                table_lines_list.append(line.strip())
            else:
                if len(table_lines_list) > 0:
                    raw_ifaces_dict.update({i: table_lines_list})
                    table_lines_list = []
                    i += 1
        ifaces_dict = {}
        for dict_key in raw_ifaces_dict:
            for list_line_idx, value in enumerate(raw_ifaces_dict[dict_key]):
                if raw_ifaces_dict[dict_key][list_line_idx].split()[0] == 'tun3':
                    ifaces_dict['tun3'] = raw_ifaces_dict[dict_key][list_line_idx + 1].split()[1].split(':')[1]
                elif raw_ifaces_dict[dict_key][list_line_idx].split()[0] == 'br0':
                    ifaces_dict['br0'] = raw_ifaces_dict[dict_key][list_line_idx + 1].split()[1].split(':')[1]
                elif 'eth' in raw_ifaces_dict[dict_key][list_line_idx].split()[0]:
                    ifaces_dict[raw_ifaces_dict[dict_key][list_line_idx].split()[0]] = raw_ifaces_dict[dict_key][list_line_idx + 1].split()[1].split(':')[1]
        if switchtype == "lxc":
            if 'br0' in list(ifaces_dict.keys()):
                return ifaces_dict['br0']
        elif 'eth0' in list(ifaces_dict.keys()):
            return ifaces_dict['eth0']
        elif 'eth1' in list(ifaces_dict.keys()):
            return ifaces_dict['eth1']

    def get_ovs_controller_ports(self, cport=None, port=None):
        """Get OVS controller ports.

        Args:
            cport(int):  Controller's port.
            port(int):  Device's port.

        Returns:
            tuple(int, int):  Controller's port and device's port

        """
        def _check_if_port_if_free(port):
            """Check if port is free.

            """
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind(('', port))
                sock.close()
                del sock
                return True
            except socket.error:
                return False

        res1 = False
        res2 = False
        if port and cport:
            res1 = _check_if_port_if_free(cport)
            res2 = _check_if_port_if_free(port)
        elif port and not cport:
            cport = get_local_port()
            res1 = _check_if_port_if_free(cport)
            res2 = _check_if_port_if_free(port)
        elif cport and not port:
            port = get_local_port()
            res1 = _check_if_port_if_free(cport)
            res2 = _check_if_port_if_free(port)
        if res1 and res2:
            pass
        elif res1 and not res2:
            port = get_local_port()
        elif res2 and not res1:
            cport = get_local_port()
        else:
            cport = get_local_port()
            sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock1.bind(('', cport))
            port = get_local_port()
            sock1.close()
            del sock1
        return cport, port

    def probe_port(self):
        """Establishing a connection to a remote host.

        Returns:
            bool:  True if connection is established

        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.json_ipaddr, int(self.port)))
            sock.close()
            return True
        except Exception:
            return False

    def probe(self):
        """Check Ovs Controller instance.

        Returns:
            dict:  Ovs Controller status

        """
        _object = {'isup': False, 'type': "unknown", 'prop': {}}
        if self.probe_port():
            _object['isup'] = True
        try:
            # Try to wait until controller is ready to process
            time.sleep(2)
            ans = self.cmdproxy.probe()
            if ans:
                _object['type'] = "ovscontroller"
                self.class_logger.info("Found a running OVS controller on %s:%s." % (self.json_ipaddr, self.port, ))
        except Exception as err:
            self.class_logger.debug("Error probing Ovs Controller port: %s" % (err,))
        self.class_logger.info(str(_object))
        return _object

    def waiton(self, timeout=30):
        """Waiting until Ovs Controller is up.

        Args:
            timeout(int):  Waiting timeout

        Raises:
            OvsControllerException:  timeout exceeded

        Returns:
            dict:  Ovs Controller status

        """
        status = None
        message = "Waiting until OVS controller on %s port #%s is up." % (self.json_ipaddr, self.port, )
        self.class_logger.info(message)
        stop_flag = False
        end_time = time.time() + timeout
        while not stop_flag:
            if loggers.LOG_STREAM:
                sys.stdout.write(".")
                sys.stdout.flush()
            if time.time() < end_time:
                time.sleep(2)
                status = self.probe()
                if status["isup"] and status["type"] == "ovscontroller":
                    stop_flag = True
                    self.class_logger.info("OVS Controller started on host %s port %s: " %
                                           (str(self.json_ipaddr), str(self.port)))
            else:
                self.class_logger.info(str(status))
                if status["isup"] and status["type"] != "ovscontroller":
                    message = "Port %s on host %s is busy. %s Check your environment! %s" % \
                              (self.port, self.json_ipaddr, self.waiton_err_message, str(status), )
                else:
                    message = "Timeout exceeded"
                self.class_logger.log(loggers.levels['WARNING'], message)
                raise OvsControllerException(message)
            time.sleep(2)
        return status

    def waitoff(self, timeout=30):
        """Waiting until Ovs Controller is down.

        Args:
            timeout(int):  Waiting timeout

        Raises:
            OvsControllerException:  timeout exceeded

        Returns:
            dict:  Ovs Controller status

        """
        status = None
        message = "Waiting until OVS controller on %s port #%s is down." % (self.ipaddr, self.port, )
        self.class_logger.info(message)
        stop_flag = False
        end_time = time.time() + timeout
        while not stop_flag:
            if loggers.LOG_STREAM:
                sys.stdout.write(".")
                sys.stdout.flush()
            if time.time() < end_time:
                status = self.probe()
                if (status["type"] == "unknown") and not status["isup"]:
                    stop_flag = True
            else:
                if status["isup"] and status["type"] == "ovscontroller":
                    message = "Timeout exceeded. The port %s on host %s is still open" % (self.port, self.ipaddr)
                    self.class_logger.log(loggers.levels['WARNING'], message)
                    raise OvsControllerException(message)
            time.sleep(2)
        return status

    def cleanup(self):
        """Mandatory method for environment specific switch classes.

        """
        pass

    def setprop(self, command, values):
        """Configuring command.

        Args:
            command(str):  XML-RPC command
            values(list):  command arguments

        """
        return getattr(self.cmdproxy, "%s" % (command, ))(*values)

    def getprop(self, command, values):
        """Mandatory method for environment specific switch classes.

        Args:
            command(str):  XML-RPC command
            values(list):  command arguments

        """
        pass

    def start(self):
        """Mandatory method for environment specific switch classes.

        """
        pass

    def stop(self):
        """Mandatory method for environment specific switch classes.

        """
        pass

    def restart(self):
        """Mandatory method for environment specific switch classes.

        """
        pass

    def get(self, init_start=False, retry_count=5):
        """Checking OVS Controller.

        Args:
            init_start(bool):  Flag to start OVS Controller
            retry_count(int):  Retry attempts count

        """
        first_loop = True
        # Try to restart if necessary at least several times
        retry = 1
        # If fail_ctrl != "restart", restart retries won't be performed
        if self.opts.fail_ctrl != "restart":
            retry_count = 1
        while retry <= retry_count:
            try:
                if first_loop:
                    if init_start:
                        self.start()
                    else:
                        self.waiton()
                else:
                    self.restart()
                retry = retry_count + 1
            except Exception:
                self.class_logger.info("Error while checking Ovs Controller %s:%s..." % (self.ipaddr, self.port))
                retry += 1
                first_loop = False
                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback_message = traceback.format_exception(exc_type, exc_value, exc_traceback)
                message = "Error while checking Ovs Controller %s:%s:\n%s" % (self.ipaddr, self.port, "".join(traceback_message))
                sys.stderr.write(message)
                sys.stderr.flush()
                self.class_logger.log(loggers.levels['ERROR'], message)
                if retry >= retry_count + 1:
                    sys.stderr.write("Could not restart Ovs Controller for %s times. Something goes wrong \n" % (retry_count, ))
                    sys.stderr.flush()
                    if self.opts.fail_ctrl == "stop":
                        pytest.exit(message)
                    else:
                        pytest.fail(message)

    def check(self):
        """Checking OVS Controller.

        Returns:
            dict:  OVS Controller status

        """
        if not self.status:
            self.class_logger.info("Skip OVS Controller id:%s(%s) check because it's has Off status." % (self.id, self.name))
            return
        return self.waiton()

    def create(self):
        """Start OVS Controller.

        """
        if not self.opts.get_only:
            init_start = True
        else:
            init_start = False
        return self.get(init_start=init_start)

    def destroy(self):
        """Destroy OVS Controller.

        """
        if not self.status:
            self.class_logger.info("Skip OVS Controller id:%s(%s) destroying because it's has already Off status." % (self.id, self.name))
            return
        if not self.opts.leave_on and not self.opts.get_only:
            return self.stop()

    def sanitize(self):
        """Perform any operations to leave device in consistent state after py.test interruption.

        """
        pass

    def _get_pid(self, name):
        """Get pid of OVS controller process.

        Args:
            name(str):  Process's name

        Returns:
            int:  Process ID

        """
        running_processes = os.popen("ps -ef | grep -v grep | grep %s" % (name, ))
        process_list = running_processes.read().split('\n')
        self.class_logger.debug(process_list)
        running_processes.close()
        if len(process_list[0]) > 0:
            self.class_logger.debug(process_list[0].split(' '))
            process_pid = int(process_list[0].split(' ')[1])
            return process_pid
        else:
            return None

    def _check_pid(self):
        """Check for the existence of a unix pid.

        Returns:
            bool:  True if process exists

        """
        try:
            if self.pid:
                os.kill(self.pid, 0)
            else:
                raise OSError
        except OSError:
            return False
        else:
            return True

    def waitpid(self, timeout=45):
        """Wait until OVS Controller process terminates.

        Args:
            timeout(int):  Waiting timeout

        Raises:
            OvsControllerException:  timeout exceeded

        """
        stop_flag = False
        stop_time = time.time() + timeout
        while not stop_flag:
            if not self._check_pid():
                stop_flag = True
            if time.time() > stop_time:
                message = "Timeout exceeded. The PID %s still exists." % (self.pid, )
                self.class_logger.log(loggers.levels['WARNING'], message)
                raise OvsControllerException(message)
            time.sleep(1)


class NoxControllerLocal(OvsControllerGeneralMixin):
    """Local Nox Controller class.

    """
    class_logger = loggers.ClassLogger()

    def __init__(self, config, opts):
        """Initialize NoxControllerLocal class.

        Args:
            config(dict):  Configuration information.
            opts(OptionParser):  py.test config.option object which contains all py.test cli options.

        """
        super(NoxControllerLocal, self).__init__(config)
        self.popen = None
        self.pid = None
        self.opts = opts
        self.cmdproxy = JsonCommand(self.json_ipaddr, self.port)
        self.waiton_err_message = "OVS controller is started but does not respond."

        # Update status to On(True) in case --get_only option is selected.
        self.status = self.opts.get_only

    def start(self):
        """Starts Nox Controller on specified host.

        Raises:
            Exception:  error on start

        """
        process = None
        if self.json_ipaddr not in ["localhost", "127.0.0.1"]:
            message = "Only local environment is supported at the moment."
            self.class_logger.log(loggers.levels['ERROR'], message)
            raise OvsControllerException(message)
        # TODO: Add possibility to run Nox Controller instances on remote hosts using paramiko.

        if self.adcomponent == "pyswitch":
            try:
                process = subprocess.Popen(["%s" % (os.path.join(os.path.curdir, "nox_core"),), "-v", "--verbose=ANY:syslog:DBG", "-i", "ptcp:%s:%s" %
                                            (self.ipaddr, str(self.cport), ),
                                            "jsonmessenger", self.adcomponent, "pyloop", "-v", "-v"], cwd=self.path, universal_newlines=True,
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            except Exception as err:
                self.class_logger.log(loggers.levels['ERROR'], str(err))
                raise err
        else:
            try:
                process = subprocess.Popen(["%s" % (os.path.join(os.path.curdir, "nox_core"),), "-v", "--verbose=ANY:syslog:DBG", "-i", "ptcp:%s:%s" %
                                            (self.ipaddr, str(self.cport), ),
                                            "jsonmessenger", "pyloop", "-v", "-v"], cwd=self.path, universal_newlines=True,
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

            except Exception as err:
                self.class_logger.log(loggers.levels['ERROR'], str(err))
                raise err

        # Wait until device is up and running:
        self.waiton()
        # Set status to On (True)
        self.status = True
        self.pid = process.pid
        self.popen = process

    def stop(self):
        """Stops Nox Controller.

        Raises:
            OvsControllerException:  error on stop

        """
        try:
            # Try to stop
            try:
                if self.popen is not None:
                    res = self.popen.kill()
                    del self.pid
                else:
                    self.pid = self._get_pid("nox")
                    if self.pid:
                        res = os.kill(self.pid, signal.SIGKILL)
                        del self.pid
            except Exception:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback_message = traceback.format_exception(exc_type, exc_value, exc_traceback)
                message = "Error while terminating Nox Controller:\n%s" % "".join(traceback_message)
                self.class_logger.log(loggers.levels['ERROR'], message)
                raise OvsControllerException(message)
            else:
                if not isinstance(res, NoneType):
                    message = "Error stopping Nox Controller"
                    self.class_logger.log(loggers.levels['ERROR'], message)
                    raise OvsControllerException(message)
                # Wait util controller stops
                self.waitoff(timeout=60)
            finally:
                self.popen = None

        # If popen.terminate call didn't work, try to kill by PID
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback_message = traceback.format_exception(exc_type, exc_value, exc_traceback)
            message = "Error while destroying Nox Controller:\n%s" % "".join(traceback_message)
            self.class_logger.log(loggers.levels['ERROR'], message)

            # Check Switch PID
            if self._check_pid():
                self.pid = self._get_pid("nox")
                if self.pid:
                    os.kill(self.pid, 9)
                    self.pid = None
            else:
                message = "The Nox Controller with PID=%s was already killed or died." % self.pid
                self.class_logger.log(loggers.levels['WARN'], message)
                raise OvsControllerException(message)

        # Set Off(False) status
        self.status = False

    def restart(self):
        """Restarts Nox Controller.

        """
        self.stop()
        return self.start()

    def getprop(self, command, values):
        """Configure command.

        Args:
            command(str):  XML-RPC command
            values(list):  command arguments

        Returns:
            Property value

        """
        prop = json.loads(getattr(self.cmdproxy, "%s" % (command, ))(*values))
        if "data" in list(prop.keys()):
            prop["data"] = json.loads(prop["data"])
            return prop
        else:
            return prop


class FloodlightControllerLocal(OvsControllerGeneralMixin):
    """Local Floodlight Controller class.

    """
    class_logger = loggers.ClassLogger()

    def __init__(self, config, opts):
        """Initialize FloodlightControllerLocal class.

        Args:
            config(dict):  Configuration information.
            opts(OptionParser):  py.test config.option object which contains all py.test cli options.

        """
        super(FloodlightControllerLocal, self).__init__(config)
        self.popen = None
        self.pid = None
        self.opts = opts
        self.cmdproxy = FloodlightCommand(self.json_ipaddr, self.port)
        self.waiton_err_message = "Ovs controller is started but does not respond."
        self.popen_logfile = "ovscontroller%s.output.log" % (self.id, )

        # Update status to On(True) in case --get_only option is selected.
        self.status = self.opts.get_only

    def start(self):
        """Starts Floodlight Controller on specified host.

        Raises:
            OvsControllerException:  not local environment
            Exception:  error on start

        """
        log_wrap_out, log_wrap_err = loggers.pipe_loggers("ovscontroller%s" % (self.id, ), self.popen_logfile)

        process = None
        if self.json_ipaddr not in ["localhost", "127.0.0.1"]:
            message = "Only local environment is supported at the moment."
            self.class_logger.log(loggers.levels['ERROR'], message)
            raise OvsControllerException(message)
        self.cport, self.port = self.get_ovs_controller_ports(cport=self.cport, port=self.port)
        self.cmdproxy = FloodlightCommand(self.json_ipaddr, self.port)
        # TODO: Add possibility to run Floodlight Controller instances on remote hosts using paramiko.
        if self.adcomponent == "forwarding":
            try:
                process = subprocess.Popen(["/usr/bin/java", '-Dnet.floodlightcontroller.core.FloodlightProvider.openflowport=%s' % (str(self.cport), ),
                                            '-Dnet.floodlightcontroller.restserver.RestApiServer.port=%s' % (self.port, ),
                                            '-jar', 'floodlight.jar', '-cf',
                                           '../src/main/resources/learningswitch.properties'], cwd=self.path, universal_newlines=True,
                                           stdin=subprocess.PIPE, stdout=log_wrap_out, stderr=log_wrap_err, shell=False)
            except Exception as err:
                self.class_logger.log(loggers.levels['ERROR'], str(err))
                raise err
        else:
            try:
                process = subprocess.Popen(["/usr/bin/java", '-Dnet.floodlightcontroller.core.FloodlightProvider.openflowport=%s' % (str(self.cport), ),
                                            '-Dnet.floodlightcontroller.restserver.RestApiServer.port=%s' % (str(self.port), ),
                                            '-jar', 'floodlight.jar', '-cf',
                                           '../src/main/resources/simple.properties'], cwd=self.path, universal_newlines=True,
                                           stdin=subprocess.PIPE, stdout=log_wrap_out, stderr=log_wrap_err, shell=False)
            except Exception as err:
                self.class_logger.log(loggers.levels['ERROR'], str(err))
                raise err
        # Wait until device is up and running:
        self.waiton()
        # Set On(True) status
        self.status = True
        self.pid = process.pid
        self.popen = process

    def stop(self):
        """Stops Floodlight Controller.

        Raises:
            OvsControllerException:  error on stop

        """
        try:
            # Try to stop
            try:
                if self.popen is not None:
                    res = self.popen.kill()
                    self.pid = self._get_pid("floodlight")
                    if self.pid:
                        res = os.kill(self.pid, signal.SIGKILL)
                        self.pid = None
                else:
                    self.pid = self._get_pid("floodlight")
                    if self.pid:
                        res = os.kill(self.pid, signal.SIGKILL)
                        self.pid = None
            except Exception:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback_message = traceback.format_exception(exc_type, exc_value, exc_traceback)
                message = "Error while terminating Floodlight Controller:\n%s" % "".join(traceback_message)
                self.class_logger.log(loggers.levels['ERROR'], message)
                raise OvsControllerException(message)
            else:
                if self.popen is not None:
                    if not isinstance(res, NoneType):
                        message = "Error stopping Floodlight Controller"
                        self.class_logger.log(loggers.levels['ERROR'], message)
                        raise OvsControllerException(message)
                # Wait until controller stops
                self.waitoff(timeout=60)
                # Wait until process terminates
            finally:
                self.popen = None

        # If popen.terminate call didn't work, try to kill by PID
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback_message = traceback.format_exception(exc_type, exc_value, exc_traceback)
            message = "Error while destroying Floodlight Controller:\n%s" % "".join(traceback_message)
            self.class_logger.log(loggers.levels['ERROR'], message)

            # Check Switch PID
            if self._check_pid():
                self.pid = self._get_pid("floodlight")
                if self.pid:
                    os.kill(self.pid, 9)
                    self.pid = None
            else:
                message = "The Floodlight Controller with PID=%s was already killed or died." % self.pid
                self.class_logger.log(loggers.levels['WARN'], message)
                raise OvsControllerException(message)
        # Set Off(False) status
        self.status = False

    def restart(self):
        """Restarts Floodlight Controller.

        """
        self.stop()
        return self.start()

    def getprop(self, command, values):
        """Configure command.

        Args:
            command(str):  XML-RPC command
            values(list):  command arguments

        Returns:
            Property value

        """
        return getattr(self.cmdproxy, "%s" % (command, ))(*values)


class OFtestControllerLocal(OvsControllerGeneralMixin):
    """Local OFtest Controller class.

    """
    class_logger = loggers.ClassLogger()

    def __init__(self, config, opts):
        """Initialize OFtestControllerLocal class.

        Args:
            config(dict):  Configuration information.
            opts(OptionParser):  py.test config.option object which contains all py.test cli options.

        """
        super(OFtestControllerLocal, self).__init__(config)
        self.popen = None
        self.pid = None
        self.opts = opts
        self.cmdproxy = xmlrpcProxy("http://%s:%s/RPC2" % (self.json_ipaddr, self.port), timeout=180)
        self.waiton_err_message = "OVS controller is started but does not respond."
        self.popen_logfile = "ovscontroller%s.output.log" % (self.id, )
        # Update status to On(True) in case --get_only option is selected.
        self.status = self.opts.get_only

    def start(self):
        """Starts OFtest Controller on specified host.

        Raises:
            OvsControllerException:  not local environment
            Exception:  error on start

        """
        log_wrap_out, log_wrap_err = loggers.pipe_loggers("ovscontroller%s" % (self.id, ), self.popen_logfile)

        process = None
        if self.json_ipaddr not in ["localhost", "127.0.0.1"]:
            message = "Only local environment is supported at the moment."
            self.class_logger.log(loggers.levels['ERROR'], message)
            raise OvsControllerException(message)
        # TODO: Add possibility to run Floodlight Controller instances on remote hosts using paramiko.
        self.cport, self.port = self.get_ovs_controller_ports(cport=self.cport, port=self.port)
        self.cmdproxy = xmlrpcProxy("http://%s:%s/RPC2" % (self.json_ipaddr, self.port), timeout=180)
        try:
            process = subprocess.Popen(["/usr/bin/python", "oftest_controller.py", self.ipaddr, str(self.cport), str(self.port)], cwd=self.path,
                                       universal_newlines=True, stdin=subprocess.PIPE, stdout=log_wrap_out, stderr=log_wrap_err, shell=False, env=os.environ)
        except Exception as err:
            self.class_logger.log(loggers.levels['ERROR'], str(err))
            raise err
        # let's wait until device is up and running:
        self.waiton()
        # Set On(True) status
        self.status = True
        self.pid = process.pid
        self.popen = process

    def stop(self):
        """Stops OFtest Controller.

        Raises:
            OvsControllerException:  error on stop

        """
        try:
            # Try to stop
            try:
                if self.popen is not None:
                    res = self.popen.kill()
                    self.pid = self._get_pid("oftest")
                    if self.pid:
                        res = os.kill(self.pid, signal.SIGKILL)
                        self.pid = None
                    del self.pid
                else:
                    self.pid = self._get_pid("oftest")
                    if self.pid:
                        res = os.kill(self.pid, signal.SIGKILL)
                        self.pid = None
            except Exception:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback_message = traceback.format_exception(exc_type, exc_value, exc_traceback)
                message = "Error while terminating OFtest Controller:\n%s" % "".join(traceback_message)
                self.class_logger.log(loggers.levels['ERROR'], message)
                raise OvsControllerException(message)
            else:
                if self.popen is not None:
                    if not isinstance(res, NoneType):
                        message = "Error stopping OFtest Controller"
                        self.class_logger.log(loggers.levels['ERROR'], message)
                        raise OvsControllerException(message)
                # Wait util controller stops
                self.waitoff(timeout=60)
            finally:
                self.popen = None

        # If popen.terminate call didn't work, try to kill by PID
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback_message = traceback.format_exception(exc_type, exc_value, exc_traceback)
            message = "Error while destroying OFtest Controller:\n%s" % "".join(traceback_message)
            self.class_logger.log(loggers.levels['ERROR'], message)

            # Check Switch PID
            if self._check_pid():
                self.pid = self._get_pid("oftest")
                if self.pid:
                    os.kill(self.pid, 9)
                    self.pid = None
            else:
                message = "The OFtest Controller with PID=%s was already killed or died." % self.pid
                self.class_logger.log(loggers.levels['WARN'], message)
                raise OvsControllerException(message)
        # Set Off(False) status
        self.status = False

    def restart(self):
        """Restarts OFtest Controller.

        """
        self.stop()
        return self.start()

    def getprop(self, command, values):
        """Configure command.

        Args:
            command(str):  XML-RPC command
            values(list):  command arguments

        Returns:
            Property value

        """
        return json.loads(getattr(self.cmdproxy, "%s" % (command, ))(*values))


class OvsControllerRemote(OvsControllerGeneralMixin):
    """Remote Controller class.

    """
    # TODO: Add functionality for remote Ovs Controller instances using paramiko.
    class_logger = loggers.ClassLogger()

    def __init__(self, config, opts):
        """Initialize OvsControllerRemote class.

        Args:
            config(dict):  Configuration information.
            opts(OptionParser):  py.test config.option object which contains all py.test cli options.

        """
        super(OvsControllerRemote, self).__init__(config)
        self.popen = None
        self.pid = None
        self.opts = opts
        self.cmdproxy = JsonCommand(self.json_ipaddr, self.port)
        # Update status to On(True) in case --get_only option is selected.
        self.status = self.opts.get_only

    def _check_pid(self):
        """Check For the existence of a unix pid.

        """
        pass

    def waitpid(self, timeout=45):
        """Wait until Nox Controller process terminates.

        Args:
            timeout(int):  Waiting timeout

        """
        pass

    def start(self):
        """Starts Nox Controller on specified host.

        """
        # Set On(True) status
        self.status = True

    def stop(self):
        """Stops Nox Controller.

        """
        # Set Off(False) status
        self.status = False

    def restart(self):
        """Restarts Nox Controller on specified host.

        """
        pass


ENTRY_TYPE = "ovscontroller"
INSTANCES = {"local_floodlight": FloodlightControllerLocal, "local_nox": NoxControllerLocal,
             "local_oftest": OFtestControllerLocal, "remote_ovs": OvsControllerRemote, }
NAME = "ovscontroller"
