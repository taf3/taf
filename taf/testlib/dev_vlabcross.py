#! /usr/bin/env python
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

@file  dev_vlabcross.py

@summary  ONS Vlab virtual cross specific functionality.
"""

from os.path import join as os_path_join
import sys
import time
import socket
from subprocess import Popen

from . import loggers
from . import environment
from . import dev_basecross

from .custom_exceptions import CrossException
from .xmlrpc_proxy import TimeoutServerProxy as xmlrpcProxy


class VlabEnv(dev_basecross.GenericXConnectMixin):
    """
    @description  Vlab from device viewpoint.
    """

    class_logger = loggers.ClassLogger()
    DEFAULT_TIMEOUT = 1

    def __init__(self, config, opts):
        """
        @brief  Initialize VlabEnv class
        @param  config:  Configuration information.
        @type  config:  dict
        @param  opts:  py.test config.option object which contains all py.test cli options.
        @type  opts:  OptionParser
        @raise  CrossException:  error in vlab path
        """
        self.id = config['id']
        self.type = config['instance_type']
        self.ipaddr = config['ip_host']
        self.port = config['ip_port'] if "ip_port" in config else "8050"
        self.ifaces = config['ports']
        self.opts = opts
        # Do xconnect on create?
        self.autoconnect = config['autoconnect'] if "autoconnect" in config else True

        self.related_conf = {}
        if "related_conf" in list(config.keys()):
            self.related_conf = config['related_conf']

        self.tgmap = []
        if "tgmap" in list(config.keys()):
            self.tgmap = config['tgmap']
        if "portmap" in list(config.keys()):
            self.portmap = config['portmap']

        if "bridged_ifaces" in list(config.keys()):
            self.bridged_ifaces = config['bridged_ifaces']
            self.ports_count = len(self.ifaces) - len(self.bridged_ifaces)
        else:
            self.ports_count = len(self.ifaces)
        self.bind_iface = config['ip_iface'] if "ip_iface" in config else None

        self.build_path = environment.get_absolute_build_path(opts.build_path)
        if not self.build_path:
            raise CrossException("Could not find vlab binaries path - %s." % (opts.build_path, ))
        self.class_logger.info("Vlab binaries path: %s." % (self.build_path, ))
        self.xmlproxy = xmlrpcProxy("http://%s:%s/RPC2" % (self.ipaddr, self.port), timeout=45)

        self.popen = None
        self.popen_logfile = "vlab%s.output.log" % (self.id, )

        # Set On/Off(True/False) status according to get_only option.
        self.status = self.opts.get_only

    def probe_port(self):
        """
        @brief  Establishing a connection to a remote host.
        @rtype:  bool
        @return:  True if connection is established
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect((self.ipaddr, int(self.port)))
            sock.close()
            return True
        except Exception:
            return False

    def probe(self):
        """
        @brief  Check if Vlab instance is run
        @rtype:  dict
        @return:  Vlab status
        """
        result = {'isup': False, 'type': "unknown", 'prop': {}}
        if self.probe_port():
            result['isup'] = True
            try:
                instance_prop = self.xmlproxy.vlab.sysinfo()
                result['type'] = "vlab"
                result['prop'] = instance_prop
                self.class_logger.info("Found a running vlab instance on %s:%s." % (self.ipaddr, self.port, ))
                self.class_logger.info("Revision: %s" % result['prop']['revision'])
            except Exception:
                pass
        return result

    def waiton(self, timeout=30):
        """
        @brief  Waiting until Vlab port is up.
        @param  timeout:  Waiting timeout
        @type  timeout:  int
        @raise  CrossException:  error on vlab start
        @rtype:  dict
        @return:  Vlab status
        """
        status = None
        message = "Waiting until vlab on %s port #%s is up." % (self.ipaddr, self.port, )
        self.class_logger.info(message)
        stop_flag = False
        end_time = time.time() + timeout
        while not stop_flag:
            if loggers.LOG_STREAM:
                sys.stdout.write(".")
                sys.stdout.flush()
            if time.time() < end_time:
                status = self.probe()
                if status["isup"] and status["type"] == "vlab":
                    stop_flag = True
                    self.class_logger.info(("VLAB started on host %(host)s port %(port)s: " +
                                            "uptime - %(uptime)s, workdir - %(workdir)s, hostname - %(hostname)s," +
                                            "xmlRpcPort - %(xmlRpcPort)s, port - %(xport)s, revision - %(revision)s") %
                                           {'host': self.ipaddr, 'port': self.port, 'uptime': status['prop']['uptime'],
                                            'workdir': status['prop']['workdir'],
                                            'hostname': status['prop']['hostname'], 'xmlRpcPort': status['prop']['xmlRpcPort'],
                                            'xport': status['prop']['port'], 'revision': status['prop']['revision']})
            else:
                if status["isup"] and status["type"] != "vlab":
                    message = (("Port %s on host %s is busy. " +
                                "Check if vlab already started or other application use the same port.") %
                               (self.port, self.ipaddr))
                else:
                    message = "Timeout exceeded."
                self.class_logger.warning(message)
                raise CrossException(message)
            if not stop_flag:
                time.sleep(self.DEFAULT_TIMEOUT)
        return status

    def waitoff(self, timeout=30):
        """
        @brief  Waiting until Vlab port is down.
        @param  timeout:  Waiting timeout
        @type  timeout:  int
        @raise  CrossException: error on vlab stop
        @rtype:  dict
        @return:  Vlab status
        """
        status = None
        message = "Waiting until vlab on %s port #%s is down." % (self.ipaddr, self.port, )
        self.class_logger.info(message)
        stop_flag = False
        end_time = time.time() + timeout
        while not stop_flag:
            if loggers.LOG_STREAM:
                sys.stdout.write(".")
                sys.stdout.flush()
            if time.time() < end_time:
                status = self.probe_port()
                if not status:
                    stop_flag = True
            else:
                if status:
                    message = "Timeout exceeded. The port %s on host %s is still open" % (self.port, self.ipaddr)
                    self.class_logger.warning(message)
                    raise CrossException(message)
            if not stop_flag:
                time.sleep(self.DEFAULT_TIMEOUT)
        message = "Waiting until vlab process with %d pid stop" % (self.popen.pid, )
        self.class_logger.info(message)
        while True:
            if loggers.LOG_STREAM:
                sys.stdout.write(".")
                sys.stdout.flush()
            if time.time() < end_time:
                if self.popen.poll() is not None:
                    self.class_logger.info("Exit code of the vlab process with PID %s = %s" %
                                           (self.popen.pid, self.popen.poll()))
                    break
            else:
                message = "Timeout exceeded. Vlab process with PID %d still exists." % (self.popen.pid, )
                self.class_logger.warning(message)
                raise CrossException(message)
            time.sleep(self.DEFAULT_TIMEOUT)

    def start(self):
        """
        @brief  Starts vlab based on provided host and port info with specified number of interfaces.
        @raise  CrossException:  not local environment, vlab is stopped
        @raise  Exception:  error on vlab start
        """
        def check_rc():
            """
            @brief  Checking Vlab process.
            """
            rc = process.poll()
            if rc is not None:
                raise CrossException("Vlab process is terminated with signal %s." % (rc, ))

        process = None
        bin_path = os_path_join(self.build_path, "bin", "vlab")
        # TODO: Add possibility to run vlab instance on remote hosts, any port using paramiko.
        if (self.ipaddr != "localhost") and (self.port != "8050"):
            message = "Only local environment is supported at the moment."
            self.class_logger.error(message)
            raise CrossException(message)
        try:
            self.class_logger.info("Starting Vlab on %s:%s" % (self.ipaddr, self.port))
            command_lst = [bin_path, "-v", "%s" % (self.ports_count, )]
            if hasattr(self, "bridged_ifaces"):
                for b_iface in self.bridged_ifaces:
                    command_lst.append("-P")
                    command_lst.append(b_iface)
            self.class_logger.debug("Start command: %s" % (" ".join(command_lst), ))
            log_wrap_out, log_wrap_err = loggers.pipe_loggers("vlab%s" % (self.id, ), self.popen_logfile)
            process = Popen(command_lst, stdout=log_wrap_out, stderr=log_wrap_err,
                            cwd=self.build_path, env={"LD_LIBRARY_PATH": os_path_join(self.build_path, "lib")})
            check_rc()
        except Exception as err:
            self.class_logger.error("Error executing vlab Popen process.")
            self.class_logger.error(str(err))
            raise
        # let's wait until device is up and running:
        self.waiton()
        self.popen = process

        check_rc()

        self.status = True

    def stop(self):
        """
        @brief  Stops vlab based on provided host and port info.
        @raise  CrossException:  error on vlab stop
        """
        if not self.popen:
            message = "No Popen object exists for Vlab. Exiting stop() method without processing."
            self.class_logger.error(message)
            raise CrossException(message)
        # Send xmlrpc shutdown query
        result = self.xmlproxy.system.shutdown("")
        if result is not 0:
            message = "Error stopping vlab instance. XMLRPC query response = %s" % (result, )
            self.class_logger.error(message)
            raise CrossException(message)
        else:
            # let's wait until device is fully stopped:
            self.waitoff()

        self.status = False

    def restart(self):
        """
        @brief  Restarting Vlab instance.
        """
        try:
            self.stop()
        except Exception as err:
            self.class_logger.warning("Fail to stop vlab instance with error: %s" % err)
        finally:
            self.start()

    def check(self):
        """
        @brief  Checking Vlab instance status.
        """
        if self.status:
            self.waiton()
        else:
            self.class_logger.info("Skip check method for vlab id:%s because it has Off status." % (self.id, ))


class VlabCross(VlabEnv):
    """
    @description  Vlab from xconnect viewpoint.
    """

    class_logger = loggers.ClassLogger()

    def _get_ports_from_config(self, connection=None):
        """
        @brief  Get ports from configuration.
        @param  connection:  Connection info in format [sw1, port1, sw2, port2]
        @type  connection:  list
        @raise  CrossException:  unsupported connection type
        @raise  ValueError:  error in configuration file
        @rtype:  list
        @return:  Ports from configuration
        """

        def get_port(conn):
            """
            @brief  Get port ID.
            """
            # If device linked to another via bridged interface
            if hasattr(self, 'portmap'):
                for elem in self.portmap:
                    if conn == elem[:2]:
                        return [0, elem[2] - 1]

            # If device id in connection == vlab id or id of related TG
            if conn[0] == self.id or conn[0] in self.tgmap:
                # Return vlab self id and vlab port id from list of ifaces
                return [0, conn[1] - 1]

            # other devices Id.
            else:
                for rkey in list(self.related_conf.keys()):
                    rconf = self.related_conf[rkey]
                    if rconf['id'] == conn[0] and rconf['entry_type'] == "switch":
                        # Return switch ID and port ID from config
                        # [devId: conf_port_Id] --> [devId: port_Id_for_vlab]
                        # E.G.
                        # conn = [1, 3]
                        # rconf = {'id': 1, ports: ["5", "6", "7"]}
                        # conf_port_id = 3, real_dev_port_id = "7", port_Id_for_vlab = 6 = (7 - 1)
                        # Vlab port list index start from 0, but switch port index from 1, so do -1
                        # Switch ID = PortNo - 8080. E.g. 8082 - 8080 = 2
                        return [int(rconf['ip_port']) - 8080, int(rconf['ports'][conn[1] - 1]) - 1]
                    elif rconf['id'] == conn[0] and rconf['entry_type'] == "hub":
                        return [rconf['hub_id'], int(rconf['ports'][conn[1] - 1]) - 1]
                    elif rconf['id'] == conn[0] and not rconf['entry_type'] in ["switch", "hub"]:
                        message = "Only connections to switch, hub or Vlab itself are supported. But found entry type = %s" % rconf['entry_type']
                        self.class_logger.error(message)
                        raise CrossException(message)
        # Part 1
        vconn1 = get_port(connection[:2])
        # Part 2
        vconn2 = get_port(connection[2:])

        try:
            vconn_full = vconn1 + vconn2
            return vconn_full
        except Exception:
            raise ValueError("Cannot make requested connection. Check config. Got following args: %s, %s" % (vconn1, vconn2))

    def xconnect(self, connection):
        """
        @brief  Create single connection
        @param  connection:  Connection info in format [sw1, port1, sw2, port2]
        @type  connection:  list
        """
        vconn = self._get_ports_from_config(connection)
        self.class_logger.debug("Connect VLAB ports: %s" % vconn)
        return self.xmlproxy.vlab.cross.connect(vconn[0], vconn[1], vconn[2], vconn[3])

    def xdisconnect(self, connection):
        """
        @brief  Destroy single connection
        @param  connection:  Connection info in format [sw1, port1, sw2, port2]
        @type  connection:  list
        """
        vconn = self._get_ports_from_config(connection)
        self.class_logger.debug("Disconnect VLAB ports: %s" % vconn)
        return self.xmlproxy.vlab.cross.disconnect(vconn[0], vconn[1], vconn[2], vconn[3])

    def cross_connect(self, conn_list):
        """
        @brief  Make connections between switches
        @param  conn_list:  Set of connections in format: [[sw1, port1, sw2, port2], ... ]
        @type  conn_list:  list[list]
        @raise  CrossException:  devices from conn_list are not in related configurations,
                                 error on connection creation
        @rtype:  bool
        @return:  True  if success or raise an error if connections were not created.
        @par  Example:
        @code
        cross_connect([[0, 1, 1, 1], [0, 2, 1, 2]])
        @endcode
        """
        if self.related_conf and conn_list:
            list_id = []
            for conn in conn_list:
                list_id.append(conn[0])
                list_id.append(conn[2])
            if set(self.related_conf.keys()) != set(list_id):
                message = ("Set of cross connected devices %s is not appropriate related config %s."
                           % (list(set(list_id)), list(set(self.related_conf.keys()))))
                self.class_logger.error(message)
                raise CrossException(message)
        for conn in conn_list:
            # make connections
            self.class_logger.info("Make connection %(sw1)s,%(port1)s, and %(sw2)s,%(port2)s." %
                                   {'sw1': conn[0], 'port1': conn[1], 'sw2': conn[2], 'port2': conn[3]})
            if self.xconnect(conn) == 0:
                message = "Cannot create connection: %s" % conn
                self.class_logger.error(message)
                raise CrossException(message)
        return True

    def cross_disconnect(self, disconn_list):
        """
        @brief  Destroy connections between switches
        @param  disconn_list:  Set of connections in format: [[sw1, port1, sw2, port2], ... ]
        @type  disconn_list:  list[list]
        @raise  CrossException:  error on connection destroying
        @rtype:  bool
        @return  True if success or False if connections were not destroyed.
        @par  Example:
        @code
        cross_disconnect([[0, 1, 1, 1], [0, 2, 1, 2]])
        @endcode
        """
        # Destroy connections using Virtual Lab
        for conn in disconn_list:
            self.class_logger.info("Destroy connection %(sw1)s,%(port1)s, and %(sw2)s,%(port2)s." %
                                   {'sw1': conn[0], 'port1': conn[1], 'sw2': conn[2], 'port2': conn[3]})
            if self.xdisconnect(conn) == 0:
                message = "Cannot destroy connection: %s" % conn
                self.class_logger.error(message)
                raise CrossException(message)
        return True

    def cross_clear(self):
        """
        @brief  Clear all connections between switches
        @raise  CrossException:  error on connections clearing
        @rtype:  bool
        @return  True if success or False if all connections were not cleared.
        @par  Example:
        @code
        cross_clear(env)
        @endcode
        """
        self.class_logger.info("Clear all connections.")
        if self.xmlproxy.vlab.cross.clear() == 0:
            message = "Cannot clear all connections"
            self.class_logger.error(message)
            raise CrossException(message)
        return True


ENTRY_TYPE = "cross"
INSTANCES = {"vlab": VlabCross}
NAME = "cross"
