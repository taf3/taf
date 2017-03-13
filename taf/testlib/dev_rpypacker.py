"""
@copyright Copyright (c) 2017, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  dev_rpypacker.py

@summary  Remote Pypacker traffic generators specific functionality.
"""
import os
import time
import json
import pickle
import itertools
from xmlrpc.client import Fault
from contextlib import suppress
from collections import defaultdict

import pytest
import pypacker
from paramiko import SSHException

from . import loggers
from . import environment
from . import dev_linux_host
from .clissh import probe_port
from .xmlrpc_proxy import TimeoutServerProxy
from .custom_exceptions import PypackerException
from .packet_processor import PacketProcessor
from .entry_template import GenericEntry
from .tg_helpers import TGHelperMixin


class RemotePypackerTG(PacketProcessor, TGHelperMixin, GenericEntry):
    """
    @description  Class for launching pypacker on remote server

    @par  Configuration examples:

    @par  Remote Pypacker Example (pypacker instance on remote host):
    @code{.json}
    {
     "name": "RemotePypacker"
     "entry_type": "tg",
     "instance_type": "rpypacker",
     "id": "TG1",
     "ports": ["eth1", "eth2"],
     "ipaddr": "1.1.1.1",
     "ssh_user": "user",
     "ssh_pass": "PassworD"
    }
    @endcode
    @par  Where:
    \b entry_type and \b instance_type are mandatory values and cannot be changed for current device type.
    \n\b id - int or str uniq device ID (mandatory)
    \n\b name - User defined device name (optional)
    \n\b ports or \b port_list - short or long ports configuration (Only one of them has to be used)
    \n\b ipaddr - remote host IP address (mandatory)
    \n\b ssh_user - remote host login user (mandatory)
    \n\b ssh_pass - remote host login password (mandatory)
    \n\b ssh_port - remote host SSH port (optional. 22 is default)
    \n\b src_path - path to folder with pypacker_server.py and associated files (optional. Current module folder will be used by default)

    @note  You can safely add additional custom attributes. Only attributes described below will be analysed.
    """

    class_logger = loggers.ClassLogger()
    # Default xmlrpc port
    XMLRPC_PORT = 8899
    RUN_SERVER = "cd /tmp/; python3 -m {0} --loglevel=DEBUG --logdir={1} --ppfile={2}"

    def __init__(self, config, opts):
        """
        @brief  Initialize RemotePypackerTG class
        """
        super().__init__(config, opts)
        self.config = config
        self.opts = opts
        self.type = config['instance_type']
        self.id = config['id']
        self.name = self.config.get('name', 'UndefinedName_{0}'.format(self.id))
        self.ipaddr = config['ipaddr']
        self.reboot_latency = config.get('reboot_latency', 5)
        self.ssh_port = config.get('ssh_port', 22)
        self.port_list = config.get('port_list', [])
        self.ports = config.get('ports', [p[0] for p in self.port_list])
        # Set pypacker_server platform
        self._lhost = dev_linux_host.GenericLinuxHost(config, opts)
        self.randomize_port = True
        self.su_user = False
        self.ssh = self._lhost.ssh
        self.ltestlib_path = os.path.dirname(__file__)
        self.rpypacker_path = os.path.join('/tmp', 'rpypacker_{0}_{1}_{2}'.format(
                        os.uname()[1], os.getpid(), self.id))
        self.logdir = os.path.join(self.rpypacker_path, 'rpypacker_{0}_log'.format(self.id))
        self.xmlproxy = None
        self.status = None

    def __getattr__(self, attr):
        """
        @brief  Redirect all unknown calls to remote pypacker server.
        """
        if attr not in self.__dict__:
            return lambda *args, **kwargs: self._send_request(attr, *args, **kwargs)

    def _send_request(self, method, *args, **kwargs):
        """
        @brief  Send xmlrpc request to remote pypacker server.
        """
        try:
            return getattr(self.xmlproxy, method)(pickle.dumps(args), pickle.dumps(kwargs))
        except Fault as err:
            err_tye_and_msg = err.faultString[-1].strip()
            if "PypackerException: " in err_tye_and_msg:
                err_msg = err_tye_and_msg.split(": ", 1)[-1].strip(" '")
                raise PypackerException(err_msg)
            elif "Skipped: " in err_tye_and_msg:
                skip_msg = err_tye_and_msg.split(": ", 1)[-1].strip(" '")
                pytest.skip(skip_msg)
            else:
                raise

    def probe_port(self):
        """
        @brief  Check if server listen on port.
        """
        return probe_port(self.ipaddr, self.ssh_port, self.class_logger)

    def start(self, wait_on=True):
        """
        @brief  Copy files to remote host and start pypacker server.
        @param  wait_on:  Wait for device is loaded
        @type  wait_on:  bool
        @raise  PypackerException:  error on start
        """
        if not self.opts.get_only:
            self.class_logger.info("Wait for RPypacker host to become Up during %s seconds", self.reboot_latency)
            end_time = time.time() + self.reboot_latency
            timeout_iter = itertools.takewhile(lambda x: x < end_time,
                                               iter(time.time, -1))
            for _ in timeout_iter:
                if self.probe_port():
                    break
                time.sleep(1)
        if not self.ssh.login_status:
            self.ssh.login()
            self.ssh.open_shell()

        rtestlib_path = os.path.join(self.rpypacker_path, "rpypacker")
        ppfile_path = os.path.join(rtestlib_path, "pypacker_server.pp")

        # Clear dst filter if one exists
        command = "rm -rf {0}".format(rtestlib_path)
        self.ssh.exec_command(command)
        # Copy testlib directory to remote host
        self.copy_folder(self.ltestlib_path, rtestlib_path)

        self.class_logger.info("Launching RPypacker...")
        # Executes script using '-m' option to allow relative imports in package(PEP 366)
        rpypacker_package = rtestlib_path.strip('/tmp/').replace('/', '.') + ".pypacker_server"
        command = self.RUN_SERVER.format(rpypacker_package, self.logdir, ppfile_path)
        # Launching pypacker in shell because we don't have to wait exit code to avoid lock
        if not self.randomize_port:
            command += " --port={0}".format(self.XMLRPC_PORT)
        if self.su_user:
            command = "sudo {0}".format(command)
        self.ssh.send_command(command)

        # Wait until pypacker creates pid file
        end_time = time.time() + 20
        timeout_iter = itertools.takewhile(lambda x: x < end_time,
                                           iter(time.time, -1))
        command = "cat {0}".format(ppfile_path)
        for _ in timeout_iter:
            lport = self.ssh.exec_command(command).stdout
            if isinstance(lport, str) and lport.isdigit():
                break
            time.sleep(1)

        if not self.randomize_port:
            lport = self.XMLRPC_PORT
        elif not lport:
            with suppress(SSHException):
                self.class_logger.error("Pypacker start output:\n%s", self.ssh.shell_read())
            raise PypackerException("RPypacker port file isn't created or empty. Failed to configure connection.")

        self.class_logger.debug("RPypacker is listening on port %s.", lport)
        self.xmlproxy = TimeoutServerProxy("http://{0}:{1}".format(self.ipaddr, lport))
        self.xmlproxy.ping()
        # Configure remote pypacker.
        self.xmlproxy.setup(self.config, pickle.dumps(None))
        self.status = True

    def stop(self):
        """
        @brief  Shutdown remote pypacker server and cleanup directory.
        """
        # Cleanup platform first.
        self._lhost.cleanup()

        if not self.ssh.login_status:
            self.ssh.login()
            self.ssh.open_shell()
        # Get logs
        try:
            self.get_logs()
        except Exception as err:
            self.class_logger.error("Failed to copy logs from RPypacker server: %s", err)
        # Stopping pypacker server
        try:
            self.xmlproxy.shutdown()
        except Exception as err:
            self.class_logger.debug("Shutdown ReturnCode: %s", err)

        # Cleanup remote folder
        self.class_logger.debug("Cleanup remote pypacker folder: %s", self.rpypacker_path)
        command = "rm -rf {0}".format(self.rpypacker_path)
        self.ssh.exec_command(command)
        self.ssh.close()
        self.xmlproxy = None
        self.status = False

    def create(self):
        """
        @brief  Start RPypacker or get running one.

        @note  This is mandatory method for all environment classes.
               Also self.opts.get_only attribute affects logic of this method.
               get_only is set in py.test command line options (read py.test --help for more information).
        """
        return self.start()

    def destroy(self):
        """
        @brief  Stop or release RPypacker.

        @note  This is mandatory method for all environment classes.
               Also self.opts.leave_on and get_only  attributes affect logic of this method.
               leave_on and get_only are set in py.test command line options (read py.test --help for more information).
        """
        if not self.status:
            self.class_logger.info("Node id:%s(%s) status is Off. Skip destroying.",
                                   self.id, self.name)
            return

        self.stop()
        self.sanitize()

    def cleanup(self, *args, **kwargs):
        """
        @brief  Cleanup host.
        """
        self._lhost.cleanup()
        return self._send_request("cleanup", *args, **kwargs)

    def check(self):
        """
        @brief  Check host.
        """
        self._lhost.check()
        if self.xmlproxy is not None:
            self.xmlproxy.ping()

    def sanitize(self):
        """
        @brief  Perform any necessary operations to leave environment in normal state.
        """
        pass

    def copy_folder(self, src, dst):
        """
        @brief  Copy folder and subfolders to remote host.
        """

        src_list, dst_list = [], []
        for folder, _, files in os.walk(src):
            rfolder = folder.replace(src, dst)
            command = "mkdir -p {0}".format(rfolder)
            self.ssh.exec_command(command)
            src_list.extend([os.path.join(folder, f) for f in files if not f.endswith(".pyc")])
            dst_list.extend([os.path.join(rfolder, f) for f in files if not f.endswith(".pyc")])

        self.ssh.put_file(src_list, dst_list)

    def get_logs(self):
        """
        @brief  Get rpypacker runtime logs from remote host to local logdir.
        """
        # Don't get logs in case logdir isn't set
        if not loggers.LOG_DIR:
            return

        out = self.ssh.exec_command("ls -1 {0}".format(self.logdir)).stdout
        file_list = list(filter(None, out.split("\n")))
        self.class_logger.debug("Files to copy: %s", file_list)

        # Make rpypacker directory in main logdir
        dst_dir = os.path.join(loggers.LOG_DIR, os.path.basename(self.logdir))
        if not os.path.isdir(dst_dir):
            os.mkdir(dst_dir)
        src_list = (os.path.join(self.logdir, log_file) for log_file in file_list)
        dst_list = (os.path.join(dst_dir, log_file) for log_file in file_list)

        # copying files
        self.ssh.get_file(src_list, dst_list)

    def stop_sniff(self, *args, **kwargs):
        """
        @brief  Convert string packets back to Pypacker objects.
        """
        data_str = pickle.loads(self.xmlproxy.stop_sniff(args, kwargs).data)
        data = defaultdict(list)
        for iface in data_str:
            for _time, packet in data_str[iface]:
                packet = pypacker.layer12.ethernet.Ethernet(packet)
                # Restore original Pypacker timestamps
                packet.time = _time
                data[iface].append(packet)
        return data

    def connect_port(self, iface):
        """
        @copydoc  testlib::tg_template::GenericTG::connect_port()
        """
        self._lhost.ifconfig("up", [iface])

    def disconnect_port(self, iface):
        """
        @copydoc  testlib::tg_template::GenericTG::disconnect_port()
        """
        self._lhost.ifconfig("down", [iface])

    def get_port_txrate(self, iface):
        """
        @brief  Get port Tx rate
        """
        pytest.skip("Method is not supported by Pypacker TG")

    def get_port_rxrate(self, iface):
        """
        @brief  Get port Rx rate
        """
        pytest.skip("Method is not supported by Pypacker TG")

    def get_port_qos_rxrate(self, iface, qos):
        """
        @brief  Get ports Rx rate for specific qos
        """
        pytest.skip("Method is not supported by Pypacker TG")

    def get_qos_frames_count(self, iface, prio):
        """
        @brief  Get QoS packets count
        """
        pytest.skip("Method is not supported by Pypacker TG")

    def set_qos_stat_type(self, iface, ptype):
        """
        @brief  Set QoS stats type
        """
        pytest.skip("Method is not supported by Pypacker TG")

    def set_flow_control(self, iface, mode):
        """
        @brief  Set Flow Control
        """
        pytest.skip("Method is not supported by Pypacker TG")


class RemotePypackerMultipleTG(PacketProcessor, GenericEntry):
    """
    @description  Class for launching pypacker on remote servers or inside Linux network namespace

    @par  Configuration examples:

    @par  Remote Pypacker Example (pypacker instance on remote host):
    @code{.json}
    {
     "name": "RemotePypackerMultiHost"
     "entry_type": "tg",
     "instance_type": "rpypacker_multiple",
     "id": "TG1",
     "related_hosts": ["TG2", "TG3"]
     "ports": ["TG2 eth1", "TG3 eth2"]
    }
    @endcode
    @par  Where:
    \b entry_type and \b instance_type are mandatory values and cannot be changed
    for current device type.
    \n\b id - int or str unique device ID (mandatory)
    \n\b related_hosts - IDs of Remote hosts where RPypacker should be started
    \n\b name - User defined device name (optional)
    \n\b ports or \b port_list - short or long ports configuration
    (Only one of them has to be used)
    @endcode

    @note  You can safely add additional custom attributes.
    Only attributes described below will be analyzed.
    """

    class_logger = loggers.ClassLogger()

    def __init__(self, config, opts):
        """
        @brief  Initialize RemotePypackerMultiHostTG class
        """
        super().__init__(config, opts)
        self.config = config
        self.opts = opts
        self.type = config['instance_type']
        self.id = config['id']
        self.name = config.get('name', 'UndefinedName_{}'.format(self.id))
        # Initialize RPypacker instances
        # Read environment JSON file
        path_to_config = environment.get_conf_file(conf_name=opts.env, conf_type="env")
        with open(path_to_config) as f:
            env_config = json.loads(f)
        self.hosts = {x['name']: RemotePypackerTG(x, opts)
                      for x in env_config if x['id'] in config['related_hosts']}

        self.port_list = config.get('port_list', [])
        self.ports = config.get('ports', [p[0] for p in self.port_list])

        self.streams = []
        self.status = None

    @staticmethod
    def get_host_port(iface):
        """
        @brief  Return host name and port name based on iface name
        @param iface: interface name in format 'host_name port_name'
        @type  iface:  str
        @rtype:  tuple
        @return:  host name, port name
        """
        host, port = iface.split(' ', 1)
        return host, port

    def get_host_port_map(self, ifaces):
        """
        @brief  Return ports related to specific host
        @param ifaces: list of interface names in format 'host_name port_name'
        @type  ifaces:  list(str)
        @rtype:  dict
        @return:  dictionary in format {'host name': [port names]}
        """
        iface_map = defaultdict(list)
        for iface in ifaces:
            host, port = self.get_host_port(iface)
            iface_map[host].append(port)
        return iface_map

    def start(self, wait_on=True):
        """
        @brief  Start hosts.
        """
        for rhost in self.hosts.values():
            rhost.start()
        self.status = True

    def stop(self):
        """
        @brief  Shutdown remote pypacker server and cleanup directory.
        """
        for rhost in self.hosts.values():
            rhost.stop()

    def create(self):
        """
        @brief  Start RPypacker or get running one.

        @note  This is mandatory method for all environment classes.
               Also self.opts.get_only attribute affects logic of this method.
               get_only is set in py.test command line options (read py.test --help for more information).
        """
        for rhost in self.hosts.values():
            rhost.create()

    def destroy(self):
        """
        @brief  Stop or release RPypacker.

        @note  This is mandatory method for all environment classes.
               Also self.opts.leave_on and get_only  attributes affect logic of this method.
               leave_on and get_only are set in py.test command line options (read py.test --help for more information).
        """
        for rhost in self.hosts.values():
            rhost.destroy()

    def cleanup(self):
        """
        @brief  Cleanup host.
        """
        self.streams = []
        for rhost in self.hosts.values():
            rhost.cleanup()

    def check(self):
        """
        @brief  Check host.
        """
        for rhost in self.hosts.values():
            rhost.check()

    def sanitize(self):
        """
        @brief  Perform any necessary operations to leave environment in normal state.
        """
        self.streams = []
        for rhost in self.hosts.values():
            rhost.sanitize()

    def stop_sniff(self, *args, **kwargs):
        """
        @brief  Convert string packets back to pypacker objects.
        """
        iface_map = self.get_host_port_map(*args)
        data = defaultdict(list)

        for host, ifaces in iface_map.items():
            data_host = self.hosts[host].stop_sniff(ifaces, **kwargs)
            for iface in ifaces:
                data['{} {}'.format(host, iface)].append(data_host[iface])
        return data

    def connect_port(self, iface):
        """
        @copydoc  testlib::tg_template::GenericTG::connect_port()
        """
        host, port = self.get_host_port(iface)
        self.hosts[host].connect_port(port)

    def disconnect_port(self, iface):
        """
        @copydoc  testlib::tg_template::GenericTG::disconnect_port()
        """
        host, port = self.get_host_port(iface)
        self.hosts[host].disconnect_port(port)

    def clear_streams(self):
        """
        @brief  Stop and remove all streams
        """
        self.streams = []
        for host in self.hosts.values():
            host.clear_streams()

    def set_stream(self, *args, **kwargs):
        """
        @copydoc  testlib::tg_template::GenericTG::set_stream()
        """
        host, kwargs['iface'] = self.get_host_port(kwargs['iface'])
        stream_id = self.hosts[host].set_stream(*args, **kwargs)
        host_stream_id = '{} {}'.format(host, stream_id)
        self.streams.append(host_stream_id)
        return host_stream_id

    def send_stream(self, stream_id, **kwargs):
        """
        @copydoc  testlib::tg_template::GenericTG::send_stream()
        """
        host, stream = self.get_host_port(stream_id)
        self.hosts[host].send_stream(int(stream), **kwargs)

    def start_streams(self, stream_list):
        """
        @copydoc  testlib::tg_template::GenericTG::start_streams()
        """
        stream_map = self.get_host_port_map(stream_list)

        for host, streams in stream_map.items():
            self.hosts[host].start_streams(list(map(int, streams)))

    def stop_streams(self, stream_list=None):
        """
        @copydoc  testlib::tg_template::GenericTG::stop_streams()
        """
        if not stream_list:
            stream_list = self.streams
        stream_map = self.get_host_port_map(stream_list)

        for host, streams in stream_map.items():
            self.hosts[host].stop_streams(list(map(int, streams)))

    def start_sniff(self, ifaces, **kwargs):
        """
        @copydoc  testlib::tg_template::GenericTG::start_sniff()
        """
        iface_map = self.get_host_port_map(ifaces)

        for host, ports in iface_map.items():
            self.hosts[host].start_sniff(ports, **kwargs)

    def clear_statistics(self, sniff_port_list):
        """
        @brief  Clearing statistics on TG ports.
        """
        iface_map = self.get_host_port_map(sniff_port_list)

        for host, ports in iface_map.items():
            self.hosts[host].clear_statistics(ports)

    def get_received_frames_count(self, iface):
        """
        @brief  Read statistics - framesReceived
        """
        host, port = self.get_host_port(iface)
        return self.hosts[host].get_received_frames_count(port)

    def get_filtered_frames_count(self, iface):
        """
        @brief  Read statistics - filtered frames received
        """
        host, port = self.get_host_port(iface)
        return self.hosts[host].get_filtered_frames_count(port)

    def get_uds_3_frames_count(self, iface):
        """
        @brief  Read statistics - UDS3 - Capture Trigger (UDS3) -
        count of non-filtered received packets (valid and invalid)
        """
        host, port = self.get_host_port(iface)
        return self.hosts[host].get_uds_3_frames_count(port)

    def clear_received_statistics(self, iface):
        """
        @brief  Clear statistics
        """
        host, port = self.get_host_port(iface)
        return self.hosts[host].clear_received_statistics(port)

    def get_sent_frames_count(self, iface):
        """
        @brief  Read Pypacker statistics - framesSent
        """
        host, port = self.get_host_port(iface)
        return self.hosts[host].get_sent_frames_count(port)

    def get_port_txrate(self, iface):
        """
        @brief  Get port Tx rate
        """
        pytest.skip("Method is not supported by Pypacker TG")

    def get_port_rxrate(self, iface):
        """
        @brief  Get port Rx rate
        """
        pytest.skip("Method is not supported by Pypacker TG")

    def get_port_qos_rxrate(self, iface, qos):
        """
        @brief  Get ports Rx rate for specific qos
        """
        pytest.skip("Method is not supported by Pypacker TG")

    def get_qos_frames_count(self, iface, prio):
        """
        @brief  Get QoS packets count
        """
        pytest.skip("Method is not supported by Pypacker TG")

    def set_qos_stat_type(self, iface, ptype):
        """
        @brief  Set QoS stats type
        """
        pytest.skip("Method is not supported by Pypacker TG")

    def set_flow_control(self, iface, mode):
        """
        @brief  Set Flow Control
        """
        pytest.skip("Method is not supported by Pypacker TG")

    def get_os_mtu(self, iface=None):
        """
        @brief  Get OS MTU
        """
        host, port = self.get_host_port(iface)
        return self.hosts[host].get_os_mtu(port)

    def set_os_mtu(self, iface=None, mtu=None):
        """
        @brief  Set OS MTU
        """
        host, port = self.get_host_port(iface)
        return self.hosts[host].set_os_mtu(port, mtu)


ENTRY_TYPE = "tg"
INSTANCES = {"rpypacker": RemotePypackerTG,
             "rpypacker_multiple": RemotePypackerMultipleTG}
NAME = "tg"
