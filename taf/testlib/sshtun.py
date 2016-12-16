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

@file  sshtun.py

@summary  Setup ssh tunnel with local port forwarding.
"""

import select
import socket
import socketserver
from threading import Thread
import time

import paramiko

from . import loggers


def get_local_port():
    """
    @brief  Get port.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("", 0))
    _port = sock.getsockname()[1]
    sock.close()
    del sock
    return _port


class ForwardHandlerMixin(socketserver.BaseRequestHandler):
    """
    @description  Base class of port forwarding handler.
    """
    class_logger = loggers.ClassLogger()

    def setup(self):
        """
        @brief  Set connection timeout.
        """
        self.request.settimeout(3)

    def handle(self):
        """
        @brief  Processing incoming request.
        """
        peername = self.request.getpeername()

        try:
            channel = self.transport.open_channel("direct-tcpip",
                                                  (self.remote_host, self.remote_port),
                                                  peername)
        except Exception as err:
            self.class_logger.warning("Failed to process incoming request to {0}:{1}. Error: {2}".
                                      format(self.remote_host, self.remote_port, err))
            return

        if channel is None:
            self.class_logger.warning("Incoming request to {0}:{1} is rejected by the SSH server.".
                                      format(self.remote_host, self.remote_port))
            return

        ch_peername = channel.getpeername()
        self.class_logger.debug("Processing request: " + str(peername[0]) + ":" + str(peername[1]) +
                                "->" + str(ch_peername[0]) + ":" + str(ch_peername[1]) +
                                "->" + str(self.remote_host) + ":" + str(self.remote_port))

        __timeout = 350
        end_time = time.time() + __timeout
        while True:
            if time.time() > end_time:
                self.class_logger.error("Request timed out: " + str(peername[0]) + ":" + str(peername[1]))
                break
            rlist, _, _ = select.select([self.request, channel], [], [], 60)
            if self.request in rlist:
                data = self.request.recv(1024)
                if len(data) == 0:
                    break
                channel.send(data)
                end_time = time.time() + __timeout
            if channel in rlist:
                data = channel.recv(1024)
                if len(data) == 0:
                    break
                self.request.send(data)
                end_time = time.time() + __timeout

        channel.close()
        self.request.close()
        self.class_logger.debug("Request is processed: " + str(peername[0]) + ":" + str(peername[1]))


class ForwardServer(socketserver.TCPServer):
    """
    @brief  Preconfigured SocketServer.TCPServer.
    """
    daemon_threads = True
    allow_reuse_address = True


class SSHTunnel(object):
    """
    @description  Main class for creating ssh tunnel.
    """

    class_logger = loggers.ClassLogger()

    def __init__(self, server, user, passwd, remote, local_port=None, local_host="127.0.0.1"):
        """
        @brief  Initialize SSHTunnel class
        @param  server:  Server information in format [ip, port]
        @type  server:  list | tuple
        @param user:  Username
        @type  user:  str
        @param passwd:  Password
        @type  passwd:  str
        @param remote:  Remote server information in format [ip, port]
        @type  remote:  list | tuple
        @param local_port:  Local port assigned for forwarding
        @type  local_port:  int
        @param local_host: Local IP to listen on, defaults to 127.0.0.1
        @type local_host: str
        """
        self.srv = server
        self.usr = user
        self.passwd = passwd
        self.remote = remote
        self.local = local_port
        self.local_port = None
        self.local_host = local_host
        self.server = None
        self.transport = None
        self.ssh_client = None
        self.thr = None

    def fwdport(self):
        """
        @brief  Launch port forwarding server.
        """
        # Taken from paramiko examples.
        # SocketServer doesn't give Handlers any way to access the outer server normally.

        class FHandler(ForwardHandlerMixin):
            """
            @description  Get configuration of  forwarding server.
            """
            remote_host = self.remote[0]
            remote_port = self.remote[1]
            transport = self.transport
            class_logger = loggers.ClassLogger()

        self.local_port = self.local or get_local_port()
        self.class_logger.debug("Try to setup port forwarding: {0} -> {1}:{2} ...".
                                format(self.local_port, self.remote[0], self.remote[1]))

        self.server = ForwardServer((self.local_host, self.local_port), FHandler)
        self.server.serve_forever()

    def connect(self):
        """
        @brief  Perform ssh connection.
        @raise  Exception:  error on connect
        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        self.class_logger.info("Establishing ssh connection to host {0}:{1} ...".format(self.srv[0], self.srv[1]))
        try:
            client.connect(self.srv[0], self.srv[1],
                           username=self.usr, password=self.passwd,
                           key_filename=None, look_for_keys=False)
            self.class_logger.info("SSH connection is established.")
        except Exception as err:
            self.class_logger.error("Failed to connect to {0}:{1}. Error: {2}".
                                    format(self.srv[0], self.srv[1], err))
            self.stop()
            raise

        self.ssh_client = client
        self.transport = client.get_transport()
        # Set keepalive to be aware if transport is active.
        self.transport.set_keepalive(15)

    def start(self, timeout=60):
        """
        @brief  Perform ssh connection and start port forwarding server in thread.
        @param  timeout:  Port forwarding configuration timeout
        @type  timeout:  int
        @raise  Exception:  timeout exceeded on start
        """
        self.connect()
        if self.ssh_client and self.transport:
            self.thr = Thread(target=self.fwdport)
            self.thr.start()
            # Add timeout to fwdport function.
            end_time = time.time() + timeout
            while self.server is None:
                if time.time() < end_time:
                    time.sleep(0.1)
                else:
                    raise Exception("SSH tunnel TCP Server isn't started in {0} seconds.".format(timeout))
        else:
            self.ssh_client = None
            self.transport = None

    def stop(self):
        """
        @brief  Stop port forwarding server and thread.
        """
        if self.server is not None:
            self.class_logger.debug("Stop port forwarding: {0} -> {1}:{2}".
                                    format(self.local_port, self.remote[0], self.remote[1]))
            self.server.shutdown()
            self.local_port = None
            self.server = None
            self.ssh_client.close()
            self.transport = None
            self.ssh_client = None
        self.class_logger.info("Stopping fwdport thread ...")
        if self.thr is not None and not self.thr.is_alive():
            self.class_logger.info("fwdport thread isn't started. Skipping stop procedures.")
            return
        if self.thr is not None:
            self.thr.join()
        self.thr = None

    def establish(self):
        """
        @brief  Start sshtun server and wait while connection is established.
        @raise  Exception:  timeout exceeded
        @rtype:  int
        @return:  local port
        """
        if self.thr is not None and self.thr.is_alive():
            self.class_logger.info("fwdport thread already started. Checking ...")
            if self.check():
                self.class_logger.info("Transport is active. Skip start tunnel procedures.")
                return
            else:
                self.close()
        self.class_logger.info("Starting fwdport thread ...")
        self.start()
        end_time = time.time() + 60
        while True:
            if self.local_port is not None:
                time.sleep(0.5)
                break
            if time.time() > end_time:
                self.stop()
                raise Exception("Timeout exceeded. Local port isn't set and port forwarding isn't established.")
            time.sleep(0.21)
        return self.server.socket.getsockname()[1]

    def close(self):
        """
        @brief  Close sshtun server.
        """
        self.class_logger.info("Stopping fwdport thread ...")
        self.stop()

    def check(self):
        """
        @brief  Return True if connection is established.
        """
        if self.transport:
            return self.transport.is_active()
        else:
            return False

    def __del__(self):
        """
        @brief  Try to close connection on object destroy.
        """
        self.class_logger.debug("SSHTunnel object has to be deleted. Try to stop forwarding if it is active.")
        self.stop()
