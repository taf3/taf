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

@file  hub.py

@summary  hub-specific functionality
"""

from . import loggers
from .custom_exceptions import HubException
from .xmlrpc_proxy import TimeoutServerProxy as xmlrpcProxy


class VlabHub(object):
    """
    @description  Class for simulated hub by Vlab.
    """

    class_logger = loggers.ClassLogger()

    def __init__(self, config, opts):
        """
        @brief  Initialize VlabHub class
        @param  config:  Configuration information.
        @type  config:  dict
        @param  opts:  py.test config.option object which contains all py.test cli options.
        @type  opts:  OptionParser
        @raise  HubException:  vlab is not present in configuration
        """
        self.id = config['id']
        self.type = config['instance_type']
        self.hub_id = config['hub_id']
        self.ports = config['ports']
        self.config = config
        self.opts = opts
        if "related_conf" in list(config.keys()):
            for rkey in list(config['related_conf'].keys()):
                if config['related_conf'][rkey]['instance_type'] == "vlab":
                    self.vlab_ip = config['related_conf'][rkey]['ip_host']
                    self.vlab_port = config['related_conf'][rkey]['ip_port']
        else:
            raise HubException("Cannot find vlab in given configuration.")
        self.xmlproxy = xmlrpcProxy("http://%s:%s/RPC2" % (self.vlab_ip, self.vlab_port), timeout=90)

    def create(self):
        """
        @brief  Creating simulated hub.
        """
        if not self.opts.get_only:
            return self.start()

    def destroy(self):
        """
        @brief  Stopping simulated hub.
        """
        if not self.opts.leave_on and not self.opts.get_only:
            return self.stop()

    def start(self):
        """
        @brief  Starting simulated hub.
        """
        self.class_logger.log(loggers.levels['INFO'], "Starting simulated hub with ID: %s" % (self.hub_id, ))
        self.xmlproxy.vlab.hub.create(self.hub_id)

    def stop(self):
        """
        @brief  Stopping simulated hub.
        """
        self.class_logger.log(loggers.levels['INFO'], "Stopping simulated hub with ID: %s" % (self.hub_id, ))
        self.xmlproxy.vlab.hub.destroy(self.hub_id)

    def check(self):
        """
        @brief  Checking simulated hub
        """
        pass

    def sanitize(self):
        """
        @brief  Sanitizing simulated hub.
        """
        pass
