"""
@copyright Copyright (c) 2016-2017, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  collectd.py

@summary  Class to abstract collectd operations
@note
collectd.conf path is retrieved from testcases/config/setup/setup.json in format:
{
    "env": [
      {
        "id": "213207",
        "collectd_conf_path": "/opt/collectd/etc/collectd.conf"
      }
    ],
    "cross": {}
}
If "collectd_conf_path" is not specified in setup.json then default value is set: /etc/collectd.conf

Examples of collectd usage in tests:

env.lhost[1].ui.collectd.start()
env.lhost[1].ui.collectd.stop()
env.lhost[1].ui.collectd.restart()
env.lhost[1].ui.collectd.update_config_file()
"""

import os
import time
from collections import OrderedDict

from testlib.linux import service_lib


OPTION_BOILERPLATE = '{}{} {}'

TAG_BOILERPLATE = (
    "\n<{tag_name} {plugin_name}>"
    "{params}"
    "\n</{tag_name}>")


def _fill_text(tag_name, data):
    """
    @brief  Fill in data into text block

    @param  tag_name:  Tag name
    @type  tag_name:  str
    @param  data:  iterable containing plugin parameters
    @type  data:  dict | OrderedDict
    @return:  text block representing part of collectd configuration file
    @rtype:  str
    """
    text = ''
    for name, params in data.items():
        opts = ''
        for key, value in params.items():
            opts = os.linesep.join([opts, OPTION_BOILERPLATE.format('\t', key, value)])
        text = ''.join([text, TAG_BOILERPLATE.format(tag_name=tag_name,
                                                     plugin_name='{}'.format(name),
                                                     params=opts)])
    return text


class Collectd(object):

    SERVICE = 'collectd'
    DEFAULT_COLLECTD_CONF = '/etc/collectd.conf'

    def __init__(self, cli_send_command, collectd_conf=None):
        """
        @brief Initialize Collectd class.
        """
        super(Collectd, self).__init__()
        self.send_command = cli_send_command
        self.collectd_conf = collectd_conf if collectd_conf else self.DEFAULT_COLLECTD_CONF
        self.service_manager = service_lib.specific_service_manager_factory(self.SERVICE, self.send_command)

        # Below objects types: dict() | OrderedDict()
        # Global options: OrderedDict([(param1_name: param1_value), ...]}
        self.global_options = OrderedDict()
        # LoadPlugin data: OrderedDict([(plugin_name: {param1_name: param1_value}), ...]
        self.loadplugin_tags = OrderedDict()
        # Plugin data: OrderedDict([(plugin_name: {param1_name: param1_value}), ...]
        self.plugins_options = OrderedDict()

        self.config_text = ''

    def start(self):
        """
        @brief  Start collectd service
        """
        return self.service_manager.start()

    def stop(self):
        """
        @brief  Stop collectd service
        """
        return self.service_manager.stop()

    def restart(self):
        """
        @brief  Restart collectd service
        """
        return self.service_manager.restart()

    def update_config_file(self):
        """
        @brief  Create collectd configuration text and write it to collectd.conf file
        """
        # Form configuration text blocks from data structures
        global_opts_text = os.linesep.join(OPTION_BOILERPLATE.format('', k, v) for k, v in self.global_options.items())
        loadplugin_text = _fill_text("LoadPlugin", self.loadplugin_tags)
        plugins_opts_text = _fill_text("Plugin", self.plugins_options)

        # Keep resulting configuration for possible data extraction/parsing
        self.config_text = os.linesep.join([global_opts_text, '', loadplugin_text, '', plugins_opts_text])
        self.send_command('cat > {} <<EOF\n{}\nEOF'.format(self.collectd_conf, self.config_text))
        # Make sure that following collectd service start will use updated configuration
        time.sleep(1)
