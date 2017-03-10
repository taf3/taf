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

"""``collectd.py``

`Class to abstract collectd operations`

Note:
    collectd.conf path is retrieved from testcases/config/setup/setup.json in format::

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

Examples of collectd usage in tests::

    # If required, stop running collectd service:
    env.lhost[1].ui.collectd.stop()

    # Start collectd service:
    env.lhost[1].ui.collectd.start()

Consistent and valid collectd.conf content is built from OrderedDict object, e.g.::

    python_plugin_config = collections.OrderedDict(
        (('ModulePath', '"/tmp/"'),
         ('Interactive', 'false'),
         ('Import', '"python_module_name"'),
         ('Module "python_module_name"', {'Test': 'arg1'})))

    env.lhost[1].ui.collectd.plugins_config = collections.OrderedDict(
        (('Interval', 3),
         ('AutoLoadPlugins', 'false'),
         ('LoadPlugin cpu', {}),
         ('LoadPlugin "csv"', {}),
         ('LoadPlugin "python"', {'Interval': 5, 'Globals': 'true'}),
         ('Plugin "csv"', {'DataDir': '"/tmp/csv_data/"'}),
         ('Plugin "python"', python_plugin_config)))

As shown above, config parts that depend on parameters order should be presented as OrderedDict objects.
Otherwise, dict() object can be used.

Transform data structure into multiline text block::

    env.lhost[1].ui.collectd.update_config_file()

If required, in other test the default plugins configuration may be changed, e.g.::

    env.lhost[1].ui.collectd.plugins_config['LoadPlugin "csv"'].update({'Interval': 9})
    env.lhost[1].ui.collectd.update_config_file()

Some plugins support multiple entries of parameter with same name.
Such case should be presented as::

    {param_name: [param1_value, ...]}

Example of resulting collectd.conf file::

    Interval 3
    AutoLoadPlugins false
    <LoadPlugin cpu>
    </LoadPlugin>
    <LoadPlugin "csv">
        Interval 9
    </LoadPlugin>
    <LoadPlugin "python">
        Interval 5
        Globals true
    </LoadPlugin>
    <Plugin "csv">
        DataDir "/tmp/csv_data/"
    </Plugin>
    <Plugin "python">
        ModulePath "/tmp/"
        Interactive false
        Import "python_module_name"
        <Module "python_module_name">
            Test arg1
        </Module>
    </Plugin>

Restart collectd service::

    env.lhost[1].ui.collectd.restart()

"""

import collections
from io import StringIO

from testlib.linux import service_lib
from testlib.custom_exceptions import CustomException

PARAM_BOILERPLATE = '{indent}{name} {value}\n'


def build_tagged_section(config_data, indent=None, buffer=None):
    """Fill in data into text block.

    Args:
        config_data(collections.Mapping):  plugins configuration data structure
        indent(int):  indentation level
        buffer(StringIO object):  resulting text block

    Returns:
        str:  resulting text block

    """
    if not buffer:
        buffer = StringIO()
    if not indent:
        indent = IndentationContext(buffer=buffer)
    for k, v in config_data.items():
        if isinstance(v, collections.Mapping):
            with TagContext(buffer, indent, *k.split(' ', 1)), indent:
                build_tagged_section(v, indent, buffer)
        elif not isinstance(v, str) and isinstance(v, collections.Iterable):
            buffer.write(''.join(PARAM_BOILERPLATE.format(indent=indent.pad, name=k, value=x) for x in v))
        else:
            buffer.write(PARAM_BOILERPLATE.format(indent=indent.pad, name=k, value=v))
    return buffer.getvalue()


class IndentationContext(object):
    def __init__(self, char=' ', count=4, buffer=None):
        super().__init__()
        self._char = char
        self._count = count
        self._pad = ''
        self._buffer = buffer

    @property
    def pad(self):
        return self._pad

    def __enter__(self):
        self._pad += self._char * self._count

    def __exit__(self, *args, **kwargs):
        self._pad = self._pad[:-self._count]


class TagContext(object):
    def __init__(self, buffer, indent, *tag_args):
        super().__init__()
        self._buffer = buffer
        self._indent = indent
        assert tag_args
        self._tag_args = tag_args

    def __enter__(self):
        self._buffer.write(self._indent.pad)
        self._buffer.write('<')
        self._buffer.write(' '.join(self._tag_args))
        self._buffer.write('>\n')

    def __exit__(self, *args, **kwargs):
        self._buffer.write(self._indent.pad)
        self._buffer.write('</')
        self._buffer.write(self._tag_args[0])
        self._buffer.write('>\n')


class Collectd(object):

    SERVICE = 'collectd'
    DEFAULT_COLLECTD_CONF = '/etc/collectd.conf'

    def __init__(self, cli_send_command, collectd_conf=None):
        """Initialize Collectd class.

        """
        super(Collectd, self).__init__()
        self.send_command = cli_send_command
        self.collectd_conf = collectd_conf if collectd_conf else self.DEFAULT_COLLECTD_CONF
        self.service_manager = service_lib.SpecificServiceManager(self.SERVICE, self.send_command)

        # Data structure presenting content of collectd.conf
        self.plugins_config = None

    def __getattr__(self, name):
        """Method for getting attribute from service_manager.

        Args:
            name(str):  attribute name

        """

        return getattr(self.service_manager, name)

    def __call__(self, cmd, expected_rc):
        """Overloaded call method.

        Args:
            cmd(str):  command to execute
            expected_rc(int | set | list | frozenset):  expected return code

        Returns:
            tuple: named tuple

        """

        return self.cli_send_command(cmd, expected_rcs=expected_rc)

    def update_config_file(self):
        """Create collectd configuration text and write it to collectd.conf file.

        """
        # Make provided collectd plugins configuration object accessible
        if not self.plugins_config:
            raise CustomException("No plugins config defined.")
        # Build up text block and make it accessible
        config_text = build_tagged_section(self.plugins_config)
        self.send_command('cat > {} <<EOF\n{}\nEOF'.format(self.collectd_conf, config_text))
