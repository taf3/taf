"""
@copyright Copyright (c) 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  suricata.py

@summary  Suricata support and helpers
"""
import os
import yaml

from testlib.linux import tool_general

from testlib.linux.commands import suricata_cmd


class Suricata(tool_general.GenericTool):
    """
    """
    def __init__(self, run_command):
        """
        @brief  Initialize Suricata class
        @param run_command: function that runs the actual commands
        @type run_command: function
        """
        super(Suricata, self).__init__(run_command, 'suricata')

    def start(self, prefix=None, options=None, command=None, **kwargs):
        """
        @brief  Generate suricata command, launch it and store results in the file
        @param prefix: command prefix
        @type  prefix: str

        @param options: intermediate iperf options list
        @type  options: list of str
        @param command: intermediate iperf command object
        @type  command: Command

        @rtype:  dict
        @return:  suricata instance process info
        """
        # intermediate operands in 'command' and 'options', if any,  prevail in this
        # respective order and overrule the (both default and set) method arguments
        cmd = suricata_cmd.CmdSuricata(**kwargs)
        if options:
            _opts_cmd = suricata_cmd.CmdSuricata(options)
            cmd.update(_opts_cmd)

        if command:
            cmd.update(command)

        cmd.check_args()
        _args_list = cmd.to_args_list()

        # TODO: do we need timeout with systemd?
        cmd_time = cmd.get('time', 10)
        timeout = int(cmd_time) + 30 if cmd_time else 60

        cmd_list = [prefix, self.tool] if prefix else [self.tool]

        if _args_list:
            cmd_list.extend(_args_list)

        cmd_str = ' '.join(map(str, cmd_list))
        instance_id = super(Suricata, self).start(cmd_str, timeout=timeout)
        process_info = self.instances[instance_id]
        process_info['launch_args'] = _args_list
        return process_info


class SuricataHelper(object):
    """
    """

    @classmethod
    def DATA_OUTPUTS_DROP_ENABLE(cls, yaml_data):
        if 'outputs' in yaml_data:
            drop = [item['drop']
                    for item in yaml_data['outputs']
                    if 'drop' in item]
            if drop:
                assert 1 == len(drop)
                drop[0]['enabled'] = True
            else:
                yaml_data['outputs'].append({'drop': {'enabled': True}})

    @classmethod
    def DATA_DETECT_ENGINE_RULE_RELOAD_ENABLE(cls, yaml_data):
        if 'detect-engine' in yaml_data:
            rule_reload = [item['rule-reload']
                           for item in yaml_data['detect-engine']
                           if 'rule-reload' in item]
            if rule_reload:
                assert 1 == len(rule_reload)
                rule_reload[0] = True
            else:
                yaml_data['detect-engine'].append({'rule-reload': True})

    @classmethod
    def config_update(cls, ssh_obj, yaml_file, yaml_mods=None, rule_mods=None):
        """
        @brief  Suricata yaml and rule files config management.
        """
        if yaml_mods or rule_mods:
            pass
        else:
            return

        yaml_data = None
        with ssh_obj.client.open_sftp() as sftp_obj:
            with sftp_obj.open(yaml_file, 'r') as yaml_read:
                yaml_data = yaml.load(yaml_read)
            assert yaml_data

            # yaml changes
            if yaml_mods:
                for ymod in yaml_mods:
                    ymod(yaml_data)

            # rule changes + write
            default_rule_path = yaml_data.get('default-rule-path')
            if not default_rule_path:
                yaml_data['default-rule-path'] = '/etc/suricata/rules'  # TODO: make it param?
                default_rule_path = yaml_data.get('default-rule-path')
            assert isinstance(default_rule_path, str)

            rule_files = yaml_data.get('rule-files')
            if not rule_files:
                yaml_data['rule-files'] = []
                rule_files = yaml_data.get('rule-files')
            assert isinstance(rule_files, list)

            if rule_mods:
                for rfile_rel, rmods in rule_mods.items():
                    fmod = 'a'
                    if rfile_rel not in rule_files:
                        rule_files.append(rfile_rel)
                        fmod = 'w'
                    if rmods:
                        rfile_abs = os.path.join(default_rule_path, rfile_rel)
                        with sftp_obj.open(rfile_abs, fmod) as rule_fstream:
                            for rmod in rmods:
                                _rargs = rmod.get('args', [])
                                _rkwargs = rmod.get('kwargs', {})
                                _rule = cls.rule_fmt(*_rargs, **_rkwargs)
                                rule_fstream.write(_rule)

            # yaml write
            with sftp_obj.open(yaml_file, 'w') as yaml_fstream:
                yaml_fstream.write('%YAML 1.1\n---\n')  # this is for some reason necessary...
                yaml.dump(yaml_data, yaml_fstream)

        # with sftp_obj

    @classmethod
    def rule_fmt(cls, action, proto, src_host, src_port, direc, dst_host, dst_port, **kwargs):
        msg_str = cls._rule_msg_fmt(**kwargs)
        msg_str = '({})'.format(msg_str)
        return ' '.join([action, proto, src_host, src_port, direc, dst_host, dst_port, msg_str])

    @classmethod
    def _rule_msg_fmt(cls, **kwargs):
        _msg_body_list = ['{0}:{1};'.format(str(k), str(v)) for k, v in kwargs.items()]
        _msg_body_str = ' '.join(_msg_body_list)
        return _msg_body_str
