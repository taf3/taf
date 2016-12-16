"""
@copyright Copyright (c) 2015 - 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file maa.py

@summary Class to abstract match action acceleration operations
"""
import re
from testlib.custom_exceptions import UIException


class MatchActionAcceleration(object):

    def __init__(self, run_command):
        """
        @param run_command: function that runs the actual commands
        @type run_command: function
        """
        super(MatchActionAcceleration, self).__init__()
        self.run_command = run_command

    def create_maa_tcam_subtable(self, source_id, table_id, table_name,
                                 max_table_entries, match_field_type_pairs,
                                 actions):
        """
        @brief  create a sub-table of tcam
        @param  source_id:  the source id in the tcam table.
        @type  source_id:  int
        @param  table_id:  a given table id.
                           If switchd is running, table id starts from 5
                           If matchd is running, table id starts from 4
        @type  table_id:  int
        @param  table_name:  a given table name.
        @type  table_name:  str
        @param  max_table_entries:  maximum number of rules can be set.
        @type  max_table_entries:  int
        @param  match_field_type_pairs:  list of given match field with match type
        @type  match_field_type_pairs:  list[tuple(str, str)]
        @param  actions:  list of actions for configurable matches
        @type  actions:  list[str]
        @raise  UIException:  System table id not supported
        @raise  UIException:  for TypeError - Not enough arguments for format string
        @raise  UIException:  In case of Command execution Error reported in MatchAPI
        """

        # Validate the create subtable request for tcam system table
        if source_id != 1:
            raise UIException('MATCH, System Table id - ({0}) not supported.'.format(source_id))

        # Fetches the match-field, match-type from the input list and builds match argument
        field_type_args = ' '.join('match {0[0]} {0[1]}'.format(pair) for pair in
                                   match_field_type_pairs)

        # Fetches the action-names from the actions list and builds action argument
        action_name_args = ' '.join('action {0}'.format(action) for action in actions)

        # family_id - 5555 and pid of fm10kd - 30001
        cmd = 'match -f 5555 -p 30001 create source {0} id {1} name {2} size {3} {4} {5}'.format(
            source_id, table_id, table_name, max_table_entries, field_type_args, action_name_args)
        cmd_status = self.run_command(command=cmd)
        if cmd_status.stderr:
            raise UIException("Return code is {0}, on command '{1}' Error '{2}'.".format(
                cmd_status.rc, cmd, cmd_status.stderr))

    def create_maa_rule(self, prio_id, handle_id, table_id,
                        match_field_value_mask_list, action, action_value=None):
        """
        @brief set a rule into the table
        @param  prio_id:  Higher id has a higher priority.
        @type  prio_id:  int
        @param  handle_id:  handle for match.
        @type  handle_id:  int
        @param  table_id:  the source table id where match to be set.
        @type  table_id:  int
        @param  match_field_value_mask_list:  field with match field, value and mask.
        @type  match_field_value_mask_list:  list[tuple(str, str, str)]
        @param  action:  given action for source table
        @type  action:  str
        @param  action_value:  action value for a specified action
        @type  action_value:  int
        @raise  UIException:  for TypeError - Not enough arguments for format string
        @raise  UIException:  In case of Command execution Error reported in MatchAPI
        """
        # Fetches the match-field, match-type & match value and builds match argument
        field_value_mask_args = ' '.join('match {0[0]} {0[1]} {0[2]}'.format(combo) for combo in
                                         match_field_value_mask_list)
        # family_id - 5555 and pid - 30001
        cmd = 'match -f 5555 -p 30001 set_rule prio {0} handle {1} table {2} {3} action {4}'.format(
            prio_id, handle_id, table_id, field_value_mask_args, action)
        if action_value is not None:
            cmd += ' {0}'.format(action_value)
        cmd_status = self.run_command(command=cmd)
        if cmd_status.stderr:
            raise UIException("Return code is {0}, on command '{1}' Error '{2}'.".format(
                cmd_status.rc, cmd, cmd_status.stderr))

    def get_maa_table(self, table_id=None):
        """
        @brief  Lists the match api tables
        @param  table_id:  table ID
        @type  table_id:  int
        @rtype:  list[dict]
        """
        cmd = "match -f 5555 -p 30001 get_tables"
        match_api_output = self.run_command(command=cmd).stdout
        pattern = re.compile(
            r'\n*(?P<table_name>\w*):(?P<table_id>\d*)\ssrc\s(?P<table_src>\d*)\sapply\s'
            r'(?P<table_apply>\d*)\ssize\s(?P<table_size>\d*)\n')
        table_pattern = re.compile(r'(\n*[\w:\s\[\]\(\)\,\=\.-]*?\n{2})')
        matches_data_pattern = re.compile(r'\s*matches:\n([\s\w:\[\]\(\)]*)\s*actions:')
        actions_data_pattern = re.compile(r'\s*actions:\n([\s\w:\(\)\.,-]*)\s*attributes:')
        attributes_data_pattern = re.compile(r'\s*attributes:\n*([\s\w:\(\),=-]*)\n{2}')
        matches_item_pattern = re.compile(r'\s*field:\s([\w\s\[\]\(\)]*)\n')
        actions_item_pattern = re.compile(r'\s*(\d+):\s([\s\w\)\(\.,-]*)\n')
        attributes_item_pattern = re.compile(r'\s+([\w\(\)\s]*)=\s([\w:]*)')
        match_api_table = []
        table_data = table_pattern.findall(match_api_output)
        for item in table_data:
            match_dict = pattern.search(item).groupdict()
            matches_data = matches_data_pattern.search(item).group()
            matches = matches_item_pattern.findall(matches_data)
            actions_data = actions_data_pattern.search(item).group()
            actions = actions_item_pattern.findall(actions_data)
            attributes_data = attributes_data_pattern.search(item).group()
            attributes = attributes_item_pattern.findall(attributes_data)
            match_dict['matches'] = matches
            match_dict['actions'] = {int(key): value for (key, value) in actions}
            match_dict['attributes'] = {key: value for (key, value) in attributes}
            match_api_table.append(match_dict)
        for entry in match_api_table:
            for key in entry:
                if isinstance(entry[key], str):
                    try:
                        entry[key] = int(entry[key])
                    except ValueError:
                        pass
        if table_id:
            return [entry for entry in match_api_table if entry["table_id"] == table_id]
        else:
            return match_api_table

    def get_maa_rules(self, table_id, handle_id=None):
        """
        @brief  Lists the match api rules of the table
        @params  table_id:  table ID (mandatory parameter)
        @type  table_id:  int
        @params  handle_id:  optional parameter
        @type  handle_id:   int
        @rtype:  list[dict]
        """
        cmd = "match -f 5555 -p 30001 get_rules table {0}".format(table_id)
        flow_rules_output = self.run_command(command=cmd).stdout.split("table : ")
        pattern = [re.search(r'^(?P<table_id>\d*)\s*uid\s:\s(?P<handle_id>\d*)\s*'
                             r'prio\s:\s(?P<pri_id>\d*)\s*bytes\s:\s(?P<bytes_count>\d*)'
                             r'\s*packets\s:\s(?P<packets_count>\d*)'
                             r'\s*(?P<values>.*)', row, re.DOTALL)
                   for row in flow_rules_output if row]
        flow_rule_table = [pattern1.groupdict() for pattern1 in pattern if pattern1]
        for entry in flow_rule_table:
            for key in entry:
                try:
                    entry[key] = int(entry[key])
                except ValueError:
                    pass
        if handle_id:
            return [entry for entry in flow_rule_table if entry["handle_id"] == handle_id]
        else:
            return flow_rule_table

    def delete_maa_rule(self, handle_id, table_id):
        """
        @brief delete a rule from the table
        @param  handle_id:  handle for rule.[MANDATORY]
        @type  handle_id:  int
        @param  table_id:  the source table id where rule to be set.[MANDATORY]
        @type  table_id:  int
        @raise  UIException:  In case of Command execution Error reported in MatchAPI
        """
        cmd = 'match -f 5555 -p 30001 del_rule handle {0} table {1}'.format(handle_id, table_id)
        cmd_status = self.run_command(command=cmd)
        if cmd_status.stderr:
            raise UIException("Return code is {0}, on command '{1}' Error '{2}'.".format(
                cmd_status.rc, cmd, cmd_status.stderr))

    def delete_maa_tcam_subtable(self, source_id, table_id=0, table_name=None):
        """
        @brief  Destroy a sub-table of tcam
        @param  source_id:  the source id in the tcam table.[MANDATORY]
        @type  source_id:  int
        @param  table_id:  a given table id.[MANDATORY if table_name not specified]
        @type  table_id:  int
        @param  table_name:  a given table name.[MANDATORY if table_id not specified]
        @type  table_name:  str
        @raise  UIException:  System table id not supported
        @raise  UIException:  In case of Command execution Error reported in MatchAPI
        """
        # Validate the create subtable request for tcam system table
        if source_id != 1:
            raise UIException('MATCH, System Table id - {0} not supported.'.format(source_id))
        cmd = 'match -f 5555 -p 30001 destroy source {0}'.format(source_id)
        if table_id > 0:
            cmd += ' id {0}'.format(table_id)
        if table_name:
            cmd += ' name {0}'.format(table_name)
        cmd_status = self.run_command(command=cmd)
        if cmd_status.stderr:
            raise UIException("Return code is {0}, on command '{1}' Error '{2}'.".format(
                cmd_status.rc, cmd, cmd_status.stderr))
