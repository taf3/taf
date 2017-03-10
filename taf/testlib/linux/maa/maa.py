# Copyright (c) 2015 - 2017, Intel Corporation.
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

"""``maa.py``

`Class to abstract match action acceleration operations`

"""
import re
from testlib.custom_exceptions import UIException


class MatchActionAcceleration(object):

    def __init__(self, run_command):
        """Initialize MatchActionAcceleration class.

        Args:
            run_command(function): function that runs the actual commands

        """
        super(MatchActionAcceleration, self).__init__()
        self.run_command = run_command

    def create_maa_tcam_subtable(self, source_id, table_id, table_name,
                                 max_table_entries, match_field_type_pairs,
                                 actions):
        """Create a sub-table of tcam.

        Args:
            source_id(int):  the source id in the tcam table.
            table_id(int): a given table id.
                           If switchd is running, table id starts from 5
                           If matchd is running, table id starts from 4
            table_name(str):  a given table name.
            max_table_entries(int):  maximum number of rules can be set.
            match_field_type_pairs(list[tuple(str, str)]):  list of given match field with match type
            actions(list[str]):  list of actions for configurable matches

        Raises:
            UIException:  System table id not supported
            UIException:  for TypeError - Not enough arguments for format string
            UIException:  In case of Command execution Error reported in MatchAPI

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
        """Set a rule into the table.

        Args:
            prio_id(int):  Higher id has a higher priority.
            handle_id(int):  handle for match.
            table_id(int):  the source table id where match to be set.
            match_field_value_mask_list(list[tuple(str, str, str)]):  field with match field, value and mask.
            action(str):  given action for source table
            action_value(int):  action value for a specified action

        Raises:
            UIException:  for TypeError - Not enough arguments for format string
            UIException:  In case of Command execution Error reported in MatchAPI

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
        """Lists the match api tables.

        Args:
            table_id(int):  table ID

        Returns:
            list[dict]

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
        """Lists the match api rules of the table.

        Args:
            table_id(int):  table ID (mandatory parameter)
            handle_id(int):  optional parameter

        Returns:
            list[dict]

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
        """Delete a rule from the table.

        Args:
            handle_id(int):  handle for rule.[MANDATORY]
            table_id(int):  the source table id where rule to be set.[MANDATORY]

        Raises:
            UIException:  In case of Command execution Error reported in MatchAPI

        """
        cmd = 'match -f 5555 -p 30001 del_rule handle {0} table {1}'.format(handle_id, table_id)
        cmd_status = self.run_command(command=cmd)
        if cmd_status.stderr:
            raise UIException("Return code is {0}, on command '{1}' Error '{2}'.".format(
                cmd_status.rc, cmd, cmd_status.stderr))

    def delete_maa_tcam_subtable(self, source_id, table_id=0, table_name=None):
        """Destroy a sub-table of tcam.

        Args:
            source_id(int):  the source id in the tcam table.[MANDATORY]
            table_id(int):  a given table id.[MANDATORY if table_name not specified]
            table_name(str):  a given table name.[MANDATORY if table_id not specified]

        Raises:
            UIException:  System table id not supported
            UIException:  In case of Command execution Error reported in MatchAPI

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
