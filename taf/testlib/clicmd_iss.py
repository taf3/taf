#! /usr/bin/env python
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

@file  clicmd_iss.py

@summary  Module for CLI specific functionality.
"""

import re
import os
import traceback
import time

import pytest
from . import clitelnet

from . import loggers
from .custom_exceptions import CLICMDException


def get_table_title(line):
    """
    @brief  Get table name
    @param  line:  output
    @type  line:  str
    """
    if ":" in line:
        table_title = line.split(":")[0]
        return table_title
    else:
        return None


def get_column_ranges(line):
    """
    @brief  Get column ranges
    @param  line:  string with "--" column delimiters
    @type  line:  str
    @rtype:  list[list[str]]
    @return:  column_indexes - list of lists with string indexes of columns
    """
    if "--" in line:
        column_indexes = []
        columns = line.split()
        idx = 0
        for column_item in columns:
            column_indexes.append([idx, idx + len(column_item.lstrip())])
            idx = idx + len(column_item) + 1
        return column_indexes
    else:
        return None


def get_column_names(table_data, column_ranges):
    """
    @brief  Get column name
    @param  table_data:  String fetched from SSH CLI with column names
    @type  table_data:  str
    @param  column_ranges:  List with columns width string indexes used to extract column names
    @type  column_ranges:  list
    @rtype:  list[str]
    @return:  column_names_list - List of strings with columns names
    """
    column_names_dict = {}
    column_names_list = []
    i = 0
    for line in table_data.split('\n'):
        col_name_lines = []
        for index_pair in column_ranges:
            col_name_lines.append(line[index_pair[0]: index_pair[1]].rstrip().lstrip())
            column_names_dict.update({i: col_name_lines})
        i += 1
    if len(list(column_names_dict.keys())) > 1:
        for j in range(len(column_names_dict[0])):
            column_name = ''
            for key in column_names_dict:
                column_name += "%s " % (column_names_dict[key][j], )
            column_names_list.append(column_name.rstrip())
    else:
        column_names_list = column_names_dict[0]
    return column_names_list


def get_dotted_table(table_lines):
    """
    @brief  Get table data
    @param  table_lines:  list of table rows
    @type  table_lines:  list
    @rtype:  list[list]
    @return:  table_list - list of lists with row names and values
    """
    table_list = []
    for line in table_lines:
        if "...." in line:
            table_list.append([re.compile(r' \.{2,} ').split(line)[0], re.compile(r' \.{2,} ').split(line)[1]])
    return table_list


def get_table_value(table_data, identifier=None, checker=None):
    """
    @brief  Gets necessary field value from the table.

    @param  table_data:  console output data (string),
    @type  table_data:  str
    @param  identifier:  Column name and row number['column', 'value'],
    @type  identifier:  list[]
    @param  checker:  column name to check value (string).
    @type  checker:  str
    @raise  CLICMDException:  invalid row length
    @rtype:  str
    @return:  Field value.
    """
    table_value = ''
    # === parse received data for table header and type of table ==================
    i = 0
    raw_tables_dict = {}
    tables_dict = {}
    table_lines_list = []
    raw_lines_list = []
    for line in table_data.split("\n"):
        raw_lines_list.append(line.replace("\r", ""))
    raw_lines_list.pop(0)
    raw_lines_list.pop(-1)
    for line in raw_lines_list:
        if line.strip():
            table_lines_list.append(line)
        else:
            if len(table_lines_list) > 0:
                raw_tables_dict.update({i: table_lines_list})
                table_lines_list = []
                i += 1

    for key in raw_tables_dict:
        # table_header = ''
        # check if table header present in line
        if ":" in raw_tables_dict[key][0].rstrip()[-1]:
            # table_header = raw_tables_dict[key][0].rstrip()
            raw_tables_dict[key].pop(0)
        elif ".." in raw_tables_dict[key][0]:
            tables_dict[key] = get_dotted_table(raw_tables_dict[key])
        else:
            j = 0
            for line in raw_tables_dict[key]:
                if '--' not in line:
                    j += 1
                else:
                    col_names_text = ''
                    column_ranges = get_column_ranges(line)
                    for idx in range(j):
                        col_names_text += '%s\n' % (raw_tables_dict[key][idx], )
                    column_names_list = get_column_names(col_names_text, column_ranges)
                    tables_dict[key] = []
                    for table_column_idx, value in enumerate(column_names_list):
                        table_column = []
                        table_column.append(column_names_list[table_column_idx])
                        for table_row_idx in range(j + 1, len(raw_tables_dict[key])):
                            table_column.append(raw_tables_dict[key][table_row_idx][column_ranges[table_column_idx][0]:
                                                                                    column_ranges[table_column_idx][1]].rstrip().lstrip())
                        tables_dict[key].append(table_column)

    # ===== getting value from table ==================================================
    # in case we have multiple tables lets find out do they have similar columns
    row_index = None

    if len(list(tables_dict.keys())) > 1:
        flags_dict = {}
        # in case tables have equal length
        if len(tables_dict[list(tables_dict.keys())[0]]) == len(tables_dict[list(tables_dict.keys())[1]]):
            # take columns from first to last from first table from dictionary
            for col_idx in range(len(tables_dict[0])):
                for table_key in range(1, len(list(tables_dict.keys()))):
                    # and compare it with according column from next tables in tables dictionary
                    if tables_dict[0][col_idx][0] == tables_dict[table_key][col_idx][0]:
                        flags_dict[table_key] = 1
                        # append values to first table
                        for list_index in range(1, len(tables_dict[table_key][col_idx])):
                            tables_dict[0][col_idx].append(tables_dict[table_key][col_idx][list_index])
                    else:
                        flags_dict[table_key] = False
            for table_key in range(1, len(list(tables_dict.keys()))):
                if flags_dict[table_key] == 1:
                    tables_dict.pop(table_key)

    # check if transfered symbols are present, check if empty element are present.
    trans_flag = False
    for key in tables_dict:
        for element_list in tables_dict[key]:
            for element in element_list:
                if not element:
                    trans_flag = True

    # lead all tables in one format (model will be firs row)
    if trans_flag:
        for key in tables_dict:
            lead_row = tables_dict[key][0]
            # check len
            for row in tables_dict[key][1:]:
                if len(lead_row) != len(row):
                    message = "Row length is invalid: {0} != {1}".format(lead_row, row)
                    raise CLICMDException(message)
                else:
                    for lead_elem, row_elem in zip(lead_row, row):
                        if bool(lead_elem) != bool(row_elem):
                            # transform row_elem in lead_format
                            # print "lead_elem, row_elem", lead_elem, row_elem
                            rowidx = tables_dict[key].index(row)
                            # print "tables_dict[key][rowidx]", tables_dict[key][rowidx]
                            row_elemidx = tables_dict[key][rowidx].index(row_elem)
                            # print "tables_dict[key][rowidx][row_elemidx]", tables_dict[key][rowidx][row_elemidx]
                            new_value = "{0}{1}".format(tables_dict[key][rowidx][row_elemidx - 1], tables_dict[key][rowidx][row_elemidx])
                            tables_dict[key][rowidx][row_elemidx - 1] = new_value
                            tables_dict[key][rowidx][row_elemidx] = ""

    for key in tables_dict:
        for column in tables_dict[key]:
            if column[0] == identifier[0]:
                for value in column:
                    if value == identifier[1]:
                        row_index = column.index(value)
                        for column1 in tables_dict[key]:
                            if column1[0] == checker:
                                table_value = column1[row_index]
                                break
                        if table_value == '':
                            row_index = None
                            break

        if table_value != '':
            break

    if table_value == '':
        table_value = "CLIException: Specified table row has not been found"
    return table_value


class CLICmd(object):
    """
    @description  Class for CLI specific functionality.

    @param  config:  environment config.
    @param  switches:  switches list.
    """
    suite_logger = loggers.ClassLogger()
    # TODO: add wait_until_value_is_changed method for CLI

    def __init__(self, ipaddr, port, login, passw, prompt, devtype, delay=None, build_path=None, img_path=None,
                 page_break="<?> - help.", xmlrpcport=None):
        """
        @brief Initialize CLICmd class
        """
        self.timeout = 9
        # find out login, password and command prompt for switches from config for defined user
        self.ipaddr = ipaddr
        self.port = port
        self.xmlrpcport = xmlrpcport
        self.login = login
        self.passw = passw
        self.prompt = prompt
        self.devtype = devtype
        self.build_path = build_path
        self.img_path = img_path
        self.is_shell = False
        self.page_break = page_break
        # create ssh connection to switches and store it in self.conn dictionary

        self.conn = clitelnet.TelnetCMD(self.ipaddr, username=self.login,
                                        password=self.passw,
                                        page_break=page_break, prompt=self.prompt)

        if delay:
            self.conn.delay = delay

    def _connect_to_switch(self, prompt, timeout=20):
        """
        @brief  SSH connect to switch and wait untill prompt string appeared.
        @param  prompt:  expected CLI prompt.
        @type  prompt:  str
        @param  timeout:  connection timeout.
        @type  timeout:  int
        @return:  None
        @par Example:
        @code
        self._connect_to_switches(sw_keys=1, prompt="Switch ")
        @endcode
        """
        cli_start_path = ''
        self.suite_logger.debug("Login on switch with login: {0} and expected prompt is: {1}".format(self.login, prompt))
        self.conn.connect()
        self.suite_logger.debug("Create Shell")
        self.conn.open_shell(raw_output=True)

    def cli_get(self, arguments_list, prompt=None, show=True, timeout=25):
        """
        @brief  Getting values by CLI.
        @param  arguments_list:  list of arguments to get values.
        @type  arguments_list:  list
        @param  prompt:  expected promt or message, takes from cli_set_result.
        @type  prompt:  str
        @param  show:  execute command with show prefix
        @type  show:  bool
        @param  timeout:  command execution timeout
        @type  timeout:  int
        @raise  Exception:  error on command execution
        @rtype:  list
        @return:  List of CLI-GET command results.
        @par  Example:
        @code
        env.switch[1].cli.cli_get(['enable, none 0 none', 'statistics, Port 1, RX Discards']])
        @endcode
        """
        if not prompt:
            prompt = self.prompt

        result = []
        try:
            self._connect_to_switch(prompt)
            if arguments_list != [["readOnly"]]:
                for arguments in arguments_list:

                    args = arguments
                    table = args[0].strip()
                    identifier = []
                    if len(args[1].strip().split(' ')) > 2:
                        # " @" - delimiter between column name and value.
                        if "@" in args[1]:
                            identifier = args[1].split(" @")
                        else:
                            str_val_temp = []
                            for str_val_idx in range(len(args[1].strip().split(' ')) - 1):
                                str_val_temp.append(args[1].strip().split(' ')[str_val_idx])
                            identifier.append(" ".join(str_val_temp))
                            identifier.append(args[1].strip().split(' ')[-1])
                    else:
                        identifier = args[1].strip().split(' ')
                    checker = args[2].strip()

                    if checker == 'none':
                        command = table
                    else:
                        if show:
                            command = 'show ' + table
                        else:
                            command = table
                    # Run cli command and get output "<?> - help."
                    alternatives = [("<?> - help.", " ", False, False), ]
                    data, err = self.conn.shell_command(command, alternatives=alternatives, timeout=timeout, ret_code=False, quiet=True, raw_output=True)

                    # Data validation
                    if len(data.split('\n')) == 5 and "....." not in data.split('\n')[-3]:
                        result.append([data.split('\n')[-3].strip()])
                    elif len(data.split('\n')) == 2:
                        result.append([data.split('\n')[-1].strip()])
                    else:
                        # Remove page break from data
                        data = data.replace("<?> - help.", "")
                        value = get_table_value(data, identifier=identifier, checker=checker)
                        result.append([value])
            else:
                result = [["readOnly"]]
        # Close SSH connections

        except Exception:
            self.suite_logger.debug("Cli_get. Exception traceback data: {0}".format(traceback.format_exc()))
            raise
        finally:
            if self.conn:
                self.conn.close()
        return result

    def cli_get_all(self, arguments_list, prompt=None, timeout=25, interval=0.1):
        """
        @brief  Getting values by CLI.
        @param  arguments_list:  list of arguments to get values.
        @type  arguments_list:  list
        @param  prompt:  expected promt or message, takes from cli_set_result.
        @type  prompt:  str
        @param  timeout:  command execution timeout
        @type  timeout:  int
        @param  interval:  time interval between read attempts
        @type  interval:  int
        @raise  Exception:  error on command execution
        @rtype:  list
        @return:  List of CLI-GET command results.
        """
        result = []
        alternatives = []
        try:
            for command in arguments_list:
                # Run cli command and get output "<?> - help."
                alternatives.append(("<?> - help.", " ", False, False))
                if "'" in command[0]:
                    command[0] = command[0].replace("'", '"')
                if "::::" in command[0]:
                    command[0], answer = command[0].split("::::")
                    alternatives.append(("('yes'/'no'):", answer, False, False))
                data, err = self.conn.shell_command(command[0], alternatives=alternatives, timeout=timeout,
                                                    ret_code=False, quiet=True, raw_output=True, interval=interval)

                data = data.replace("<?> - help.", "")
                result.append(data.replace(command[0], "").strip())
        except Exception:
            self.suite_logger.debug("Cli_get_all. Exception traceback data: {0}".format(traceback.format_exc()))
            raise
        return result

    def cli_set(self, commands_list, timeout=5, prompt=None, connect=True):
        """
        @brief  Setting values by CLI.
        @param  commands_list:  list of commands.
        @type  commands_list:  list
        @param  prompt:  expected promt or message, takes from cli_set_result.
        @type  prompt:  str
        @param  timeout:  commnad execution timeout
        @type  timeout:  int
        @param connect: Flag if connection should be established before login procedure.
        @type  connect:  bool
        @raise  Exception:  error on command execution
        @rtype:  list
        @return:  List of CLI-SET command results.
        @par  Example:
        @code
        env.switch[1].cli.cli_set([["enable"], ["vlan-database"], ["vlan 10"]])
        @endcode
        """
        alternatives = []
        tabulation = False

        if not prompt:
            prompt = self.prompt
        result = []
        try:
            if connect:
                self._connect_to_switch(prompt)
                self.suite_logger.debug("Connection to switch established.")
            if commands_list != [["readOnly"]]:
                for commands in commands_list:
                    command = commands[0]
                    if len(commands) == 2:
                        if isinstance(commands[1], int):
                            timeout = commands[1]
                        elif isinstance(commands[1], str) or isinstance(commands[1], str):
                            if "\t" in commands[1]:
                                tabulation = commands[1]
                    # Replace ' by ", for cli support
                    if "'" in command:
                        command = command.replace("'", '"')
                    if "::::" in command:
                        command, answer = command.split("::::")
                        alternatives = [("('yes'/'no'):", answer, False, False), ]

                    # Run CLI commands and get answer
                    data, err = self.conn.shell_command(command, alternatives=alternatives,
                                                        timeout=timeout, ret_code=False,
                                                        quiet=True, raw_output=True)

                    # Return error message if it present in output data
                    if len(data.split('\n')) > 2 and ("Error!" in data or
                                                      "CLIException" in data or
                                                      "Invalid command has been entered" in data or
                                                      "Incomplete command has been" in data or
                                                      "Notice" in data):
                        data = data.replace("<?> - help.", "")
                        # Split multi error message if exist in one row
                        result.append([(("".join(data.split('\n')[2:-1])).strip()).replace("\r", " ")])

                    else:
                        # tabulation support processing:
                        # one tab case:
                        if tabulation == "\t":
                            res = []
                            for line in data.split('\n')[1:-1]:
                                for elem in line.split(' '):
                                    res.append(elem.strip())
                            result.append(res)
                        # double tab case:
                        elif tabulation == "\t\t":
                            res = []
                            split_data = []

                            for line in data.split('\n'):
                                split_data.append(line.strip())

                            split_point = split_data[:-1].index(split_data[-1])
                            for line in split_data[split_point + 1:-1]:
                                res.append(line.strip())
                            result.append(res)
                        elif tabulation == "\t\t\t":
                            res = []
                            for line in data.split('\n')[1:-1]:
                                res.append(line.strip())
                            result.append(res)
                        else:
                            result.append([data.split('\n')[-1].strip()])
            else:
                result = [["readOnly"]]

        except Exception as err:
            self.suite_logger.error("Cli_set error: %s" % (err, ))
            self.suite_logger.error("Cli_set. Exception traceback data:\n%s" % (traceback.format_exc(), ))
            raise
        finally:
            if connect:
                if self.conn:
                    self.conn.close()

        return result

    def cli_connect(self, prompt=None):
        """
        @brief  SSH connect to switch and wait untill prompt string appeared.
        @param  prompt:  expected CLI prompt.
        @type  prompt:  str
        @return:  None
        @par Example:
        @code
        env.switch[1].cli.cli_connect(prompt="Switch ")
        @endcode
        """
        if not prompt:
            prompt = self.prompt
        self._connect_to_switch(prompt)

    def cli_disconnect(self):
        """
        @brief  Close ssh connection to switch
        @raise  CLICMDException:  error on disconnect
        @return:  None
        @par Example:
        @code
        env.switch[1].cli.cli_disconnect()
        @endcode
        """
        try:
            if self.conn:
                self.conn.close()
        except Exception as err:
            raise CLICMDException(err)

    def update_prompt(self, prompt):
        """
        @brief  Updating prompt in both clissh and clicmd_ons objects.
        @param  prompt:  Prompt to be updated
        @type  prompt:  str
        """
        self.prompt = prompt
        self.conn.prompt = prompt
