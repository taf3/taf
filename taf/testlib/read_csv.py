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

@file  read_csv.py

@summary  Reading Ixia CSV files
"""

import csv
import os.path
import sys
import traceback

from . import loggers


class ReadCsv(object):
    """
    @description  Class to read Ixia CSV files.
    """

    logger = loggers.ClassLogger()

    def __init__(self, filename):
        """
        @brief  Initialize ReadCsv class
        @param  filename:  File name.
        @type  filename:  str
        @raise  Exception:  error on openning/reading csv file
        """
        self.content = []
        self.line_number = 0
        filename = os.path.expandvars(os.path.expanduser(filename))
        self.key = {}
        self.title_line = 11
        self.logger.debug("open : %s " % (filename, ))

        try:
            _file = open(filename, 'r')
        except Exception as err:
            self.logger.error("Failed to open csv file :%s, ERROR: %s" % (filename, err))
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback_message = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
            self.logger.error("\n{0}".format(traceback_message))
            raise

        try:
            reader = csv.reader(_file)
            for line in reader:
                self.content.append(line)
                self.line_number += 1
                if self.line_number == self.title_line:
                    col = 0
                    for each_column in line:
                        self.key[each_column] = col
                        col = col + 1
        except Exception as err:
            self.logger.error("Failed read csv file :%s, ERROR: %s" % (filename, err))
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback_message = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
            self.logger.error("\n{0}".format(traceback_message))
            _file.close()
            raise
        finally:
            _file.close()

    def get_cell(self, row, col):
        """
        @brief  Get cell.
        @param  row:  Row ID.
        @type  row:  int
        @param  col:  Column ID.
        @type  col:  int
        @rtype:  str
        @return:  Column value
        """
        try:
            ret = self.content[row][col]
        except Exception as err:
            self.logger.error("ERROR get cell [%d] [%d]: %s" % (row, col, err))
            print(">" * 100)
            print("Max rows:", len(self.content))
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback_message = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
            self.logger.error("\n{0}".format(traceback_message))
            return None

        return ret

    def get_cell_by_name(self, row, name):
        """
        @brief  Get cell by name.
        @param  row:  Row ID.
        @type  row:  int
        @param  name:  Column name.
        @type  name:  str
        @rtype:  str
        @return:  Column value
        """
        col = self.key[name]
        self.logger.debug("get cell by name %s, row = %d, col = %d" % (name, row, col))
        return self.get_cell(row, self.key[name])

    def get_ave_max_min(self, start, stop, name):
        """
        @brief  Get average, maximum, minimum cell.
        @param  start:  Start row ID value.
        @type  start:  int
        @param  stop:  Stop row ID value.
        @type  stop:  int
        @param  name:  Column name.
        @type  name:  str
        @rtype:  tuple
        @return:  average, maximum, minimum cell values
        """
        average = float(0)
        n = stop - start
        maximum = float(0)
        minimum = sys.float_info.max
        for index in range(start, stop):
            current = float(self.get_cell_by_name(index, name))
            average = average + (current / n)
            if current > maximum:
                maximum = current
            if current < minimum:
                minimum = current
        return average, maximum, minimum
