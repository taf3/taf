# Copyright (c) 2011 - 2017, Intel Corporation.
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

"""``read_csv.py``

`Reading Ixia CSV files`

"""

import csv
import os.path
import sys
import traceback

from . import loggers


class ReadCsv(object):
    """Class to read Ixia CSV files.

    """

    logger = loggers.ClassLogger()

    def __init__(self, filename):
        """Initialize ReadCsv class.

        Args:
            filename(str):  File name.

        Raises:
            Exception:  error on openning/reading csv file

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
        """Get cell.

        Args:
            row(int):  Row ID.
            col(int):  Column ID.

        Returns:
            str:  Column value

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
        """Get cell by name.

        Args:
            row(int):  Row ID.
            name(str):  Column name.

        Returns:
            str:  Column value

        """
        col = self.key[name]
        self.logger.debug("get cell by name %s, row = %d, col = %d" % (name, row, col))
        return self.get_cell(row, self.key[name])

    def get_ave_max_min(self, start, stop, name):
        """Get average, maximum, minimum cell.

        Args:
            start(int):  Start row ID value.
            stop(int):  Stop row ID value.
            name(str):  Column name.

        Returns:
            tuple:  average, maximum, minimum cell values

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
