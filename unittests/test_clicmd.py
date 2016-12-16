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

@file test_clicmd.py

@summary Unittests for CLI functions.
"""

import os

from testlib import clicmd_ons


class TestCliCmd(object):
    """
    @description  Unittests for testlib.clicmd_ons
    """

    line = "---- -------- ------- ------------ ----------------- -----------"

    # Unittests:
    def test_get_table_value(self):
        """
        @brief  Test get_table_value method
        """
        datafile = os.path.join("/".join(__file__.split("/")[:-1]) + "/cli_ports_table")
        f = open(datafile, 'r')
        table_data = f.read()

        fun = clicmd_ons.get_table_value(table_data, identifier=["Port", "24"], checker="Learning Mode")

        assert fun == "Hardware"

    def test_get_column_ranges(self):
        """
        @brief  Test get_column_ranges method
        """
        column_ranges = clicmd_ons.get_column_ranges(self.line)
        assert column_ranges == [[0, 4], [5, 13], [14, 21], [22, 34], [35, 52], [53, 64]]

    def test_get_column_names(self):
        """
        @brief  Test get_column_names method
        """
        col_names_text = "Port Address  Address Address      Address Interface Address OID\n              Subtype Interface ID ID Subtype\n"
        column_ranges = clicmd_ons.get_column_ranges(self.line)

        column_names_list = clicmd_ons.get_column_names(col_names_text, column_ranges)
        assert column_names_list == ['Port', 'Address', 'Address Subtype', 'Address Interface ID', 'Address Interface ID Subtype', 'Address OID']

    def test_get_dotted_table(self):
        """
        @brief  Test get_dotted_table method
        """
        raw_tables_dict = ['Port .................................... xe1',
                           'LLDP Port Name .......................... xe1',
                           'LLDP Port Subtype ....................... 1',
                           'Administrative Status ................... TxAndRx',
                           'Port Description ........................ N/A',
                           'Port Description Transmit Enable ........ Enabled',
                           'System Name Transmit Enable ............. Enabled',
                           'System Description Transmit Enable ...... Enabled',
                           'System Capability Transmit Enable ....... Enabled',
                           'Management Address Transmit Enable ...... Enabled',
                           'Management Neighbors .................... 0',
                           'Multiple Neighbors ...................... 0',
                           'Port Neighbors .......................... 0',
                           'Too Many Neighbors ...................... 0',
                           'Something Changed Local ................. 0',
                           'Something Changed Remote ................ 0']

        tables_dict = clicmd_ons.get_dotted_table(raw_tables_dict)

        expected_results = [['Port', 'xe1'],
                            ['LLDP Port Name', 'xe1'],
                            ['LLDP Port Subtype', '1'],
                            ['Administrative Status', 'TxAndRx'],
                            ['Port Description', 'N/A'],
                            ['Port Description Transmit Enable', 'Enabled'],
                            ['System Name Transmit Enable', 'Enabled'],
                            ['System Description Transmit Enable', 'Enabled'],
                            ['System Capability Transmit Enable', 'Enabled'],
                            ['Management Address Transmit Enable', 'Enabled'],
                            ['Management Neighbors', '0'],
                            ['Multiple Neighbors', '0'],
                            ['Port Neighbors', '0'],
                            ['Too Many Neighbors', '0'],
                            ['Something Changed Local', '0'],
                            ['Something Changed Remote', '0']]

        assert tables_dict == expected_results
