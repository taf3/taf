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

"""``lldptool_unittest.py``

"""


import unittest

from linux.lldp import lldptool


lldptool_tni = """Chassis ID TLV
\tIPv4: 10.0.0.150
Port ID TLV
\tIfname: Te 0/13
Time to Live TLV
\t120
Port Description TLV
\tTe 0/13
System Name TLV
\tbroc150_jack
System Description TLV
\tCEE Switch
System Capabilities TLV
\tSystem capabilities:  Bridge, Router
\tEnabled capabilities: Bridge
Management Address TLV
\tIPv4: 10.0.0.150
Unknown interface subtype: 0
CEE DCBX TLV
\tControl TLV:
\t  SeqNo: 1, AckNo: 3
\tPriority Groups TLV:
\t  Enabled, Not Willing, No Error
\t  PGID Priorities:  0:[0,1,5,7] 1:[3] 2:[4] 3:[2] 4:[6]
\t  PGID Percentages: 0:20% 1:10% 2:40% 3:20% 4:10% 5:0% 6:0% 7:0%
\t  Number of TC's supported: 8
\tPriority Flow Control TLV:
\t  Enabled, Not Willing, No Error
\t  PFC enabled priorities: 2, 3, 4, 6
\t  Number of TC's supported: 8
\tApplication TLV:
\t  Enabled, Not Willing, No Error
\t  Ethertype: 0x8906, Priority Map: 0x04
\t  TCP/UDP Port: 0x0cbc, Priority Map: 0x10
\tUnknown DCBX sub-TLV: 0000800080
\tUnknown DCBX sub-TLV: 0000800180
End of LLDPDU TLV
"""

lldptool_ti = """Chassis ID TLV
\tMAC: 00:1b:21:87:ac:7d
Port ID TLV
\tMAC: 00:1b:21:87:ac:7d
Time to Live TLV
\t120
CEE DCBX TLV
\tControl TLV:
\t  SeqNo: 8, AckNo: 2
\tPriority Groups TLV:
\t  Enabled, Willing, No Error
\t  PGID Priorities:  0:[0] 1:[1] 2:[2] 3:[3] 4:[4] 5:[5] 6:[6] 7:[7]
\t  PGID Percentages: 0:13% 1:13% 2:13% 3:13% 4:12% 5:12% 6:12% 7:12%
\t  Number of TC's supported: 8
\tPriority Flow Control TLV:
\t  Enabled, Willing, No Error
\t  PFC enabled priorities: none
\t  Number of TC's supported: 8
\tApplication TLV:
\t  Enabled, Willing, No Error
\t  Ethertype: 0x8906, Priority Map: 0x08
\t  TCP/UDP Port: 0x0cbc, Priority Map: 0x10
\t  Ethertype: 0x8914, Priority Map: 0x08
End of LLDPDU TLV
"""

ieee_lldptool_ti = """Chassis ID TLV
\tMAC: 00:1b:21:55:23:90
Port ID TLV
\tMAC: 00:1b:21:55:23:90
Time to Live TLV
\t120
IEEE 8021QAZ ETS Configuration TLV
\t Willing: no
\t CBS: not supported
\t MAX_TCS: 8
\t PRIO_MAP: 0:0 1:1 2:2 3:3 4:4 5:5 6:6 7:7
\t TC Bandwidth: 12% 12% 12% 12% 13% 13% 13% 13%
\t TSA_MAP: 0:ets 1:ets 2:ets 3:ets 4:ets 5:ets 6:ets 7:ets
IEEE 8021QAZ ETS Recommendation TLV
\t PRIO_MAP:  0:0 1:0 2:1 3:1 4:2 5:2 6:3 7:3
\t TC Bandwidth: 25% 25% 25% 25% 0% 0% 0% 0%
\t TSA_MAP: 0:ets 1:ets 2:ets 3:ets 4:strict 5:strict 6:strict 7:strict
IEEE 8021QAZ PFC TLV
\t Willing: yes
\t MACsec Bypass Capable: no
\t PFC capable traffic classes: 8
\t PFC enabled: none
End of LLDPDU TLV
"""

ieee_lldptool_ti = """Chassis ID TLV
\tMAC: 00:1b:21:5a:6a:2c
Port ID TLV
\tMAC: 00:1b:21:5a:6a:2c
Time to Live TLV
\t120
IEEE 8021QAZ ETS Configuration TLV
\tWilling: no
\tCBS: not supported
\tMAX_TCS: 8
\tPRIO_MAP: 0:0 1:1 2:2 3:3 4:4 5:5 6:6 7:7
\tTC Bandwidth: 12% 12% 12% 12% 13% 13% 13% 13%
\tTSA_MAP: 0:ets 1:ets 2:ets 3:ets 4:ets 5:ets 6:ets 7:ets
IEEE 8021QAZ ETS Recommendation TLV
\tPRIO_MAP: 0:0 1:1 2:2 3:3 4:4 5:5 6:6 7:7
\tTC Bandwidth: 12% 12% 12% 12% 13% 13% 13% 13%
\tTSA_MAP: 0:ets 1:ets 2:ets 3:ets 4:ets 5:ets 6:ets 7:ets
IEEE 8021QAZ PFC TLV
\tWilling: yes
\tMACsec Bypass Capable: no
\tPFC capable traffic classes: 8
\tPFC enabled: none
IEEE 8021QAZ APP TLV
       App#0:
\tPriority: 0
\tSel: 1
\tEthertype: 0x8906
End of LLDPDU TLV
"""

ieee_lldptool_tni = """Chassis ID TLV
\tMAC: 00:1b:21:90:8d:e8
Port ID TLV
\tMAC: 00:1b:21:90:8d:e8
Time to Live TLV
\t120
IEEE 8021QAZ ETS Configuration TLV
\tWilling: yes
\tCBS: not supported
\tMAX_TCS: 8
\tPRIO_MAP: 0:0 1:1 2:2 3:3 4:4 5:5 6:6 7:7
\tTC Bandwidth: 12% 12% 12% 12% 13% 13% 13% 13%
\tTSA_MAP: 0:ets 1:ets 2:ets 3:ets 4:ets 5:ets 6:ets 7:ets
IEEE 8021QAZ PFC TLV
\tWilling: yes
\tMACsec Bypass Capable: no
\tPFC capable traffic classes: 8
\tPFC enabled: none
IEEE 8021QAZ APP TLV
       App#0:
\tPriority: 0
\tSel: 1
\tEthertype: 0x8906
End of LLDPDU TLV
"""
lldptool_ti = """Chassis ID TLV
\tMAC: 00:1b:21:87:ac:7d
Port ID TLV
\tMAC: 00:1b:21:87:ac:7d
Time to Live TLV
\t120
CEE DCBX TLV
\tControl TLV:
\t  SeqNo: 8, AckNo: 2
\tPriority Groups TLV:
\t  Enabled, Willing, No Error
\t  PGID Priorities:  0:[0] 1:[1] 2:[2] 3:[3] 4:[4] 5:[5] 6:[6] 7:[7]
\t  PGID Percentages: 0:13% 1:13% 2:13% 3:13% 4:12% 5:12% 6:12% 7:12%
\t  Number of TC's supported: 8
\tPriority Flow Control TLV:
\t  Enabled, Willing, No Error
\t  PFC enabled priorities: none
\t  Number of TC's supported: 8
\tApplication TLV:
\t  Enabled, Willing, No Error
\t  Ethertype: 0x8906, Priority Map: 0x08
\t  TCP/UDP Port: 0x0cbc, Priority Map: 0x10
\t  Ethertype: 0x8914, Priority Map: 0x08
End of LLDPDU TLV
"""

ieee_lldptool_pfc = """Chassis ID TLV
\tMAC: 00:1b:21:c1:90:0c
Port ID TLV
\tMAC: 00:1b:21:c1:90:0c
Time to Live TLV
\t120
IEEE 8021QAZ ETS Configuration TLV
\t Willing: yes
\t CBS: not supported
\t MAX_TCS: 4
\t PRIO_MAP: 0:0 1:1 2:2 3:0 4:0 5:3 6:0 7:1
\t TC Bandwidth: 50% 25% 12% 13% 0% 0% 0% 0%
\t TSA_MAP: 0:ets 1:ets 2:ets 3:ets 4:strict 5:strict 6:strict 7:strict
IEEE 8021QAZ PFC TLV
\t Willing: yes
\t MACsec Bypass Capable: no
\t PFC capable traffic classes: 4
\t PFC enabled: 1 2 5 7
End of LLDPDU TLV
"""


ieee_lldptool_ti_app = """Chassis ID TLV
\tMAC: a0:36:9f:0b:3f:9c
Port ID TLV
\tMAC: a0:36:9f:0b:3f:9c
Time to Live TLV
\t120
IEEE 8021QAZ ETS Configuration TLV
\t Willing: no
\t CBS: not supported
\t MAX_TCS: 4
\t PRIO_MAP: 0:0 1:0 2:1 3:1 4:2 5:2 6:3 7:3
\t TC Bandwidth: 25% 25% 25% 25% 0% 0% 0% 0%
\t TSA_MAP: 0:ets 1:ets 2:ets 3:ets 4:strict 5:strict 6:strict 7:strict
IEEE 8021QAZ ETS Recommendation TLV
\t PRIO_MAP:  0:0 1:0 2:1 3:1 4:2 5:2 6:3 7:3
\t TC Bandwidth: 25% 25% 25% 25% 0% 0% 0% 0%
\t TSA_MAP: 0:ets 1:ets 2:ets 3:ets 4:strict 5:strict 6:strict 7:strict
IEEE 8021QAZ PFC TLV
\t Willing: no
\t MACsec Bypass Capable: no
\t PFC capable traffic classes: 4
\t PFC enabled: 1 2 5 7
IEEE 8021QAZ APP TLV
\tApp#0:
\t Priority: 2
\t Sel: 2
\t {S}TCP Port: 3260

\tApp#1:
\t Priority: 5
\t Sel: 1
\t Ethertype: 0x8906

End of LLDPDU TLV
"""


class TestLldptool(unittest.TestCase):

    def test_tlv_name(self):

        # p = lldptool.parse_into_list("Chassis ID TLV\n")
        # self.assertEquals(p[0][0], 'Chassis ID TLV')
        self.assertRaises(
            SyntaxError, lldptool.parse_into_list, "Chassis ID TLV\nTLV")

    def test_tlv_name_end_junk(self):
        # p = lldptool.parse_into_list("Chassis ID TLV\nTLV")
        # self.assertEquals(p[0][0], 'Chassis ID TLV')
        self.assertRaises(
            SyntaxError, lldptool.parse_into_list, "Chassis ID TLV\nTLV")

    def test_tlv_data(self):

        p = lldptool.parse_into_list("""Chassis ID TLV
\tIPv4: 10.0.0.150
End of LLDPDU TLV
""")
        self.assertEquals(p[0][0], 'Chassis ID TLV')
        self.assertEquals(p[0][1], [['IPv4', '10.0.0.150']])
        self.assertEquals(p[1][0], 'End of LLDPDU TLV')

    def test_only_errors(self):

        p = lldptool.parse_into_list("""Unknown interface subtype: 0
Unknown interface subtype: 0
Unknown interface subtype: 0
Unknown interface subtype: 0
Unknown interface subtype: 0
End of LLDPDU TLV
""")
        self.assertEquals(p[0][0], 'Unknown interface subtype: 0')
        self.assertEquals(p[1][0], 'Unknown interface subtype: 0')
        self.assertEquals(p[2][0], 'Unknown interface subtype: 0')
        self.assertEquals(p[3][0], 'Unknown interface subtype: 0')
        self.assertEquals(p[4][0], 'Unknown interface subtype: 0')
        self.assertEquals(p[5][0], 'End of LLDPDU TLV')

    def test_just_tlv_data(self):

        self.assertRaises(SyntaxError, lldptool.parse_into_list, """	IPv4: 10.0.0.150
""")

    def test_tlv_no_data_with_error(self):
        self.assertRaises(SyntaxError, lldptool.parse_into_list, """Chassis ID TLV
Unknown interface subtype: 0
End of LLDPDU TLV
""")

    def test_tlv_no_data_end_tlv(self):
        self.assertRaises(SyntaxError, lldptool.parse_into_list, """Chassis ID TLV
End of LLDPDU TLV
""")

    def test_mutiple_tlv_names_no_data(self):

        self.assertRaises(SyntaxError, lldptool.parse_into_list, """Chassis ID TLV
Port ID TLV
Time to Live TLV
Port Description TLV
System Name TLV
System Description TLV
System Capabilities TLV
Management Address TLV
CEE DCBX TLV
End of LLDPDU TLV
""")

    def test_whitespace_before_tlv_name(self):

        self.assertRaises(SyntaxError, lldptool.parse_into_list, """       Chassis ID TLV
\tIPv4: 10.0.0.150
End of LLDPDPU TLV""")

    def test_zero_lenght_value(self):
        p = lldptool.parse_into_list("""Chassis ID TLV
\tIPv4: 10.0.0.150
Port ID TLV
\tIfname: Te 0/13
Time to Live TLV
\t120
Port Description TLV
\t
System Name TLV
\tbroc150_jack
System Description TLV
\tCEE Switch
End of LLDPDU TLV
""")
        self.assertEquals(p[0][0], 'Chassis ID TLV')
        self.assertEquals(p[1][0], 'Port ID TLV')
        self.assertEquals(p[2][0], 'Time to Live TLV')
        self.assertEquals(p[3][0], 'Port Description TLV')
        self.assertEquals(p[3][1], [])

    def test_full_tni(self):
        p = lldptool.parse_into_list(lldptool_tni)
        self.assertEquals(p[0][0], 'Chassis ID TLV')
        self.assertEquals(p[1][0], 'Port ID TLV')
        self.assertEquals(p[2][0], 'Time to Live TLV')
        self.assertEquals(p[3][0], 'Port Description TLV')
        self.assertEquals(p[4][0], 'System Name TLV')
        self.assertEquals(p[5][0], 'System Description TLV')
        self.assertEquals(p[6][0], 'System Capabilities TLV')
        self.assertEquals(p[7][0], 'Management Address TLV')
        self.assertEquals(p[8][0], 'Unknown interface subtype: 0')
        self.assertEquals(p[9][0], 'CEE DCBX TLV')
        self.assertEquals(p[10][0], 'End of LLDPDU TLV')

    def test_full_ti(self):
        p = lldptool.parse_into_list(lldptool_ti)
        self.assertEquals(p[0][0], 'Chassis ID TLV')
        self.assertEquals(p[1][0], 'Port ID TLV')
        self.assertEquals(p[2][0], 'Time to Live TLV')
        self.assertEquals(p[3][0], 'CEE DCBX TLV')
        self.assertEquals(p[4][0], 'End of LLDPDU TLV')

    def test_ieee_full_ti(self):
        p = lldptool.parse_into_list(ieee_lldptool_ti)
        self.assertEquals(p[0][0], 'Chassis ID TLV')
        self.assertEquals(p[1][0], 'Port ID TLV')
        self.assertEquals(p[2][0], 'Time to Live TLV')
        self.assertEquals(p[3][0], 'IEEE 8021QAZ ETS Configuration TLV')
        self.assertEquals(p[4][0], 'IEEE 8021QAZ ETS Recommendation TLV')
        self.assertEquals(p[5][0], 'IEEE 8021QAZ PFC TLV')
        self.assertEquals(p[6][0], 'IEEE 8021QAZ APP TLV')
        self.assertEquals(p[7][0], 'End of LLDPDU TLV')

    def test_ieee_full_tni(self):
        p = lldptool.parse_into_list(ieee_lldptool_tni)
        self.assertEquals(p[0][0], 'Chassis ID TLV')
        self.assertEquals(p[1][0], 'Port ID TLV')
        self.assertEquals(p[2][0], 'Time to Live TLV')
        self.assertEquals(p[3][0], 'IEEE 8021QAZ ETS Configuration TLV')
        self.assertEquals(p[4][0], 'IEEE 8021QAZ PFC TLV')
        self.assertEquals(p[5][0], 'IEEE 8021QAZ APP TLV')
        self.assertEquals(p[6][0], 'End of LLDPDU TLV')


class LLDPToolParse(unittest.TestCase):

    def test_pg(self):
        p = lldptool.parse(lldptool_ti)
        # assert p['CEE DCBX TLV']['Priority Groups TLV:'] == {}
        assert p['CEE DCBX TLV']['Priority Groups TLV:']['PGID Priorities'] == \
            {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7}

    def test_ieee_pfc(self):
        p = lldptool.parse(ieee_lldptool_pfc)
        # assert p['CEE DCBX TLV']['Priority Groups TLV:'] == {}
        assert p['IEEE 8021QAZ PFC TLV']['PFC enabled'] == {
            0: False,
            1: True,
            2: True,
            3: False,
            4: False,
            5: True,
            6: False,
            7: True
        }

    def test_cee_app(self):
        p = lldptool.parse(lldptool_ti)
        assert p['CEE DCBX TLV']['Application TLV:']['Applications'] == {
            ('Ethertype', 35078): 8,
            ('Ethertype', 35092): 8,
            ('TCP/UDP Port', 3260): 16,
        }

    def test_pgid_priorites(self):
        pgid_priorites = lldptool.pgid_priorities(
            '0:[0,1,5,7] 1:[3] 2:[4] 3:[2] 4:[6]')
        assert pgid_priorites == {0: 0, 1: 0, 2: 3, 3: 1, 4: 2, 5:
                                  0, 6: 4, 7: 0}

    def test_pgid_percentages(self):
        pgids = lldptool.pgid_percentages(
            '0:20% 1:10% 2:40% 3:20% 4:10% 5:0% 6:0% 7:0%')
        assert pgids == (20, 10, 40, 20, 10, 0, 0, 0)

    def test_set_config_pfc(self):

        r = lldptool.parse_set(
            "lldptool -Ti eth3 -V PFC enableTx=yes willing=yes enabled=6,4,3,2")

        self.assertEqual(r['willing'], True)
        self.assertEqual(r['advertise'], True)
        self.assertEqual(r['interface'], "eth3")
        self.assertEqual(r['enabled'], {
            0: False,
            1: False,
            2: True,
            3: True,
            4: True,
            5: False,
            6: True,
            7: False
        })

    @staticmethod
    def test_lldptool_set():
        p = lldptool.parse_set(
            "lldptool -T -i eth2 -V PFC enableTx=yes willing=no enabled=0,1,2,3,4,5,6,7")
        assert p['interface'] == "eth2"
        assert not p['willing']
        assert p['advertise']
        assert p['max_tcs'] == 8
        assert p['enabled'] == {0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1}

    def test_set_config_ets(self):

        r = lldptool.parse_set(
            "lldptool -Ti eth3 -V ETS-CFG enableTx=yes willing=yes "
            "tsa=0:ets,1:ets,2:ets,3:ets,4:ets,5:ets,6:ets,7:ets "
            "up2tc=0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7 tcbw=12,12,12,12,13,13,13,13")

        self.assertEqual(r['willing'], True)
        self.assertEqual(r['advertise'], True)
        self.assertEqual(r['interface'], "eth3")
        self.assertEqual(r['tsa'], {0: 'ets', 1: 'ets', 2: 'ets',
                                    3: 'ets', 4: 'ets', 5: 'ets', 6: 'ets', 7: 'ets'}),
        self.assertEqual(
            r['up2tc'], {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7})
        self.assertEqual(r['tcbw'], (12, 12, 12, 12, 13, 13, 13, 13))

if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestLldptool)
    # suite = unittest.TestSuite()
    # suite.addTest(TestLldptool('test_full_tni'))
    unittest.TextTestRunner(verbosity=2).run(suite)
