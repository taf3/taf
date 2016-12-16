#! /usr/bin/env python
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

@file tg_generators.py

@summary  This module contains collection of TG related generators.
"""

import random

import pypacker


class BaseGenerator(object):
    """
    @description  Base generator used for creating field values generators
    """

    def __init__(self, start_value, end_value, increment, count):
        """
        @brief  Initialize BaseGenerator class
        @param  start_value:  Generator's start value
        @type  start_value:  int, str
        @param  end_value:  Generator's start value
        @type  end_value:  int, str
        @param  increment:  Generator's step value
        @type  increment:  int
        @param  count:  Generator's count value
        @type  count:  int
        @raise  ValueError:  start_value is mandatory
        """
        if start_value is None:
            raise ValueError("start_value has to be set.")
        self.start_value = start_value
        self.value = start_value
        self.end_value = end_value
        self.increment = increment
        self.count = count
        self.iterator = 1

    def __iter__(self):
        """
        @brief  Return iterator object
        """
        return self

    def __next__(self):
        """
        @brief  Return next item fron container
        """
        return self


class PypackerMacGenerator(BaseGenerator):
    """
    @description  Iteration class for list of MAC addresses generation
    @param start_value:  initial MAC value
    @type start_value:  str
    @param increment:  incrementation step
    @type increment:  int
    @param count:  number of iteration steps
    @type count:  int
    """

    def __next__(self):
        """
        @brief  Get next generated MAC address.
        """
        current = self.value
        if self.iterator >= self.count and self.count != 0:
            self.value = self.start_value
            self.iterator = 1
        else:
            int_mac = int(self.value.replace(":", ""), 16)
            int_mac = int_mac + self.increment
            if int_mac > int("FFFFFFFFFFFF", 16):
                diff = int_mac - int("FFFFFFFFFFFF", 16)
                int_mac = int("000000000000", 16) + diff
            if int_mac < int("000000000000", 16):
                diff = int_mac - int("000000000000", 16)
                int_mac = int("FFFFFFFFFFFF", 16) + diff
            hex_mac = hex(int_mac).replace('L', '')[2:].zfill(12)
            self.value = "%s:%s:%s:%s:%s:%s" % (hex_mac[:2], hex_mac[2:4], hex_mac[4:6], hex_mac[6:8], hex_mac[8:10], hex_mac[10:12])
            self.iterator += 1
        return current


class PypackerARPMacGenerator(BaseGenerator):
    """
    @description  Iteration class for list of ARP MAC addresses generation
    @param start_value:  initial MAC value
    @type start_value:  str
    @param increment:  incrementation step
    @type increment:  int
    @param count:  number of iteration steps
    @type count:  int
    """

    def __next__(self):
        """
        @brief  Get next generated ARP MAC address.
        """
        current = self.value
        if self.iterator >= self.count and self.count != 0:
            self.value = self.start_value
            self.iterator = 1
        else:
            mac_string = self.value.replace(":", "")
            int_mac_start = mac_string[:4]
            int_mac_end = int(mac_string[4:], 16)
            int_mac_end = int_mac_end + self.increment
            if int_mac_end > int("FFFFFFFF", 16):
                diff = int_mac_end - int("FFFFFFFF", 16)
                int_mac_end = int("00000000", 16) + diff
            if int_mac_end < int("00000000", 16):
                diff = int_mac_end - int("00000000", 16)
                int_mac_end = int("FFFFFFFF", 16) + diff
            hex_mac = hex(int(int_mac_start + hex(int_mac_end).replace('L', '')[2:].zfill(8)[:8], 16)).replace('L', '')[2:].zfill(12)
            self.value = "%s:%s:%s:%s:%s:%s" % (hex_mac[:2], hex_mac[2:4], hex_mac[4:6], hex_mac[6:8], hex_mac[8:10], hex_mac[10:12])
            self.iterator += 1
        return current


class PypackerIPGenerator(BaseGenerator):
    """
    @description  Iteration class for list of IP addresses generation
    @param start_value:  initial IP value
    @type start_value:  str
    @param increment:  incrementation step
    @type increment:  int
    @param count:  number of iteration steps
    @type count:  int
    """

    def __next__(self):
        """
        @brief  Get next generated IP address.
        """
        current = self.value
        if self.iterator >= self.count and self.count != 0:
            self.value = self.start_value
            self.iterator = 1
        else:
            ip = self.value.split('.')
            ip_initval_str = \
                str(hex(int(ip[0])))[2:].zfill(2) + str(hex(int(ip[1])))[2:].zfill(2) + str(hex(int(ip[2])))[2:].zfill(2) + str(hex(int(ip[3])))[2:].zfill(2)
            ip_initval_int = int(ip_initval_str, 16)
            int_ip = ip_initval_int + self.increment
            if int_ip > int("FFFFFFFF", 16):
                diff = int_ip - int("FFFFFFFF", 16)
                int_ip = int("00000000", 16) + diff
            if int_ip < int("00000000", 16):
                diff = int_ip - int("00000000", 16)
                int_ip = int("FFFFFFFF", 16) + diff
            hex_ip = hex(int_ip)[2:].zfill(8)
            self.value = "%s.%s.%s.%s" % (int(hex_ip[:2], 16), int(hex_ip[2:4], 16), int(hex_ip[4:6], 16), int(hex_ip[6:8], 16))
            self.iterator += 1
        return current


class PypackerUDPGenerator(BaseGenerator):
    """
    @brief  Iteration class for list of UDP addresses generation
    @param start_value:  initial UDP value
    @type start_value:  str
    @param increment:  incrementation step
    @type increment:  int
    @param count:  number of iteration steps
    @type count:  int
    """

    def __next__(self):
        """
        @brief  Get next generated UDP address.
        """
        current = self.value
        if self.iterator >= self.count and self.count != 0:
            self.value = self.start_value
            self.iterator = 1
        else:
            self.value = self.value + self.increment
            if self.value > 65535:
                diff = self.value - 65535
                self.value = 1 + diff
            if self.value < 1:
                diff = self.value - 1
                self.value = 65535 + diff
            self.iterator += 1
        return current


class PypackerTCPGenerator(BaseGenerator):
    """
    @description  Iteration class for list of TCP addresses generation
    @param start_value:  initial TCP value
    @type start_value:  str
    @param increment:  incrementation step
    @type increment:  int
    @param count:  number of iteration steps
    @type count:  int
    """

    def __next__(self):
        """
        @brief  Get next generated UDP address.
        """
        current = self.value
        if self.iterator >= self.count and self.count != 0:
            self.value = self.start_value
            self.iterator = 1
        else:
            self.value = self.value + self.increment
            if self.value > 65535:
                diff = self.value - 65535
                self.value = 1 + diff
            if self.value < 1:
                diff = self.value - 1
                self.value = 65535 + diff
            self.iterator += 1
        return current


class PypackerRandomPayloadGenerator(BaseGenerator):
    """
    @description  Iteration class for random payload generation
    @param start_value:  initial payload value
    @type start_value:  str
    @param end_value:  maximum payload value
    @type end_value:  str
    """

    def __next__(self):
        """
        @brief  Get next generated payload value.
        """
        current = self.end_value
        rand_length = random.randint(self.start_value, len(current))
        return current[:rand_length]


class PypackerIncrementPayloadGenerator(BaseGenerator):
    """
    @description  Iteration class for incremented payload generation
    @param start_value:  initial payload value
    @type start_value:  str
    @param end_value:  maximum payload value
    @type end_value:  str
    @param increment:  incrementation step
    @type increment:  int
    """

    def __next__(self):
        """
        @brief  Get next generated payload value.
        """
        current = ""
        if self.value > len(self.end_value):
            self.value = self.start_value
        current = self.end_value[:self.value]
        self.value += self.increment
        return current


class PypackerVlanGenerator(BaseGenerator):
    """
    @description  Iteration class for list of VLANs generation
    @param start_value:  initial Vlan value
    @type start_value:  str
    @param increment:  incrementation step
    @type increment:  int
    @param count:  number of iteration steps
    @type count:  int
    """

    def __next__(self):
        """
        @brief  Get next generated VLAN.
        """
        current = self.value
        if self.iterator >= self.count and self.count != 0:
            self.value = self.start_value
            self.iterator = 1
        else:
            self.value = self.value + self.increment
            if self.value > 4094:
                diff = self.value - 4094
                self.value = 1 + diff
            if self.value < 1:
                diff = self.value - 1
                self.value = hex(4094 + diff)
            self.iterator += 1
        return current


class PypackerTypeGenerator(BaseGenerator):
    """
    @description  Iteration class for list of types generation
    @param start_value:  initial Ether.type value
    @type start_value:  str
    @param increment:  incrementation step
    @type increment:  int
    @param count:  number of iteration steps
    @type count:  int
    """

    def __next__(self):
        """
        @brief  Get next type generation value.
        """
        current = self.value
        if self.iterator >= self.count and self.count != 0:
            self.value = self.start_value
            self.iterator = 1
        else:
            self.value = self.value + self.increment
            if self.value > 65535:
                diff = self.value - 65535
                self.value = diff - 1
            if self.value < 0:
                diff = self.value
                self.value = 65536 + diff
            self.iterator += 1
        return current


class PypackerProtocolGenerator(BaseGenerator):
    """
    @description  Iteration class for list of protocols generation
    @param start_value:  initial protocol value
    @type start_value:  str
    @param increment:  incrementation step
    @type increment:  int
    @param count:  number of iteration steps
    @type count:  int
    """

    def __next__(self):
        """
        @brief  Get next generated protocol value.
        """
        current = self.value
        if self.iterator >= self.count and self.count != 0:
            self.value = self.start_value
            self.iterator = 1
        else:
            self.value = self.value + self.increment
            if self.value > 255:
                diff = self.value - 255
                self.value = diff - 1
            if self.value < 0:
                diff = self.value
                self.value = 256 + diff
            self.iterator += 1
        return current


class PypackerIPv6Generator(BaseGenerator):
    """
    @description  Iteration class for list of IPv6 addresses generation
    @param start_value:  initial IPv6 value
    @type start_value:  str
    @param increment:  incrementation step
    @type increment:  int
    @param count:  number of iteration steps
    @type count:  int
    """

    def __next__(self):
        """
        @brief  Get next generated IPv6 address.
        """
        import ipaddress as ipaddr
        current = self.value
        if self.iterator >= self.count and self.count != 0:
            self.value = self.start_value
            self.iterator = 1
        else:
            ip = ipaddr.IPv6Address(self.value)
            try:
                hex_ip = hex(int(ip))
                part_hex_lo = hex_ip[-8:]
                part_hex_hi = hex_ip[0:-8]
                int_hex_lo = int(part_hex_lo, 16)
                int_lo = int_hex_lo + self.increment
                if int_lo > int("FFFFFFFF", 16):
                    diff = int_lo - int("FFFFFFFF", 16)
                    int_lo = int("00000000", 16) + diff
                if int_lo < int("00000000", 16):
                    diff = int_lo - int("00000000", 16)
                    int_lo = int("FFFFFFFF", 16) + diff
                part_hex_lo = hex(int_lo)[2:]
                new_ip_hex = part_hex_hi + part_hex_lo.zfill(8)
                ip = ipaddr.IPv6Address(int(new_ip_hex, 16))
                self.value = str(ip)
            except ipaddr.AddressValueError:
                self.value = self.start_value
            self.iterator += 1
        return current


class PypackerFlowLabelGenerator(BaseGenerator):
    """
    @description  Iteration class for list of Flow Label generation
    @param start_value:  initial Flow value
    @type start_value:  str
    @param increment:  incrementation step
    @type increment:  int
    @param count:  number of iteration steps
    @type count:  int
    """

    def __next__(self):
        """
        @brief  Get next generated Flow Label value.
        """
        current = self.value
        if self.iterator >= self.count and self.count != 0:
            self.value = self.start_value
            self.iterator = 1
        else:
            self.value = self.value + self.increment
            if self.value > 1048575:
                diff = self.value - 1048575
                self.value = diff - 1
            if self.value < 0:
                diff = self.value
                self.value = 1048576 + diff
            self.iterator += 1
        return current


class PypackerLspIdGenerator(BaseGenerator):
    """
    @description  Iteration class for list of LSP IDs one byte generation
    @param start_value:  initial LSP ID value
    @type start_value:  str
    @param increment:  incrementation step
    @type increment:  int
    @param count:  number of iteration steps
    @type count:  int
    """

    def __next__(self):
        """
        @brief  Get next generated MAC address.
        """
        current = self.value
        if self.iterator >= self.count and self.count != 0:
            self.value = self.start_value
            self.iterator = 1
        else:
            int_val = int(self.value.split('.')[2], 16) + self.increment
            if int_val > 65535:
                int_val = 1
            self.value = self.value[:10] + str(hex(int_val)[2:]).zfill(4) + self.value[14:]
            self.iterator += 1
        return current
