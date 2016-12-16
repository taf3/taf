#!/usr/bin/env python
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

@file  test_ui_iss_cli.py

@summary  ISS CLI UI wrappers.unittests
"""



SAMPLE = """\
Gi0/8 up, line protocol is down (not connect)
Bridge Port Type: Customer Bridge Port

Interface SubType: gigabitEthernet
Interface Alias: Slot0/8

Hardware Address is 00:00:00:00:00:00
MTU  1500 bytes,
Error in Duplex status
10 Mbps,  No-Negotiation
HOL Block Prevention enabled.
CPU Controlled Learning disabled.
Auto-MDIX on
Input flow-control is off,output flow-control is off

Link Up/Down Trap is enabled

Reception Counters
   Octets                    : 32628
   Unicast Packets           : 32628
   Multicast Packets         : 32628
   Broadcast Packets         : 0
   Discarded Packets         : 0
   Error Packets             : 0
   Unknown Protocol          : 0

Transmission Counters
   Octets                    : 0
   Unicast Packets           : 1195516439
   Multicast Packets         : 1195516448
   Broadcast Packets         : 1195516448
   Discarded Packets         : 1195516448
   Error Packets             : 1195516448

cpu0 up, line protocol is up (connected)
Interface SubType: Not Applicable
Interface Alias: p1p1

Hardware Address is a0:36:9f:5d:00:3f
MTU  1500 bytes,
Error in Duplex status
Auto-speed,  Auto-Negotiation
HOL Block Prevention disabled.
CPU Controlled Learning disabled.
Input flow-control is off,output flow-control is off

Link Up/Down Trap is enabled

Reception Counters
   Octets                    : 0
   Unicast Packets           : 0
   Multicast Packets         : 0
   Broadcast Packets         : 0
   Discarded Packets         : 0
   Error Packets             : 0
   Unknown Protocol          : 0

Transmission Counters
   Octets                    : 0
   Unicast Packets           : 0
   Multicast Packets         : 0
   Broadcast Packets         : 0
   Discarded Packets         : 0
   Error Packets             : 0
"""