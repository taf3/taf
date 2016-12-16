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

@file hugepages.py

@summary Class to abstract hugepages operations
"""


class HugePages(object):

    def __init__(self, cli_send_command):
        """
        @brief Initialize Hugepages class.
        """
        super(HugePages, self).__init__()
        self.cli_send_command = cli_send_command

    def mount(self, nr_hugepages, hugepage_size='2048kB'):
        """
        @brief  Mount hugepages
        @param nr_hugepages: Number of hugepages
        @type nr_hugepages: int
        @param hugepage_size: Current hugepage allocated size
        @type hugepage_size: str
        """
        self.cli_send_command("mkdir -p /mnt/huge")
        self.change_number(nr_hugepages, hugepage_size)
        self.cli_send_command("mount -t hugetlbfs nodev /mnt/huge")

    def get_number(self, hugepage_size='2048kB'):
        """
        @brief  Get number of hugepages
        @param hugepage_size: Current hugepage allocated size
        @type hugepage_size: str
        @rtype:  int
        @return:  Returns number of hugepages
        """
        output = self.cli_send_command(
            command='cat /sys/devices/system/node/node0/hugepages/hugepages-{}/nr_hugepages'.format(hugepage_size)).stdout
        return int(output)

    def change_number(self, nr_hugepages, hugepage_size='2048kB'):
        """
        @brief  Change number of hugepages
        @param nr_hugepages: Number of hugepages
        @type nr_hugepages: int
        @param hugepage_size: Current hugepage allocated size
        @type hugepage_size: str
        """
        self.cli_send_command(
            command='echo {} > /sys/devices/system/node/node0/hugepages/hugepages-{}/nr_hugepages'.format(nr_hugepages,
                                                                                                          hugepage_size))
