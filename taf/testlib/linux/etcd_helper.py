# Copyright (c) 2016 - 2017, Intel Corporation.
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

"""``etcd_helper.py``

"""

import itertools
from contextlib import suppress
import time

import etcd
from plugins import loggers
from testlib.linux.utils import wait_for


ROOT_KEY = '/intel.com/tests'


class EtcdHelperException(Exception):
    pass


class EtcdHelper(object):

    CLASS_LOGGER = loggers.ClassLogger()

    def __init__(self, endpoint):
        if isinstance(endpoint, str):
            etcd_protocol, address_port = endpoint.split('://')
            etcd_address, etcd_port = address_port.split(':')
            self.etcd_config = {
                'host': etcd_address,
                'port': int(etcd_port),
                'protocol': etcd_protocol
            }
        elif isinstance(endpoint, dict):
            self.etcd_config = endpoint

        self.etcd = etcd.Client(**self.etcd_config)

        self._root_key = ROOT_KEY
        self._cwd = ROOT_KEY
        self._latest_id_key = '/'.join([ROOT_KEY, 'latest'])

    def init_etcd(self):
        self.CLASS_LOGGER.debug("Initializing etcd test entries")
        self.etcd.write(self._latest_id_key, "0")

    def change_dir(self, directory):
        self._cwd = '/'.join([self._root_key, directory])

    def _get_key(self, item):
        return '/'.join(itertools.chain([self._cwd], item.split('__')[1:]))

    def _get_root_key(self, item):
        return '/'.join(itertools.chain([self._root_key], item.split('__')[1:]))

    def __getattr__(self, item):
        if item.startswith('key__'):
            return self._get_key(item)
        elif item.startswith('rootvalue__'):
            return self.etcd.read(self._get_root_key(item))
        elif item.startswith('value__'):
            return self.etcd.read(self._get_key(item))
        raise AttributeError('Unknown attribute {}'.format(item))

    def __setattr__(self, item, value):
        if item.startswith('rootvalue__'):
            self.etcd.write(self._get_root_key(item), value)
        elif item.startswith('value__'):
            self.etcd.write(self._get_key(item), value)
        else:
            super().__setattr__(item, value)

    @property
    def latest_id(self):
        with suppress(AttributeError):
            return self._latest_id
        for _ in range(2):
            with suppress(etcd.EtcdKeyNotFound):
                self._latest_id = int(self.etcd.read(self._latest_id_key).value)  # pylint: disable=no-member
                return self._latest_id
            self.init_etcd()
        raise EtcdHelperException("Failed to find test_id")


    def read_list(self, key):
        return self.etcd.read(key).leaves

    def wait_for_key_count(self, key, count, timeout=15):
        def get_key_count():
            with suppress(etcd.EtcdKeyNotFound):
                return len(list(self.read_list(key)))
            return 0

        self.CLASS_LOGGER.info('Waiting for %s to give %d. Timeout is %d.', key, count, timeout)
        wait_for(iter(get_key_count, count), timeout)
        self.CLASS_LOGGER.debug('%s gave %d', key, count)
