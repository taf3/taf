"""
@copyright Copyright (c) 2015-2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  sfc_client.py

@summary  Tempest client for SFC neutron extension
"""
# Documentation of SFC API:
# http://docs.openstack.org/developer/networking-sfc/api.html
from tempest.lib.services.network import base

# Suppress the following pylint warnings:
# W0622 Redefining built-in 'id'
# C0103 invalid argument name 'id'
# Reasoning: It is used here just to pass data from a dictionary returned
# by OpenStack. It is has very limited scope - only inside one line function.
# pylint: disable=W0622,C0103

class SfcClient(base.BaseNetworkClient):

    base_uri = '/sfc'

    port_pair_uri = base_uri + '/port_pairs'
    port_pair_uri_fmt = port_pair_uri + '/%s'

    port_pair_group_uri = base_uri + '/port_pair_groups'
    port_pair_group_uri_fmt = port_pair_group_uri + '/%s'

    port_chain_uri = base_uri + '/port_chains'
    port_chain_uri_fmt = port_chain_uri + '/%s'

    flow_classifier_uri = base_uri + '/flow_classifiers'
    flow_classifier_uri_fmt = flow_classifier_uri + '/%s'

    # Port pairs
    # name: string
    # description: string
    # ingress: <port-id>
    # egress: <port-id>
    def create_port_pair(self, **kwargs):
        post_data = {'port_pair': kwargs}
        return self.create_resource(self.port_pair_uri, post_data)

    def update_port_pair(self, id, **kwargs):
        post_data = {'port_pair': kwargs}
        return self.udpate_resource(self.port_pair_uri_fmt % id, post_data)

    def show_port_pair(self, id):
        return self.show_resource(self.port_pair_uri_fmt % id)

    def delete_port_pair(self, id):
        return self.delete_resource(self.port_pair_uri_fmt % id)

    def list_port_pairs(self):
        return self.list_resources(self.port_pair_uri)

    # Port Groups
    # name: string
    # description: string
    # port_pairs: [<port_pair-id>, <port_pair-id> ]
    def create_port_pair_group(self, **kwargs):
        post_data = {'port_pair_group': kwargs}
        return self.create_resource(self.port_pair_group_uri, post_data)

    def update_port_pair_group(self, id, **kwargs):
        post_data = {'port_pair_group': kwargs}
        return self.update_resource(self.port_pair_group_uri_fmt % id, post_data)

    def show_port_pair_group(self, id):
        return self.show_resource(self.port_pair_group_uri_fmt % id)

    def delete_port_pair_group(self, id):
        return self.delete_resource(self.port_pair_group_uri_fmt % id)

    def list_port_pair_groups(self):
        return self.list_resources(self.port_pair_group_uri)

    # Port Chains
    # name: string
    # description: string
    # flow_classifiers: [<fc-id>, <fc-id>, ... ]
    # port_pair_groups: [<pg-id>, <pg-id>, ... ]
    def create_port_chain(self, **kwargs):
        post_data = {'port_chain': kwargs}
        return self.create_resource(self.port_chain_uri, post_data)

    def update_port_chain(self, id, **kwargs):
        post_data = {'port_chain': kwargs}
        return self.update_resource(self.port_chain_uri_fmt % id, post_data)

    def show_port_chain(self, id):
        return self.show_resource(self.port_chain_uri_fmt % id)

    def delete_port_chain(self, id):
        return self.delete_resource(self.port_chain_uri_fmt % id)

    def list_port_chains(self):
        return self.list_resources(self.port_chain_uri)

    # Flow classifiers
    # name: string
    # description: string
    # ethertype: string (IPV4 or IPV6)
    # protocol: ip protocol name (string)
    # source_port_range_min: integer
    # source_port_range_max: integer
    # destination_port_range_min: integer
    # destination_port_range_max: integer
    # source_ip_prefix: CIDR
    # destination_ip_prefix: CIDR
    # logical_source_port: uuid
    # logical_destination_port: uuid
    # l7_parameters: Dict. of L7 parameters
    def create_flow_classifier(self, **kwargs):
        post_data = {'flow_classifier': kwargs}
        return self.create_resource(self.flow_classifier_uri, post_data)

    def update_flow_classifier(self, id, **kwargs):
        post_data = {'flow_classifier': kwargs}
        return self.update_resource(self.flow_classifier_uri_fmt % id, post_data)

    def show_flow_classifier(self, id):
        return self.show_resource(self.flow_classifier_uri_fmt % id)

    def delete_flow_classifier(self, id):
        return self.delete_resource(self.flow_classifier_uri_fmt % id)

    def list_flow_classifiers(self):
        return self.list_resources(self.flow_classifier_uri)
