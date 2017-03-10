# Copyright (c) 2015 - 2017, Intel Corporation.
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

"""``magnum.py``

`Support for magnum feature of Openstack`

Uses magnum tempest client that was taken form the upstream magnum repository.
When using magnum clients, the environment.json file should contain some additional entries:

"""

###############################################################################
# Requires the following fiels in environment json in addition to what's needed
# for the virtual_env:
# {
#   ...
#   "dns_nameserver": "10.248.2.1",
#   "http_proxy": "http://proxy.example.com"
#   "https_proxy": "https://proxy.example.com"
#   "no_proxy": "10.0.0.1,10.0.0.2"
#   "insecure_registry": "20.0.0.1:4000"
#   "ntp_server": "ntp.example.com",
#   ...
# }
#
###############################################################################

from testlib.tempest_clients.magnum.clients.cluster_client import ClusterClient
from testlib.tempest_clients.magnum.clients.cluster_template_client import ClusterTemplateClient
from testlib.tempest_clients.magnum.clients.magnum_service_client import MagnumServiceClient
import testlib.tempest_clients.magnum.models
from plugins import loggers
import pprint
import copy


DISTRO_METADATA = {
    'fedora-atomic': {
        'ssh_user': 'fedora',
        'ssh_port': 22,
    },
}


CLUSTER_TEMPLATE_DEFAULTS = {
    'coe': 'kubernetes',
    'network_driver': 'flannel',
    'docker_volume_size': 5,
    'labels': {'flannel_backend': 'vxlan'},
    'flavor_id': 'm1.small',
    'master_flavor_id': 'm1.medium',
    'tls_disabled': 'True',
}


CLUSTER_CONSTS = {
    'os_distro': 'fedora-atomic',
}


class Magnum(object):

    CLASS_LOGGER = loggers.ClassLogger()

    def __init__(self, venv):
        self.venv = venv
        self.config = venv.config
        self.admin_manager = venv.handle.admin_manager
        self.manager = venv.handle.manager
        self.magnum_models = testlib.tempest_clients.magnum.models
        self.tempest_lib = venv.tempest_lib

        try:
            self.manager.cluster_client = ClusterClient(self.manager.auth_provider)
            self.admin_manager.cluster_client = ClusterClient(self.admin_manager.auth_provider)

            self.manager.cluster_template_client = \
                ClusterTemplateClient(self.manager.auth_provider)
            self.admin_manager.cluster_template_client = \
                ClusterTemplateClient(self.admin_manager.auth_provider)

            self.manager.magnum_service_client = MagnumServiceClient(self.manager.auth_provider)
            self.admin_manager.magnum_service_client = \
                MagnumServiceClient(self.admin_manager.auth_provider)

        except:
            self.CLASS_LOGGER.error('Error adding magnum clients.')
            raise

    def delete_cluster(self, uuid, wait=True):

        self.CLASS_LOGGER.info("Deleting the cluster (id=%s).", uuid)

        client = self.manager.cluster_client
        client.delete_cluster(uuid)
        if wait:
            client.wait_for_cluster_to_delete(uuid)

    def create_cluster(self, wait=True, **kwargs):

        client = self.manager.cluster_client

        kwargs.setdefault('name',
                          self.venv.tempest_lib.common.utils.data_utils.rand_name('onp_cluster'))
        kwargs.setdefault('discovery_url', None)

        if loggers.LOG_LEVEL == 'DEBUG':
            self.CLASS_LOGGER.debug("Cluster dict:\n%s", pprint.pformat(kwargs))

        model = self.magnum_models.cluster_model.ClusterEntity.from_dict(kwargs)

        self.CLASS_LOGGER.info("Creating a cluster.")
        resp, cluster = client.post_cluster(model)
        assert resp['status'] == '202'

        if wait:
            client.wait_for_created_cluster(cluster.uuid, delete_on_error=False)
            _, cluster = client.get_cluster(cluster.uuid)
            assert cluster.status == 'CREATE_COMPLETE'

        self.venv.handle.addCleanup(self.delete_cluster, cluster.uuid)
        return cluster

    def delete_cluster_template(self, uuid):
        self.CLASS_LOGGER.info("Deleting the cluster template(id=%s).", uuid)
        client = self.manager.cluster_template_client
        client.delete_cluster_template(uuid)

    def create_cluster_template(self, template, **kwargs):

        client = self.manager.cluster_template_client
        image_client = self.manager.image_client_v2

        template = copy.deepcopy(template)

        template.setdefault('external_network_id', self.config.network.public_network_id)
        template.setdefault('keypair_id', self.venv.key['name'])
        for key, default_value in CLUSTER_TEMPLATE_DEFAULTS.items():
            template.setdefault(key, default_value)

        for setting in ['dns_nameserver', 'http_proxy', 'https_proxy', 'no_proxy']:
            template.setdefault(setting, self.venv.env_settings.get(setting))

        try:
            image = image_client.show_image(template['image_id'])
            assert image['id'] == template['image_id']
        except self.tempest_lib.exceptions.NotFound:
            template['image_id'] = self.venv.get_image_by_name(template['image_id'])['id']

        metadata = {'os_distro': kwargs.setdefault('os_distro', CLUSTER_CONSTS['os_distro'])}

        self.manager.compute_images_client.set_image_metadata(template['image_id'], metadata)

        if loggers.LOG_LEVEL == 'DEBUG':
            self.CLASS_LOGGER.debug("Template dict:\n%s", pprint.pformat(template))

        self.CLASS_LOGGER.info("Creating a cluster template.")
        model = self.magnum_models.cluster_template_model.ClusterTemplateEntity.from_dict(template)
        resp, cluster_template = client.post_cluster_template(model)
        assert resp['status'] == '201'
        self.venv.handle.addCleanup(self.delete_cluster_template, cluster_template.uuid)
        return cluster_template
