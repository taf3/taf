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

"""``kubernetes.py``

"""

from k8sclient.client import api_client
from k8sclient.client.apis import apiv_api


class KubernetesHelper(object):

    def __init__(self, kubernetes):
        super().__init__()
        self.kubernetes = kubernetes

    def label_node(self, name, labels):
        return self.kubernetes.api.patch_namespaced_node(body={'metadata': {'labels': labels}},
                                                         name=name)

    def get_number_of_pods(self):
        return len(self.kubernetes.api.list_namespaced_pod(
                   namespace='default').items)

    def clear_labels(self, nodes, labels):
        for a_node in nodes:
            self.label_node(labels={key: None for key in labels}, name=a_node)


class Kubernetes(object):

    def __init__(self, endpoint):
        super().__init__()
        self.client = api_client.ApiClient(endpoint)
        self.api = apiv_api.ApivApi(self.client)
        self.helper = KubernetesHelper(self)

    def __getattr__(self, name):
        attr = getattr(self.api, name)
        setattr(self, name, attr)
        return attr
