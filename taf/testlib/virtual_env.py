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

"""``virtual_env.py``

Tempest API UI specific functionality.

Note:
    TEMPEST_VERSION  201610100101

    Requires settings environment json entry. Example:
    {
     "name": "settings",
     "entry_type": "settings",
     "instance_type": "settings",
     "id": "993",
     "images_share_path": "/path/to/openstack/vm/images",
     "external_net_gw_ip_cidr": "192.168.31.1/24",
     "external_net_pool_start": "100",
     "external_net_pool_end": "199",
     "other_configs": {"ovs_type": "ovs",}
    }
"""

import time
import re
import os
import json
import pprint
import itertools
import ast
from functools import wraps
from itertools import chain

import netaddr
import pytest

from . import loggers
from . import environment
from .custom_exceptions import TAFCoreException
from .dev_linux_host_vm import GenericLinuxVirtualHost
from .helpers import merge_dicts
from .common3 import Environment, custom_classes


# external_net_pool_start and external_net_pool_end values have to be inside
# range defined by following two constants:
NET_POOL_MINIMUM = 1
NET_POOL_MAXIMUM = 254


class OpenStackNoSuchImage(Exception):
    pass


def only_with_neutron_extension(extension):
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if self.has_neutron_extension(extension):
                return func(self, *args, **kwargs)
            else:
                self.class_logger.error(('Function %s called that expects neutron extension '
                                         '%s which is not installed.'), func.__name__, extension)
        return wrapper
    return decorator


def only_with_service(service):
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if self.has_service(service):
                return func(self, *args, **kwargs)
            else:
                self.class_logger.error(('Function %s called that expects %s service '
                                         ' which is not available.'), func.__name__, service)
        return wrapper
    return decorator


class VirtualEnv(object):
    """VirtualEnv Main class of all test virtual environment using tempest.

    Note:
        This class has to be used as base fixture in all tempest test cases.
        It provides number of common methods to initialize, shutdown,
        cleanup environment functions which basically call appropriate methods
        of particular device classes.

    """

    class_logger = loggers.ClassLogger()

    _DEFAULT_FLAVOR_SPEC = {
        'ram': 1024,
        'disk': 10,
        'vcpus': 4,
    }
    DPDK_EXTRA_SPECS = {'hw:mem_page_size': 'large'}

    OVS_FLAVOR_SPEC = merge_dicts(
        _DEFAULT_FLAVOR_SPEC,
        {'name': 'venv-ovs-flavor'},
    )
    DPDK_FLAVOR_SPEC = merge_dicts(
        _DEFAULT_FLAVOR_SPEC,
        DPDK_EXTRA_SPECS,
        {'name': 'venv-dpdk-flavor'},
    )

    # Example: my_vIPS_image-fedora-bare.qcow2
    IMAGE_NAME_PATTERN = r'\S*{0}\S*-(?P<user>\w+)-(?P<cont_frmt>\w+)\.(?P<disk_frmt>\w+)'

    def __init__(self, opts=None):
        super(VirtualEnv, self).__init__()
        self.class_logger.info('Initializing virtual environment...')
        self.opts = opts
        self.env_settings = self._get_settings(self.opts.env)
        self.tempest_path = self.opts.tempest_path
        self.reuse_venv = ast.literal_eval(self.opts.reuse_venv)
        self.neutron_extensions = None
        self.services = None

        import tempest
        from tempest.scenario.manager import NetworkScenarioTest
        self.tempest_lib = tempest.lib

        NetworkScenarioTest.runTest = None
        self.config = tempest.config.CONF

        try:
            self.handle = NetworkScenarioTest()
            self.handle.set_network_resources()
            self.handle.setUpClass()
            self.handle._resultForDoCleanups = self.handle.defaultTestResult()
            self.handle.setUp()

        except Exception:
            self.class_logger.exception(
                'Could not create tempest handle object. \
                Please re-check tempest config in %s', self.tempest_path)

            pytest.exit("VirtualEnv::__init__")

        if self.has_neutron_extension('sfc'):
            self._add_sfc_client()

        if self.has_service('magnum'):
            self._add_magnum_clients()

        self.other_config = self.env_settings.get('other_configs', {})
        self.ovs_type = self.other_config.get('ovs_type')

        # create initial parameters required by all instances
        self.images_path = self.env_settings.get("images_share_path")
        self.create_loginable_secgroup_rule()
        self.ensure_keypair()
        self.tenant_id = self.handle.networks_client.tenant_id

        _default_spec = self.DPDK_FLAVOR_SPEC if self.is_DPDK() else self.OVS_FLAVOR_SPEC
        self.DEFAULT_FLAVOR = self.get_flavor_by_spec(_default_spec)
        assert self.DEFAULT_FLAVOR

        public_access_kwargs = {
            'try_reuse': self.reuse_venv,
            'name': self.tempest_lib.common.utils.data_utils.rand_name('tempest-public-net'),
            'tenant_id': self.handle.os_adm.networks_client.tenant_id,  # we want public in admin project
        }
        assert self.ensure_public_access(**public_access_kwargs)

        # Prepare environment objects
        self.env = Environment(self.opts)
        self.get_ports = self.env.get_ports
        instances = (entry['entry_type'] for entry in self.env.config if 'entry_type' in entry)
        for entry_type in instances:
            entry_name = custom_classes[entry_type]['NAME']
            setattr(self, entry_name, getattr(self.env, entry_name))

    def ensure_keypair(self):
        generate = False
        key = {}
        try:
            keyfile = self.env_settings['ssh_key']
            pubkeyfile = self.env_settings['ssh_pubkey']
        except KeyError:
            self.class_logger.debug("ssh key not provided, a new will be generated")
            generate = True
        else:
            self.class_logger.debug("Reading private key from %s", keyfile)
            self.class_logger.debug("Reading public key from %s", pubkeyfile)
            try:
                with open(keyfile, 'r') as stream:
                    key['private_key'] = stream.read()
                with open(pubkeyfile, 'r') as stream:
                    key['public_key'] = stream.read()
            except IOError as e:
                self.class_logger.info("ssh key provided but can't be used! (%s)", format(e))
                generate = True
            else:
                client = self.handle.manager.keypairs_client
                name = self.tempest_lib.common.utils.data_utils.rand_name('tempest-key')
                self.key = client.create_keypair(name=name,
                                                 public_key=key['public_key'])['keypair']
                self.key['private_key'] = key['private_key']

        if generate:
            self.key = self.handle.create_keypair()

        assert 'private_key' in self.key
        assert 'public_key' in self.key

    def _get_neutron_extensions(self):
        if self.neutron_extensions is None:
            client = self.handle.admin_manager.network_extensions_client
            self.neutron_extensions = client.list_extensions()['extensions']
        return self.neutron_extensions

    def _get_services(self):
        if self.services is None:
            client = self.handle.admin_manager.identity_services_client
            self.services = client.list_services()['OS-KSADM:services']
        return self.services

    def has_service(self, service):
        services = self._get_services()
        return service in [s['name'] for s in services]

    def has_neutron_extension(self, extension):
        extensions = self._get_neutron_extensions()
        return extension in [e['alias'] for e in extensions]

    def _add_sfc_client(self):
        from testlib.tempest_clients.sfc_client import SfcClient

        self.class_logger.info('Adding SfcClient.')

        try:
            # FIXME: do I need admin_manager?
            self.handle.sfc_client = SfcClient(
                self.handle.manager.auth_provider,
                self.config.network.catalog_type,
                self.config.network.region or self.config.identity.region,
                endpoint_type=self.config.network.endpoint_type,
                build_interval=self.config.network.build_interval,
                build_timeout=self.config.network.build_timeout,
                **self.handle.admin_manager.default_params)
        except Exception:
            self.class_logger.exception('Could not create sfc client!')

    def _add_magnum_clients(self):
        from .magnum import Magnum
        self.class_logger.info('Adding Magnum clients.')
        self.magnum = Magnum(self)

    def _get_settings(self, file_name=None):
        """Load environment config from file.

        Args:
            file_name(str):  Name of a json file with a test environment configuration.

        Raises:
            TAFCoreException:  configuration file is not found
            IOError:  error on reading configuration file

        Returns:
            dict:  dict of the selected configuration.

        Notes:
            This method shouldn't be used outside this class.
            Use "config" attribute to access environment configuration.

        """
        if not file_name:
            self.class_logger.info("Environment file isn't set." +
                                   " All configurations will be taken from setup file.")
            # Return empty dict
            return {}
        path_to_config = environment.get_conf_file(conf_name=file_name, conf_type="env")
        if not path_to_config:
            message = "Specified configuration file %s not found." % file_name,
            raise TAFCoreException(message)
        try:
            config = json.loads(open(path_to_config).read())
        except:
            message = "Cannot read specified configuration: %s" % path_to_config
            self.class_logger.error(message)
            raise IOError(message)
        return next(cfg for cfg in config if cfg['instance_type'] == 'settings')

    def cleanup(self):
        self.class_logger.info('Cleaning virtual environment...')
        # Order defined by unittest: tearDown -> doCleanups -> tearDownClass
        for cleaner in [self.handle.tearDown,
                        self.handle.doCleanups,
                        self.handle.tearDownClass]:
            try:
                cleaner()
            except Exception:
                self.class_logger.exception('Exception in tempest cleanup -> %s', cleaner.__name__)
                continue

    def is_DPDK(self, force_check=False):
        if force_check or self.ovs_type is None:
            return self._is_DPDK()
        return 'dpdk' in self.ovs_type

    def _is_DPDK(self):
        # TODO assess the presence of DPDK in the OpenStack installation
        return False

    def create_loginable_secgroup_rule(self):
        return self.handle._create_loginable_secgroup_rule()  # pylint: disable=protected-access

    def wait_for_server_status(self, vm_id, status):
        # waiters wrapper method
        from tempest.common import waiters
        return waiters.wait_for_server_status(self.handle.servers_client, vm_id, status)

    def ensure_public_access(self, try_reuse=True, name=None, tenant_id=None):
        """Create or reuse public/external network.

        Args:
            try_reuse(bool): attempt at reusing the public network or delete it
            name:
            tenant_id:

        Returns:
            bool: is the public network available (whether by creating or reusing)

        """

        if not name:
            name = self.tempest_lib.common.utils.data_utils.rand_name('tempest-public-network')
        if not tenant_id:
            tenant_id = self.tenant_id

        _external_net_gw_ip_cidr = self.env_settings.get('external_net_gw_ip_cidr')
        assert _external_net_gw_ip_cidr
        net_ip = netaddr.IPNetwork(_external_net_gw_ip_cidr)
        _external_net_pool_start = self.env_settings.get('external_net_pool_start')
        _external_net_pool_end = self.env_settings.get('external_net_pool_end')

        assert NET_POOL_MINIMUM <= int(_external_net_pool_start) < int(_external_net_pool_end) <= NET_POOL_MAXIMUM

        # Try to reuse existing stuff that meets requirements, if desirable (devstack)
        if try_reuse and self._reuse_public_access(net_ip):
            self.class_logger.debug('Reused')
            return True

        self.class_logger.debug('No reuse')
        # cleanup
        self._delete_external_elements()

        # create new public network
        public_network_kwargs = {
            'name': name,
            'tenant_id': tenant_id,
        }
        public_network = self.create_public_network(**public_network_kwargs)
        assert public_network

        subnet_name = self.tempest_lib.common.utils.data_utils.rand_name('tempest-public-subnet')
        allocation_prefix = _external_net_gw_ip_cidr.rsplit('.', 1)[0]
        subnet_kwargs = {
            'cidr': '{}'.format(net_ip.cidr),
            'name': subnet_name,
            'tenant_id': tenant_id,
            'ip_version': 4,
            'allocation_pools': [{
                'start': '{}.{}'.format(allocation_prefix, _external_net_pool_start),
                'end': '{}.{}'.format(allocation_prefix, _external_net_pool_end)}],
            'gateway_ip': net_ip.ip,
            'enable_dhcp': False,
        }
        self._create_subnet(public_network['id'], **subnet_kwargs)

        self.config.network.public_network_id = public_network['id']
        return self.config.network.public_network_id

    def _get_external_elements(self):
        routers_client = self.handle.os_adm.routers_client
        net_filter = {'router:external': True}
        net_2_router_map = {net['id']: [] for net in self.handle._list_networks(**net_filter)}  # pylint: disable=protected-access
        routers_resp = routers_client.list_routers()
        for router in routers_resp['routers']:
            ext_gateway = router.get('external_gateway_info', {})
            # external_gateway_info always exists and can be None
            if ext_gateway:
                net_id = ext_gateway.get('network_id', object())
                net_2_router_map.get(net_id, []).append(router['id'])
        return net_2_router_map

    def _delete_external_elements(self):
        """Look for the external networks and delete them.

        """
        routers_client = self.handle.os_adm.routers_client
        networks_client = self.handle.os_adm.networks_client

        net_2_router_map = self._get_external_elements()
        for network_id, routers in net_2_router_map.items():
            floating_ips = self.handle.os_adm.floating_ips_client.list_floatingips(floating_network_id=network_id)
            for f_ip in floating_ips['floatingips']:
                self.handle.os_adm.floating_ips_client.delete_floatingip(f_ip['id'])
            for router_id in routers:
                routers_client.update_router(router_id, external_gateway_info={})

            self.class_logger.debug('Removing external network: (%s)',
                                    networks_client.show_network(network_id)['network']['name'])
            networks_client.delete_network(network_id)

    def _reuse_public_access(self, net_ip):
        """Search for the external networks and verify gateway IP in required network(net_ip)

        """
        subnets = self.handle._list_subnets()
        net_filter = {'router:external': True}
        nets = self.handle._list_networks(**net_filter)
        try:
            net = nets.pop(0)
            assert not nets
        except (IndexError, AssertionError):
            # if multiple external network, we need to cleanup all
            return False

        for subnet_id in net['subnets']:
            subnet_gateway_ip = next((sub for sub in subnets if sub['id'] == subnet_id), {}).get('gateway_ip')
            if subnet_gateway_ip and subnet_gateway_ip in net_ip:
                self.config.network.public_network_id = net['id']
                return True
        return False

    def create_router(self, routers_client=None, name=None, network_id=None, tenant_id=None,
                      enable_snat=False, **kwargs):
        """Create a router.

        Args:
            network_id(str): id of the network subnet of which to connect to the router

        Returns:
            dict: the created router

        """
        if not routers_client:
            routers_client = self.handle.os_adm.routers_client

        if not name:
            name = self.tempest_lib.common.utils.data_utils.rand_name('tempest-router')
        if not tenant_id:
            tenant_id = self.tenant_id

        ext_gw_info = {}
        if network_id:
            ext_gw_info['network_id'] = network_id
        if enable_snat:
            ext_gw_info['enable_snat'] = True

        router_kwargs = merge_dicts(
            kwargs,
            {
                'name': name,
                'tenant_id': tenant_id,
                'external_gateway_info': ext_gw_info,
            },
        )

        router_resp = routers_client.create_router(**router_kwargs)
        router = router_resp['router']
        if router:
            self.handle.addCleanup(routers_client.delete_router, router['id'])
        return router

    def add_router_interface(self, router_id, routers_client=None, subnet_id=None):
        """
        """
        if not routers_client:
            routers_client = self.handle.os_adm.routers_client

        routers_client.add_router_interface(router_id, subnet_id=subnet_id)
        iface_cleaner = routers_client.remove_router_interface
        self.handle.addCleanup(iface_cleaner, router_id, subnet_id=subnet_id)

    def delete_router(self, router_id, routers_client=None, ports_client=None):
        """
        """
        if not routers_client:
            routers_client = self.handle.os_adm.routers_client
        if not ports_client:
            ports_client = self.handle.os_adm.ports_client

        clients = {
            'routers_client': routers_client,
            'ports_client': ports_client,
        }

        self._remove_router_interfaces(router_id, **clients)
        routers_client.delete_router(router_id)

    def _remove_router_interfaces(self, router, routers_client=None, ports_client=None):
        """
        """
        if not routers_client:
            routers_client = self.handle.os_adm.routers_client
        if not ports_client:
            ports_client = self.handle.os_adm.ports_client

        router_id = None
        try:
            if isinstance(router, dict) and router['id']:
                pass
            else:
                router = routers_client.show_router(router)['router']
            router_id = router['id']
        except IndexError:
            raise Exception("Invalid router parameter specified: {}".format(router))

        router_ports = ports_client.list_ports(device_id=router_id)['ports']
        for port in router_ports:
            try:
                routers_client.remove_router_interface(router_id, port_id=port['id'])
                ports_client.delete_port(port['id'])
            except self.tempest_lib.exceptions.NotFound:
                pass

        routers_client.update_router(router_id, external_gateway_info={})

    def create_network(self, with_router=False, with_subnet=False, name=None, tenant_id=None,
                       **kwargs):
        """Create standard network, subnet, router.

        Args:
            with_router(bool): whether or not to add the network to tenant_id router
            with_subnet(bool): whether or not to create a subnet for the network
            name:
            tenant_id:
            kwargs:

        """

        if with_router and not with_subnet:
            raise Exception('Cannot add network w/o subnet to router (with_router=True,\
                            with_subnet=False)')

        if not name:
            name = self.tempest_lib.common.utils.data_utils.rand_name('tempest-network')
        if not tenant_id:
            tenant_id = self.tenant_id

        network_kwargs = merge_dicts(
            kwargs,
            {
                'name': name,
                'tenant_id': tenant_id,
            },
        )
        subnet_kwargs = {
            'name': self.tempest_lib.common.utils.data_utils.rand_name('tempest-subnet'),
            'tenant_id': tenant_id,
            'enable_dhcp': True,
        }

        subnet = None
        router = None
        network = self._create_bare_network(**network_kwargs)
        assert network

        if with_subnet:
            subnet = self._create_subnet(network['id'], **subnet_kwargs)
            assert subnet

        if with_router:
            router = self.handle._get_router(tenant_id=tenant_id)  # pylint: disable=protected-access
            self.add_router_interface(router['id'], subnet_id=subnet['id'])

        return network, subnet, router

    def create_port(self, network_id, name=None, ports_client=None, tenant_id=None, **kwargs):

        if not ports_client:
            ports_client = self.handle.os_adm.ports_client

        if not name:
            name = self.tempest_lib.common.utils.data_utils.rand_name('tempest-port')
        if not tenant_id:
            tenant_id = self.tenant_id

        port_kwargs = merge_dicts(
            kwargs,
            {
                'name': name,
                'tenant_id': tenant_id,
                'network_id': network_id,
            },
        )

        port = ports_client.create_port(**port_kwargs)['port']
        if port:
            self.handle.addCleanup(ports_client.delete_port, port['id'])

        return port

    def create_public_network(self, name=None, tenant_id=None):
        """Creates a public networks with an optional subnet.

        Args:
            name:
            tenant_id:

        """

        if not name:
            name = self.tempest_lib.common.utils.data_utils.rand_name('tempest-public-network')
        if not tenant_id:
            tenant_id = self.tenant_id

        network_kwargs = {
            'name': name,
            'tenant_id': tenant_id,
            'router:external': True,
        }
        return self._create_bare_network(**network_kwargs)

    def _create_bare_network(self, networks_client=None, name=None, tenant_id=None, **kwargs):
        """Creates a network.

        There is no router and no subnet created for this network.

        Returns:
            dict: the created bare network

        """
        if not networks_client:
            networks_client = self.handle.os_adm.networks_client

        if not name:
            name = self.tempest_lib.common.utils.data_utils.rand_name('tempest-network-bare')
        if not tenant_id:
            tenant_id = self.tenant_id

        network_kwargs = merge_dicts(
            kwargs,
            {
                'name': name,
                'tenant_id': tenant_id,
            },
        )
        network_resp = networks_client.create_network(**network_kwargs)
        network = network_resp['network']
        if network:
            self.handle.addCleanup(networks_client.delete_network, network['id'])
        return network

    def _create_subnet(self, network_id, subnets_client=None,
                       cidr=None, mask_bits=None, name=None, tenant_id=None,
                       pool_start=None, pool_end=None, **kwargs):
        """Create subnet for the specified network.

        The allocation range is defined for ONP lab environment.

        Args:
            network_id(str): the network to create the subnet in
            cidr(str): IP/mask of the mgmt interface, None for project default
            mask_bits(int): subnet mask length in bits
            pool_start(int): allocation pool first host ipv4 tuple (host part)
            pool_end(int): allocation pool last host ipv4 tuple (host part)

        Returns:
            DeletableSubnet: the created subnet

        """
        if not subnets_client:
            subnets_client = self.handle.os_adm.subnets_client

        if not name:
            name = self.tempest_lib.common.utils.data_utils.rand_name('tempest-subnet')
        if not tenant_id:
            tenant_id = self.tenant_id

        if cidr is None:
            cidr = self.config.network.project_network_cidr
            tenant_cidr = netaddr.IPNetwork(cidr)
            if mask_bits is None:
                mask_bits = self.config.network.project_network_mask_bits
        else:
            tenant_cidr = netaddr.IPNetwork(cidr)
            if mask_bits is None:
                mask_bits = tenant_cidr.prefixlen

        def cidr_in_use(cidr, tenant_id):
            cidr_in_use = self.handle._list_subnets(tenant_id=tenant_id, cidr=cidr)  # pylint: disable=protected-access
            return len(cidr_in_use) != 0

        def alloc_pools(cidr, start, end):
            it = cidr.iter_hosts()
            if start is not None:
                it = itertools.dropwhile(lambda x: not str(x).endswith(str(start)),
                                         cidr.iter_hosts())
            if end is not None:
                it = itertools.takewhile(lambda x: not str(x).endswith(str(end)), it)

            return it

        subnet = None
        for subnet_cidr in tenant_cidr.subnet(mask_bits):
            cidr_str = str(subnet_cidr)
            if cidr_in_use(cidr_str, tenant_id=tenant_id):
                continue

            allocation_pools = {}
            if pool_start or pool_end:
                hosts_it = alloc_pools(subnet_cidr, pool_start, pool_end)
                hosts = [h for h in hosts_it]
                if hosts:
                    pool = {
                        'start': hosts[0],
                        'end': hosts[-1],
                    }
                    allocation_pools.update({'allocation_pools': [pool]})

            subnet_kwargs = merge_dicts(
                kwargs,
                allocation_pools,
                {
                    'network_id': network_id,
                    'cidr': cidr_str,
                    'name': name,
                    'tenant_id': tenant_id,
                    'ip_version': 4,
                },
            )
            from tempest.lib import exceptions as lib_exc
            try:
                subnet_resp = subnets_client.create_subnet(**subnet_kwargs)
                self.handle.assertIsNotNone(subnet_resp, 'Unable to allocate tenant network')
                subnet = subnet_resp['subnet']
                if subnet:
                    self.handle.addCleanup(subnets_client.delete_subnet, subnet['id'])
                break

            except lib_exc.Conflict as e:
                is_overlapping_cidr = 'overlaps with another subnet' in str(e)
                if not is_overlapping_cidr:
                    raise e

        return subnet

    def create_image(self, name, fmt, path, disk_format=None):
        """Create OpenStack image.

        Args:
            name:
            fmt:
            path:
            disk_format:

        """
        image_client = self.handle.manager.image_client_v2
        self.class_logger.debug('Creating image %s', name)
        with open(path, 'rb') as image_file:
            params = {
                'name': name,
                'container_format': fmt,
                'disk_format': disk_format if disk_format else fmt,
            }
            image = image_client.create_image(**params)
            assert image['status'] == "queued"
            self.class_logger.debug('Storing image ...')
            image_client.store_image_file(image['id'], image_file)

        return image

    def get_image_by_name(self, img_name):
        image_client = self.handle.manager.image_client_v2
        regex = re.compile(self.IMAGE_NAME_PATTERN.format(img_name))

        try:
            image = next(img for img in image_client.list_images()['images']
                         if img['name'] == img_name or regex.search(img['name']))
        except StopIteration:
            pass
        else:
            self.class_logger.debug('Desired image (%s) for instance found', img_name)
            return image

        # image not in glance (yet) - find it on disk and upload it
        try:
            image = next(img for img in os.listdir(self.images_path)
                         if img == img_name or regex.search(img))
        except StopIteration:
            raise OpenStackNoSuchImage("Image {} not found in {}".format(img_name,
                                                                         self.images_path))
        else:
            match = regex.search(image)
            image = self.create_image(os.path.basename(image),
                                      match.group('cont_frmt'),
                                      os.path.join(self.images_path, image),
                                      match.group('disk_frmt'))
            return image

    def create_flavor(self, name, ram=64, disk=0, vcpus=1, **kwargs):
        """Create flavor.

        Args:
            name(str):
            ram(int):
            disk(int):
            vcpus(int):
            kwargs:

        """
        params = {
            'name': name,
            'ram': ram,
            'disk': disk,
            'vcpus': vcpus,
        }

        flavor_id = kwargs.pop('flavor_id', '')
        if flavor_id:
            params['id'] = flavor_id

        flv_client = self.handle.os_adm.flavors_client
        rand_prefix = params['name']
        num_retry = 10
        flavor = None
        for _ in range(num_retry):
            try:
                resp = flv_client.create_flavor(**params)
            except self.tempest_lib.exceptions.Conflict as exc:
                self.class_logger.debug('Conflict: %s', exc)
                params['id'] = None
                params['name'] = self.tempest_lib.common.utils.data_utils.rand_name(rand_prefix)
            else:
                flavor = resp['flavor']
                break
        assert flavor

        self.handle.addCleanup(flv_client.delete_flavor,
                               flavor['id'])

        if kwargs:
            try:
                flv_client.set_flavor_extra_spec(flavor['id'], **kwargs)
            except self.tempest_lib.exceptions.RestClientException:
                try:
                    for key, val in kwargs.items():
                        resp = flv_client.show_flavor_extra_spec(flavor['id'], key)
                        if resp.get(key) != val:
                            flv_client.update_flavor_extra_spec(flavor['id'], key, val)
                except self.tempest_lib.exceptions.RestClientException:
                    pass
        return flavor

    def _get_flavors(self, flavors_client=None, do_show=False, do_extra_specs=False):
        if not flavors_client:
            flavors_client = self.handle.os_adm.flavors_client

        flavors_map = {}
        flavors = flavors_client.list_flavors()['flavors']
        for f in flavors:
            flavors_map[f['id']] = f_spec = {}
            if do_show:
                f_show = flavors_client.show_flavor(f['id'])['flavor']
                f_spec.update(f_show)
            if do_extra_specs:
                f_extra = flavors_client.list_flavor_extra_specs(f['id'])
                f_spec.update(f_extra)

        return flavors_map

    def get_flavors(self, flavors_client=None):
        return self._get_flavors(flavors_client=flavors_client, do_show=True, do_extra_specs=True)

    def get_flavor_by_spec(self, flavor_spec, flavors_client=None):
        """Flavor retrieval helper method.

        Attempts to satisfy the requirements in the flavor specification input parameter.
        The 'name' property is preference only (but the combination of the other properties is
        overwhelming) and serves mostly for storage purposes instead, naming the newly created
        flavor should the need for one arise - in case of the spec reqs not met by the already
        existing ones.

        """
        if not flavors_client:
            flavors_client = self.handle.os_adm.flavors_client
        flavors_map = self.get_flavors(flavors_client=flavors_client)

        name = flavor_spec.pop('name', None)

        all_flv_keys = set(flavor_spec)
        standard_flv_keys = all_flv_keys.intersection({'ram', 'disk', 'vcpus'})
        extra_flv_keys = all_flv_keys - standard_flv_keys

        _not_found = object()

        def make_iter(keys, data):
            return (value == comp_value for value, comp_value in
                    ((flavor_spec[k], data.get(k, _not_found)) for k in keys))

        def filter_test(comp):
            return all(
                chain(make_iter(standard_flv_keys, comp), make_iter(extra_flv_keys, comp.get('extra_specs', {}))))

        matching_specs = list(filter(filter_test, flavors_map.values()))
        if matching_specs:
            # return desired flavor (can be with different name)
            return next((f for f in matching_specs if f['name'] == name), matching_specs[0])
        elif not name:
            name = 'generic-flavor'
        elif any(f['name'] == name for f in flavors_map.values()):
            # except on THE Undesired flavor (with the matching name)
            raise Exception('Flavor conflict: EEXIST with different specs')

        # create and return THE Desired flavor
        return self.create_flavor(name=name, **flavor_spec)

    def get_server_port_map(self, server, ip_addr=None):
        ports = self.handle._list_ports(device_id=server['id'], fixed_ip=ip_addr)  # pylint: disable=protected-access

        port_map = [
            (p['id'], fxip['ip_address'])
            for p in ports for fxip in p['fixed_ips']
            if netaddr.valid_ipv4(fxip['ip_address']) and fxip['ip_address'] == ip_addr['addr']
        ]

        return port_map

    def allow_forwarding(self, server_id):
        """Allowing forwarding

        If a virtual instance is to forward a traffic,
        the security extension 'port_security' must be allowed in the
        Open Stack. This allows create ports with port_security_enabled
        set to False. If this is set to false, then certain iptable
        rules are not generated and anti-spoofing checks are not done.

        """
        ip_addresses = self.get_interfaces(server_id)
        port_ids = (ip['port_id'] for ip in ip_addresses)

        kwargs = {
            'security_groups': [],
            'port_security_enabled': False,
        }

        for a_port_id in port_ids:
            self.handle.ports_client.update_port(a_port_id, **kwargs)

    def get_aggregates(self):
        return self.handle.os_adm.aggregates_client.list_aggregates()

    def get_avail_zones(self):
        return self.handle.os_adm.availability_zone_client.list_availability_zones()

    def get_compute_nodes(self):
        return self.handle.os_adm.hypervisor_client.list_hypervisors()

    def get_hosts(self):
        """Returns an array of dictionaries with available hypervisors.

        Example of the output::

            [{u'hypervisor_hostname': u'pod4-compute2',
              u'id': 1,
              u'state': u'up',
              u'status': u'enabled'},
             {u'hypervisor_hostname': u'pod4-compute1',
              u'id': 2,
              u'state': u'up',
              u'status': u'enabled'}]

        """
        client = self.handle.os_adm.hosts_client
        hosts = client.list_hosts()
        return hosts.get('hosts', hosts)

    def get_interfaces(self, server_id):
        interface_client = self.handle.interface_client
        return interface_client.list_interfaces(server_id)['interfaceAttachments']

    def get_ips(self, server_id):
        iface_client = self.handle.interface_client
        return [ip['ip_address']
                for val in iface_client.list_interfaces(server_id)['interfaceAttachments']
                for ip in val['fixed_ips']]

    def get_host_zone_maps(self, service_type='compute'):
        hosts = self.get_hosts()

        z2h_map = {}
        h2z_map = {}
        for h in hosts:
            if service_type == h['service']:
                h_zone = h['zone']
                h_name = h['host_name']

                z2h_map.setdefault(h_zone, set()).add(h_name)
                h2z_map.setdefault(h_name, set()).add(h_zone)

        def dj_rec(map_level, zone_closed, zone_open, host_closed):
            """'disjoint recursive' zone/host maps build helper.

            GOAL: disjoint host aggregates to hosts mapping
            TODO: Need another helper to traverse the map-tree
            TODO: Use host aggregates instead of availability zones?

            """
            cnt_level = 0
            _cnt_level = 0

            zone_not_disjoint = (z for z in zone_open if not z2h_map[z].isdisjoint(host_closed))
            for z in zone_not_disjoint:
                _hosts = z2h_map[z] - host_closed
                if _hosts:
                    cnt_level = 1

                    _zone_open = zone_open - {z}
                    _zone_closed = zone_closed | {z}

                    _host_closed = host_closed | _hosts
                    map_level[z] = {}

                    r = dj_rec(map_level[z], _zone_closed, _zone_open, _host_closed)
                    _cnt_level = max(_cnt_level, r)

            return cnt_level + _cnt_level

        the_map = {}
        dj_rec(the_map, set(), set(z2h_map.keys()), set())

        return z2h_map, h2z_map, the_map

    def get_single_host_zones(self, z2h=None):
        if z2h is None:
            z2h, h2z, disjoint = self.get_host_zone_maps()

        single_host_zones = [zone for zone in z2h.keys() if len(z2h[zone]) == 1 if zone != 'nova']
        return single_host_zones

    def get_hosts_without_aggregate(self, z2h=None):
        if z2h is None:
            z2h, h2z, distinct = self.get_host_zone_maps()

        # hosts out of any aggregate are grouped under
        # 'nova' availability zone
        return z2h.get('nova', [])

    def _delete_aggregate(self, aggregate):
        self.handle.os_adm.aggregates_client.delete_aggregate(aggregate['id'])

    def _create_aggregate(self, **kwargs):
        aggregate = self.handle.os_adm.aggregates_client.create_aggregate(**kwargs)
        aggregate = aggregate['aggregate']
        self.handle.addCleanup(self._delete_aggregate, aggregate)
        assert kwargs['name'] == aggregate['name']
        assert kwargs['availability_zone'] == aggregate['availability_zone']
        return aggregate

    def create_aggregate(self, name="aggr", availability_zone="zone"):
        """Creates an aggregate and availability zone.

        """
        aggregate_name = "{}-{}".format(name, int(time.time()))
        zone_name = "{}-{}".format(availability_zone, int(time.time()))
        kwargs = {
            'name': aggregate_name,
            'availability_zone': zone_name,
        }

        self.class_logger.info("Creating new aggregate %s.", aggregate_name)
        self.class_logger.info("Creating new availability zone %s.", zone_name)
        return self._create_aggregate(**kwargs)

    def remove_host_from_aggregate(self, aggregate_id, host):
        aggregate = self.handle.os_adm.aggregates_client.remove_host(aggregate_id, host=host)
        assert host not in aggregate['aggregate']['hosts']

    def add_host_to_aggregate(self, aggregate_id, host):
        aggregates_client = self.handle.os_adm.aggregates_client
        aggregate = aggregates_client.add_host(aggregate_id, host=host)['aggregate']
        self.handle.addCleanup(self.remove_host_from_aggregate,
                               aggregate['id'],
                               host)

        assert host in aggregate['hosts']
        return True

    def create_server(self, nets=None, ports=None, zone=None, image=None, flavor=None, **kwargs):
        """Create instance in OpenStack.

        Args:
            nets(list[dict]representing OpenStack network(,subnet,router)s): networks for the virtual instance to be created
            ports(list[dict] representing OpenStack ports): ports for the virtual instance to be createds
            zone(dict representing OpenStack availability-zone): availability-zone for the virtual instance to be created
            image(dict representing OpenStack image): image for the virtual instance to be created
            flavor(dict representing OpenStack flavor): flavor for the virtual instance to be created

        Returns:
            GenericLinuxVirtualHost

        """

        if ports is None:
            ports = []
        if nets is None:
            nets = []

        if ports or nets:
            _ports = [{'port': port['id']} for port in ports]
            _nets = [{'uuid': network['id']} for (network, _, _) in nets]
            kwargs['networks'] = _ports + _nets

        if zone:
            kwargs['availability_zone'] = zone

        if self.key['name']:
            kwargs['key_name'] = self.key['name']

        # If the image name is not given, the img_ref from tempest.conf will be used.
        # TODO
        if image:
            kwargs['image_id'] = image['id']

        if flavor:
            kwargs['flavor'] = flavor['id']
        else:
            kwargs['flavor'] = self.DEFAULT_FLAVOR['id']

        self.class_logger.debug('Create server with:\n%s', pprint.pformat(kwargs))
        server = self.handle.create_server(**kwargs)
        self.class_logger.info('Created server:\n%s', pprint.pformat(server))

        server_dict = {
            'name': server['name'],
            'id': server['id'],
            'entry_type': 'openstack',
            'instance_type': 'instance',
            'ipaddr': None,
            'ssh_port': image.get('ssh_port', 22),
            'ssh_user': image.get('ssh_user', 'root'),
        }
        _ssh_pass = image.get('ssh_pass')
        if _ssh_pass:
            server_dict['ssh_pass'] = _ssh_pass
        else:
            server_dict['ssh_pkey'] = self.key.get('private_key')

        new_server = GenericLinuxVirtualHost(server_dict, self.opts)
        new_server.tempest_ui = self.handle
        new_server.os_networks = nets
        new_server.os_ports = ports
        return new_server

    def assign_floating_ip(self, host, private_net_name=None, public_network_id=None,
                           management=False):
        """Assign floating IP to ACTIVE instance.

        Args:
            host(GenericLinuxVirtualHost): instance to wich assign the floating IP
            private_net_name(str): private networks name, if not specified takes last from
                                   host.os_networks
            public_network_id: public network id, if not specified using one from tempest.conf
            management: is this floating IP be management IP via which we communicate with the
                        instance

        Returns:
            generated floating IP

        """

        # the management interface is the one into the last (right most network in)
        # host.os_networks or the right most port in host.os_ports if host.os_networks is empty.
        # That's because the json is constructed as networks = ports + nets (see the create_server)

        server = self.get_nova_instance(host.id)

        last_port = None
        # If private_net_name not defined use the last one
        if private_net_name:
            list_ip_addresses = server['addresses'].get(private_net_name)
        elif host.os_networks:
            list_ip_addresses = server['addresses'][host.os_networks[-1][0]['name']]
            # we are interested in the first IP only
            ip_address_dict = list_ip_addresses[0]
            ip_address = ip_address_dict['addr']
        elif host.os_ports:
            last_port = host.os_ports[-1]
            ip_address = last_port['fixed_ips'][-1]['ip_address']
            port_id = last_port['id']

        if not last_port:
            port_map = self.get_server_port_map(server, ip_address_dict)
            self.class_logger.debug(port_map)
            port_id, _ = port_map[0]

        if not public_network_id:
            public_network_id = self.config.network.public_network_id

        floating_ip = self.handle.create_floating_ip(server, public_network_id, port_id=port_id)

        self.class_logger.debug("floating ip: %s <-> fixed ip=%s",
                                floating_ip['floating_ip_address'],
                                ip_address)

        if management:
            host.nated_mgmt = ip_address
            host._set_ssh(floating_ip['floating_ip_address'])  # pylint: disable=protected-access

        return floating_ip['floating_ip_address']

    def get_nova_instance(self, instance_id):
        return self.handle.servers_client.show_server(instance_id)['server']

    @only_with_neutron_extension('sfc')
    def create_port_pair(self, **kwargs):
        sfc_client = self.handle.sfc_client
        port_pair = sfc_client.create_port_pair(**kwargs)['port_pair']
        self.handle.addCleanup(sfc_client.delete_port_pair, port_pair['id'])
        return port_pair

    @only_with_neutron_extension('sfc')
    def create_port_pair_group(self, **kwargs):
        sfc_client = self.handle.sfc_client
        port_pair_group = sfc_client.create_port_pair_group(**kwargs)['port_pair_group']
        self.handle.addCleanup(sfc_client.delete_port_pair_group,
                               port_pair_group['id'])
        return port_pair_group

    @only_with_neutron_extension('sfc')
    def update_port_pair_group(self, **kwargs):
        sfc_client = self.handle.sfc_client
        return sfc_client.update_port_pair_group(**kwargs)['port_pair_group']

    @only_with_neutron_extension('sfc')
    def update_port_chain(self, **kwargs):
        sfc_client = self.handle.sfc_client
        return sfc_client.update_port_chain(**kwargs)['port_chain']

    @only_with_neutron_extension('sfc')
    def create_flow_classifier(self, **kwargs):
        sfc_client = self.handle.sfc_client
        flow_classifier = sfc_client.create_flow_classifier(**kwargs)['flow_classifier']
        self.handle.addCleanup(sfc_client.delete_flow_classifier,
                               flow_classifier['id'])
        return flow_classifier

    @only_with_neutron_extension('sfc')
    def create_port_chain(self, **kwargs):
        sfc_client = self.handle.sfc_client
        port_chain = sfc_client.create_port_chain(**kwargs)['port_chain']
        self.handle.addCleanup(sfc_client.delete_port_chain,
                               port_chain['id'])
        return port_chain

    def list_security_groups(self):
        return self.handle.manager.security_groups_client.list_security_groups()

    def create_security_group_rule(self, **kwargs):
        return self.handle.manager.security_group_rules_client.create_security_group_rule(**kwargs)

    def delete_security_group_rule(self, rule_id):
        return self.handle.manager.security_group_rules_client.delete_security_group_rule(rule_id)

    def get_all_instances(self):
        client = self.handle.manager.servers_client

        instances = [self.get_nova_instance(i['id'])
                     for i in client.list_servers()['servers']]

        return instances

    def get_host_instance_dict(self, instances=None):
        """Gets a dictionary of details of all instances in the current project grouped by hostId.

        """
        if instances is None:
            instances = self.get_all_instances()

        res = {}
        for x in instances:
            res.setdefault(x['hostId'], []).append(x)

        return res

    def get_services(self, service_filter=None):
        client = self.handle.admin_manager.services_client
        services = client.list_services()['services']
        if service_filter is None:
            return services
        return filter(service_filter, services)

    def enable_service(self, service):
        client = self.handle.admin_manager.services_client
        client.enable_service(host=service['host'], binary=service['binary'])

    def disable_service(self, service):
        client = self.handle.admin_manager.services_client
        client.disable_service(host=service['host'], binary=service['binary'])
        self.handle.addCleanup(self.enable_service, service)
