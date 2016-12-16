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

@file common.py

@summary Unittests common functionality.
"""
import threading
from xmlrpc.server import SimpleXMLRPCServer

from testlib.custom_exceptions import SwitchException

TCP_PORT = 9999


class FakeXMLRPCServer(object):

    def __init__(self, port=TCP_PORT):
        self.server = SimpleXMLRPCServer(("localhost", port))
        self.server.register_function(self.applications_gettable,
                                      'nb.Applications.getTable')
        self.server.register_function(self.applications_set_loglevel,
                                      'nb.Applications.set.logLevel')
        self.server.register_function(self.applications_get_size, 'nb.Applications.size')
        self.server.register_function(self.applications_find, 'nb.Applications.find')
        self.server.register_function(self.applications_exists, 'nb.Applications.exists')
        self.server.register_function(self.system_tables_ready, 'system.tablesReady')
        self.server.register_function(self.platform_get_row, 'nb.Platform.getRow')
        # self.server.register_function(self.platform_get_table, 'nb.Platform.getTable')
        self.server.register_function(self.platform_get_size, 'nb.Platform.size')
        self.server.register_function(self.ports_get_name, 'nb.Ports.get.name')
        self.server.register_function(self.ports_get_size, 'nb.Ports.size')
        self.server.register_function(self.ports_get_info, 'nb.Ports.getInfo')
        self.server.register_function(self.ports_get_info_name, 'nb.Ports.getInfo.name')
        self.server.register_function(self.method_help, 'system.methodHelp')
        self.server.register_function(self.ports_add_row, 'nb.Ports.addRow')
        self.server.register_function(self.ports_del_row, 'nb.Ports.delRow')
        self.server.register_function(self.system_multicall, 'system.multicall')
        self.server.register_function(self.ports_lags_get_table,
                                      'nb.Ports2LagAdmin.getTable')
        self.server.register_function(self.ports_lags_get_size, 'nb.Ports2LagAdmin.size')
        self.server.register_function(self.lags_get_table, 'nb.LagsAdmin.getTable')
        self.server.register_function(self.lags_get_size, 'nb.LagsAdmin.size')
        self.server.register_function(self.lags_add_row, 'nb.LagsAdmin.addRow')
        self.server.register_function(self.ports_lag_add_row, 'nb.Ports2LagAdmin.addRow')

        self.applications = [
            {'name': 'ONSApplicationServer', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'SimSwitchApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'ONSCoreServer', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'ONSNorthboundServer', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'L3DhcpRelayControlApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'L2MirrorControlApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'L2QosControlApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'L2StormControlApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'L2StatsControlApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'ONSOpenVSwitchApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'L1SfpControlApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'L2VlanControlApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'L1PortControlApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'L2QinqControlApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'L2FdbControlApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'L2AclControlApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'L1SwitchControlApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'L2MulticastControlApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'L2LagControlApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'L3ControlApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'L2LldpControlApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'},
            {'name': 'L2StpControlApp', 'logLevel': 'test level',
             'adminState': 'Run', 'appId': 1, 'operationalState': 'Run'}
        ]

        self.platform = [{'ethernetSwitchType': 'SimSwitch Switch',
                          'name': 'ONS CoreSwitch',
                          'cpuArchitecture': 'x86_64',
                          'chipVersion': '2.0',
                          'chipSubType': 'simswitch',
                          'apiVersion': 'SimSwitch 2.0.0',
                          'switchppVersion': '1.2.0.1405-1',
                          'chipName': 'SimSwitch', 'osType':
                          'Linux', 'model': 'ONS', 'osVersion':
                          '3.2.0-61-generic',
                          'cpu': 'x86_64',
                          'serialNumber': ''}]

        self.ports = [
            {'portId': 1, 'adminMode': 'Up', 'pvid': 1, 'type': 'Physical',
             'operationalStatus': 'Up', 'speed': 10000, 'name': 'xe1'},
            {'portId': 2, 'adminMode': 'Up', 'pvid': 1, 'type': 'Physical',
             'operationalStatus': 'Up', 'speed': 10000, 'name': 'xe2'},
            {'portId': 3, 'adminMode': 'Up', 'pvid': 1, 'type': 'Physical',
             'operationalStatus': 'Down', 'speed': 10000, 'name': 'xe3'},
            {'portId': 4, 'adminMode': 'Up', 'pvid': 1, 'type': 'Physical',
             'operationalStatus': 'Down', 'speed': 10000, 'name': 'xe4'},
            {'portId': 5, 'adminMode': 'Up', 'pvid': 1, 'type': 'Physical',
             'operationalStatus': 'Down', 'speed': 10000, 'name': 'xe5'},
            {'portId': 6, 'adminMode': 'Up', 'pvid': 1, 'type': 'Physical',
             'operationalStatus': 'Down', 'speed': 10000, 'name': 'xe6'},
            {'portId': 7, 'adminMode': 'Up', 'pvid': 1, 'type': 'Physical',
             'operationalStatus': 'Down', 'speed': 10000, 'name': 'xe7'},
            {'portId': 8, 'adminMode': 'Up', 'pvid': 1, 'type': 'Physical',
             'operationalStatus': 'Down', 'speed': 10000, 'name': 'xe8'},
            {'portId': 9, 'adminMode': 'Up', 'pvid': 1, 'type': 'Physical',
             'operationalStatus': 'Down', 'speed': 10000, 'name': 'xe9'},
            {'portId': 10, 'adminMode': 'Up', 'pvid': 1, 'type': 'Physical',
             'operationalStatus': 'Down', 'speed': 10000, 'name': 'xe10'}]

        self.ports_info = {'primary_key': ['portId'],
                           'persistent': 'True',
                           'description':
                               'Ports table includes all type of ports in a single table.',
                           'columns': ['portId', 'adminMode', 'name',
                                       'pvid', 'speed', 'operationalStatus', 'type'],
                           'mode': 'rw'}

        self.ports_name_info = {'restrictions': {'size': '32'}, 'type': 'string',
                                'description': 'This ports name (a 32-byte string).',
                                'mode': 'ro'}

        self.ports_get_row_help = 'Method for getting variable from table Ports'

        self.error_multicall = False

        self.lags = []
        self.ports_to_lags = []
        self.th = None

    def start(self):
        self.th = threading.Thread(target=self.server.serve_forever)
        self.th.start()

    def stop(self):
        if self.th.is_alive():
            self.server.shutdown()
            self.server.server_close()
            self.th.join()

    def applications_gettable(self):
        return self.applications

    def applications_set_loglevel(self, app_id, loglevel):
        if loglevel == 'error':
            raise SwitchException("Error loglevel")
        for row in self.applications:
            if row['appId'] == app_id:
                row['logLevel'] = loglevel
        return 0

    def applications_find(self, app_id, pid_id, app_name):
        index = 0
        for row in self.applications:
            index += 1
            if row['appId'] == app_id and row['name'] == app_name:
                return index
        return -1

    def applications_get_size(self):
        return len(self.applications)

    def applications_exists(self, app_id, pid_id, app_name):
        return self.applications_find(app_id, pid_id, app_name)

    def system_tables_ready(self):
        return 0

    def platform_get_row(self, row):
        row = row - 1
        return self.platform[row]

    def platform_get_table(self):
        return self.platform

    def platform_get_size(self):
        return len(self.platform)

    def ports_gettable(self):
        return self.ports

    def ports_get_name(self, row_id):
        row_id = row_id - 1
        return self.ports[row_id]['name']

    def ports_get_size(self):
        return len(self.ports)

    def ports_get_info(self):
        return self.ports_info

    def ports_get_info_name(self):
        return self.ports_name_info

    def ports_add_row(self, *row):
        port = {
            'portId': row[0],
            'adminMode': row[1],
            'pvid': row[2],
            'type': row[3],
            'operationalStatus': row[4],
            'speed': row[5],
            'name': row[6]
        }
        self.ports.append(port)
        return 0

    def ports_del_row(self, row_id):
        self.ports.remove(self.ports[row_id - 1])
        return 0

    def clear_config(self):
        return 0

    def method_help(self, method):
        if method == 'nb.Ports.getRow':
            return self.ports_get_row_help
        raise SwitchException('Method %s does not exist' % (method, ))

    def system_multicall(self, *calls):
        res = []
        for _ in calls[0]:
            res.append(0)
        if self.error_multicall:
            return res[: -1]
        return res

    def ports_lags_get_table(self):
        return self.ports_to_lags

    def ports_lags_get_size(self):
        return len(self.ports_to_lags)

    def lags_get_table(self):
        return self.lags

    def lags_get_size(self):
        return len(self.lags)

    def lags_add_row(self, *row):
        lag = {
            'lagId': row[0],
            'name': row[1],
            'lagControlType': row[3],
            'actorAdminLagKey': row[2],
            'hashMode': row[4]
        }
        port = {
            'portId': row[0],
            'adminMode': 'Up',
            'pvid': 1,
            'type': 'LAG',
            'operationalStatus': 'Down',
            'speed': 10000,
            'name': row[1]
        }
        self.lags.append(lag)
        self.ports.append(port)
        return 0

    def ports_lag_add_row(self, *row):
        port_lag = {
            'lagId': row[1],
            'portId': row[0],
            'actorPortPriority': row[2],
            'actorAdminPortKey': row[3],
            'adminAggregation': row[4],
            'adminActive': row[5],
            'adminTimeout': row[6],
            'adminSynchronization': row[7],
            'adminCollecting': row[8],
            'adminDistributing': row[9],
            'adminDefaulted': row[10],
            'adminExpired': row[11]
        }
        port = [x for x in self.ports if x['portId'] == row[0]][0]
        port['type'] = 'LagMember'
        self.ports_to_lags.append(port_lag)
        return 0
