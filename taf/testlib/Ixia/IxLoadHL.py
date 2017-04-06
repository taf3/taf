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

"""``IxLoadHL.py``

`IxLoad HL API`

"""

import os
import random
import time

from . import IxLoadTclAPI
from ..loggers import ClassLogger


class IxLoadHelpersMixin(object):
    """The cass contains helpers methods for IxLoad configuration.

    """

    # Default network configuration parameters.
    RRSEED_RANGE = (pow(2, 28), pow(2, 31))

    IP_RANGE_CFG = {"count": 64, "enableGatewayArp": False,
                    # "randomizeSeed": 3529357496,
                    "generateStatistics": False, "autoCountEnabled": False,
                    "enabled": True, "autoMacGeneration": True,
                    "_Stale": False,
                    "mss": 1460, "randomizeAddress": False,
                    "gatewayIncrement": "0.0.0.0", "gatewayIncrementMode": "perSubnet",
                    "incrementBy": "0.0.0.1", "prefix": 24,
                    "gatewayAddress": "192.168.0.1",
                    "ipAddress": "192.168.0.101",
                    "ipType": "IPv4", }

    MAC_RANGE_CFG = {"count": 64, "enabled": True, "mtu": 1500,
                     "mac": "00:C0:A8:00:65:00",
                     "incrementBy": "00:00:00:00:00:01",
                     "_Stale": False, }

    VLAN_RANGE_CFG = {"incrementStep": 1, "innerIncrement": 1,
                      "uniqueCount": 4094, "firstId": 1,
                      "tpid": "0x8100", "idIncrMode": 2,
                      "enabled": False,
                      "innerFirstId": 1, "innerIncrementStep": 1,
                      "priority": 1, "_Stale": False,
                      "increment": 1, "innerTpid": "0x8100",
                      "innerUniqueCount": 4094, "innerEnable": False,
                      "innerPriority": 1, }

    GRAT_ARP_CFG = {"forwardGratArp": False,
                    "enabled": True,
                    "maxFramesPerSecond": 0,
                    "_Stale": False,
                    "rateControlEnabled": False}

    TCP_CFG = {'tcp_bic': 0, 'tcp_tw_recycle': True, 'tcp_vegas_alpha': 2, 'tcp_rto_max': 120000,
               'disable_min_max_buffer_size': True, 'tcp_retries1': 3, 'tcp_keepalive_time': 7200,
               'tcp_rfc1337': False, 'tcp_ipfrag_time': 30, 'tcp_keepalive_intvl': 75,
               'tcp_window_scaling': False, 'tcp_mem_low': 24576, 'delayed_acks': True,
               'udp_port_randomization': False, 'tcp_retries2': 5, 'tcp_wmem_max': 262144,
               'tcp_bic_low_window': 14, 'tcp_ecn': False, 'tcp_westwood': 0, 'delayed_acks_segments': 0,
               'inter_packet_delay': 0, 'tcp_vegas_cong_avoid': 0, 'tcp_tw_rfc1323_strict': False,
               'tcp_rmem_max': 262144, 'tcp_orphan_retries': 0, 'bestPerfSettings': False,
               'tcp_max_tw_buckets': 180000, '_Stale': False, 'tcp_low_latency': 0, 'tcp_rmem_min': 4096,
               'accept_ra_all': False, 'tcp_adv_win_scale': 2, 'tcp_wmem_default': 4096, 'tcp_wmem_min': 4096,
               'tcp_port_min': 1024, 'tcp_stdurg': False, 'tcp_port_max': 65535, 'tcp_fin_timeout': 60,
               'tcp_max_syn_backlog': 1024, 'tcp_dsack': True, 'tcp_mem_high': 49152, 'tcp_frto': 0,
               'tcp_app_win': 31, 'tcp_vegas_beta': 6, 'llm_hdr_gap': 8, 'tcp_max_orphans': 8192,
               'accept_ra_default': False, 'tcp_syn_retries': 5, 'tcp_moderate_rcvbuf': 0,
               'tcp_no_metrics_save': False, 'tcp_rto_min': 200, 'tcp_fack': True,
               'tcp_retrans_collapse': True, 'llm_hdr_gap_ns': 10, 'tcp_rmem_default': 4096,
               'tcp_keepalive_probes': 9, 'tcp_abort_on_overflow': False, 'tcp_tw_reuse': False,
               'delayed_acks_timeout': 0, 'tcp_vegas_gamma': 2, 'tcp_synack_retries': 5,
               'tcp_timestamps': True, 'tcp_reordering': 3, 'ip_no_pmtu_disc': True,
               'tcp_sack': True, 'tcp_bic_fast_convergence': 1, 'tcp_mem_pressure': 32768}

    DNS_CFG = {"domain": "", "_Stale": False, "timeout": 30}

    def config_ethernet(self, network, **ethcfg):
        """Performs standard L1 configuration for network object.

        Args:
            network(str):  RouteInterface network
            ethcfg(kwargs): configuration params for network object
            elm(dict):  Optional ELM params (dict)
            phy(dict):  Optional Phy params (dict)

        """

        elm = ethcfg.pop("elm") if "elm" in ethcfg else None
        phy = ethcfg.pop("phy") if "phy" in ethcfg else None

        ethernet = network.new_l1plugin()

        elm_params = {"negotiationType": "master", "_Stale": False, "negotiateMasterSlave": True}
        if elm is not None:
            elm_params.update(elm)
        _elm = IxLoadTclAPI.IxLoadixNetEthernetELMPlugin(ethernet.tcl)
        _elm.config(**elm_params)
        ethernet.elm = _elm

        phy_params = {"medium": "auto", "_Stale": False}
        if phy is not None:
            phy_params.update(phy)
        _phy = IxLoadTclAPI.IxLoadixNetDualPhyPlugin(ethernet.tcl)
        _phy.config(**phy_params)
        ethernet.phy = _phy

        eth_params = {"cardElm": _elm, "cardDualPhy": _phy}
        eth_params.update(ethcfg)
        ethernet.config(**eth_params)

        return ethernet

    def config_network(self, network, name, tcp=None, grat_arp=None, dns=None, nsettings=None, nfilter=None):
        """Configure ARP, TCP, DNS default network settings.

        """
        settings_cfg = {"teardownInterfaceWithUser": False, "_Stale": False, "interfaceBehavior": 0}
        filter_cfg = {"all": False, "pppoecontrol": False, "isis": False, "auto": True,
                      "udp": "", "tcp": "", "mac": "", "_Stale": False, "pppoenetwork": False,
                      "ip": "", "icmp": ""}

        if nsettings is not None:
            settings_cfg.update(nsettings)
        if nfilter is not None:
            filter_cfg.update(nfilter)

        settings2 = network.new_plugin("Settings")
        settings2.config(**settings_cfg)
        filter2 = network.new_plugin("Filter")
        filter2.config(**filter_cfg)

        tcp_cfg = self.TCP_CFG.copy()
        grat_arp_cfg = self.GRAT_ARP_CFG.copy()
        dns_cfg = self.DNS_CFG.copy()

        if tcp is not None:
            tcp_cfg.update(tcp)
        if grat_arp is not None:
            grat_arp_cfg.update(tcp)
        if dns is not None:
            dns_cfg.update(tcp)

        grat_arp = network.new_plugin("GratARP")
        grat_arp.config(**grat_arp_cfg)
        tcp = network.new_plugin("TCP")
        tcp.config(**tcp_cfg)
        dns = network.new_plugin("DNS")
        dns.config(**dns_cfg)
        network.config(name=name)

    def add_ip_ranges(self, ip, ipr=None, macr=None, vlanr=None):
        """Create and add IP(and lower MAC/VLAN) ranges to TG IP object.

        Args:

            ip:  TG IP plugin object.
            ipr:  IP range.
            macr:  MAC range.
            vlanr:  Vlan range.

        """
        ipr_cfg = self.IP_RANGE_CFG.copy()
        macr_cfg = self.MAC_RANGE_CFG.copy()
        vlanr_cfg = self.VLAN_RANGE_CFG.copy()

        if ipr is not None:
            ipr_cfg.update(ipr)
        if macr is not None:
            macr_cfg.update(macr)
        if vlanr is not None:
            vlanr_cfg.update(vlanr)

        if "randomizeSeed" not in ipr_cfg:
            ipr_cfg['randomizeSeed'] = random.randrange(*self.RRSEED_RANGE)

        ip_range = ip.new_range()
        ip_range.config(**ipr_cfg)
        mac_range1 = ip_range.get_macrange()
        mac_range1.config(**macr_cfg)
        vlan_range1 = ip_range.get_vlanidrange()
        vlan_range1.config(**vlanr_cfg)
        ip.append_iprange(ip_range)

        return ip_range

    def config_http_client(self, http_client, sustain_time, objective_value, objective_type, dst, page_name):
        """Config standard HTTP Client.

        """
        timeline = http_client.config_timeline(sustainTime=sustain_time,
                                               rampUpValue=10,
                                               # rampUpType=-1,
                                               # rampUpInterval=128,
                                               # timelineType=0,
                                               )
        http_client.config(name=http_client.name,
                           userObjectiveValue=objective_value,
                           userObjectiveType=objective_type,
                           timeline=timeline)
        http_client.add_command(destination=dst, cmdName="Get 1",
                                commandType="GET", pageObject=page_name)
        http_client.add_header("Accept: */*")
        http_client.add_header("Accept-Language: en-us")
        http_client.add_header("Accept-Encoding: gzip, deflate")
        http_client.add_header("User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)")
        http_client.config_agent(browserEmulationName="Custom1", maxSessions=50, commandTimeout=60)
        http_client.config_percentagecmdlist()

    def config_http_server(self, http_server, page_list=None):
        """Perform standard HTTP server configuration.

        """
        http_server.config_timeline()

        # Default page list. Format [("<size, bytes>", "<name>", "<response code>"), ]
        _page_list = [("1", "1b", "200"), ("64", "64b", "200"), ("4096", "4k", "200"),
                      ("8192", "8k", "200"), ("16536", "16k", "200"), ("32768", "32k", "200"),
                      ("65536", "64k", "200"), ("131072", "128k", "200"), ("262144", "256k", "200"),
                      ("524288", "512k", "200"), ("1048576", "1024k", "200"),
                      ]

        # Set page_list to defined or default one.
        page_list = page_list or _page_list

        for page in page_list:
            http_server.add_pageobject(response=page[2], Md5Option=3,
                                       payloadSize=page[0], page="/{0}.html".format(page[1]))

        http_server.add_cookie([{"name": "firstName", "value": "Joe"},
                                {"name": "lastName", "value": "Smith"}])
        http_server.cookielist[-1].config()
        http_server.add_cookie([{"value": "joesmith"},
                                {"name": "password", "value": "foobar"}])
        http_server.cookielist[-1].config(mode=2, name="LoginCookie", description="Login name and password")
        http_server.add_payload(name="AsciiCustomPayload",
                                asciiPayloadValue="Ixia-Ixload-Http-Server-Custom-Payload",
                                payloadPosition="Start With")
        http_server.add_payload(name="HexCustomPayload", payloadmode=1,
                                hexPayloadValue="49 78 69 61 2d 49 78 6c 6f 61 64 2d 48 74 74 70 2d "
                                                "53 65 72 76 65 72 2d 43 75 73 74 6f 6d 2d 50 61 79 6c 6f 61 64",
                                payloadPosition="Start With", id=1)
        _200 = http_server.new_response("200")
        http_server.append_responseheaderlist(_200)
        _404 = http_server.new_response("404")
        http_server.append_responseheaderlist(_404)

        http_server.config_agent()

    def get_stat_files(self, res_path, dst_path, file_list, silent=False):
        """Get stat files from IxLoad host.

        Args:
            res_path(str):  Origin folder.
            dst_path(str):  Destination folder.
            file_list(list[str]):  List of files to be copied.
            silent(bool):  If True then an exception won't be raised in case files aren't downloaded.

        """
        try:
            for file_name in file_list:
                self.copy_remote_file(res_path + "\\" + file_name, os.path.join(dst_path, file_name))
        except Exception as err:
            self.class_logger.debug("Failed to get stat files. Err: {0}".format(err))
            if silent:
                return False
            else:
                raise
        else:
            return True

    def wait_test_start(self, res_path, temp_dir=None, timeout=180, interval=10, file_list=None):
        """Wait until test is started.

        Note:
            Method will wait until report file is appear.

        """
        if not temp_dir:
            temp_dir = "/tmp/taf_temp.{0}".format(os.getpid())
            if not os.path.isdir(temp_dir):
                os.mkdir(temp_dir)

        if file_list is None:
            file_list = ["TestInfo.ini", ]

        end_time = time.time() + timeout

        while True:
            if time.time() > end_time:
                self.class_logger.error("Test wasn't started in 3 minutes. Force stop execution.")
                self.test_controller.stop(force=True)
                return False
            if self.get_stat_files(res_path, temp_dir, file_list, silent=True):
                self.class_logger.info(">" * 30)
                self.class_logger.info("Test is started.")
                break
            else:
                time.sleep(interval)

        return True


class IxLoadHL(IxLoadTclAPI.IxLoadTclAPI, IxLoadHelpersMixin):

    class_logger = ClassLogger()

    def __init__(self, config, opts):

        self.__opts = opts
        self.__config = config

        self.id = config['id']
        self.type = config['instance_type']

        self.ixload_ip = config['ixload_ip']
        self.ixload_user = config['ixload_user']
        self.ports = config['ports']
        self.chassis_list = config['chassis_list']

        super(IxLoadHL, self).__init__(self.ixload_ip, self.ixload_user)

        # Replace respath if it is set in config
        if "res_path" in config:
            self.ixload_respath = config['res_path'].replace("/", "\\")

        self.chassischain = None

    def check(self):
        try:
            # TODO: Add proper connect status verification.
            pass
        except Exception:
            try:
                self.disconnect()
            except Exception:
                pass
            self.__init__(self.__config, self.__opts)

    def create(self):
        """Obligatory class for entry_type = tg.

        """
        return self.connect()

    def destroy(self):
        """Obligatory class for entry_type = tg.

        """
        self.cleanup(mode="fast")
        self.logger_delete()
        self.disconnect()

    def cleanup(self, mode="complete"):
        """This method should do IxLoad config cleanup.

        Args:
            mode(str): "fast" or "complete". Not implemented.

        """
        # TODO: Implement proper config cleanup method.
        self.test_controller.cleanup()
        self.chassischain = None
        # ::IxLoad delete $qtConfig
        # ::IxLoad delete $repository

    def sanitize(self):
        """Clear ownership before exit.

        """
        self.test_controller.cleanup()
        self.disconnect()

    def set_chassischain(self, chassis_list):
        self.chassischain = IxLoadTclAPI.IxLoadChassisChain(self.tcl, chassis_list)

    def create_test(self):
        test = IxLoadTclAPI.IxLoadixTest(self.tcl)
        test.eventhandlersettings = IxLoadTclAPI.IxLoadixEventHandlerSettings(self.tcl)
        test.viewoptions = IxLoadTclAPI.IxLoadixViewOptions(self.tcl)
        return test

    def create_trafficelement(self):
        return IxLoadTclAPI.IxLoadixTrafficColumn(self.tcl)

    def new_testcontroller(self):
        return IxLoadTclAPI.IxLoadTestController(self.tcl, self.ixload_respath)
