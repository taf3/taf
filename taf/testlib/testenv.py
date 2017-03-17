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

"""``testenv.py``

`Environment verifying functionality`

"""


import time
import pytest

from . import loggers


def get_env_prop(env):
    """Read properties from all devices.

    Args:
        env(Environment):  Environment instance

    """

    def get_param(param):
        """Get single param.

        """
        return "_".join(
            {str(switch.get_env_prop(param)) for switch in getattr(env, "switch", {}).values()})

    env_dict = {
        'switchppVersion': get_param("switchppVersion"),
        'chipName': get_param("chipName"),
        'cpuArchitecture': get_param("cpuArchitecture"),
    }
    # Get params from devices
    return env_dict


def setup_teardown(function):
    """Setup/Teardown decorator.

    """
    def wrapper(*args, **kwargs):
        args[0]._setup()  # pylint: disable=protected-access
        result = function(*args, **kwargs)
        args[0]._teardown()  # pylint: disable=protected-access
        return result
    return wrapper


class TestLinks(object):
    """Links verification class.

    """
    class_logger = loggers.ClassLogger()

    def __init__(self, env):
        """Initialize TestLinks class.

        Args:
            env(Environment):  Environment instance

        """
        self.env = env
        self.class_logger.info("Links verification enabled.")

        # Perform import on __init__ to avoid logger output redirection by pytest.
        from . import helpers
        self.wait_until_value_is_changed = helpers.wait_until_value_is_changed
        self.set_all_ports_admin_disabled = helpers.set_all_ports_admin_disabled
        self.set_ports_admin_enabled = helpers.set_ports_admin_enabled

    def _setup(self):
        """Prepare env for test_links.

        """
        self.class_logger.info("Links verification setup.")
        # Clean up tg objects before tests in case use sanity_check_only before
        # only if tg are present
        for tg in getattr(self.env, "tg", {}).values():
            tg.cleanup()

        # check if env is alive
        self.env.check()

        # Perform clearconfig with 10 times retry
        clear_config_ok = False
        retry_max = 10
        # Keep reboot count for each switch
        retry_current = dict.fromkeys(self.env.switch, 0)
        # General retry count
        retry_current[0] = 0
        while not clear_config_ok:
            try:
                switch_id = None
                for switch_id in list(self.env.switch.keys()):
                    self.env.switch[switch_id].cleanup()
                self.class_logger.debug("clearConfig is OK")
                self.env.check()
                clear_config_ok = True
            except Exception as err:
                self.class_logger.debug("Exception has been caught...")
                if switch_id is not None:
                    retry_current[switch_id] += 1
                else:
                    retry_current[0] += 1
                # Check retry count. If any of switch counters has reached retry_max launch env check method
                if retry_max in iter(retry_current.values()):
                    pytest.softexit("Cannot perform clearconfig on all devices. Last received error : %s" % err,
                                    self.env)
                    break
                else:
                    if switch_id is None:
                        self.env.switch[switch_id].restart()
                    self.env.check()
            finally:
                self.class_logger.debug("Current retry counts: %s" % (retry_current, ))

    def _teardown(self):
        """Check procedure on teardown.

        """
        self.class_logger.info("Links verification teardown.")
        self.env.check()

    def _check_tg_links(self, ports, sw):
        """This function verifies links between Traffic Generator and Device.

        Args:
            ports(dict):  Ports dictionary in format {("sw1", "tg1"):{1: 25, 2: 26}}
            sw(str):  Device acronym, e.g."sw1"

        Notes:
            Verification based on STP packet "portid" field contents.

        """
        self.class_logger.debug("Analyzing links for device %s" % (sw, ))

        self.set_all_ports_admin_disabled(self.env.switch)
        message = "Port on switch does not pass to Up state after retry."
        self.set_ports_admin_enabled(self.env.switch, ports, fail_func=(pytest.softexit, [message, self.env]))

        sw_id = int(sw[2:])
        sw_bridge_port = ports[('sw1', 'tg1')][1]
        sw_mac = self.env.switch[sw_id].ui.get_table_ports([sw_bridge_port])[0]["macAddress"].upper()
        for tg_port, sw_port in zip(iter(ports[('tg1', sw)].values()), iter(ports[(sw, 'tg1')].values())):
            self.class_logger.info("Verifying link TG:%s SW(id%s):%s" % (tg_port, sw_id, sw_port))
            self.class_logger.debug("Starting sniffer on %s interface" % (tg_port, ))
            self.env.tg[1].start_sniff([tg_port, ], filter_layer="STP", sniffing_time=5, packets_count=1)
            data = self.env.tg[1].stop_sniff([tg_port, ])
            if tg_port in data:
                for packet in data[tg_port]:
                    portid = self.env.tg[1].get_packet_field(packet=packet, layer="STP", field="portid")
                    mac_from_pack = self.env.tg[1].get_packet_field(packet=packet, layer="Dot3", field="src").upper()
                    prt = portid % 256
                    self.class_logger.debug("Got port %s from sniffed STP data..." % (prt, ))
                    try:
                        assert prt == sw_port
                    except Exception:
                        self.class_logger.error(("Port ID got from sniffed data (%s) and provided in config (%s) " +
                                                 "are different. SwId: %s, SwIP: %s. Reporting failure...") %
                                                (prt, sw_port, self.env.switch[sw_id].id,
                                                 self.env.switch[sw_id].ipaddr))
                        pytest.softexit("Wrong connection detected!", self.env)
                    try:
                        assert sw_mac == mac_from_pack
                    except Exception:
                        self.class_logger.error(("Device mac address got from sniffed data (%s) " +
                                                 "and provided in config (%s) " +
                                                 "are different. SwId: %s, SwIP: %s. Reporting failure...") %
                                                (mac_from_pack, sw_mac, self.env.switch[sw_id].id,
                                                 self.env.switch[sw_id].ipaddr))
                        pytest.softexit("Wrong connection detected!", self.env)
            else:
                self.class_logger.error("Nothing sniffed on link tg1:%s<->sw%s:%s. Failure." %
                                        (tg_port, sw_id, sw_port))
                pytest.softexit("No data for port!", self.env)

    def _check_sw_links(self, ports, sw1, sw2, check_method="direct"):
        """This function verifies links between Devices.

        Args:
            ports(dict):  Ports dictionary in format {("sw1", "tg1"):{1: 25, 2: 26}}
            sw1(str):  Device acronym, e.g."sw1"
            sw2(str):  Device acronym, e.g."sw2"
            check_method(str):  Validation type. direct|indirect

        Raises:
            ValueError:  unknown check_method value

        Notes:
            Verification based on operational state change as a response to admin disable/enable on the other end of the link.
            (applicable only for real devices)

        """
        self.class_logger.info("Verify link between switches {0} and {1}".format(sw1, sw2))
        sw1_id = int(sw1[2:])
        sw2_id = int(sw2[2:])
        self.class_logger.info("{0} - {1}, {2} - {3}".format(sw1, self.env.switch[sw1_id].ipaddr,
                                                             sw2, self.env.switch[sw2_id].ipaddr))

        for link_key in list(ports.keys()):
            if (link_key[0] == sw1) and (link_key[1] == sw2):
                for prt_key in list(ports[(sw1, sw2)].keys()):
                    dev1prt = ports[(sw1, sw2)][prt_key]
                    dev2prt = ports[(sw2, sw1)][prt_key]
                    dev1prt_id = self.env.switch[sw1_id].findprop("Ports", [dev1prt])
                    dev2prt_id = self.env.switch[sw2_id].findprop("Ports", [dev2prt])
                    flag1 = False
                    flag2 = False
                    self.class_logger.info("Check ports {0}-{1}".format(dev1prt, dev2prt))

                    if check_method == "direct":
                        try:
                            assert self.env.switch[sw2_id].getprop("Ports", "operationalStatus", dev2prt_id) == "Up"
                        except Exception:
                            self.class_logger.warning(("Operational status of given port (%s) on paired device (Id: %s, IP: %s) " +
                                                       "is already 'Down'. Check config!") %
                                                      (dev2prt, self.env.switch[sw2_id].id, self.env.switch[sw2_id].ipaddr))
                            self.class_logger.warning("SW1: %s, ip: %s, port: %s\nSW2: %s, ip: %s, port: %s" %
                                                      (self.env.switch[sw1_id].id, self.env.switch[sw1_id].ipaddr, dev1prt,
                                                       self.env.switch[sw2_id].id, self.env.switch[sw2_id].ipaddr, dev2prt))
                        self.env.switch[sw1_id].setprop("Ports", "adminMode", [dev1prt_id, "Down"])
                        time.sleep(2)
                        try:
                            self.wait_until_value_is_changed(self.env.switch[sw2_id], "Ports",
                                                             "operationalStatus", "Down", dev2prt_id, 10)
                            assert self.env.switch[sw2_id].getprop("Ports", "operationalStatus", dev2prt_id) == "Down"
                        except Exception:
                            self.class_logger.error("Port (%s) on paired device did not change its state! Reporting failure..." %
                                                    (dev2prt, ))
                            self.class_logger.error("SW1: %s, ip: %s, port: %s\nSW2: %s, ip: %s, port: %s" %
                                                    (self.env.switch[sw1_id].id, self.env.switch[sw1_id].ipaddr, dev1prt,
                                                     self.env.switch[sw2_id].id, self.env.switch[sw2_id].ipaddr, dev2prt))
                            self.class_logger.info("The following ports were checked:\n%s" % (ports, ))
                            pytest.softexit("Wrong connection detected!", self.env)
                        self.env.switch[sw1_id].setprop("Ports", "adminMode", [dev1prt_id, "Up"])

                    elif check_method == "indirect":
                        dev1_ports_tbl = self.env.switch[sw1_id].getprop_table("Ports")
                        for record in dev1_ports_tbl:
                            if record['portId'] == dev1prt:
                                dev1_prt_name = record['name']
                                break
                        dev2_ports_tbl = self.env.switch[sw2_id].getprop_table("Ports")
                        for record in dev2_ports_tbl:
                            if record['portId'] == dev2prt:
                                dev2_prt_name = record['name']
                                break
                        self.class_logger.debug("Port name for %s is '%s' and for %s is '%s'" %
                                                (dev1prt, dev1_prt_name, dev2prt, dev2_prt_name))
                        dev1_lldp_tbl = self.env.switch[sw1_id].getprop_table("LldpRemotes")
                        self.class_logger.debug("LldpRemotes table length is %s on 1st device." % (len(dev1_lldp_tbl), ))
                        for record in dev1_lldp_tbl:
                            if record['remPortId'] == dev2_prt_name and record['remLocalPortNum'] == dev1prt:
                                flag1 = True
                                self.class_logger.debug("1st Record found!")
                                break
                            else:
                                self.class_logger.debug("1st Record not found. Moving forward!")
                        dev2_lldp_tbl = self.env.switch[sw2_id].getprop_table("LldpRemotes")
                        self.class_logger.debug("LldpRemotes table length is %s on 2nd device." % (len(dev2_lldp_tbl), ))
                        for record in dev2_lldp_tbl:
                            if record['remPortId'] == dev1_prt_name and record['remLocalPortNum'] == dev2prt:
                                flag2 = True
                                self.class_logger.debug("2nd Record found!")
                                break
                            else:
                                self.class_logger.debug("2nd Record not found. Moving forward!")
                        try:
                            assert flag1
                            assert flag2
                        except Exception:
                            self.class_logger.error("SW1: %s, ip: %s, port: %s\nSW2: %s, ip: %s, port: %s" %
                                                    (self.env.switch[sw1_id].id, self.env.switch[sw1_id].ipaddr, dev1prt,
                                                     self.env.switch[sw2_id].id, self.env.switch[sw2_id].ipaddr, dev2prt))
                            self.class_logger.info("The following ports were checked:\n%s" % (ports, ))
                            pytest.softexit("Wrong connection detected!", self.env)
                    else:
                        raise ValueError("Unknown value for 'check_method' argument specified: %s." % (check_method, ))

    @setup_teardown
    def test_links_simplified5(self):
        """ "simplified" (5-links) setup:

        """
        ports = self.env.get_ports(links=[['tg1', 'sw1', 5], ])
        self._check_tg_links(ports, "sw1")

    @setup_teardown
    def test_links_simplified4(self):
        """ "simplified" 5-links setup:

        """
        ports = self.env.get_ports(links=[['tg1', 'sw1', 4], ])
        time.sleep(15)
        self._check_tg_links(ports, "sw1")

    @setup_teardown
    def test_links_simplified3(self):
        """ "simplified" 3-links setup:

        """
        ports = self.env.get_ports(links=[['tg1', 'sw1', 3], ])
        time.sleep(15)
        self._check_tg_links(ports, "sw1")

    @setup_teardown
    def test_links_simplified2(self):
        """ "simplified" 2-links setup:

        """
        ports = self.env.get_ports(links=[['tg1', 'sw1', 2], ])
        time.sleep(15)
        self._check_tg_links(ports, "sw1")

    @setup_teardown
    def test_links_golden(self):
        """std "golden" setup:

        """
        ports = self.env.get_ports([['tg1', 'sw1', 5], ['tg1', 'sw2', 4], ['tg1', 'sw3', 3],
                                    ['sw1', 'sw2', 9], ['sw1', 'sw3', 4], ['sw2', 'sw3', 4]])
        time.sleep(15)
        self._check_tg_links(ports, "sw1")
        self._check_tg_links(ports, "sw2")
        self._check_tg_links(ports, "sw3")
        self.class_logger.info("Ports to TG are OK.")
        self._check_sw_links(ports, "sw1", "sw2")
        self._check_sw_links(ports, "sw1", "sw3")
        self._check_sw_links(ports, "sw2", "sw3")
        self.class_logger.info("Ports among switches are OK.")

    @setup_teardown
    def test_links_diamond(self):
        """std "diamond" setup:

        """
        ports = self.env.get_ports([['tg1', 'sw1', 3], ['tg1', 'sw2', 2], ['tg1', 'sw3', 2], ['tg1', 'sw4', 2],
                                    ['sw1', 'sw2', 2], ['sw1', 'sw3', 2], ['sw1', 'sw4', 1],
                                    ['sw2', 'sw4', 2], ['sw4', 'sw3', 2]])
        time.sleep(15)
        self._check_tg_links(ports, 'sw1')
        self._check_tg_links(ports, 'sw2')
        self._check_tg_links(ports, 'sw3')
        self._check_tg_links(ports, 'sw4')
        self.class_logger.info("Ports to TG are OK.")
        self._check_sw_links(ports, 'sw1', 'sw2')
        self._check_sw_links(ports, 'sw1', 'sw3')
        self._check_sw_links(ports, 'sw1', 'sw4')
        self._check_sw_links(ports, 'sw2', 'sw4')
        self._check_sw_links(ports, 'sw3', 'sw4')
        self.class_logger.info("Ports among switches are OK.")

    @setup_teardown
    def test_links_mixed(self):
        """ "mixed" setup:

        """
        ports = self.env.get_ports(links=[['tg1', 'sw1', 2], ['tg1', 'sw2', 1], ['tg1', 'sw3', 1],
                                          ['sw1', 'sw2', 1], ['sw1', 'sw3', 1], ['sw2', 'sw3', 2]])
        time.sleep(15)
        self._check_tg_links(ports, 'sw1')
        self._check_tg_links(ports, 'sw2')
        self._check_tg_links(ports, 'sw3')
        self.class_logger.info("Ports to TG are OK.")
        # Time to establish LLDP
        time.sleep(35)
        self._check_sw_links(ports, 'sw1', 'sw2', check_method="indirect")
        self._check_sw_links(ports, 'sw1', 'sw3', check_method="indirect")
        self._check_sw_links(ports, 'sw2', 'sw3')
        self.class_logger.info("Ports among switches are OK.")
