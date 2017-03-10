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

"""``IxLoadTclAPI.py``

`IxLoad Tcl API wrapper module`

"""

import json
import os
import time

# from ..custom_exceptions import IxiaException
from . import ixia_helpers
from ..loggers import ClassLogger
from ..read_csv import ReadCsv


# To log tcl commands without execution set to True.
SIMULATE = False


class IxLoadTclAPI(object):
    """IxLoad Tcl API base wrapper class.

    """

    class_logger = ClassLogger()

    def __init__(self, ipaddr, user):
        """Initializes connection to IxLoad.

        Args:
            ipaddr(str):  IxLoad host IP address.
            user(str):  IxLoad windows user.

        """
        import tkinter
        self.tcl_interpret = tkinter.Tcl()

        def tcl_puts(*args):
            if len(args) >= 2:
                stream = args[0]
                if stream == "stdout":
                    self.class_logger.debug(" ".join(args[1:]))
                elif stream == "stderr":
                    self.class_logger.error(" ".join(args[1:]))
                else:
                    self.class_logger.debug("stream <%s>: %s" % (args[0], " ".join(args[1:])))
            elif len(args) == 1:
                self.class_logger.debug(args[0])
            else:
                self.class_logger.error("Called puts without arguments.")
            return None

        self.tcl_interpret.createcommand("tcl_puts", tcl_puts)
        self.class_logger.debug("Insert tcl script to catch puts output.")
        ixia_helpers.tcl_puts_replace(self.tcl_interpret)

        self.ixload_ip = ipaddr
        self.ixload_user = user

        # Temp path for sending rxf files to IxLoad
        self.ixload_tmppath = "C:\\Users\\{0}\\AppData\\Local\\Temp\\".format(self.ixload_user)
        # Path for storing test csv reports. It could be override in child IxLoadHL class.
        self.ixload_respath = self.ixload_tmppath
        self.__log_name = "IxLoadTclAPI-{0}-{1}-{2}".format(os.uname()[1], os.getuid(), int(time.time()))
        self.ixload_logpath = None

        ixia_helpers.ixtclhal_import(self.tcl_interpret)
        ixia_helpers.ixload_import(self.tcl_interpret)

        self.test_controller = None
        self.tst = None

    def tcl(self, cmd):
        """Tcl wrapper.

        """
        self.class_logger.debug("Run tcl command: %s", cmd)
        if not SIMULATE:
            return self.tcl_interpret.eval(cmd)
        else:
            return ""

    def connect(self):
        """Logs in to IXIA and takes ports ownership.

        Returns:
            None

        """
        # Set simple config
        # self.tcl("namespace eval ::IxLoadPrivate {};" +
        #         "namespace eval ::IxLoadPrivate::SimpleSettings {};" +
        #         "variable ::IxLoadPrivate::SimpleSettings::remoteServer {0};".format(self.ixload_ip) +
        #         "::IxLoad connect $::IxLoadPrivate::SimpleSettings::remoteServer")
        self.tcl("::IxLoad connect {0}".format(self.ixload_ip))
        # Set up logger
        self.ixload_logpath = (self.ixload_respath + "\\" + self.__log_name).replace("\\", "\\\\")
        self.logger_setup()
        # Define test controller.
        self.test_controller = IxLoadTestController(self.tcl, self.tcl_interpret, self.ixload_respath)
        # self.tcl("set testController [::IxLoad new ixTestController -outputDir 1];")
        self.tcl("global ixAppPluginManager")
        self.class_logger.info("IxLoad startup complete.")

    def disconnect(self):
        """Logs out from IXIA and clears ports ownership.

        Returns:
            None

        """
        self.tcl("::IxLoad disconnect")

    def logger_setup(self):
        self.class_logger.info("Setting up IxLoad logger...")
        self.tcl("set logtag \"IxLoad-api\";" +
                 "set logName \"{0}\";".format(self.__log_name) +
                 "set logger [::IxLoad new ixLogger $logtag 1];" +
                 "set logEngine [$logger getEngine];" +
                 "$logEngine setLevels $::ixLogger(kLevelDebug) $::ixLogger(kLevelInfo);" +
                 "$logEngine setFile {0} 2 1024 1".format(self.ixload_logpath))
        #        "$logEngine setFile $logName 2 256 1")

    def logger_delete(self):
        self.tcl("::IxLoad delete $logger;" +
                 "::IxLoad delete $logEngine")

    def load_repo(self, repo=None):
        """Loading rxf repo file or create new one.

        """
        if repo is None:
            self.tcl("set repository [::IxLoad new ixRepository]")
        else:
            self.class_logger.info("Loading repo: {0}".format(repo))
            _repo_name = os.path.basename(repo)
            ixload_repo = self.ixload_tmppath + _repo_name
            self.copy_local_file(repo, ixload_repo)
            self.tcl("set repository [::IxLoad new ixRepository -name \"{0}\"]".format(ixload_repo).replace("\\", "\\\\"))
            self.repo_file = repo
        # self.tst = IxLoadTests(self.tcl)
        self.tst = IxLoadTests(self.tcl, self.test_controller,
                               "{0}{1}".format(self.ixload_respath, self.__log_name))
        self.class_logger.debug("Discovered tests list: {0}".format(self.tst.tc_list))

    def copy_local_file(self, local_path, remote_path):
        """Copy local file to IxLoad host.

        """
        self.tcl("::IxLoad sendFileCopy \"{0}\" \"{1}\"".format(local_path, remote_path).replace("\\", "\\\\"))

    def copy_remote_file(self, remote_path, local_path):
        """Copy remote file from IxLoad host to local host.

        """
        self.tcl("::IxLoad retrieveFileCopy \"{0}\" \"{1}\"".format(remote_path, local_path).replace("\\", "\\\\"))

    def retrieve_results(self, dst_path):
        """Retrieve result csv files from IxLoad host to local dst_path.

        """
        self.tcl("::IxLoad retrieveResults \"{0}\"".format(dst_path).replace("\\", "\\\\"))

    def load_plugin(self, plugin):
        self.tcl("$ixAppPluginManager load \"{0}\"".format(plugin))

    def update_stats(self, stype="file", stat_name=None):

        def s2i_safe(val):
            try:
                return int(val.replace("kInt ", "").replace("timestamp ", ""))
            except Exception:
                try:
                    return float(val.replace("kInt ", "").replace("timestamp ", ""))
                except Exception:
                    return val

        if stype == "file":
            if self.test_controller.test_result_path is None:
                raise Exception("Any test is started or csv result path isn't set.")
            tmp_path = os.path.join("/tmp", "taf_ixload_file_stats.{0}".format(os.getpid()))
            if stat_name:
                stat_names = [stat_name, ]
            else:
                stat_names = [sn[0] for sn in self.test_controller.stats_list]
            for stat_name in stat_names:
                self.copy_remote_file(self.test_controller.test_result_path + "\\" + stat_name.replace(" ", "_") + ".csv", tmp_path)
                csv = ReadCsv(tmp_path)
                # 15 is minimal acceptable length of csv report. Take bigger number for assurance.
                if len(csv.content) < 18:
                    self.class_logger.warning("IxLoad {0} csv file is empty yet.".format(stat_name))
                    return False
                # Remove unnecessary lines from IxLoad csv
                # -1 because last line could be not full filled.
                for i in [-1, 12, 11, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]:
                    csv.content.pop(i)
                self.test_controller.file_stats[stat_name] = IxLoadStats()
                self.test_controller.file_stats[stat_name].extend([list(map(s2i_safe, x)) for x in csv.content[1:]])
                self.test_controller.file_stats[stat_name].add_header(csv.content[0])

        elif stype == "runtime":
            for stat_item in self.test_controller.stats_list:
                stat_name = stat_item[0]
                _h = ["Elapsed Time", ]
                _h.extend(stat_item[1])
                self.test_controller.runtime_stats[stat_name] = IxLoadStats()
                self.test_controller.runtime_stats[stat_name].add_header(_h)
            for stat in self.test_controller.stats[:]:
                time_stamp = s2i_safe(stat[1])
                # Convert time_stamp to seconds
                time_stamp = time_stamp / 1000 if isinstance(time_stamp, int) else time_stamp
                stat_values = list(map(s2i_safe, stat[2]))
                last_stat_item = 0
                for stat_item in self.test_controller.stats_list:
                    stat_name = stat_item[0]
                    stat_num = len(stat_item[1])
                    _l = stat_values[last_stat_item:stat_num + last_stat_item]
                    _l.insert(0, time_stamp)
                    last_stat_item += stat_num
                    self.test_controller.runtime_stats[stat_name].append(_l)

        else:
            raise Exception("Unknown stats type: {0}".format(stype))

        return True

    def get_stats(self, stype="file"):
        if stype == "file":
            return self.test_controller.file_stats
        elif stype == "runtime":
            return self.test_controller.runtime_stats
        else:
            raise Exception("Incorrect stats type: {0}".format(stype))


class IxLoadTests(object):
    """Class for managing IxLoad Tests.

    """

    def __init__(self, tcl, test_controller, res_path=""):
        self.tcl = tcl
        self.tc_list = []
        self.load_tclist()
        self.res_path = res_path
        self.test_controller = test_controller

    def load_tclist(self):
        """Loading list of IxLoad Tests.

        """
        _tlist = []
        num_tests = self.tcl("$repository testList.indexCount")
        for _i in range(int(num_tests)):
            tc_name = self.tcl("$repository testList({0}).cget -name".format(_i))
            _tlist.append(tc_name)

        # Test list is read. Cleanup previous one and store new list.
        self.tc_list = _tlist

    def start(self, t_name):
        """Start ixLoad test without waiting for result.

        """
        self.tcl("puts {0}".format(t_name))

    def run(self, t_name, res_path=None):
        """Run ixLoad test until completion.

        """
        # Set result dir.
        res_path = res_path if res_path is not None else self.res_path
        res_path = "{0}\\{1}".format(res_path, t_name)
        self.tcl("${0} setResultDir \"{1}\"".format(self.test_controller.name, res_path).replace("\\", "\\\\"))
        # Execute the test.
        self.tcl("set test [$repository testList.getItem {}];".format(t_name) +
                 "${0} run $test".format(self.test_controller.name))
        self.tcl("vwait ::ixTestControllerMonitor; puts $::ixTestControllerMonitor")
        return res_path

    def cleanup(self):
        self.tcl("${0} releaseConfigWaitFinish;".format(self.test_controller.name) +
                 "if {[lsearch [info vars] test] >= 0} {$test clearDUTList; ::IxLoad delete $test}")

    def report(self, pdf=False):
        """Enable/Disable report options.

        """
        self.tcl("ixNet setAttribute [ixNet getRoot]/testConfiguration -enableGenerateReportAfterRun {0}".format(pdf))


class IxLoadStats(list):
    """Custom list class to support columns header names.

    """

    headers = None

    def add_header(self, header):
        self.headers = dict((hi, header.index(hi)) for hi in header)

    def _get(self, row_num, col_names):
        if col_names is None:
            # Return whole row
            return self[row_num]
        elif isinstance(col_names, str):
            return self[row_num][self.headers[col_names]]
        elif isinstance(col_names, list):
            indexes = [self.headers[x] for x in col_names]
            return [self[row_num][x] for x in indexes]
        else:
            raise TypeError("Incorrect col_names type: {0}. str/list of str/None are allowed.".format(type(col_names)))

    def get(self, row_num=-1, col_names=None):
        if isinstance(row_num, int):
            return self._get(row_num, col_names)
        elif isinstance(row_num, list):
            return [self._get(x, col_names) for x in row_num]
        else:
            raise TypeError("Incorrect row_num type: {0}. int and list are allowed.".format(type(row_num)))


class IxLoadGenericObjectMixin(object):

    IXLOAD_CLASS = None
    TCL_VARS = ""

    def __init__(self, tcl):
        self.tcl = tcl
        self.name = self.get_free_name()
        if self.IXLOAD_CLASS is not None:
            self.tcl("set {0} [::IxLoad new {1}]".format(self.name, self.IXLOAD_CLASS))

    def __del__(self):
        self.tcl("::IxLoad delete ${0}".format(self.name))
        self.tcl("unset {0}".format(self.name))

    def get_free_name(self):

        def is_int(num):
            try:
                return int(num)
            except ValueError:
                return None

        if not SIMULATE:
            _tcl_vars = self.tcl("info vars")
        else:
            self.tcl("")
            _tcl_vars = IxLoadGenericObjectMixin.TCL_VARS
        # Return unused number for class variable.
        _id = max([is_int(_v.replace(self.NAME, "")) for _v in _tcl_vars.split(" ") if _v.startswith(self.NAME)] or [0, ]) or 0
        if SIMULATE:
            IxLoadGenericObjectMixin.TCL_VARS += " " + self.NAME + str(_id + 1)
        return self.NAME + str(_id + 1)

    def _gen_params(self, **kw):
        def arg_repr(arg):
            if isinstance(arg, IxLoadGenericObjectMixin):
                return "${0}".format(arg.name)
            elif isinstance(arg, str):
                return '"{0}"'.format(arg)
            else:
                return arg

        return " ".join(["-{0} {1}".format(k, arg_repr(kw[k])) for k in kw])

    def config(self, **kwargs):
        params = self._gen_params(**kwargs)
        self.tcl("${0} config {1}".format(self.name, params))

    def clear(self, target):
        self.tcl("${0} {1}.clear".format(self.name, target))


class IxLoadTestController(IxLoadGenericObjectMixin):

    NAME = "testController"
    class_logger = ClassLogger()

    def __init__(self, tcl, tcl_interpret, root_path="", res_path=None):
        super(IxLoadTestController, self).__init__(tcl)
        self.tcl("set {0} [::IxLoad new ixTestController -outputDir True]".format(self.name))
        self.res_path = res_path or "TAF-{0}-{1}-{2}".format(os.uname()[1], os.getuid(), int(time.time()))
        self.root_path = root_path
        self.test_result_path = None
        self.statcollector = None
        self.testserverhandle = None
        # Stats collector for runtime statistics collecting.
        self.stats = []
        self.runtime_stats = {}
        self.file_stats = {}
        self.stats_list = []
        self.statmap = {}

        def collect_stats(*args):
            try:
                # Try to pars stat args.
                a1, a2 = args
                time_stamp, stat_args = a2.split(" stats ")
                time_stamp = time_stamp.replace("timestamp ", "")
                stat_args = stat_args.lstrip("{{").rstrip("}}").split("} {")
                self.stats.append((a1, time_stamp, stat_args))
            except Exception as err:
                # Append stat args as is.
                self.class_logger.warning("Failed to parse stat args. Err: {0}".format(err))
                self.stats.append(args)

        tcl_interpret.createcommand("collect_stats", collect_stats)
        self.set_statcollector()
        self.get_testserverhandle()
        self.statcollector.init_tsh(self.testserverhandle)

    def __del__(self):
        self.cleanup()
        super(IxLoadTestController, self).__del__()

    def cleanup(self):
        tcs = self.status()
        if tcs == "1":
            self.stop(force=True)
        else:
            self.tcl("${0} releaseConfigWaitFinish".format(self.name))

    def clear_stats(self):
        self.runtime_stats = {}
        self.file_stats = {}
        # self.stats_list = []
        self.statcollector.clear()

    def set_resultdir(self, root_path=None, res_dir=None):
        root_path = root_path or self.root_path
        _result_path = "{0}{1}\\{2}".format(root_path, self.res_path, res_dir)
        self.tcl("${0} setResultDir {1}".format(self.name, _result_path).replace("\\", "\\\\"))
        return _result_path

    def apply(self, test):
        self.tcl("${0} applyConfig ${1}".format(self.name, test))

    def run_test(self, test, test_name=None, stats=None):
        self.test_result_path = self.set_resultdir(self.root_path, test_name or test.name)
        statmap = {}
        if stats:
            self.stats_list = stats
            _stat_list = ""
            _stat_types_file = os.path.join(os.path.dirname(__file__), "ixload_stat_types")
            _stat_types = json.loads(open(_stat_types_file).read().encode("ascii"), encoding="latin-1")
            for stat in stats:
                self.runtime_stats[stat[0]] = IxLoadStats()
                _stat_list_name = stat[0].replace(" ", "_") + "_StatList"
                _stat_items = ""
                statmap[stat[0]] = {}
                for stat_item in stat[1]:
                    _stat_items += " {\"%s\" \"%s\" \"%s\"}" % (stat[0], stat_item,
                                                                _stat_types[stat[0]][stat_item])
                    statmap[stat[0]][stat_item] = len(statmap[stat[0]])
                self.tcl("set %s { %s }" % (_stat_list_name, _stat_items))
                _stat_list += " $" + _stat_list_name
            self.statmap = statmap
            self.tcl("${0} clearGridStats".format(test.name))
            self.tcl("set statList [concat {0}]".format(_stat_list))
            self.tcl("set count 1; " +
                     "foreach stat $statList { " +
                     "  set caption [format \"Watch_Stat_%s\" $count]; " +
                     "  set statSourceType [lindex $stat 0]; " +
                     "  set statName [lindex $stat 1]; " +
                     "  set aggregationType [lindex $stat 2]; " +
                     "  ${%s}::AddStat " % (self.statcollector.name, ) +
                     "    -caption $caption " +
                     "    -statSourceType $statSourceType " +
                     "    -statName $statName " +
                     "    -aggregationType $aggregationType " +
                     "    -filterList {}; "
                     "  incr count}")
            self.statcollector.start()
        self.tcl("set ::ixTestControllerMonitor \"\"; ${0} run ${1}".format(self.name, test.name))
        return self.test_result_path

    def stop(self, force=False):
        if force:
            self.tcl("${0} stopRun".format(self.name))
        else:
            self.tcl("${0} stopRunGraceful".format(self.name))

    def status(self):
        return self.tcl("${0} isBusy".format(self.name))

    def wait_test(self):
        self.tcl("vwait ::ixTestControllerMonitor; puts $::ixTestControllerMonitor")
        if self.statcollector is not None:
            self.statcollector.stop()

    def check_testexecution(self):
        rc = self.tcl("if { $::ixTestControllerMonitor == \"\" } {return \"RUN\"}")
        if rc == "RUN":
            return True
        else:
            return False

    def get_testserverhandle(self):
        self.testserverhandle = IxLoadTestServerHandle(self.tcl)
        self.tcl("set {0} [${1} getTestServerHandle]".format(self.testserverhandle.name, self.name))
        return self.testserverhandle

    def set_statcollector(self):
        self.statcollector = IxLoadstatCollectorUtils(self.tcl)


class IxLoadChassisChain(IxLoadGenericObjectMixin):

    NAME = "chassisChain"
    IXLOAD_CLASS = "ixChassisChain"

    def __init__(self, tcl, ipaddr=None):
        super(IxLoadChassisChain, self).__init__(tcl)
        if ipaddr is None:
            ipaddr = ["127.0.0.1", ]
        self.__ipaddr = ipaddr
        for _ipaddr in self.__ipaddr:
            self.tcl("${0} addChassis {1}".format(self.name, _ipaddr))


class IxLoadixEventHandlerSettings(IxLoadGenericObjectMixin):

    NAME = "ixEventHandlerSettings"
    IXLOAD_CLASS = "ixEventHandlerSettings"

    def __init__(self, tcl):
        super(IxLoadixEventHandlerSettings, self).__init__(tcl)
        self.tcl("${0} config".format(self.name))


class IxLoadixViewOptions(IxLoadGenericObjectMixin):

    NAME = "ixViewOptions"
    IXLOAD_CLASS = "ixViewOptions"

    def __init__(self, tcl):
        super(IxLoadixViewOptions, self).__init__(tcl)
        self.tcl("${0} config".format(self.name))


class IxLoadixTest(IxLoadGenericObjectMixin):

    NAME = "ixTest"
    IXLOAD_CLASS = "ixTest"

    def __init__(self, tcl):
        super(IxLoadixTest, self).__init__(tcl)
        self.clear("scenarioList")
        self.scenarioelement = None
        self.scenariofactory = None
        self.scenario = None
        self.eventhandlersettings = None
        self.viewoptions = None
        self.sessionspecificdata = {}
        self.profiledir = None

    def __del__(self):
        self.tcl("${0} clearDUTList".format(self.name))
        super(IxLoadixTest, self).__del__()

    def get_scenarioelementfactory(self):
        self.scenarioelement = IxLoadScenarioElementFactory(self.tcl)
        self.tcl("set {0} [${1} getScenarioElementFactory]".format(self.scenarioelement.name, self.name))
        return self.scenarioelement

    def get_scenariofactory(self):
        self.scenariofactory = IxLoadScenarioFactory(self.tcl)
        self.tcl("set {0} [${1} getScenarioFactory]".format(self.scenariofactory.name, self.name))
        return self.scenariofactory

    def get_scenario(self):
        if self.scenariofactory is None:
            self.get_scenariofactory()
        self.scenario = self.scenariofactory.create_scenario()
        return self. scenario

    def get_sessionspecificdata(self, _type):
        ssd = IxLoadixTestSessionSpecificData(self.tcl)
        self.tcl("set {0} [${1} getSessionSpecificData \"{2}\"]".format(ssd.name, self.name, _type))
        self.sessionspecificdata[ssd.name] = ssd
        return ssd

    def get_profiledir(self):
        self.profiledir = IxLoadixTestProfileDirectory(self.tcl)
        self.tcl("set {0} [${1} cget -profileDirectory]".format(self.profiledir.name, self.name))
        return self.profiledir


class IxLoadScenarioElementFactory(IxLoadGenericObjectMixin):

    NAME = "scenarioElementFactory"

    def create_nettraffic(self):
        nettraffic = IxLoadSETkNetTraffic(self.tcl)
        self.tcl("set {0} [${1} create $::ixScenarioElementType(kNetTraffic)]".format(nettraffic.name, self.name))
        return nettraffic

    def create_dut(self):
        dut = IxLoadSETkDutBasic(self.tcl)
        self.tcl("set {0} [${1} create $::ixScenarioElementType(kDutBasic)]".format(dut.name, self.name))
        return dut


class IxLoadScenarioFactory(IxLoadGenericObjectMixin):

    NAME = "scenarioFactory"
    # IXLOAD_CLASS = "getScenarioFactory"

    def create_scenario(self):
        scenario = IxLoadScenario(self.tcl)
        self.tcl("set {0} [${1} create \"Scenario\"]".format(scenario.name, self.name))
        scenario.clear("columnList")
        scenario.clear("links")
        return scenario


class IxLoadScenario(IxLoadGenericObjectMixin):

    NAME = "Scenario"

    def __init__(self, tcl):
        super(IxLoadScenario, self).__init__(tcl)
        self.columnlist = []

    def append_columnlist(self, column):
        self.tcl("${0} columnList.appendItem -object ${1}".format(self.name, column.name))
        self.columnlist.append(column)

    def new_traffic_column(self):
        return IxLoadixTrafficColumn(self.tcl)


class IxLoadixTrafficColumn(IxLoadGenericObjectMixin):

    NAME = "ixTrafficColumn"
    IXLOAD_CLASS = "ixTrafficColumn"

    def __init__(self, tcl):
        super(IxLoadixTrafficColumn, self).__init__(tcl)
        self.clear("elementList")
        self.elementlist = []

    def append_elementlist(self, element):
        self.tcl("${0} elementList.appendItem -object ${1}".format(self.name, element.name))
        self.elementlist.append(element)


class IxLoadixNetIxLoadSettingsPlugin(IxLoadGenericObjectMixin):

    NAME = "Settings"
    IXLOAD_CLASS = "ixNetIxLoadSettingsPlugin"


class IxLoadixNetFilterPlugin(IxLoadGenericObjectMixin):

    NAME = "Filter"
    IXLOAD_CLASS = "ixNetFilterPlugin"


class IxLoadixNetGratArpPlugin(IxLoadGenericObjectMixin):

    NAME = "GratARP"
    IXLOAD_CLASS = "ixNetGratArpPlugin"


class IxLoadixNetTCPPlugin(IxLoadGenericObjectMixin):

    NAME = "TCP"
    IXLOAD_CLASS = "ixNetTCPPlugin"


class IxLoadixNetDnsPlugin(IxLoadGenericObjectMixin):

    NAME = "DNS"
    IXLOAD_CLASS = "ixNetDnsPlugin"

    def __init__(self, tcl):
        super(IxLoadixNetDnsPlugin, self).__init__(tcl)
        self.clear("hostList")
        self.clear("searchList")
        self.clear("nameServerList")


ixNetIxLoadPlugins = {"Settings": IxLoadixNetIxLoadSettingsPlugin,
                      "Filter": IxLoadixNetFilterPlugin,
                      "GratARP": IxLoadixNetGratArpPlugin,
                      "TCP": IxLoadixNetTCPPlugin,
                      "DNS": IxLoadixNetDnsPlugin, }


class IxLoadixNetEthernetELMPlugin(IxLoadGenericObjectMixin):

    NAME = "ixNetEthernetELMPlugin"
    IXLOAD_CLASS = "ixNetEthernetELMPlugin"


class IxLoadixNetDualPhyPlugin(IxLoadGenericObjectMixin):

    NAME = "ixNetDualPhyPlugin"
    IXLOAD_CLASS = "ixNetDualPhyPlugin"


class IxLoadIPRMacRange(IxLoadGenericObjectMixin):

    NAME = "MAC_R"


class IxLoadIPRVlanIdRange(IxLoadGenericObjectMixin):

    NAME = "VLAN_R"


class IxLoadixNetIpV4V6Range(IxLoadGenericObjectMixin):

    NAME = "IP_R"
    IXLOAD_CLASS = "ixNetIpV4V6Range"

    def __init__(self, tcl):
        super(IxLoadixNetIpV4V6Range, self).__init__(tcl)
        self.macrange = None
        self.vlanidrange = None

    def get_macrange(self):
        self.macrange = IxLoadIPRMacRange(self.tcl)
        self.tcl("set {0} [${1} getLowerRelatedRange \"MacRange\"]".format(self.macrange.name, self.name))
        return self.macrange

    def get_vlanidrange(self):
        self.vlanidrange = IxLoadIPRVlanIdRange(self.tcl)
        self.tcl("set {0} [${1} getLowerRelatedRange \"VlanIdRange\"]".format(self.vlanidrange.name, self.name))
        return self.vlanidrange


class IxLoadixNetRangeGroup(IxLoadGenericObjectMixin):

    NAME = "DistGroup"
    IXLOAD_CLASS = "ixNetRangeGroup"

    def __init__(self, tcl):
        super(IxLoadixNetRangeGroup, self).__init__(tcl)
        self.clear("rangeList")
        self.ranges = []

    def append_range(self, iprange):
        self.tcl("${0} rangeList.appendItem -object ${1}".format(self.name, iprange.name))
        self.ranges.append(iprange)


class IxLoadixNetIpV4V6Plugin(IxLoadGenericObjectMixin):

    NAME = "IP"
    IXLOAD_CLASS = "ixNetIpV4V6Plugin"

    def __init__(self, tcl):
        super(IxLoadixNetIpV4V6Plugin, self).__init__(tcl)
        self.clear("childrenList")
        self.clear("extensionList")
        self.clear("rangeList")
        self.clear("rangeGroups")
        self.ranges = []
        self.distgroup = None

    def new_range(self):
        _range = IxLoadixNetIpV4V6Range(self.tcl)
        self.tcl("${0} rangeList.appendItem -object ${1}".format(self.name, _range.name))
        self.ranges.append(_range)
        return _range

    def new_distgroup(self):
        self.distgroup = IxLoadixNetRangeGroup(self.tcl)
        self.tcl("${0} rangeGroups.appendItem -object ${1}".format(self.name, self.distgroup.name))
        return self.distgroup

    def append_iprange(self, ip_range):
        if self.distgroup is None:
            self.new_distgroup()
        self.tcl("${0} rangeList.appendItem -object ${1}".format(self.distgroup.name, ip_range.name))
        self.distgroup.config(distribType=0, _Stale=False, name=self.distgroup.name)


class IxLoadixNetL2EthernetPlugin(IxLoadGenericObjectMixin):

    NAME = "MAC_VLAN"
    IXLOAD_CLASS = "ixNetL2EthernetPlugin"

    def __init__(self, tcl):
        super(IxLoadixNetL2EthernetPlugin, self).__init__(tcl)
        self.clear("childrenList")
        self.clear("extensionList")
        self.ipplugin = None

    def new_ipplugin(self):
        self.ipplugin = IxLoadixNetIpV4V6Plugin(self.tcl)
        self.tcl("${0} childrenList.appendItem -object ${1}".format(self.name, self.ipplugin.name))
        self.ipplugin.config(_Stale=False)
        return self.ipplugin


class IxLoadNetworkL1Plugin(IxLoadGenericObjectMixin):

    NAME = "Ethernet"

    def __init__(self, tcl):
        super(IxLoadNetworkL1Plugin, self).__init__(tcl)
        self.elm = None
        self.phy = None
        self.l2plugin = []

    def init(self):
        self.clear("childrenList")
        self.clear("extensionList")

    def new_l2plugin(self):
        l2plugin = IxLoadixNetL2EthernetPlugin(self.tcl)
        self.tcl("${0} childrenList.appendItem -object ${1}".format(self.name, l2plugin.name))
        l2plugin.config(_Stale=False)
        self.l2plugin.append(l2plugin)
        return l2plugin


class IxLoadixLinearTimeSegment(IxLoadGenericObjectMixin):

    NAME = "Linear_Segment"
    IXLOAD_CLASS = "ixLinearTimeSegment"


class IxLoadixAdvancedIteration(IxLoadGenericObjectMixin):

    NAME = "ixAdvancedIteration"
    IXLOAD_CLASS = "ixAdvancedIteration"

    def __init__(self, tcl):
        super(IxLoadixAdvancedIteration, self).__init__(tcl)
        self.clear("segmentList")
        self.segmentlist = []

    def append_segmentlist(self, segment):
        self.tcl("${0} segmentList.appendItem -object ${1}".format(self.name, segment.name))
        self.segmentlist.append(segment)

    def add_segment(self, **kwargs):
        segment = IxLoadixLinearTimeSegment(self.tcl)
        segment.config(**kwargs)
        self.append_segmentlist(segment)


class IxLoadixTimeline(IxLoadGenericObjectMixin):

    NAME = "Timeline"
    IXLOAD_CLASS = "ixTimeline"

    def __init__(self, tcl):
        super(IxLoadixTimeline, self).__init__(tcl)
        self.iteration = None

    def new_iteration(self):
        self.iteration = IxLoadixAdvancedIteration(self.tcl)
        return self.iteration


class IxLoadixMatchLongestTimeline(IxLoadGenericObjectMixin):

    NAME = "Timeline_Match_Longest"
    IXLOAD_CLASS = "ixMatchLongestTimeline"


class IxLoadixHttpCommand(IxLoadGenericObjectMixin):

    NAME = "ixHttpCommand"
    IXLOAD_CLASS = "ixHttpCommand"


class IxLoadixHttpHeaderString(IxLoadGenericObjectMixin):

    NAME = "ixHttpHeaderString"
    IXLOAD_CLASS = "ixHttpHeaderString"


class IxLoadResponseHeader(IxLoadGenericObjectMixin):

    NAME = "RespondHeader"
    IXLOAD_CLASS = "ResponseHeader"

    def __init__(self, tcl):
        super(IxLoadResponseHeader, self).__init__(tcl)
        self.clear("responseList")


class IxLoadPageObject(IxLoadGenericObjectMixin):

    NAME = "PageObject"
    IXLOAD_CLASS = "PageObject"
    response = None


class IxLoadCookieObject(IxLoadGenericObjectMixin):

    NAME = "CookieObject"
    IXLOAD_CLASS = "CookieObject"

    def __init__(self, tcl):
        super(IxLoadCookieObject, self).__init__(tcl)
        self.clear("cookieContentList")
        self.cookiecontentlist = []

    def append_cookiecontent(self, cookiecontent):
        self.tcl("${0} cookieContentList.appendItem -object ${1}".format(self.name, cookiecontent.name))
        self.cookiecontentlist.append(cookiecontent)


class IxLoadixCookieContent(IxLoadGenericObjectMixin):

    NAME = "ixCookieContent"
    IXLOAD_CLASS = "ixCookieContent"


class IxLoadCustomPayloadObject(IxLoadGenericObjectMixin):

    NAME = "CustomPayloadObject"
    IXLOAD_CLASS = "CustomPayloadObject"


class IxLoadHTTPClient(IxLoadGenericObjectMixin):

    NAME = "HTTPClient"

    def __init__(self, tcl):
        super(IxLoadHTTPClient, self).__init__(tcl)

    def init(self):
        self.clear("agent.actionList")
        self.clear("agent.cmdPercentagePool.percentageCommandList")
        self.agent_actionlist = []
        self.agent_headerlist = []
        self.timeline = None

    def append_agent_actionlist(self, agent_action):
        self.tcl("${0} agent.actionList.appendItem -object ${1}".format(self.name, agent_action.name))
        self.agent_actionlist.append(agent_action)

    def append_agent_headerlist(self, agent_header):
        self.tcl("${0} agent.headerList.appendItem -object ${1}".format(self.name, agent_header.name))
        self.agent_headerlist.append(agent_header)

    def new_timeline(self):
        self.timeline = IxLoadixTimeline(self.tcl)
        return self.timeline

    def config_percentagecmdlist(self, **kwargs):
        params = self._gen_params(**kwargs) if kwargs else ""
        self.tcl("${0} agent.cmdPercentagePool.percentageCommandList.clear".format(self.name))
        self.tcl("${0} agent.cmdPercentagePool.config {1}".format(self.name, params))

    def config_agent(self, **kwargs):
        params = self._gen_params(**kwargs) if kwargs else ""
        self.tcl("${0} agent.config {1}".format(self.name, params))

    def modify_objectivevalue(self, value):
        return self.tcl("$%s config -objectiveValue %s; " % (self.name, value) +
                        "set canSetObjectiveValue [$%s canSetObjectiveValue]; " % (self.name, ) +
                        "puts \"Can set objective value? - $canSetObjectiveValue\"; " +
                        "if { $canSetObjectiveValue } { $%s applyObjectiveValues } " % (self.name, ) +
                        "{puts \"Failed to set objectiveValue for %s.\"}; " % (self.name, ) +
                        "return $canSetObjectiveValue")

    def config_timeline(self, **kwargs):
        self.new_timeline()
        segments = kwargs.pop("segments") if "segments" in kwargs else []
        if segments:
            iteration = self.timeline.new_iteration()
            for segment in segments:
                iteration.add_segment(**segment)
            kwargs.update({"advancedIteration": iteration})
        self.timeline.config(**kwargs)
        return self.timeline

    def add_command(self, **kwargs):
        httpcmd = IxLoadixHttpCommand(self.tcl)
        httpcmd.config(**kwargs)
        self.append_agent_actionlist(httpcmd)

    def add_header(self, data):
        header = IxLoadixHttpHeaderString(self.tcl)
        header.config(data=data)
        self.append_agent_headerlist(header)


class IxLoadHTTPServer(IxLoadGenericObjectMixin):

    NAME = "HTTPServer"

    def __init__(self, tcl):
        super(IxLoadHTTPServer, self).__init__(tcl)
        self.timeline = None
        self.pagelist = []
        self.cookielist = []
        self.payloadlist = []
        self.responseheaderlist = []

    def init(self):
        self.clear("agent.cookieList")
        self.clear("agent.webPageList")
        self.clear("agent.customPayloadList")
        self.clear("agent.responseHeaderList")

    def new_timeline(self):
        self.timeline = IxLoadixMatchLongestTimeline(self.tcl)
        return self.timeline

    def append_pageobject(self, page):
        self.tcl("${0} agent.webPageList.appendItem -object ${1}".format(self.name, page.name))
        self.pagelist.append(page)

    def new_response(self, code="200"):
        response = IxLoadResponseHeader(self.tcl)
        _t1 = time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime())
        _t2 = time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(time.time() + 2592000))
        if code == "200":
            name = "200_OK"
        elif code == "404":
            name = "404_PageNotFound"
        else:
            name = "Custom"
        response.config(code=code, name=name, description=name,
                        lastModifiedDateTimeValue=_t1, dateTimeValue=_t1,
                        expirationDateTimeValue=_t2)
        return response

    def add_pageobject(self, response="200", **kwargs):
        page = IxLoadPageObject(self.tcl)
        page.response = self.new_response(response)
        page.config(response=page.response, **kwargs)
        self.append_pageobject(page)

    def append_cookielist(self, cookie):
        self.tcl("${0} agent.cookieList.appendItem -object ${1}".format(self.name, cookie.name))
        self.cookielist.append(cookie)

    def add_cookie(self, cookiecontentlist):
        _cookie = IxLoadCookieObject(self.tcl)
        for cookie_params in cookiecontentlist:
            _cookiecontent = IxLoadixCookieContent(self.tcl)
            _cookiecontent.config(**cookie_params)
            _cookie.append_cookiecontent(_cookiecontent)
        self.append_cookielist(_cookie)

    def append_payloadlist(self, payload):
        self.tcl("${0} agent.customPayloadList.appendItem -object ${1}".format(self.name, payload.name))
        self.payloadlist.append(payload)

    def add_payload(self, **kwargs):
        payload = IxLoadCustomPayloadObject(self.tcl)
        payload.config(**kwargs)
        self.append_payloadlist(payload)

    def append_responseheaderlist(self, responseheader):
        self.tcl("${0} agent.responseHeaderList.appendItem -object ${1}".format(self.name, responseheader.name))
        self.responseheaderlist.append(responseheader)

    def config_agent(self, **kwargs):
        params = self._gen_params(**kwargs) if kwargs else ""
        self.tcl("${0} agent.config {1}".format(self.name, params))

    def config_timeline(self, **kwargs):
        self.new_timeline()
        self.config(name=self.name, timeline=self.timeline)


activityListItems = {"HTTP Client": IxLoadHTTPClient,
                     "HTTP Server": IxLoadHTTPServer, }


class IxLoadNetTrafficNetwork(IxLoadGenericObjectMixin):

    NAME = "NetTrafficNetwork"

    def __init__(self, tcl):
        super(IxLoadNetTrafficNetwork, self).__init__(tcl)
        self.plugins = {}
        self.l1plugin = None
        self.activities = {}

    def append_portlist(self, port):
        chass, card, pid = port.split("/")
        self.tcl("${0} portList.appendItem -chassisId {1} -cardId {2} -portId {3}".
                 format(self.name, chass, card, pid))

    def clear_plugins(self):
        # self.clear("childrenList")
        self.clear("globalPlugins")

    def new_plugin(self, plugin):
        _plugin = ixNetIxLoadPlugins[plugin](self.tcl)
        self.tcl("${0} globalPlugins.appendItem -object ${1}".format(self.name, _plugin.name))
        if _plugin.NAME not in self.plugins:
            self.plugins[_plugin.NAME] = {}
        self.plugins[_plugin.NAME][_plugin.name] = _plugin
        return _plugin

    def new_l1plugin(self):
        self.l1plugin = IxLoadNetworkL1Plugin(self.tcl)
        self.tcl("set {0} [${1} getL1Plugin]".format(self.l1plugin.name, self.name))
        self.l1plugin.init()
        return self.l1plugin


class IxLoadSETkNetTraffic(IxLoadGenericObjectMixin):

    # NAME = "NetworkTraffic"
    NAME = "Traffic_Network"
    PORTOPERMODE = {"ThroughputAcceleration": "kOperationModeThroughputAcceleration"}

    def __init__(self, tcl):
        super(IxLoadSETkNetTraffic, self).__init__(tcl)
        self.activities = {}
        self.activitydst = None

    def new_network(self):
        network = IxLoadNetTrafficNetwork(self.tcl)
        self.tcl("set {0} [${1} cget -network]".format(network.name, self.name))
        network.clear_plugins()
        return network

    def set_portopermode(self, mode):
        self.tcl("${0} setPortOperationModeAllowed $::ixPort(kOperationModeThroughputAcceleration) {1}".format(self.name, mode))

    def set_tcpaccel(self, mode):
        self.tcl("${0} setTcpAccelerationAllowed $::ixAgent(kTcpAcceleration) {1}".format(self.name, mode))

    def config_traffic(self):
        self.tcl("${0} traffic.config".format(self.name))

    def new_activity(self, activity):
        _activity = activityListItems[activity](self.tcl)
        self.tcl("set {0} [${1} activityList.appendItem -protocolAndType \"{2}\"]".
                 format(_activity.name, self.name, activity))
        _activity.init()
        if activity not in self.activities:
            self.activities[activity] = []
        # self.activities[activity][_activity.name] = _activity
        self.activities[activity].append(_activity)
        return _activity

    def get_activitydst(self, *args):
        self.activitydst = IxLoadDestinationForActivity(self.tcl)
        params = str(args)[1:-1].replace("'", '"').replace(",", "")
        self.tcl("set {0} [${1} getDestinationForActivity {2}]".format(self.activitydst.name, self.name, params))
        return self.activitydst

    def set_activityendpoint(self, iprange, activity, activity_type, enable):
        self.tcl("${0} setActivityEndPointAvailableForSmRange ${1} \"{2}\" \"{3}\" {4}".
                 format(self.name, iprange.name, activity.name, activity_type, enable))


class IxLoadSETkDutBasic(IxLoadGenericObjectMixin):

    NAME = "DUT"

    def __init__(self, tcl):
        super(IxLoadSETkDutBasic, self).__init__(tcl)
        self.cfg_packetswitch = None
        self.cfg_vip = None

    def new_cfg_packetswitch(self):
        self.cfg_packetswitch = IxLoadixDutConfigPacketSwitch(self.tcl)
        return self.cfg_packetswitch

    def new_cfg_vip(self):
        self.cfg_vip = IxLoadixDutConfigVip(self.tcl)
        return self.cfg_vip


class IxLoadixDutConfigPacketSwitch(IxLoadGenericObjectMixin):

    NAME = "ixDutConfigPacketSwitch"
    IXLOAD_CLASS = "ixDutConfigPacketSwitch"

    def __init__(self, tcl):
        super(IxLoadixDutConfigPacketSwitch, self).__init__(tcl)
        self.clear("originateProtocolPortRangeList")
        self.clear("terminateProtocolPortRangeList")
        self.clear("terminateNetworkRangeList")
        self.clear("originateNetworkRangeList")
        self.originatenetworkrangelist = []
        self.terminatenetworkrangelist = []

    def append_networkrangelist(self, dst, networkrange):
        self.tcl("${0} {1}NetworkRangeList.appendItem -object ${2}".format(self.name, dst, networkrange.name))
        getattr(self, "{0}networkrangelist".format(dst)).append(networkrange)

    def add_networkrange(self, dst, **kwargs):
        networkrange = IxLoadixDutNetworkRange(self.tcl)
        name = "DUT NetworkRange{0} {1}+{2}".format(len(getattr(self, "{0}networkrangelist".format(dst))),
                                                    kwargs['firstIp'], kwargs['ipCount'])
        networkrange.config(name=name, **kwargs)
        self.append_networkrangelist(dst, networkrange)


class IxLoadixDutNetworkRange(IxLoadGenericObjectMixin):

    NAME = "ixDutNetworkRange"
    IXLOAD_CLASS = "ixDutNetworkRange"


class IxLoadDestinationForActivity(IxLoadGenericObjectMixin):

    NAME = "DestinationForActivity"


class IxLoadixTestSessionSpecificData(IxLoadGenericObjectMixin):

    NAME = "SessionSpecificData"


class IxLoadixTestProfileDirectory(IxLoadGenericObjectMixin):

    NAME = "profileDirectory"


class IxLoadixDutConfigVip(IxLoadGenericObjectMixin):

    NAME = "ixDutConfigVip"
    IXLOAD_CLASS = "ixDutConfigVip"


class IxLoadstatCollectorUtils(IxLoadGenericObjectMixin):

    NAME = "NS"

    def __init__(self, tcl):
        super(IxLoadstatCollectorUtils, self).__init__(tcl)
        self.tcl("set {0} statCollectorUtils".format(self.name))
        self.status = False
        # self.tcl("proc ::my_stat_collector_command {args} { " +
        #          "puts \"=====================================\"; " +
        #          "puts \"INCOMING STAT RECORD >>> $args\"; " +
        #          "puts \"=====================================\";" +
        #          "}")

    def init_tsh(self, tsh):
        self.tcl("${%s}::Initialize -testServerHandle $%s;" % (self.name, tsh.name) +
                 "${%s}::ClearStats" % (self.name, ))

    def start(self):
        # self.tcl("${%s}::StartCollector -command ::my_stat_collector_command -interval 2" % (self.name, ))
        # self.tcl("${%s}::StartCollector -command collect_stats -interval 2" % (self.name, ))
        self.tcl("${%s}::StartCollector -command collect_stats -interval 4" % (self.name, ))
        self.status = True

    def stop(self):
        if self.status:
            self.tcl("${%s}::StopCollector" % (self.name, ))
            self.status = False

    def clear(self):
        self.tcl("${%s}::ClearStats" % (self.name, ))


class IxLoadTestServerHandle(IxLoadGenericObjectMixin):

    NAME = "TestServerHandle"
