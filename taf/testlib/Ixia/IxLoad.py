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

"""``IxLoad.py``

`IxLoad specific functionality`

"""

import os
import time

# from ..custom_exceptions import IxiaException
from . import ixia_helpers


class IxLoad(object):
    """IXIA interaction base class.

    """

    class_logger = None

    def __init__(self, config, opts):
        """Initializes connection to IxLoad.

        Args:
            config(dict):  IxLoad related part of environment configuration
            opts(OptionParser):  py.test config.option object which contains all py.test cli options

        """
        self.__opts = opts
        self.__config = config

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

        self.id = config['id']
        self.type = config['instance_type']

        self.ixload_ip = config['ixload_ip']
        self.ixload_user = config['ixload_user']
        self.ports = config['ports']

        self.ixload_tmppath = "C:\\Users\\{0}\\AppData\\Local\\Temp\\".format(self.ixload_user)
        self.ixload_respath = "C:\\IxLoadWD\\"
        self.__log_name = "TAF-{0}-{1}-{2}".format(os.uname()[1], os.getuid(), int(time.time()))

        ixia_helpers.ixtclhal_import(self.tcl_interpret)
        ixia_helpers.ixload_import(self.tcl_interpret)

        self.qt = None
        self.tst = None
        self.repo_file = None

    def tcl(self, cmd):
        """Log end execute tcl code.

        Args:
            cmd(str):  Tcl script

        Returns:
            str:  Result of execution

        """
        self.class_logger.debug("Run tcl command: %s", cmd)
        return self.tcl_interpret.eval(cmd)

    def connect(self):
        """Logs in to IXIA and takes ports ownership.

        Returns:
            None

        """
        # Set simple config
        self.tcl("namespace eval ::IxLoadPrivate {};" +
                 "namespace eval ::IxLoadPrivate::SimpleSettings {};" +
                 "variable ::IxLoadPrivate::SimpleSettings::remoteServer {0};".format(self.ixload_ip) +
                 "::IxLoad connect $::IxLoadPrivate::SimpleSettings::remoteServer")
        # Set up logger
        self.logger_setup()
        # Define test controller.
        self.tcl("set testController [::IxLoad new ixTestController -outputDir 1];")

        self.class_logger.info("IxLoad startup complete.")

    def disconnect(self):
        """Logs out from IXIA and clears ports ownership.

        Returns:
            None

        """
        self.tcl("::IxLoad disconnect")

    def check(self):
        """Check if TG object is alive and ready for processing

        Returns:
            None or raise and exception.

        """
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
        """Perform all necessary procedures to initialize TG device and prepare it for interaction.

        Returns:
            None or raise and exception.

        Notes:
            Method has to check --get_only option.
            Set of steps to configure TG device is related to particular TG type.

        """
        return self.connect()

    def destroy(self):
        """Perform all necessary procedures to uninitialize TG device.

        Returns:
            None or raise and exception.

        Note:
            Method has to check --get_only and --leave_on options.
            Set of steps to unconfigure TG device is related to particular TG type.
            Method has to clear all connections and stop all captures and data streams.

        """
        self.cleanup(mode="fast")
        self.disconnect()

    def cleanup(self, mode="complete"):
        """This method should do IxLoad config cleanup.

        Args:
            mode(str):  "fast" or "complete". Not implemented

        Returns:
            None

        """
        # TODO: Implement proper config cleanup method.
        self.tcl("$testController releaseConfigWaitFinish;" +
                 "::IxLoad delete $testController;" +
                 "::IxLoad delete $logger;" +
                 "::IxLoad delete $logEngine")
        # ::IxLoad delete $qtConfig
        # ::IxLoad delete $repository

    def sanitize(self):
        """This method has to clear all stuff which can cause device inconsistent state after exit or unexpected exception.

        Note:
            E.g. clear connections, stop threads. This method is called from pytest.softexit

        """
        self.disconnect()

    def logger_setup(self):
        """Enable IxLoad logger.

        Returns:
            None

        """
        self.class_logger.info("Setting up IxLoad logger...")
        self.tcl("set logtag \"IxLoad-api\";" +
                 "set logName \"{0}\";".format(self.__log_name) +
                 "set logger [::IxLoad new ixLogger $logtag 1];" +
                 "set logEngine [$logger getEngine];" +
                 "$logEngine setLevels $::ixLogger(kLevelDebug) $::ixLogger(kLevelInfo);" +
                 "$logEngine setFile $logName 2 256 1")

    def load_repo(self, repo=None):
        """Loading rxf repo file or create new one.

        Args:
            repo(str):  Repository name

        Returns:
            None

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
        self.tst = IxLoadTests(self.tcl, "{0}{1}".format(self.ixload_respath, self.__log_name))
        self.class_logger.debug("Discovered tests list: {0}".format(self.tst.tc_list))

    def copy_local_file(self, local_path, remote_path):
        """Copy local file to IxLoad host.

        Args:
            local_path(str):  Local path to file
            remote_path(str):  Remote path to file

        Returns:
            None

        """
        self.tcl("::IxLoad sendFileCopy \"{0}\" \"{1}\"".format(local_path, remote_path).replace("\\", "\\\\"))


class IxLoadTests(object):
    """Class for managing IxLoad Tests.

    """

    def __init__(self, tcl, res_path=""):
        self.tcl = tcl
        self.tc_list = []
        self.load_tclist()
        self.res_path = res_path

    def load_tclist(self):
        """Loading list of IxLoad Tests.

        Returns:
            None

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

        Args:
            t_name(str):  test case name

        Returns:
            None

        """
        self.tcl("puts {0}".format(t_name))

    def run(self, t_name, res_path=None):
        """Run ixLoad test until completion.

        Args:
            t_name(str):  test case name
            res_path(str):  Path to result

        Returns:
            str:Path to report

        """
        # Set result dir.
        res_path = res_path if res_path is not None else self.res_path
        res_path = "{0}\\{1}".format(res_path, t_name)
        self.tcl("$testController setResultDir \"{0}\"".format(res_path).replace("\\", "\\\\"))
        # Execute the test.
        self.tcl("set test [$repository testList.getItem {}];".format(t_name) +
                 "$testController run $test")
        self.tcl("vwait ::ixTestControllerMonitor; puts $::ixTestControllerMonitor")
        return res_path

    def cleanup(self):
        """Cleanup list of IxLoad Tests.

        Returns:
            None

        """
        self.tcl("$testController releaseConfigWaitFinish;" +
                 "if {[lsearch [info vars] test] >= 0} {$test clearDUTList; ::IxLoad delete $test}",
                 )

    def report(self, pdf=False):
        """Enable/Disable report options.

        Args:
            pdf(bool):  Enable/Disable PDF report

        Returns:
            None

        """
        self.tcl("ixNet setAttribute [ixNet getRoot]/testConfiguration -enableGenerateReportAfterRun {0}".format(pdf))


class QuickTests(object):
    """Class for managing QuickTests.

    """

    def __init__(self, tcl):
        """Initialize QuickTests class.

        Args:
            tcl(Tkinter.Tcl):  Tcl interpreter

        """
        self.tcl = tcl
        self.tc_list = []
        self.load_tclist()

    def load_tclist(self):
        """Loading list of QuickTests.

        Returns:
            None

        """

        def store_tc(qt):
            """Store quick test in tc_list.

            """
            qt_name, qt_id = qt.split(":")
            self.tc_list.append((qt_name, qt_id))

        # TODO: Do some staff to get QT list.
        _qtlist = []

        # QT list is read. Cleanup previous one and store new list.
        self.tc_list = []
        if _qtlist:
            list(map(store_tc, _qtlist))

    def start(self, qt_name, qt_id):
        """Start QuickTest without waiting for result.

        Args:
            qt_name(str):  QuickTest name
            qt_id(int):  QuickTest id

        Returns:
            str: Result of execution

        """
        self.tcl("ixNet exec start [ixNet getRoot]/quickTest/{0}:{1}".format(qt_name, qt_id))

    def run(self, qt_name, qt_id):
        """Run QuickTest until completion.

        Args:
            qt_name(str):  QuickTest name
            qt_id(int):  QuickTest id

        Returns:
            str:  Result of execution

        """
        rc = self.tcl("ixNet exec run [ixNet getRoot]/quickTest/{0}:{1}".format(qt_name, qt_id))
        return rc

    def report(self, pdf=False):
        """Enable/Disable report options.

        Args:
            pdf(bool):  Enable/Disable PDF report

        Returns:
            None

        """
        self.tcl("ixNet setAttribute [ixNet getRoot]/testConfiguration -enableGenerateReportAfterRun {0}".format(pdf))
