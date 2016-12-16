#! /usr/bin/env python
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

@file  IxLoad.py

@summary  IxLoad specific functionality.
"""

import os
import time

# from ..custom_exceptions import IxiaException
from . import ixia_helpers


class IxLoad(object):
    """
    @description  IXIA interaction base class.
    """

    class_logger = None

    def __init__(self, config, opts):
        """
        @brief  Initializes connection to IxLoad
        @param config:  IxLoad related part of environment configuration
        @type  config:  dict
        @param opts:  py.test config.option object which contains all py.test cli options
        @type  opts:  OptionParser
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
        """
        @brief  Log end execute tcl code
        @param cmd:  Tcl script
        @type  cmd:  str
        @rtype:  str
        @return:  Result of execution
        """
        self.class_logger.debug("Run tcl command: %s", cmd)
        return self.tcl_interpret.eval(cmd)

    def connect(self):
        """
        @brief  Logs in to IXIA and takes ports ownership.
        @return:  None
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
        """
        @brief  Logs out from IXIA and clears ports ownership.
        @return:  None
        """
        self.tcl("::IxLoad disconnect")

    def check(self):
        """
        @copydoc testlib::tg_template::GenericTG::check()
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
        """
        @copydoc testlib::tg_template::GenericTG::create()
        """
        return self.connect()

    def destroy(self):
        """
        @copydoc testlib::tg_template::GenericTG::destroy()
        """
        self.cleanup(mode="fast")
        self.disconnect()

    def cleanup(self, mode="complete"):
        """
        @brief  This method should do IxLoad config cleanup
        @param mode:  "fast" or "complete". Not implemented
        @type  mode:  str
        @return:  None
        """
        # TODO: Implement proper config cleanup method.
        self.tcl("$testController releaseConfigWaitFinish;" +
                 "::IxLoad delete $testController;" +
                 "::IxLoad delete $logger;" +
                 "::IxLoad delete $logEngine")
        # ::IxLoad delete $qtConfig
        # ::IxLoad delete $repository

    def sanitize(self):
        """
        @copydoc testlib::tg_template::GenericTG::sanitize()
        """
        self.disconnect()

    def logger_setup(self):
        """
        @brief  Enable IxLoad logger
        @return:  None
        """
        self.class_logger.info("Setting up IxLoad logger...")
        self.tcl("set logtag \"IxLoad-api\";" +
                 "set logName \"{0}\";".format(self.__log_name) +
                 "set logger [::IxLoad new ixLogger $logtag 1];" +
                 "set logEngine [$logger getEngine];" +
                 "$logEngine setLevels $::ixLogger(kLevelDebug) $::ixLogger(kLevelInfo);" +
                 "$logEngine setFile $logName 2 256 1")

    def load_repo(self, repo=None):
        """
        @brief  Loading rxf repo file or create new one
        @param repo:  Repository name
        @type  repo:  str
        @return:  None
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
        """
        @brief  Copy local file to IxLoad host
        @param local_path:  Local path to file
        @type  local_path:  str
        @param remote_path:  Remote path to file
        @type  remote_path:  str
        @return:  None
        """
        self.tcl("::IxLoad sendFileCopy \"{0}\" \"{1}\"".format(local_path, remote_path).replace("\\", "\\\\"))


class IxLoadTests(object):
    """
    @description  Class for managing IxLoad Tests
    """

    def __init__(self, tcl, res_path=""):
        self.tcl = tcl
        self.tc_list = []
        self.load_tclist()
        self.res_path = res_path

    def load_tclist(self):
        """
        @brief  Loading list of IxLoad Tests
        @return:  None
        """
        _tlist = []
        num_tests = self.tcl("$repository testList.indexCount")
        for _i in range(int(num_tests)):
            tc_name = self.tcl("$repository testList({0}).cget -name".format(_i))
            _tlist.append(tc_name)

        # Test list is read. Cleanup previous one and store new list.
        self.tc_list = _tlist

    def start(self, t_name):
        """
        @brief  Start ixLoad test without waiting for result
        @param t_name:  test case name
        @type  t_name:  str
        @return:  None
        """
        self.tcl("puts {0}".format(t_name))

    def run(self, t_name, res_path=None):
        """
        @brief  Run ixLoad test until completion
        @param t_name:  test case name
        @type  t_name:  str
        @param res_path:  Path to result
        @type  res_path:  str
        @return:  Path to report
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
        """
        @brief  Cleanup list of IxLoad Tests
        @return:  None
        """
        self.tcl("$testController releaseConfigWaitFinish;" +
                 "if {[lsearch [info vars] test] >= 0} {$test clearDUTList; ::IxLoad delete $test}"
                 )

    def report(self, pdf=False):
        """
        @brief  Enable/Disable report options
        @param pdf:  Enable/Disable PDF report
        @type  pdf:  bool
        @return:  None
        """
        self.tcl("ixNet setAttribute [ixNet getRoot]/testConfiguration -enableGenerateReportAfterRun {0}".format(pdf))


class QuickTests(object):
    """
    @description  Class for managing QuickTests.
    """

    def __init__(self, tcl):
        """
        @brief  Initialize QuickTests class
        @param tcl:  Tcl interpreter
        @type  tcl:  Tkinter.Tcl
        """
        self.tcl = tcl
        self.tc_list = []
        self.load_tclist()

    def load_tclist(self):
        """
        @brief  Loading list of QuickTests
        @return:  None
        """

        def store_tc(qt):
            """
            @brief  Store quick test in tc_list
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
        """
        @brief  Start QuickTest without waiting for result
        @param qt_name:  QuickTest name
        @type  qt_name:  str
        @param qt_id:  QuickTest id
        @type  qt_id:  int
        @rtype:  str
        @return:  Result of execution
        """
        self.tcl("ixNet exec start [ixNet getRoot]/quickTest/{0}:{1}".format(qt_name, qt_id))

    def run(self, qt_name, qt_id):
        """
        @brief  Run QuickTest until completion
        @param qt_name:  QuickTest name
        @type  qt_name:  str
        @param qt_id:  QuickTest id
        @type  qt_id:  int
        @rtype:  str
        @return:  Result of execution
        """
        rc = self.tcl("ixNet exec run [ixNet getRoot]/quickTest/{0}:{1}".format(qt_name, qt_id))
        return rc

    def report(self, pdf=False):
        """
        @brief  Enable/Disable report options
        @param  pdf:  Enable/Disable PDF report
        @type  pdf:  bool
        @return:  None
        """
        self.tcl("ixNet setAttribute [ixNet getRoot]/testConfiguration -enableGenerateReportAfterRun {0}".format(pdf))
