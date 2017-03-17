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

"""``XML.py``

`XML and HTML report classes`

"""

import json
import os
import sys
import tempfile
import traceback
from xml.sax.saxutils import unescape as xml_unescape
import unicodedata as ud
import ast
import base64

from py.xml import Namespace  # pylint: disable=no-name-in-module
from py import std as py_std  # pylint: disable=no-name-in-module

from . import _reporter as reporter
from plugins.pytest_helpers import get_failure_reason, get_skipped_reason, get_html_xml_path
import loggers


def str2dict(dictstr):
    """Convert string to dictionary

    """
    _dict = ast.literal_eval(dictstr)
    if not isinstance(_dict, dict):
        _dict = ast.literal_eval(dictstr.replace('"', ''))
    if not isinstance(_dict, dict):
        _dict = ast.literal_eval(dictstr.replace("'", ""))
    if not isinstance(_dict, dict):
        raise Exception("Cannot convert given string (%s) to dictionary." % (dictstr, ))
    return _dict


def get_full_path(fname):
    """Return full file path by given relative.

    Args:
        fname(str):  File name

    Returns:
        str: Full path to file

    """
    fname = os.path.normpath(os.path.expanduser(os.path.expandvars(fname)))
    abs_path = os.path.normpath(os.path.join(os.path.realpath(os.curdir), fname))
    if os.path.isfile(abs_path):
        return abs_path
    else:
        return None


def get_uniq_filename(filename):
    """If file with given name exists return file with -N suffix.

    Args:
        filename(str):  File name

    Returns:
        str: File with modified name

    """
    _file = filename
    flag = False
    counter = 0
    while not flag:
        if os.path.isfile(_file):
            gen_file = list(os.path.splitext(filename))
            counter += 1
            gen_file.insert(-1, "-{0}".format(counter))
            _file = "".join(gen_file)
        else:
            flag = True
    return _file


# TODO: add processing of xfail TCs
class XML(object):
    """XML report specific functionality.

    """

    class_logger = loggers.ClassLogger()

    def __init__(self, connectors=None):
        """Initialize XML class

        """

        class Junit(Namespace):
            """Junit is a child of abstract Namespace class.

            """
            pass

        self.Junit = Junit

        # XML report attributes
        self.logfile = None
        self.dump_count = 0
        self.prefix = None

        self.total = self.passed = self.skipped = self.failed = self.errors = 0

        self.status_register = [None, None]
        self.setupfailed = 0

        # Fail traceback
        self.fail_traceback = None

        # Use connectors to Test Management System to obtain additional TC information.
        self._use_connector = False
        self.__connectors = connectors
        self._connector = None
        self.subtests = None
        self.infodict = None

        self.cfgfile = None

        # TC instances
        self.tests = []

        # Additional info to XML report

        self.update = None
        self.host = None
        self.project = None
        self.platform = None
        self.buildname = None
        self.test_plan_id = None
        self.test_plan_link = None
        self.current_client = None

        # XML styles
        self._css = None
        self._xsl = None

        # HTML report attributes
        self.htmlconf = None
        self.htmlfile = None
        # HTMLReport instance (assigned in __setattr__)
        self.__html_report = None

    def __setattr__(self, name, value):
        """Perform additional configuration procedures on setting some attributes.

        Args:
            name(str):  Attribute name
            value:  Attribute value

        """
        if name == "logfile" and value is not None:
            self.__dict__[name] = os.path.normpath(os.path.join(os.path.realpath(os.curdir),
                                                                os.path.expanduser(os.path.expandvars(value))))
            self.class_logger.info("Set XML logfile: {0}.".format(self.__dict__[name]))

        elif name == "cfgfile":
            if value is None:
                value = os.path.join(os.path.dirname(__file__), "xmlreport_cfg.json")
            self.__dict__[name] = value
            self.class_logger.info("Set config file: {0}.".format(value))
            self.__configinit(value)

        elif name == "info_dict" and isinstance(value, list):
            self.__dict__["infodict"][value[0]] = value[1]
            self.class_logger.info("Appending InfoDict: {0} - {1}.".format(value[0], value[1]))

        elif name == "htmlcfg":
            self.__dict__[name] = value
            if value is None:
                value = os.path.join(os.path.dirname(__file__), "htmlreport_cfg.json")
            self.class_logger.info("Set html config file: {0}.".format(value))
            self.__dict__['htmlconf'] = value
            self.__htmlconfig(value)

        else:
            self.class_logger.debug("Setting attr: {0} - {1}.".format(name, value))
            self.__dict__[name] = value

    def __htmlconfig(self, configfile):
        """Create HTMLReport instance.

        Args:
            configfile(str):  Path to HTML report configuration file.

        Returns:
            None

        """
        self.class_logger.debug("Creating HTMLReport instance.")
        self.__html_report = HTMLReport(configfile)

    def __configinit(self, cfgfile):
        """Read XML report configuration from file.

        Args:
            cfgfile(str):  Path to XML report config file.

        Returns:
            None

        """
        config_file = get_full_path(cfgfile)
        self.class_logger.info("Loading config from file {0}...".format(config_file))
        config = {}

        try:
            config = json.loads(open(config_file).read())
        except Exception as err:
            self.class_logger.error("cannot open configuration file: {0}.".format(err))

        if "css" in config:
            self._css = config['css']
        if "xsl" in config:
            self._xsl = config['xsl']
        if "info_dict" in config:
            info = config['info_dict']
            if self.infodict:
                info.update(self.infodict)
            self.infodict = info
        if "connectors" in config:
            for _c in config['connectors']:
                if _c.upper() in self.__connectors:
                    self._use_connector = True
                    self._connector = self.__connectors[_c.upper()]
                    break
#            self.class_logger.info("Use connector: {0}.".format(self._connector.name))

    def append_infodict(self, attr, value):
        """Append xml report infodict (it's shown in report header).

        Args:
            attr(str):  Attribute name
            value:  Attribute value

        """
        self.class_logger.info("Appending infodict: {0} = {1}".format(attr, value))
        self.infodict[attr] = value

    def info(self):
        """Return dict of report settings.

        Returns:
            dict: Report settings

        """
        return {'xml file': self.logfile,
                'html file': self.htmlfile,
                'tests count': len(self.tests),
                'dump count': self.dump_count}

    def process_cmd(self, cmd):
        """Get and process command from client.

        Args:
            cmd(dict):  Command

        """
        if (self.platform is None or self.platform == 'undetermined') and 'build_info' in list(cmd.keys()):
            self.platform = cmd['build_info']['platform']

        if self.buildname is None and 'build_info' in list(cmd.keys()):
            self.buildname = cmd['build_info']['build']

        if self.current_client is None and cmd['client'] is not None:
            self.current_client = cmd['client']

        if "close" not in cmd:
            self.opentc(cmd['suite'], cmd['tc'], cmd['status'], cmd['report'])
        else:
            self.dump_xmllog(cmd['duration'], cmd.get('detailed_duration'))

    def append_prev_reason(self, value):
        """Append failure reason.

        Args:
            value(str):  Failure reason

        """
        res = self.Junit.results(message="Failure Reason")  # pylint: disable=no-member
        res.append(value)
        self.append(res)

    def _get_failure_res(self, current_status, previous_freason, current_freason):
        """Get failure reason

        Args:
            current_status(str):  Current test case's status
            previous_freason(str):  Previous failure reason
            current_freason(str):  Current failure reason

        Returns:
            str: Failure reason

        """
        if current_status == 'Failed' and previous_freason == current_freason:
            return "Same Failure"
        elif current_status == 'Failed' and previous_freason != current_freason:
            return "Diff Failure"
        else:
            return "Failure"

    def opentc(self, classnames, tcname, status, report, prev_data=None):
        """Adding TC to xml report.

        Args:
            classnames(str):  py.test dot separated module/class names
            tcname(str):  test case name
            status(str):  TC run status
            report(dict):  TC status report. It's generated by py.test and depends on TC status

        Example::

            classnames = "functional_tests.feature.test_module.TestClass"
            tcname = "test_some_feature_behaviour"
            status = "Passed"
            report = {"duration": 123}
            xml_report.opentc(classnames, tcname, status, report)

        """
        if not isinstance(report, dict):
            # Exit method if report are not ready
            self.class_logger.info("Skip XML opentc step. Test case run isn't finished yet.")
            return

        self.class_logger.info("Processing {0}/{1} with status {2}.".format(classnames, tcname, status))
        if self.prefix:
            classnames.insert(0, self.prefix)
        attrs = {'classname': classnames, 'name': tcname}
        if "retval" in report:
            attrs['retval'] = report['retval']

        attrs['time'] = report['duration'] if "duration" in report else 0
        if report.get('detailed_duration'):
            attrs['setup_time'] = report['detailed_duration']['setup']
            attrs['longrepr_time'] = report['detailed_duration']['longrepr']

        attrs['connector'] = self._connector
        prev_status = None
        prev_reason = None
        _prev_bug_ids = None
        config = None
        if self.update is not None and self._connector is not None and self._connector.get_tracker():
            try:
                config = self._connector.get_config()
                current_tc = None
                previous_tc = None
                if self.subtests is None and self.current_client is not None and self.current_client in list(self._connector.subtests.keys()):
                    # store subtests from connector
                    self.subtests = self._connector.subtests[self.current_client]

                if self.subtests is not None and tcname in list(self.subtests.keys()) and self.current_client is not None:
                    current_tc = self._connector.get_tc_by_key(self.subtests[tcname]['stkey'])
                    if self.platform != 'undetermined':
                        previous_tc = self._connector.get_previous_subtask(tcname, self.subtests[tcname]['stkey'], self.platform)

                if previous_tc is not None:
                    attrs['build'] = self._connector.get_cf_value(previous_tc, 'Build number')
                    prev_status = self._connector.get_cf_value(previous_tc, 'Test Case State')
                    prev_reason = self._connector.get_cf_value(previous_tc, 'Failure Reason')
                    if prev_status == "Failed":
                        curr_reason = get_failure_reason(report['longrepr'])
                        attrs['failed_status'] = self._get_failure_res(status, prev_reason, curr_reason)
                    attrs['prev_status'] = prev_status
                if current_tc is not None:
                    if self.test_plan_id is None and self._connector.test_plan.get(self.current_client) \
                            and self._connector.test_plan[self.current_client].get('key'):
                        self.test_plan_id = self._connector.test_plan[self.current_client]['key']
                        self.test_plan_link = self._connector.get_issue_link(self.test_plan_id)
                        attrs['testplan_id'] = self.test_plan_id
                        attrs['test_plan_link'] = self._connector.get_issue_link(self.test_plan_id)
                    current_key = self._connector.get_issue_key(current_tc)
                    if current_key is not None:
                        attrs['testid'] = self._connector.get_issue_key(current_tc)
                    attrs['test_case_link'] = self._connector.get_issue_link(self.subtests[tcname]['stkey'])
                    _prev_bug_ids = self._connector.get_defects_list(self.subtests[tcname]['stkey'])
            except Exception:
                self.class_logger.error("Unknown error of connector")

        if self._use_connector:
            _tc_id = self._connector_cmd("get_tcid", [tcname, ])
            if _tc_id is not None:
                attrs['testid'] = _tc_id
                self.class_logger.info("TestMgmtSystem TC Id of {0} = {1}".format(tcname, _tc_id))
                _prev_bug_ids = self._connector_cmd("get_defectids", [tcname, ])
            if self.host is None and config:
                self.host = config[0]
            if self.project is None and config:
                self.project = config[1]
            _platform = self.platform
            attrs['history_link'] = "%s/issues/?jql=issuetype='SubTest' AND project='%s' AND Platform='%s' AND 'Automated TC Name'~'%s' ORDER BY updated DESC" % \
                                    (self.host, self.project, _platform, tcname)
        # Creating TC xml element
        if 'when' in list(report.keys()) and not report['when'] == "teardown":
            self.tests.append(self.Junit.testcase(**attrs))  # pylint: disable=no-member
            self.total += 1
            self.fail_traceback = None
        if status == "Passed":
            self.append_pass(report)
            # Save case result (case not failed)
            self.status_register = [tcname, "Passed"]
        elif status == "Failed":
            if report['when'] in ["setup", "teardown"]:
                self.append_error(report, report['when'])
            else:
                self.append_failure(report)

            # If case passed, but failed on teardown, we increase fail rate.
            if self.status_register == [tcname, "Passed"]:
                self.setupfailed += 1
            if prev_reason is not None:
                self.append_prev_reason(prev_reason)
            self.status_register = [tcname, "Failed"]
        elif status == "Skipped":
            self.append_skipped(report)
            if self.status_register == [tcname, "Skipped"]:
                self.skipped -= 1
            self.status_register = [tcname, "Skipped"]
        elif status == "Monitor":
            self.append_monitor(report['monitor'])
        else:
            self.class_logger.error("Unknown status of TC: {0} - {1}. TC will be marked as \"Blocked\"".format(tcname, status))
            if self.status_register == [tcname, "Passed"]:
                # self.failed += 1
                self.passed -= 1
            if self.status_register == [tcname, "Failed"]:
                self.failed -= 1
            if self.status_register == [tcname, "Skipped"]:
                self.skipped -= 1
            if self.status_register == [tcname, "Error"]:
                self.failed -= 1
                self.errors -= 1
            self.append_error(report, report['when'])
            self.status_register = [tcname, "Error"]
            if report.get('monitor', None):
                self.append_monitor(report['monitor'])
        # Adding bug ids to report
        if _prev_bug_ids is not None and len(_prev_bug_ids) > 0:
            self.append_defectids(_prev_bug_ids, config)

    def append(self, obj):
        """General method for appending xml object. It's used in append_<status> methods().

        Args:
            obj(Junit):  Junit object to be appended

        """
        self.tests[-1].append(obj)

    def append_monitor(self, images):
        self.class_logger.info("Appending XML report with Collectd info.")
        file_nodes = []
        for file_name in images:
            with open(file_name, 'rb') as f:
                image_src = base64.b64encode(f.read()).decode('utf-8')
                file_nodes.append(
                    self.Junit.file(src="data:image/png;base64,{}".format(image_src)),  # pylint: disable=no-member
                )
        monitor = self.Junit.monitor(file_nodes)  # pylint: disable=no-member
        self.append(monitor)

    def append_error(self, report, when=""):
        """Append xml report with error (in case TC failed on setup or teardown).

        Args:
            report(dict):  Error report
            when(str):  Error occurance stage (setup|call|teardown)

        """
        self.class_logger.info("Appending XML report with error.")
        if 'longrepr' in list(report.keys()):
            longrepr = xml_unescape(report['longrepr'])
            if self.fail_traceback is not None:
                failure_reason = None
                if len(self.tests[-1]) > 0:
                    failure_reason = self.tests[-1].pop()
                if self.update is not None and len(self.tests[-1]) > 0:
                    self.tests[-1].pop()
                    try:
                        self.tests[-1].pop()
                    except IndexError:
                        pass
                self.append(
                    self.Junit.error(longrepr,  # pylint: disable=no-member
                                     message="Test error on %s and Test failure" % (when, )))
                if hasattr(failure_reason.attr, "message") and failure_reason.attr.message == "Failure Reason":
                    self.tests[-1].append(failure_reason)
                self.tests[-1][0].extend("\n" + "-" * 80 + "\nTest Case Failure\n" + "-" * 80 + "\n")
                self.tests[-1][0].extend(self.fail_traceback)
            else:
                self.append(
                    self.Junit.error(longrepr,  # pylint: disable=no-member
                                     message="Test error on %s" % (when, )))
        self.errors += 1
        self.failed += 1

    def append_xfail(self, report):
        """Append xml report with xfailed TC.

        Args:
            report(dict):  XFail report

        """
        self.class_logger.info("Appending XML report with xfail.")
        self.append(
            self.Junit.skipped(str(xml_unescape(report['keywords']['xfail'])),  # pylint: disable=no-member
                               message="expected test failure"))

    def append_skipped(self, report):
        """Append xml reports with skipped TC.

        Args:
            report(dict):  Skipped report

        """
        self.class_logger.info("Appending XML report with skip.")
        # filename, lineno, skipreason = report['longrepr']
        # self.class_logger.debug("Received longrepr: {0}".format(xml_unescape(report['longrepr'])))
        longrepr = xml_unescape(report['longrepr'])
        # TODO: fixed bug with longrepr crashing
        skipreason = get_skipped_reason(report['longrepr'])
        self.append(self.Junit.skipped("%s" % longrepr,  # pylint: disable=no-member
                                       type="pytest.skip", message=skipreason))
#        self.append(self.Junit.skipped("%s:%s: %s" % longrepr, type="pytest.skip", message=skipreason))
        self.skipped += 1

    def append_pass(self, report):
        """Append xml report with passed TC.

        Args:
            report(dict):  Passed report

        """
        self.class_logger.info("Appending XML report with pass.")
        self.append(self.Junit.passed(message="Test passed"))  # pylint: disable=no-member
        self.passed += 1

    def append_failure(self, report):
        """Append xml report with failed TC.

        Args:
            report(dict):  Failure report

        """
        self.class_logger.info("Appending XML report with fail.")
        for i in range(len(report['sections'])):
            report['sections'][i] = xml_unescape(report['sections'][i])  # pylint: disable=no-member
        sec = dict(report['sections'])
        self.fail_traceback = self.Junit.failure(message="Test failure")  # pylint: disable=no-member
        # Removing BASH escape symbols (decolorizing)
        # longrepr = xml_unescape(re_sub(r"\x1b.*?m", "", report['longrepr']))
        longrepr = xml_unescape(report['longrepr'])
        # TODO: Change str to encode for unicode text

        try:
            self.fail_traceback.append(str(longrepr))
        except UnicodeEncodeError as err:
            self.fail_traceback.append(ud.normalize('NFKD', longrepr))
            self.class_logger.warning("Unicode data in traceback: %s" % (err, ))

        self.append(self.fail_traceback)

        for name in ("out", "err"):
            content = sec.get("Captured std{0}".format(name))
            if content:
                tag = getattr(self.Junit, "system-{0}".format(name))
                self.append(tag(content))
        self.failed += 1

    def append_defectids(self, defect_ids, config=None):
        """Add defect ids to report.

        Args:
            defect_ids(list):  Defect IDs
            config(dict):  Connectors configuration

        """
        self.class_logger.info("Appending TC with related defects IDs {0}".format(defect_ids))
        _host = None

        if config is not None:
            _host = config[0]

        for defect_id in defect_ids:
            self.append(self.Junit.defect(d_id=defect_id, d_host=_host))  # pylint: disable=no-member

    def dump_xmllog(self, totaltime=None, detailed_duration=None):
        """Generating xml file.

        Args:
            totaltime(int):  Total execution time of TCs in report. (It should be returned by py.test.)
            detailed_duration(dict):  Detailed execution time of TCs in report.

        """
        self.logfile = get_html_xml_path(self.logfile, self.buildname)
        self.htmlfile = get_html_xml_path(self.htmlfile, self.buildname)

        self.class_logger.info("Dumping XML Log to {0}.".format(self.logfile))
        # Define xml logfile name.
        dump_logfile = get_uniq_filename(self.logfile)
        if dump_logfile != self.logfile:
            self.class_logger.info("Dumping XML Log path changed to {0}.".format(dump_logfile))

        _path_arr = dump_logfile.split("/")
        if _path_arr and not os.path.exists(dump_logfile[:-len(_path_arr[-1])]):
            os.makedirs(dump_logfile[:-len(_path_arr[-1])])

        if py_std.sys.version_info[0] < 3:
            logfile = py_std.codecs.open(dump_logfile, "w", encoding="utf-8")
        else:
            logfile = open(dump_logfile, "w", encoding="utf-8")

        logfile.write("<?xml version=\"1.0\" encoding=\"utf-8\"?>")
        if self._css:
            logfile.write("<?xml-stylesheet type=\"text/css\" href=\"%s\"?>" % (self._css, ))
        if self._xsl:
            logfile.write("<?xml-stylesheet type=\"text/xsl\" href=\"%s\"?>" % (self._xsl, ))
        if self.infodict:
            info_nodes = []
            for info_node in list(self.infodict.keys()):
                info_nodes.append(
                    self.Junit.info_node(self.infodict[info_node],  # pylint: disable=no-member
                                         name=info_node))
            self.tests.append(self.Junit.header(info_nodes))  # pylint: disable=no-member
        try:
            logfile.write(self.Junit.testsuite(self.tests,  # pylint: disable=no-member
                                               name="",
                                               errors=self.errors,
                                               failures=self.failed,
                                               setupfailures=self.setupfailed,
                                               skips=self.skipped,
                                               test_plan_id=self.test_plan_id,
                                               test_plan_link=self.test_plan_link,
                                               tests=self.total,
                                               time="%.3f" % totaltime,
                                               connector=self._connector,
                                               ).unicode(indent=0))
        except Exception as err:
            self.class_logger.error("Cannot dump XML report to file {0}. ERRTYPE: {1}, ERR: {2}".format(dump_logfile, type(err), err))
            logfile.close()
        else:
            self.class_logger.info("XML report is successfully dumped to file {0}.".format(dump_logfile))
            self.tests = []
            self.dump_count += 1

            logfile.close()

            # Creating HTML report
            if self.htmlfile is not None and self.__html_report is not None:
                self.class_logger.info("Dumping HTML report to {0}...".format(self.htmlfile))
                self.__html_report.dump_html(dump_logfile, self.htmlfile)

    def _connector_cmd(self, cmd, args):
        """Call connector method.

        Args:
            cmd(str):  connector method name
            args(list):  connector method arguments

        Returns:
            Connector method return code or None in case exception.

        """
        try:
            ret = getattr(self._connector, cmd)(*args)
            return ret
        except Exception:
            # self.class_logger.error("Cannot execute Connector({0}) command {1}({2}). ERR_TYPE: {3}. ERR: {4}".
            # format(self._connector.name, cmd, args, type(err), err))
            return None


class HTMLReport(object):
    """Class for generating HTML reports from xml files.

    """

    class_logger = loggers.ClassLogger()

    def __init__(self, config_file):
        """Initialize HTMLReport class.

        """
        self.xslt_style = None
        self.xslt_concat = None
        self.html_resources = None

        self.class_logger.info("CurDir {0}.".format(os.path.abspath(os.curdir)))
        # Define config file location if one
        self.__config_file = config_file
        if not os.path.isfile(self.__config_file):
            self.class_logger.warning("Config file ({0}) for HTML report not found.".format(self.__config_file))
            self.__config_file = None

        # Read attributes from config if one
        if self.__config_file is not None:
            config = json.loads(open(self.__config_file).read(), encoding="latin-1")
            for key in config:
                setattr(self, key, os.path.join(os.path.dirname(__file__), config[key]))
        self.class_logger.info("Resources: xslt - {0}, {1}; html - {2}".
                               format(self.xslt_style, self.xslt_concat,
                                      self.html_resources))

    def dump_html(self, xmlpath, htmlpath):
        """Create the HTML report from an XML.

        Args:
            xmlpath(str):  Path to input xml report
            htmlpath(str):  Path to output html report

        Returns:
            None

        """
        temp_file = None
        try:
            temp_file = tempfile.mkstemp(prefix='html_report.', suffix='.tmp', dir=os.curdir)
            self.class_logger.info("Creating pure html report: {0} ...".format(temp_file))

            reporter.create_pure_html(temp_file[1], xmlpath, None, self.xslt_style, self.xslt_concat)

            _path_arr = htmlpath.split("/")
            if _path_arr and len(_path_arr) > 1 and not os.path.exists(htmlpath[:-len(_path_arr[-1])]):
                os.makedirs(htmlpath[:-len(_path_arr[-1])])

            htmlpath = get_uniq_filename(os.path.normpath(os.path.join(os.path.realpath(os.curdir),
                                                                       os.path.expanduser(os.path.expandvars(htmlpath)))))
            self.class_logger.info("Creating single html report: {0} ...".format(htmlpath))
            reporter.create_single_html(htmlpath, temp_file[1], self.html_resources)
        except Exception as err:
            self.class_logger.info("Creating HTML report failed. ERROR: {0}".format(err))
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback_message = traceback.format_exception(exc_type, exc_value,
                                                           exc_traceback)
            self.class_logger.error("Traceback:\n{0}".format("".join(traceback_message)))
        finally:
            if temp_file is not None:
                os.remove(temp_file[1])
