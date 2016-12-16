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

@file  _reporter.py

@summary py.test log parser and gmail mail sender.
"""
# TODO: Replace prints with logger

import os
import re
import sys
import time
import tempfile
import html.parser
import configparser
import argparse
import unicodedata


class LogParser(object):
    """
    @description  Class for parsing py.test logs
    """

    def __init__(self, logfile=None, logdir=None):
        """
        @brief  Initialize instance of LogParser class
        @param  logfile:  Path to logfile
        @type  logfile:  str
        @param  logdir:  Path to logdir
        @type  logdir:  str
        @raise  Exception:  logfile or logdir option must be specified
        """
        if logfile and logdir:
            raise Exception("Only single option file or dir must be specified.")
        elif not logfile and not logdir:
            raise Exception("Any option file or dir was specified.")
        self.file = logfile
        self.dir = logdir
        self.pytestlog_dir = None
        self.customlog_dir = None
        if self.dir:
            self.pytestlog_dir = self.dir + '/pytest'
            self.customlog_dir = self.dir + '/custom'
        self.error_key = 'E'
        self.pytest_error_key = '!'
        self.statuses = {'.': 'passed', 'F': 'failed', 'f': 'failed', 's': 'skipped', self.error_key: 'error',
                         'x': 'xfailed', self.pytest_error_key: 'pytest collection failures'}

    def _read_file(self, logfile=None):
        """
        @brief  Read logfile
        @param  logfile:  Path to logfile
        @type  logfile:  str
        @raise  Exception:  error while open file
        @rtype:  list[str]
        @return:  Lines from logfile
        """
        try:
            logs = open(logfile, "rb").readlines()
        except Exception as err:
            print("Cannot open log file.")
            raise err
        else:
            return logs

    def get_full_logs(self, logfile=None, logdir=None):
        """
        @brief  Return full log (list of string with \\n at the end)
        @param  logfile:  Path to logfile
        @type  logfile:  str
        @param  logdir:  Path to logdir
        @type  logdir:  str
        @rtype:  list[str]
        @return:  Lines from logfile and files in logdir
        """
        logs = []
        if logfile:
            logs = self._read_file(logfile)
        if logdir:
            logkey = ".log$"
            for filename in os.listdir(logdir):
                path = os.path.join(logdir, filename)
                if not os.path.isfile(path):
                    continue
                elif not re.search(logkey, filename):
                    continue
                logs = logs + self._read_file(path)
        return logs

    def get_pytest_short(self):
        """
        @brief  Return only lines with result of running test cases(list of string)
        @rtype:  list[str]
        @return:  Lines with test case results
        """
        logs = self.get_full_logs(logdir=self.pytestlog_dir)
        lines = []
        for line in logs:
            if not re.match('^ .*', line) and not re.match('^$', line):
                lines.append(line.strip())
        return lines

    def get_pytest_stats(self):
        """
        @brief  Return number of passed/failed/skipped tests
        @rtype:  dict
        @return:  Number of passed/failed/skipped tests
        """
        summary = {}
        for stat in self.get_pytest_short():
            if not stat[0] in list(summary.keys()):
                summary[stat[0]] = 1
            else:
                summary[stat[0]] += 1
        return summary

    def get_pytest_stats_hr(self, items=None, header=None):
        """
        @brief  Return human readable short report - number passed/failed/skipped tests
        @param  items:  Passed/failed/skipped items statistics
        @type  items:  dict
        @param  header:  Report header
        @type  header:  str
        @rtype:  str
        @return:  Number of passed/failed/skipped tests in human readable short report
        """
        if header:
            status = "{0} (".format(header)
        else:
            status = "("
        total = 0
        errors = ""
        items_keys = list(items.keys())
        items_keys.sort()
        for key in items_keys:
            if key != self.error_key and key != self.pytest_error_key:
                status += "%(status)s %(number)d, " % {"number": items[key], "status": self.statuses[key]}
                total += items[key]
            elif key == self.error_key or key == self.pytest_error_key:
                errors = "%(status)s %(number)d" % {"number": items[key], "status": self.statuses[key]}
        status += "total: %d" % (total, )
        if errors:
            status += ", %s)" % (errors, )
        else:
            status += ")"
        return status

    def get_pytest_cases(self):
        """
        @brief  Return pytest cases
        @rtype:  dict
        @return:  Dictionary of test cases
        """
        cases = {}
        for item in self.get_pytest_short():
            item = item[0:item.find(".py::")]
            if not item[2:] in cases:
                cases[item[2:]] = {}
                cases[item[2:]][item[0]] = 1
            else:
                if not item[0] in cases[item[2:]]:
                    cases[item[2:]][item[0]] = 1
                else:
                    cases[item[2:]][item[0]] += 1
        return cases

    def get_pytest_stats_full(self):
        """
        @brief  Return full automated test cases execution results.
        @rtype:  str
        @return:  Automated test cases execution results
        """
        report = "Environment:\n"
        report += "Switchpp: {0}\n".format(self.get_spp_full_info())
        vlab_info = self.get_vlab_full_info()
        if vlab_info:
            report += "VLAB: {0}\n\n".format(vlab_info)
        report += self.get_pytest_stats_hr(items=self.get_pytest_stats(), header="Total summary.")
        report += "\n\n"
        tc_list = self.get_pytest_cases()
        for case in tc_list:
            report += self.get_pytest_stats_hr(items=tc_list[case], header=case)
            report += "\n"
        return report

    def get_spp_version(self):
        """
        @brief  Get a switchpp version from a custom log file.
        @rtype:  str
        @return:  switchppVersion value (build number)
        """
        version = ""
        logs = self.get_full_logs(logdir=self.customlog_dir)
        regx = re.compile(r'.*switchppVersion: ([a-zA-Z0-9-\._]*).*')
        for line in logs:
            if regx.match(line):
                version = regx.match(line).group(1)
        return version

    def get_spp_cpu_arch(self):
        """
        @brief  Get a switchpp cpu architecture from a custom log file.
        @rtype:  str
        @return:  cpuArchitecture value
        """
        arch = ""
        logs = self.get_full_logs(logdir=self.customlog_dir)
        regx = re.compile(r'.*cpuArchitecture: ([a-zA-Z0-9-\._]*).*')
        for line in logs:
            if regx.match(line):
                arch = regx.match(line).group(1)
        return arch

    def get_spp_chip_name(self):
        """
        @brief  Get a switchpp chipName from a custom log file.
        @rtype:  str
        @return:  chipName value
        """
        chip = ""
        logs = self.get_full_logs(logdir=self.customlog_dir)
        regx = re.compile(r'.*chipName: ([a-zA-Z0-9-\._]*).*')
        for line in logs:
            if regx.match(line):
                chip = regx.match(line).group(1)
        return chip

    def get_spp_full_info(self):
        """
        @brief  Get a switchpp chipSubType from a custom log file.
        @rtype:  str
        @return:  chipSubType value
        """
        info = ""
        logs = self.get_full_logs(logdir=self.customlog_dir)
        regx = re.compile(r'.*Switch.*: ([a-zA-Z0-9-+\.,_ $#%&@]*).*')
        for line in logs:
            if regx.match(line):
                info = regx.match(line).group(1)
        return info

    def get_vlab_full_info(self):
        """
        @brief  Get Vlab info from a custom log file.
        @rtype:  str
        @return:  Vlab info
        """
        info = ""
        logs = self.get_full_logs(logdir=self.customlog_dir)
        regx = re.compile(r'.*VLAB[\w\. ]*: ([a-zA-Z0-9-+\.,:_/ $#%&@]*).*')
        for line in logs:
            if regx.match(line):
                info = regx.match(line).group(1)
        return info


class MailSender(object):
    """
    @description  Send report mails with attachment
    """

    def __init__(self, test_info=None, message=None, attachment_file=None, attachment_dir=None, rcpt=None):
        """
        @brief  Initialize instance of MailSender class
        @param  test_info:  Test info (subject)
        @type  test_info:  str
        @param  message:  Mail message
        @type  message:  str
        @param  attachment_file:  Path to file to be attached
        @type  attachment_file:  str
        @param  attachment_dir:  Path to directory to be attached
        @type  attachment_dir:  str
        @param  rcpt:  List of recepients
        @type  rcpt:  list[str]
        """

        # Import necessary modules only in case using MailSender
        import smtplib
        import mimetypes
        from email import encoders
        from email.mime.text import MIMEText
        from email.mime.base import MIMEBase
        from email.mime.multipart import MIMEMultipart
        self.smtplib = smtplib
        self.mimetypes = mimetypes
        self.encoders = encoders
        self.MIMEText, self.MIMEBase, self.MIMEMultipart = MIMEText, MIMEBase, MIMEMultipart

        self.subject = "Automation testing report. {0}".format(test_info)
        self.message = "{0}\n\n".format(message)
        self.attachment_file = attachment_file
        self.attachment_dir = attachment_dir
        self.logkey = ".log"
        self.gmail_user = "test-reporter@toroki.com"
        self.gmail_pwd = "JeiKei6Guj"
        self.rcpt = rcpt

    def mail_attachment(self, path=None):
        """
        @brief  Add attachment from file
        @param  path:  Path to file
        @type  path:  str
        @raise  IOError:  file is not attached to mail
        @rtype:  MIMEBase
        @return:  attachment
        """
        attachment = None
        ctype, encoding = self.mimetypes.guess_type(path)
        if ctype is None or encoding is not None:
            # No guess could be made, or the file is encoded (compressed), so use a generic bag-of-bits type.
            ctype = "application/octet-stream"
        maintype, subtype = ctype.split("/", 1)
        try:
            fp = open(path, "rb")
        except IOError as err:
            print("WARNING: Cannot load file {0} - {1}".format(path, err))
            print("WARNING: Mail will be send without attachments.")
            raise
        else:
            attachment = self.MIMEBase(maintype, subtype)
            attachment.set_payload(fp.read())
            # Encode the payload using Base64
            self.encoders.encode_base64(attachment)
            attachment.add_header("Content-Disposition", "attachment", filename=str(os.path.basename(path)))
            fp.close()
            return attachment

    def create_msg(self, rcpt=None):
        """
        @brief  Create message body
        @param  rcpt:  List of recepients
        @type  rcpt:  str
        @rtype:  MIMEMultipart
        @return:  Email message
        """
        msg = self.MIMEMultipart()
        msg['Subject'] = self.subject
        msg['From'] = self.gmail_user
        msg['To'] = rcpt
        msg.attach(self.MIMEText(self.message))

        if self.attachment_file:
            msg.attach(self.mail_attachment(path=self.attachment_file))
        elif self.attachment_dir:
            for root, dirs, files in os.walk(self.attachment_dir):
                for filename in files:
                    path = os.path.join(root, filename)
                    if not os.path.isfile(path):
                        continue
                    elif not re.search(self.logkey, filename):
                        continue
                    msg.attach(self.mail_attachment(path=path))
        return msg

    def send_message(self, msg=None, rcpt=None):
        """
        @brief  Sending message
        @param  msg:  Email message
        @type  msg:  MIMEMultipart
        @param  rcpt:  List of recepients
        @type  rcpt:  str
        @raise  Exception:  error on mail sending
        """
        smtpserver = self.smtplib.SMTP("smtp.gmail.com", 587)
        smtpserver.ehlo()
        smtpserver.starttls()
        # smtpserver.ehlo()
        smtpserver.login(self.gmail_user, self.gmail_pwd)
        try:
            print('Sending to ' + rcpt)
            smtpserver.sendmail(self.gmail_user, rcpt, msg.as_string())
        except Exception as err:
            print("Caught an exception while sending mail: %s" % (err, ))
            raise
        else:
            print('done!')
        finally:
            smtpserver.close()

    def send(self):
        """
        @brief  Create and send message to all recipients
        @rtype:  bool
        @return:  True is send message successfully
        """
        for rcpt in self.rcpt:
            msg = self.create_msg(rcpt=rcpt)
            self.send_message(rcpt=rcpt, msg=msg)
        return True


class SingleHTMLConverter(html.parser.HTMLParser):
    """
    @description  This class transform any _local_ HTML page to a single HTML file with embedded js, css and images
    """

    def __init__(self, *args, **kwargs):

        # Import necessary modules only in case class usage
        import base64
        self.base64 = base64

        html.parser.HTMLParser.__init__(self)
        self.stack = []
        self.collect_errors = []
        self.html_file_name = None
        self.html_resources_path = None
        self.output_file = None

    def handle_starttag(self, tag, attrs):
        """
        @brief  Handle HTML start tag
        @param  tag:  HTML tag name
        @type  tag:  str
        @param  attrs:  HTML tag attributes
        @type  attrs:  dict
        @raise  Exception:  error on adding data to html file
        """
        attrs = dict(attrs)
        error = ''
        if tag.lower() == 'link' and attrs['type'].lower() == 'text/css' and attrs['href']:
            css_data, error = self.__get_data(attrs['href'])
            if css_data and not error:
                self.stack.append(self.__html_start_tag('style', {'type': 'text/css'}))
                self.stack.append(''.join(['<!--\n', self.__replace_images(css_data, attrs['href'], 'css'), '\n-->']))
                self.stack.append(self.__html_end_tag('style'))
            elif not css_data and not error:
                self.stack.append(self.__html_start_tag(tag, attrs))
                sys.stderr.write("WARNING: File %s not found.\n" % attrs['href'])
            else:
                self.stack.append(self.__html_start_tag(tag, attrs))
                self.collect_errors.append((self.getpos(), error))
                sys.stderr.write("WARNING: %s\n" % error)
        elif tag.lower() == 'script' and attrs['type'].lower() == 'text/javascript' and attrs['src']:
            js_data, error = self.__get_data(attrs['src'])
            if js_data and not error:
                self.stack.append(self.__html_start_tag('script', {'type': 'text/javascript'}))
                try:
                    self.stack.append(js_data.decode('utf-8'))
                except Exception as err:
                    print(tag, attrs)
                    raise err
            elif not js_data and not error:
                self.stack.append(self.__html_start_tag(tag, attrs))
                sys.stderr.write("WARNING: File %s not found.\n" % attrs['src'])
            else:
                self.stack.append(self.__html_start_tag(tag, attrs))
                self.collect_errors.append((self.getpos(), error))
                sys.stderr.write("WARNING: %s\n" % error)
        else:
            self.stack.append(self.__html_start_tag(tag, attrs))

    def handle_endtag(self, tag):
        """
        @brief  Handle HTML end tag
        @param  tag:  HTML tag name
        @type  tag:  str
        """
        self.stack.append(self.__html_end_tag(tag))
        if tag.lower() == 'a':
            self.stack.append(self.__html_end_tag('blink'))

    def handle_startendtag(self, tag, attrs):
        """
        @brief  Handle HTML startend tag
        @param  tag:  HTML tag name
        @type  tag:  str
        @param  attrs:  HTML tag attributes
        @type  attrs:  dict
        """
        self.stack.append(self.__html_startend_tag(tag, attrs))

    def handle_data(self, data):
        """
        @brief  Handle HTML data
        @param  data:  HTML data
        @type  data:  str
        """
        self.stack.append(data)

    def __html_start_tag(self, tag, attrs):
        """
        @brief  Handle HTML start tag
        @param  tag:  HTML tag name
        @type  tag:  str
        @param  attrs:  HTML tag attributes
        @type  attrs:  dict
        @rtype:  str
        @return:  HTML start tag
        """
        return '<%s%s>' % (tag, self.__html_attrs(attrs))

    def __html_startend_tag(self, tag, attrs):
        """
        @brief  Handle HTML startend tag
        @param  tag:  HTML tag name
        @type  tag:  str
        @param  attrs:  HTML tag attributes
        @type  attrs:  dict
        @rtype:  str
        @return:  HTML startend tag
        """
        return '<%s%s/>' % (tag, self.__html_attrs(attrs))

    def __html_end_tag(self, tag):
        """
        @brief  Handle HTML end tag
        @param  tag:  HTML tag name
        @type  tag:  str
        @rtype:  str
        @return:  HTML end tag
        """
        return '</%s>' % tag

    def __html_attrs(self, attrs):
        """
        @brief  Handle HTML tag attributes
        @param  attrs:  HTML tag attributes
        @type  attrs:  dict
        @rtype:  str
        @return:  HTML tag attributes
        """
        _attrs = ''
        if attrs:
            _attrs = ' %s' % (' '.join([('%s="%s"' % (k, v)) for k, v in attrs.items()]))
        return _attrs

    def __get_data(self, data_file_name=None):
        """
        @brief  Return content of the file as one line string with new lines.
        @param  data_file_name:  Path to the file
        @type  data_file_name:  str
        @rtype:  tuple(str, Exception)
        @return:  Content of the file, error while file reading
        """
        data = None
        error = None

        _abs_path_1 = os.path.join(os.path.realpath(os.curdir), data_file_name)
        _abs_path_2 = os.path.join(os.path.realpath(os.path.dirname(self.html_file_name)), data_file_name)
        _abs_path_3 = None
        if self.html_resources_path:
            _abs_path_3 = os.path.join(os.path.realpath(os.path.dirname(self.html_resources_path)), data_file_name)

        _file_name = None
        if os.path.isfile(_abs_path_1):
            _file_name = _abs_path_1
        elif os.path.isfile(data_file_name):
            _file_name = data_file_name
        elif os.path.isfile(_abs_path_2):
            _file_name = _abs_path_2
        elif _abs_path_3:
            if os.path.isfile(_abs_path_3):
                _file_name = _abs_path_3

        if _file_name:
            try:
                data = open(_file_name, 'rb').read()
            except Exception as err:
                error = err
                data = data_file_name
        return data, error

    # TODO: this function must found all images, not only the first
    def __replace_images(self, data, data_path, ctype='tag'):
        """
        @brief  Replace images links to embedded base64 encoded images in data.
        @param  data:  HTML data
        @type  data:  str
        @param  data_path:  Path to the directory with images
        @type  data_path:  str
        @param  ctype:  Image content type (css|tag)
        @type  ctype:  str
        @rtype:  str
        @return:  Modified HTML data
        """
        if ctype == "css":
            # image_re = re.compile('.*:[\s]*url\(([\w\-\./]+\.gif)\).*', re.M | re.S)
            image_re = re.compile(r'.*:[\s]*url\(([\w\-\./]+\.(?:png|gif))\).*')
        else:
            image_re = re.compile(r'([\w\-\./]+.gif)\).*')
        images_dict = {}
        # TODO: Here the problem. Search return only first occurrence of a pattern
        if isinstance(data, bytes):
            data = data.decode()
        images = image_re.findall(data)
        if images:
            for image in images:
                image_source_file = os.path.join(os.path.dirname(data_path), image)
                image_data = self.__get_data(image_source_file)[0]
                if image_data is None:
                    continue
                if image_data != image_source_file:
                    images_dict[image] = "data:image/png;base64,{}".format(self.base64.b64encode(image_data).decode())
        for image in images_dict:
            data = data.replace(image, images_dict[image])
        return data

    def convert_file(self, html_file_name=None, resources_path=None, output_file_name=None):
        """
        @brief  Convert html_file_name to single html with embedded js, css and images
                and write it to output_file_name if one,
                or return converted content of the file.
        @param  html_file_name:  Path to html file
        @type  html_file_name:  str
        @param  resources_path:  Path to html resources
        @type  resources_path:  str
        @param  output_file_name:  Path to the output html file
        @type  output_file_name:  str
        @raise  Exception:  html_file_name argument is None
        @rtype:  list or tuple
        @return:  List of errors or tuple(html output, list of errors)
        """
        self.output_file_name = None
        if not html_file_name:
            raise Exception('Argument html_file_name is obligated.')
        if resources_path:
            self.html_resources_path = resources_path
        self.html_file_name = html_file_name
        _html_string = open(html_file_name, 'r').read()
        self.stack = []
        self.collect_errors = []
        self.feed(_html_string)
        if output_file_name:
            self.output_file_name = output_file_name
            open(self.output_file_name, 'w').write('')
            for line in self.stack:
                try:
                    open(self.output_file_name, 'a+').write(line)
                except UnicodeEncodeError:
                    open(self.output_file_name, 'a+').write(unicodedata.normalize('NFKD', line))
            if self.collect_errors:
                return self.collect_errors
        else:
            return ''.join(self.stack), self.collect_errors


class ExternalXSLTProcessor(object):
    """
    @description  Convert XML to HTML. This class use external Linux utility xsltproc.
    """

    def __init__(self, xslt_style, concat_xslt=None):

        # Import necessary modules only in case class usage
        from subprocess import Popen, PIPE
        self.Popen, self.PIPE = Popen, PIPE

        self.xsltproc = "xsltproc"
        self.xsltproc_path = self._which()
        self.xslt_style = xslt_style
        self.concat_xslt = concat_xslt
        if not self.xsltproc_path:
            raise Exception("Program %s not found." % self.xsltproc)

    def _which(self):
        """
        @brief  Analog of Unix command 'which'.
        @rtype:  str
        @return:  Path to executable file (xsltproc) if one.
        """
        def is_exe(fpath):
            return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

        fpath, fname = os.path.split(self.xsltproc)
        if fpath:
            if is_exe(self.xsltproc):
                return self.xsltproc
        else:
            for path in os.environ["PATH"].split(os.pathsep):
                exe_file = os.path.join(path, self.xsltproc)
                if is_exe(exe_file):
                    return exe_file
        return None

    def _create_index_xml(self, xmlfile_list, output_xml):
        """
        @brief  Create index.xml
        @param  xmlfile_list:  List of xml files
        @type  xmlfile_list:  list[str]
        @param  output_xml:  Path to output xml file
        @type  output_xml:  str
        """
        open(output_xml, 'w').write('')
        try:
            header = '<?xml version="1.0" encoding="utf-8"?><files>'
            footer = '</files>'
            xfile = open(output_xml, 'a+')
            xfile.write(header.encode('utf-8'))
            for xmlfile in xmlfile_list:
                element = '<file name="%s" />' % xmlfile
                xfile.write(element.encode('utf-8'))
            xfile.write(footer.encode('utf-8'))
        finally:
            xfile.close()

    def process_xml(self, xml_file, xslt_file, output_xml=None):
        """
        @brief  Process xml file with xslt processor.
        @param  xml_file:  Input xml file
        @type  xml_file:  str
        @param  xslt_file:  Input xslt file
        @type  xslt_file:  str
        @param  output_xml:  Path to output xml file
        @type  output_xml:  str
        @raise  Exception:  xsltproc returns an error
        @rtype:  tuple
        @return:  returncode, stdoutdata, stderrdata
        """
        # Generate xsltproc command and args
        popen_cmd = [str(self.xsltproc_path)]
        if output_xml:
            popen_cmd.append("--maxdepth")
            popen_cmd.append("10000")
            popen_cmd.append("-o")
            popen_cmd.append(str(output_xml))
        popen_cmd.append(str(xslt_file))
        popen_cmd.append(str(xml_file))
        # run xsltproc
        process = self.Popen(popen_cmd, stdout=self.PIPE, stderr=self.PIPE)
        # save stdout, stderr
        p_out, p_err = process.communicate()
        retcode = process.wait()
        # Return result. If no output_xml p_out will contain result xml file
        if retcode != 0:
            raise Exception("xsltproc return an error code: %s\nStdOut:\n%s\nStdErr:\n%s\n" % (retcode, p_out, p_err,))
        return retcode, p_out, p_err

    def concat_xml(self, xmlfile_list, output_xml=None):
        """
        @brief  Create united xml report.
        @param  xmlfile_list:  List of xml files
        @type  xmlfile_list:  list[str]
        @param  output_xml:  Path to output xml file
        @type  output_xml:  str
        @rtype:  tuple
        @return:  returncode, stdoutdata, stderrdata
        """
        _tmp_file = tempfile.mkstemp(prefix='xsltproc.', suffix='.tmp', dir=os.curdir)
        try:
            self._create_index_xml(xmlfile_list, _tmp_file[1])
            return self.process_xml(_tmp_file[1], self.concat_xslt, output_xml)
        finally:
            # clear temp file
            os.remove(_tmp_file[1])

    def convert_xml(self, xml_file, output_html=None):
        """
        @brief  Create html report from single xml file
        @param  xml_file:  Input xml file
        @type  xml_file:  str
        @param  output_html:  Path to output html file
        @type  output_html:  str
        @rtype:  tuple
        @return:  returncode, stdoutdata, stderrdata
        """
        return self.process_xml(xml_file, self.xslt_style, output_html)

    def convert_xml_list(self, xmlfile_list, html_file):
        """
        @brief  Create html report from xml files list
        @param  xmlfile_list:  List of xml files
        @type  xmlfile_list:  list[str]
        @param  html_file:  Path to output html file
        @type  html_file:  str
        @rtype:  tuple
        @return:  returncode, stdoutdata, stderrdata
        """
        _tmp_file = tempfile.mkstemp(prefix='xsltproc.', suffix='.tmp', dir=os.curdir)
        try:
            self.concat_xml(xmlfile_list, _tmp_file[1])
            return self.convert_xml(_tmp_file[1], html_file)
        finally:
            # clear temp file
            os.remove(_tmp_file[1])

    def convert_dir(self, xml_dir, html_file):
        """
        @brief  Create summary html report from all xml files in given directory
        @param  xml_dir:  Path to the directory with xml files
        @type  xml_dir:  str
        @param  html_file:  Path to output html file
        @type  html_file:  str
        @rtype:  tuple
        @return:  returncode, stdoutdata, stderrdata
        """
        xmlfile_list = []
        for root, dirs, files in os.walk(xml_dir):
            if xml_dir != root:
                continue
            for filename in files:
                path = os.path.join(root, filename)
                if not os.path.isfile(path):
                    continue
                elif not re.search('.xml$', filename):
                    continue
                xmlfile_list.append(path)
                xmlfile_list.sort()
        return self.convert_xml_list(xmlfile_list, html_file)


#
# Functions used in __main__
#

def _expvars(path):
    """
    @brief  Alias to os.path methods to expand vars and user in path
    @param  path:  Path
    @type  path:  str
    @rtype:  str
    @return:  Modified path
    """
    return os.path.expanduser(os.path.expandvars(path))


def _get_real_file_path(filename):
    """
    @brief  Return absolute file path
    @param  filename:  File name
    @type  filename:  str
    @rtype:  str
    @return:  Absolute file path
    """
    _file_name = None
    filename = os.path.normpath(_expvars(filename))
    _abs_path_1 = os.path.normpath(os.path.join(os.path.realpath(os.curdir), filename))
    if os.path.isfile(_abs_path_1):
        _file_name = _abs_path_1
    elif os.path.isfile(filename):
        _file_name = filename
    return _file_name


def _is_file_in_dir(directory, file_mask):
    """
    @brief  Check if file with file_mask exists in directory
    @param  directory:  directory
    @type  directory:  str
    @param  file_mask:  mask of the file. E.g. '.xml$'
    @type  file_mask:  str
    @rtype:  bool
    @return:  True if file exists in the directory
    """
    for root, dirs, files in os.walk(directory):
        if directory != root:
            continue
        for filename in files:
            path = os.path.join(root, filename)
            if not os.path.isfile(path):
                continue
            elif not re.search(file_mask, filename):
                continue
            return True
    return False


def _get_xmls_path(xmlpath=None, logdir=None):
    """
    @brief  Return path to directory with xml files for create html report
    @param  xmlpath:  Path to xml files
    @type  xmlpath:  str
    @param  logdir:  Path to logdir
    @type  logdir:  str
    @rtype:  str
    @return:  Path to directory with xml files
    """
    # Priority 1: xmlpath defined explicitly
    _abs_path_1 = None
    if xmlpath:
        xmlpath = _expvars(xmlpath)
        _abs_path_1 = os.path.realpath(xmlpath)
    # Priority 2: Given py.test log directory from buildbot
    _abs_path_2 = None
    if logdir:
        logdir = _expvars(logdir)
        _abs_path_2 = os.path.realpath(os.path.dirname(os.path.join(logdir, 'pytest/')))
    # Priority 3: Nothing defined, search in current directory
    _abs_path_3 = os.path.realpath(os.curdir)

    search_mask = '.xml$'

    _file_name = None
    if _abs_path_1:
        if _is_file_in_dir(_abs_path_1, search_mask):
            _file_name = _abs_path_1
    elif _abs_path_2:
        if _is_file_in_dir(_abs_path_2, search_mask):
            _file_name = _abs_path_2
    elif _is_file_in_dir(_abs_path_3, search_mask):
        _file_name = _abs_path_3

    return _file_name


def parse_options():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--logfile", action="store", dest="log_file", default=None,
                      help="Path to log file created by buildbot.")
    parser.add_argument("--logdir", action="store", dest="log_dir", default=None,
                      help="Path to directory with log files created by buildbot.")
    parser.add_argument("--type", action="store", dest="attype", default='none',
                      help="Type of the attachment (html|text|none).")
    parser.add_argument("--html", action="store", dest="html", default=None,
                      help="Path to save html report.")
    parser.add_argument("--addtest", action="store", dest="addtest", default=None,
                      help="Add test if it not exists.")
    parser.add_argument("--htmlres", action="store", dest="html_res", default=None,
                      help="Path to html resources (css, js, images).")
    parser.add_argument("--xmlpath", action="store", dest="xml_path", default=None,
                      help="Path to xml files for html report.")
    parser.add_argument("--xsltstyle", action="store", dest="xslt_style", default="junit_full.xsl",
                      help="Path to xslt style sheet.")
    parser.add_argument("--xsltconcat", action="store", dest="xslt_concat", default="junit_concat.xsl",
                      help="Path to xslt concatenation style.")
    parser.add_argument("--maillist", action="store", dest="mail_list", default=None,
                      help="Path to file with email list.")
    parser.add_argument("--info", action="store", dest="info", default="",
                      help="Additional info for subject.")
    options = parser.parse_args()

    allowed_report_types = ['html', 'text', 'none']
    if options.attype not in allowed_report_types:
        raise Exception("Invalid --type option.")

    mail_list = []
    if options.mail_list:
        config = configparser.RawConfigParser()
        try:
            config.read(options.mail_list)
        except Exception as err:
            raise err
        else:
            mail_list = eval(config.get('subscribers', 'emails'))

    return {'logfile': options.log_file, 'logdir': options.log_dir, 'info': options.info,
            'attype': options.attype, 'maillist': mail_list,
            'html': options.html, 'htmlres': options.html_res, 'addtest': options.addtest, 'xmlpath': options.xml_path,
            'xslt_style': options.xslt_style, 'xslt_concat': options.xslt_concat}


def get_mail_opts(maillist, info, logdir=None, logfile=None, attype="none", html_file=None):
    """
    @brief  Return email dictionary
    @param  maillist:  List of recepients
    @type  maillist:  str
    @param  info:  Additional info
    @type  info:  str
    @param  logdir:  Path to directoru with logs
    @type  logdir:  str
    @param  logfile:  Path to txt file
    @type  logfile:  str
    @param  attype:  Type of attached file (none|text|html)
    @type  attype:  str
    @param  html_file:  Path to html file
    @type  html_file:  str
    @rtype:  dict
    @return:  Mail options dictionary
    """
    if logdir:
        log = LogParser(logdir=logdir)
    elif logfile:
        log = LogParser(logfile=logfile)

    # Define mail send options
    current_time = "{0} UTC".format(time.asctime(time.gmtime()))
    mail_options = {}
    if maillist:
        mail_subject = "Chip: %(chipname)s. Arch: %(cpuarch)s. Build: %(sppver)s. %(time)s. %(info)s" % \
                       {'chipname': log.get_spp_chip_name(), 'cpuarch': log.get_spp_cpu_arch(),
                        'sppver': log.get_spp_version(), 'time': current_time, 'info': info}
        mail_options['message'] = log.get_pytest_stats_full()
        mail_options['test_info'] = mail_subject
        mail_options['rcpt'] = maillist

        # Add poor text reports as mail attachment
        if attype == "text":
            print("Text logs selected.")
            if logdir:
                mail_options['attachment_dir'] = _expvars(logdir)
            elif logfile:
                mail_options['attachment_file'] = _expvars(logfile)
        elif attype == "html":
            mail_options['attachment_file'] = _expvars(html_file)

    return mail_options


def create_pure_html(output_file, xmlpath, logdir, xslt_style, xslt_concat):
    """
    @brief  Create html report from xml logs
    @param  output_file:  Generated HTML destination path
    @type  output_file:  str
    @param  xmlpath:  Path to xml reports
    @type  xmlpath:  str
    @param  logdir:  Path to buildbot logdir
    @type  logdir:  str | None
    @param  xslt_style:  Path to xslt files for generating HTML
    @type  xslt_style:  str
    @param  xslt_concat:  Path to concatenation xslt style.
            It's used for generating single HTML file from multiple xml files
    @type  xslt_concat:  str
    @raise  Exception:  XSLT style not found; XML files not found
    """
    # Check existence of xslt styles
    xslt_style = _get_real_file_path(xslt_style)
    xslt_concat = _get_real_file_path(xslt_concat)
    if xslt_style and xslt_concat:
        xsltproc = ExternalXSLTProcessor(xslt_style, xslt_concat)
    else:
        if not xslt_style and not xslt_concat:
            raise Exception("XSLT styles %s, and %s not found." % (xslt_style, xslt_concat,))
        elif not xslt_style and xslt_concat:
            raise Exception("XSLT style %s not found." % xslt_style)
        elif xslt_style and not xslt_concat:
            raise Exception("XSLT style %s not found." % xslt_concat)

    # Check existence of directory with xml files
    xml_path = _get_xmls_path(xmlpath, logdir)
    # Check if given xmlpath is single xml file
    xml_file = None
    if xmlpath:
        xml_file = _get_real_file_path(xmlpath)

    # Create pure html file
    if xml_file:
        xsltproc.convert_xml(xml_file, output_file)
    elif xml_path:
        xsltproc.convert_dir(xml_path, output_file)
    else:
        raise Exception("XML files not found. Path: {0}".format(xml_path))


def create_single_html(output_file, pure_html, html_resources):
    """
    @brief  Create all in one html report
    @param  output_file:  SingleHTML destination path
    @type  output_file:  str
    @param  pure_html:  Path to current HTML file
    @type  pure_html:  str
    @param  html_resources:  Path to resources (css, js, images) for given HTML file
    @type  html_resources:  str
    """
    html_converter = SingleHTMLConverter()
    html_converter.convert_file(pure_html, html_resources, output_file)
    del html_converter


def create_report(logfile, logdir, info, attype, maillist,
                  html, htmlres, xmlpath, xslt_style, xslt_concat, **kwargs):
    """
    @brief  Contain full reporting steps

    @param  logfile:  Path to txt file
    @type  logfile:  str
    @param  logdir:  Path to directoru with logs
    @type  logdir:  str
    @param  info:  Additional info
    @type  info:  str
    @param  attype:  Type of attached file (none|text|html)
    @type  attype:  str
    @param  maillist:  List of recepients
    @type  maillist:  str
    @param  html:  Path to current HTML file
    @type  html:  str
    @param  htmlres:  Path to resources (css, js, images) for given HTML file
    @type  htmlres:  str
    @param  xmlpath:  Path to xml reports
    @type  xmlpath:  str
    @param  xslt_style:  Path to xslt files for generating HTML
    @type  xslt_style:  str
    @param  xslt_concat:  Path to concatenation xslt style.
            It's used for generating single HTML file from multiple xml files
    @type  xslt_concat:  str
    """
    # Temporary files if no options for save report
    temp_file_1 = None
    temp_file_2 = None

    try:
        # Pretty html report
        if html or attype == "html":
            print("HTML report selected.")

            # Define file name to save html report
            if html:
                html_file = _expvars(html)
            else:
                temp_file_1 = tempfile.mkstemp(prefix='reporter.', suffix='.tmp', dir=os.curdir)
                html_file = temp_file_1[1]
            # Crete temporary file
            temp_file_2 = tempfile.mkstemp(prefix='reporter.', suffix='.tmp', dir=os.curdir)

            create_pure_html(output_file=temp_file_2[1],
                             xmlpath=xmlpath, logdir=logdir,
                             xslt_style=xslt_style, xslt_concat=xslt_concat)
            create_single_html(output_file=html_file,
                               pure_html=temp_file_2[1], html_resources=htmlres)

        # Send mail
        if maillist:
            mail_options = get_mail_opts(maillist, info, logdir, logfile, attype, html_file)
            if mail_options:
                mail = MailSender(**mail_options)
                if mail.send():
                    print("Send OK!")
                else:
                    print("Send Fail! See the log.")

    finally:
        # Remove temporary data
        if temp_file_1:
            os.remove(temp_file_1[1])
        if temp_file_2:
            os.remove(temp_file_2[1])


###########################
###########################
###########################
if __name__ == "__main__":
    create_report(**parse_options())
