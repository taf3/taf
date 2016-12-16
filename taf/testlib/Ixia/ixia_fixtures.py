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

@file  ixia_fixtures.py

@summary  Useful Ixia related fixture functions/patterns for TAF.
"""

import os


class QTRun(object):
    """
    @description Run Ixia QuickTest.
    """

    def __init__(self, request, tg):
        """
        @brief  Initialize QTRun class
        @param  request:  pytest request
        @type  request:  pytest.request
        @param  tg:  Ixia TG object
        @type  tg:  Environment instance
        @raise  Exception:  Incorrect fixture scope
        @raise  Exception:  Incorrect type of TG
        @raise  Exception:  TG object isn't configured to use IxNetwork
        @return:  None
        """
        if request.scope != "function":
            raise Exception("This fixture has to be used only in function scope.")

        # Passed tg object has to be Ixia
        if "ixia" not in tg.type:
            raise Exception("Provided TG object isn't Ixia.")
        if not tg.is_protocol_emulation_present:
            raise Exception("Provided Ixia TG object isn't configured to use IxNetwork API.")
        self.tg = tg

        self.__name__ = request.function.__name__

        self.qtpath = request.config.option.qtpath
        if self.qtpath is None:
            _filename = request.function.__code__.co_filename
            _dir = os.path.dirname(_filename)
            _basefilename = os.path.splitext(os.path.basename(_filename))[0]
            self.qtpath = os.path.join(_dir, "ixncfg", _basefilename + ".ixncfg")

    def _load_cfg(self):
        """
        @brief Loading ixncfg file.
        @return:  None
        """
        if self.tg.ixncfg_file is None or os.path.basename(self.tg.ixncfg_file) != os.path.basename(self.qtpath):
            self.tg.load_ixncfg(self.qtpath)

    def run(self, qt_name=None, qt_id=None, pdf=True):
        """
        @brief  Execute QT and wait for result.
        @param  qt_name:  QuickTest name
        @type  qt_name:  str
        @param  qt_id:  QuickTest id
        @type  qt_id:  str
        @param  pdf:  Enable/Disable PDF report
        @type  pdf:  bool
        @rtype:  list
        @return:  Path to results
        """
        # Load config if it isn't loaded yet.
        self._load_cfg()
        # Variable to save destinations of QT results on IxNetwork host.
        rc_path = []
        # Enable pdf reports if requested
        self.tg.qt.report(pdf=pdf)
        # Run test(s)
        if qt_name is None or qt_id is None:
            qts = self.tg.qt.tc_list
        else:
            qts = [(qt_name, qt_id), ]
        for qt_n, qt_i in qts:
            rc = self.tg.qt.run(qt_n, qt_i, self.__name__)
            rc_path.append(rc)
        return rc_path
