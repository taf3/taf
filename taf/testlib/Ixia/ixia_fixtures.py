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


"""``ixia_fixtures.py``

`Useful Ixia related fixture functions/patterns for TAF`

"""

import os


class QTRun(object):
    """Run Ixia QuickTest.

    """

    def __init__(self, request, tg):
        """Initialize QTRun class.

        Args:
            request(pytest.request):  pytest request
            tg(Environment instance):  Ixia TG object

        Raises:
            Exception:  Incorrect fixture scope
            Exception:  Incorrect type of TG
            Exception:  TG object isn't configured to use IxNetwork

        Returns:
            None

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
        """Loading ixncfg file.

        Returns:
            None

        """
        if self.tg.ixncfg_file is None or os.path.basename(self.tg.ixncfg_file) != os.path.basename(self.qtpath):
            self.tg.load_ixncfg(self.qtpath)

    def run(self, qt_name=None, qt_id=None, pdf=True):
        """Execute QT and wait for result.

        Args:
            qt_name(str):  QuickTest name
            qt_id(str):  QuickTest id
            pdf(bool):  Enable/Disable PDF report

        Returns:
            list: Path to results

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
