# Copyright (c) 2016 - 2017, Intel Corporation.
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

"""``dev_settings.py``

`Settings entry class. 'settings' entry can contain any setup related info that is necessary for testing on that setup`

"""

from . import entry_template


class GenericSettings(entry_template.GenericEntry):
    """Settings entry is used just to pass necessary info to tests and doesn't require any actions.

    Notes:
        Class returns settings dictionary without modifications on call.

    """

    def __get__(self, instance, owner):
        """Get configuration.

        """
        return self.config

    def create(self):
        """Mandatory method for environment specific switch classes.

        """
        pass

    def destroy(self):
        """Mandatory method for environment specific switch classes.

        """
        pass

    def check(self):
        """Mandatory method for environment specific switch classes.

        """
        pass

    def cleanup(self):
        """Mandatory method for environment specific switch classes.

        """
        pass

    def sanitize(self):
        """Mandatory method for environment specific switch classes.

        """
        pass


ENTRY_TYPE = "settings"
INSTANCES = {"settings": GenericSettings,
             "ui_settings": GenericSettings,
             "syslog_settings": GenericSettings,
             "ntp": GenericSettings,
             "radius_tacacs_settings": GenericSettings,
             "collectd_settings": GenericSettings,
             }
NAME = "settings"
