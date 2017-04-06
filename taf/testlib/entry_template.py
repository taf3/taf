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

"""``entry_template.py``

`Interface class for any TAF environment configuration entry`

"""

from abc import ABCMeta, abstractmethod


class GenericEntry(object, metaclass=ABCMeta):
    """Interface class for any TAF environment configuration entry.

    """

    # Config dictionaries of entries listed in related_id list
    related_conf = None
    # Instances of entries listed in related_id list
    related_obj = None

    def __init__(self, config, opts):
        """Entry __init__ method has to take 2 parameters.

        Args:
            config(dict):  Configuration information.
            opts(OptionParser):  py.test config.option object which contains all py.test cli options.

        """
        super(GenericEntry, self).__init__()
        self.config = config
        self.opts = opts
        self.type = config['instance_type']
        self.id = config['id']

    @abstractmethod
    def create(self):
        """Called on environment initialize step. It should contain any steps necessary to start using device instance.

        """
        pass

    @abstractmethod
    def destroy(self):
        """Called on environment shutdown step. It should contain any necessary steps to release used device.

        """
        pass

    @abstractmethod
    def check(self):
        """Called in environment check method. Used before/after TC to verify that environment is ready to use.

        """
        pass

    @abstractmethod
    def sanitize(self):
        """Called in environment sanitize method. It's used by pytest.softexit and should contain any steps to release possible locks.

        """
        pass

    @abstractmethod
    def cleanup(self):
        """Called in environment cleanup method. It's used to delete all runtime configuration and return entry to default state.

        """
        pass

    def start(self):
        """This method could be called by create method and has to prepare entry object for processing commands.

        E.g. It can power on device, or launch some service on it.
        You can use create method itself for this. But usually create method checks some CLI options (--get_only) and decides to invoke start or not.

        """
        pass

    def stop(self):
        """This method could be called by destroy method and has to release entry object configuration.

        E.g. It can power off device, or stop some service on it.
        You can use destroy method itself for this. But usually destroy method checks some CLI options (--get_only, --leave_on) and decides to invoke
        stop or not.

        """
        pass

    def get_env_prop(self, param):
        pass


# Obligatory constants for any entry module.
# This is a template so those constants are empty.
ENTRY_TYPE = ""
INSTANCES = {}
NAME = ""
LINK_NAME = ""
# ENTRY_TYPE  is the same as you will use in env/setup files.
#             It's allowed to create multiple modules of the same ENTRY_TYPE with different instance types.
# INSTANCES  contains instance_type as key and proper instance class as value.
#            It's possible to override already loaded instance classes.
#            Modules are loaded according to file names returned by os.listdir method
# NAME  is used to access proper entry dict in Environment object. (E.g. env.just_router[1])
#       It is read only once in the first loaded module and is ignored in others modules of the same ENTRY_TYPE.
# LINK_NAME is used for obtaining links information from env.get_ports method. In case LINK_NAME isn't set NAME is used.
# Example:
# ENTRY_TYPE = "brand_router"
# INSTANCES = {"simulated": MySimulatedRouter, "real": MyPhisicalRouter}
# NAME = "just_router"
# LINK_NAME = "ro"
