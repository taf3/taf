# Copyright (c) 2013 - 2017, Intel Corporation.
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

"""``service_lib.py``

`SystemD service library`

"""

import os
from tempfile import mktemp

USAGE = """

import service_lib

# to generate raw list of str commands, e.g.  ["systemctl", "start", "networkd"]
systemd_cmd_gen = service_lib.systemd_command_generator()
cmd = " ".join(systemd_cmd_gen.start("networkd"))

# to directly call cli_send_command but still accepts kwargs for cli_send_command
networkd = service_lib.SpecificServiceManager("networkd", self.cli_send_command)
networkd.stop(expected_rcs={0, 3})
networkd.start(expected_rcs={1})

# to directly call cli_send_command but still accepts kwargs for cli_send_command
systemd = service_lib.systemd_manager_factory(self.cli_send_command)
systemd.stop("networkd", expected_rcs={0, 3})
systemd.list(expected_rcs={0, 3})
systemd.start(service="networkd", expected_rcs={0, 3})
systemd.change_default_runlevel("rescue.target")

"""


COMMAND_TABLE_DOC = """

service frobozz start
systemctl start frobozz.service
 Used to start a service (not reboot persistent)

service frobozz stop
systemctl stop frobozz.service
 Used to stop a service (not reboot persistent)

service frobozz restart
systemctl restart frobozz.service
 Used to stop and then start a service

service frobozz reload
systemctl reload frobozz.service
 When supported, reloads the config file without interrupting pending operations.

service frobozz condrestart
systemctl condrestart frobozz.service
 Restarts if the service is already running.

service frobozz status
systemctl status frobozz.service
 Tells whether a service is currently running.

ls /etc/rc.d/init.d/
systemctl list-unit-files --type=service (preferred)
 Used to list the services that can be started or stopped
ls /lib/systemd/system/*.service /etc/systemd/system/*.service
 Used to list all the services and other units

chkconfig frobozz on
systemctl enable frobozz.service
 Turn the service on, for start at next boot, or other trigger.

chkconfig frobozz off
systemctl disable frobozz.service
 Turn the service off for the next reboot, or any other trigger.

chkconfig frobozz
systemctl is-enabled frobozz.service
 Used to check whether a service is configured to start or not in the current environment.

chkconfig --list
systemctl list-unit-files --type=service(preferred)
ls /etc/systemd/system/*.wants/
 Print a table of services that lists which runlevels each is configured on or off

chkconfig frobozz --list
ls /etc/systemd/system/*.wants/frobozz.service
 Used to list what levels this service is configured on or off

chkconfig frobozz --add
systemctl daemon-reload
 Used when you create a new service file or modify any configuration


"""


class ReturnCodes(object):
    SUCCESS = 0
    RUNNING = 0
    STOPPED = 3
    UNKNOWN = None


class SystemdReturnCodes(ReturnCodes):
    pass


REPLACE_COMMAND_LIST = {
    'is_enabled',
    'is_active',
    'daemon_reload',
}


COMMANDS = {
    "start",
    "stop",
    "reload",
    "restart",
    "condrestart",
    "status",
    "enable",
    "disable",
    "is_enabled",
    "is_active",
    "list",
    "daemon_reload",
}


def systemd_command_generator(command):

    command_name = "systemctl"
    if command in REPLACE_COMMAND_LIST:
        command = command.replace('_', '-')

    if command == "list":
        # noinspection PyUnusedLocal
        def list_command(_):
            return [command_name, "list-unit-files", "--type=service"]
        return list_command
    elif command == "daemon-reload":
        def daemon_reload_command(*_):
            return [command_name, command, '']
        return daemon_reload_command

    def method(service_name):
        return [command_name, command, "{}.service".format(service_name)]
    return method


class ServiceCommandGenerator(object):

    def __getattr__(self, name):
        if name not in self:
            raise AttributeError(name)
        command = self.command_generator(name)
        setattr(self, name, command)
        return command

    def __iter__(self):
        return iter(self.commands)

    def __contains__(self, value):
        return value in self.commands

    def __init__(self, command_generator, return_codes=ReturnCodes, command_list=None):
        super(ServiceCommandGenerator, self).__init__()
        if command_list is None:
            command_list = COMMANDS
        self.commands = command_list
        self.command_generator = command_generator
        self.return_codes = return_codes


class GenericServiceManager(object):
    def __init__(self, run_func, command_list=None):
        super().__init__()
        if command_list is None:
            command_list = COMMANDS
        self.service_command_generator = ServiceCommandGenerator(systemd_command_generator,
                                                                 SystemdReturnCodes,
                                                                 command_list)

        self.return_codes = SystemdReturnCodes
        self.run_func = run_func

    def __getattr__(self, name):
        def run(service='', **kwargs):
            return self.run_func(' '.join(command(service)), **kwargs)
        command = getattr(self.service_command_generator, name)
        setattr(self, name, run)
        return run

    def _get_running_status(self, service=''):
        return self.status(service=service, expected_rcs={self.return_codes.RUNNING,
                                                          self.return_codes.STOPPED})

    def is_running(self, service=''):
        rv = self._get_running_status(service)
        return rv.rc == self.return_codes.RUNNING

    def is_stopped(self, service=''):
        rv = self._get_running_status(service)
        return rv.rc == self.return_codes.STOPPED


class SpecificServiceManager(GenericServiceManager):
    def __init__(self, service_name, run_func):
        command_list = [c for c in COMMANDS if c != "list"]
        super().__init__(run_func, command_list)
        self.service_name = service_name

    def __getattr__(self, name):
        def run(**kwargs):
            kwargs.pop('service', None)  # remove any value associated with the service key
            return self.run_func(command, **kwargs)
        command = getattr(self.service_command_generator, name)
        command = ' '.join(command(self.service_name))
        setattr(self, name, run)
        return run


class SystemdServiceManager(GenericServiceManager):

    def __init__(self, run):
        super().__init__(run)

    @staticmethod
    def change_default_runlevel(runlevel='multi-user.target'):
        # atomic symlinking, symlink and then rename
        tmp_symlink = mktemp(dir="/etc/systemd/system")
        os.symlink("/usr/lib/systemd/system/{}".format(runlevel), tmp_symlink)
        os.rename(tmp_symlink, "/etc/systemd/system/default.target")


class ServiceConfigChangeContext(object):
    """Context manager suitable for service configuration.

    """

    def __init__(self, specific_service_manager):
        super().__init__()
        self.rcs = specific_service_manager.return_codes
        self.was_running = None
        self.specific_service_manager = specific_service_manager

    def __enter__(self):
        self.was_running = self.specific_service_manager.is_running()
        if self.was_running:
            self.specific_service_manager.stop()

    def __exit__(self, exc_type, exc, exc_tb):
        self.specific_service_manager.daemon_reload()
        if self.was_running:
            self.specific_service_manager.start()
