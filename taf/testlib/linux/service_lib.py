"""
@copyright Copyright (c) 2013 - 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file service_lib.py

@summary SystemD service library
"""
import os
from tempfile import mktemp

USAGE = """

import service_lib

# to generate raw list of str commands, e.g.  ["systemctl", "start", "networkd"]
systemd_cmd_gen = service_lib.systemd_command_generator()
cmd = " ".join(systemd_cmd_gen.start("networkd"))

# to directly call cli_send_command but still accepts kwargs for cli_send_command
networkd = service_lib.specific_service_manager_factory("networkd", self.cli_send_command)
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


def systemd_command_generator(command):

    command_name = "systemctl"
    if command == "is_enabled":
        command = "is-enabled"
    elif command == "is_active":
        command = "is-active"
    elif command == "list":
        # noinspection PyUnusedLocal
        def list_command(service_name):
            return [command_name, "list-unit-files", "--type=service"]
        return list_command

    def method(service_name):
        return [command_name, command, "%s.service" % service_name]
    return method

COMMANDS = (
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
)


class ServiceCommandGenerator(object):

    def __init__(self, command_generator, command_list=COMMANDS):
        super(ServiceCommandGenerator, self).__init__()
        self.commands = command_list
        for command in self.commands:
            setattr(self, command, command_generator(command))


class SpecificServiceManager(object):

    def __init__(self, service_name, service_command_generator, run):
        super(SpecificServiceManager, self).__init__()
        for cmd in service_command_generator.commands:
            setattr(self, cmd,
                    self.generate_run_function(run, getattr(service_command_generator, cmd), service_name))

    @staticmethod
    def generate_run_function(run_func, command, service_name):
        def run(**kwargs):
            return run_func(" ".join(command(service_name)), **kwargs)
        return run


class GenericServiceManager(object):

    def __init__(self, service_command_generator, run):
        super(GenericServiceManager, self).__init__()
        for cmd in service_command_generator.commands:
            setattr(self, cmd,
                    self.generate_run_function(run, getattr(service_command_generator, cmd)))

    @staticmethod
    def generate_run_function(run_func, command):
        def run(service="", **kwargs):
            return run_func(" ".join(command(service)), **kwargs)
        return run


class SystemdServiceManager(GenericServiceManager):

    def __init__(self, service_command_generator, run):
        super(SystemdServiceManager, self).__init__(service_command_generator, run)

    @staticmethod
    def change_default_runlevel(runlevel='multi-user.target'):
        # atomic symlinking, symlink and then rename
        tmp_symlink = mktemp(dir="/etc/systemd/system")
        os.symlink("/usr/lib/systemd/system/%s" % runlevel, tmp_symlink)
        os.rename(tmp_symlink, "/etc/systemd/system/default.target")


_command_generators = {"systemd": systemd_command_generator}

_service_managers = {"systemd": SystemdServiceManager}


def specific_service_manager_factory(service_name, run_func):
    command_list = [c for c in COMMANDS if c != "list"]
    service_command_generator = ServiceCommandGenerator(systemd_command_generator, command_list)
    return SpecificServiceManager(service_name, service_command_generator, run_func)


def systemd_manager_factory(run_func):
    return SystemdServiceManager(ServiceCommandGenerator(systemd_command_generator), run_func)
