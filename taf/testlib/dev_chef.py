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


"""``dev_chef_server.py``

`Chef Server host device related functionality`

"""

import os
import time

from . import clissh
from . import entry_template
from . import loggers


class GenericChefServerHost(entry_template.GenericEntry):
    """Generic Chef Server host pattern class.

    """
    class_logger = loggers.ClassLogger()

    ipaddr = None
    ssh_user = None
    ssh_pass = None
    ssh_port = 22

    def __init__(self, config, opts):
        """Initialize GenericChefServerHost class.

        """
        super(GenericChefServerHost, self).__init__(config, opts)
        self.name = config.get('name', "noname")
        self.id = config['id']
        self.type = config['instance_type']
        self.ipaddr = str(config.get('ip_host', self.__class__.ipaddr))
        self.ssh_port = int(config.get('ip_port', self.__class__.ssh_port))
        self.ssh_user = str(config.get('username', self.__class__.ssh_user))
        self.ssh_pass = str(config.get('password', self.__class__.ssh_pass))
        self.chef_repo_path = config['installed_path']
        self.roles_list = []

        if self.ipaddr and self.ssh_user and self.ssh_pass:
            self.ssh = clissh.CLISSH(self.ipaddr, self.ssh_port, self.ssh_user, self.ssh_pass)

        self.class_logger.info("Init Chef Server: {}".format(self.ipaddr))

        self.config = config
        self.opts = opts
        self.status = False

    def exec_cmd(self, command, from_repo_root=True, check_root=True, timeout=None):
        """Exec shell command with root privileges and print warning message in case StdErr isn't empty.

        Args:
            command(str):  Command to be executed
            from_repo_root(bool):  Directory chef-repo resides in
            check_root(bool):  Notify user has admin privileges
            timeout(int):  Max command execution time on chef server

        Returns:
            tuple (stdout, stderr, return code)

        Examples::

            env.chef[1].exec_cmd('ls -la')

        """
        if check_root:
            if self.ssh_user != "root":
                command = "sudo " + command
        if from_repo_root:
            command = "cd '{0}'; {1}".format(self.chef_repo_path, command)
        cmd_status = self.ssh.exec_command(command, timeout=timeout)
        # Delay, to stabilize calls
        time.sleep(1)
        return cmd_status

    def start(self, wait_on=True):
        """Mandatory method for environment specific classes.

        """
        self.ssh.login(timeout=25)

    def stop(self, with_cleanup=True):
        """Mandatory method for environment specific classes.

        """
        self.ssh.close()

    def cleanup(self):
        """Remove created configuration.

        """
        pass

    def create(self):
        """Start Chef server or get running one.

        Notes:
            This is mandatory method for all environment classes.
            Also self.opts.get_only attribute affects logic of this method.
            get_only is set in py.test command line options (read py.test --help for more information).

        """
        self.start()
        self.status = True

    def destroy(self):
        """Stop or release Chef server.

        Notes:
            This is mandatory method for all environment classes.
            Also self.opts.leave_on and get_only  attributes affect logic of this method.
            leave_on and get_only are set in py.test command line options (read py.test --help for more information).

        """
        if not self.status:
            self.class_logger.info("Skip id:{}({}) destroying because it already "
                                   "has Off status.".format(self.id, self.name))
            return
        self.stop()

        self.sanitize()

    def sanitize(self):
        """Perform any necessary operations to leave environment in normal state.

        """
        pass

    def check(self):
        """Mandatory method for environment specific classes.

        """
        pass

    def set_role(self, src):
        """Put role file to Chef server chef-repo/roles dir and add it to Chef database.

        """
        dst = os.path.join(self.chef_repo_path, 'roles', os.path.split(src)[-1])
        self.class_logger.debug("Transfer generated role file to chef server.")
        self.ssh.put_file(src, dst, proto="sftp")
        self.exec_cmd("knife role from file '{}'".format(dst))
        self.roles_list.append(dst)

    def set_run_list(self, role_file, fqdn_hostname):
        """Set chosen JSON role file as target node run list.

        """
        _cmd = 'knife node run_list set {} "role[{}]"'.format(fqdn_hostname,
                                                              os.path.splitext(role_file)[0])
        self.exec_cmd(_cmd)

    def bootstrap_node(self, switch_config, timeout=90):
        """Install chef client on target device.

        """
        _cmd = "cd '{}'; knife bootstrap {} -V --bootstrap-template {} --environment {}".format(
            self.chef_repo_path, switch_config['ip_host'],
            self.config['distro'], self.config['environment'])
        _alter = [('assword:', switch_config['sshtun_pass'], False, True)]
        self.class_logger.info("Install chef client on device '{}'.".format(switch_config['name']))
        self.ssh.open_shell()
        self.ssh.shell_command(_cmd, alternatives=_alter, timeout=timeout)
        self.ssh.close_shell()

    def remove_role(self):
        """Cleanup generated role files on chef server.

        """
        self.class_logger.info("Perform cleanup on chef server.")
        for x in self.roles_list:
            self.exec_cmd("knife role delete '{}' -y".format(
                os.path.splitext(os.path.split(x)[-1])[0]))
            # Remove role files generated during test run
            self.exec_cmd("rm -f -- '{}'".format(x))

    def delete_node(self, fqdn_hostname):
        """Delete node from chef database.

        """
        self.exec_cmd('knife node delete -y {}'.format(fqdn_hostname))
        self.exec_cmd('knife client delete -y {}'.format(fqdn_hostname))


ENTRY_TYPE = "chef-settings"
INSTANCES = {"chef": GenericChefServerHost}
NAME = "chef"
