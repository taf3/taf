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

"""``tool_general.py``

`General functionality for Linux tool`

"""

import os

from testlib.linux import service_lib
from testlib.custom_exceptions import UICmdException


# service manager return codes
RC_SUCCESS = 0
RC_SERVICE_FAILED = 3
RC_SERVICE_INACTIVE = 5


class GenericTool(object):
    """General Linux tool functionality.

    """

    def __init__(self, run_command, tool):
        """Initialize GenericTool class.

        Args:
            run_command(function): function that runs the actual commands.

        """
        super(GenericTool, self).__init__()
        self.run_command = run_command
        self.tool = tool
        self.instances = {}

    def cleanup(self):
        """Cleanup the Iperf instance.

        """
        self.instances.clear()

    def next_id(self):
        """Generate an id for the next instance.

        Returns:
            int:  the generated id

        """
        return (max(self.instances) + 1) if self.instances else 1

    def start(self, command, prefix=None, timeout=None, tool_name=None, tool_instance_id=None,
              pid=None, service_name=None, **kwargs):
        """Generate command for tool execution.

        Args:
            command(str): tool command
            prefix(str): command prefix
            timeout(int): time of tool execution

        Returns:
            int: tool instance ID

        """
        if not tool_name:
            tool_name = self.tool
        if not tool_instance_id:
            tool_instance_id = self.next_id()
        if not pid:
            pid = os.getpid()

        if not service_name:
            service_name = "{}_{}_{}".format(tool_name, tool_instance_id, pid)

        # use --scope for synchronous execution in the current enviroment,
        # and maybe --pty and no -q
        systemd_cmd_str = "systemd-run --unit={0} -q -- {1}".format(service_name, command)
        cmd_str = (prefix if prefix else '') + systemd_cmd_str
        self.run_command(cmd_str, **kwargs)
        self.instances[tool_instance_id] = {
            'command': cmd_str,
            'instance_id': tool_instance_id,
            'service_name': service_name,
            'service_manager': service_lib.SpecificServiceManager(service_name, self.run_command),
        }
        # Wait for tool instance to start
        self.is_active(tool_instance_id)
        return tool_instance_id

    def get_results(self, instance_id):
        """Read the tool results from the file.

        Args:
            instance_id(int): instance_id

        Returns:
            str: tool output

        """
        service_name = self.instances[instance_id]['service_name']
        # -o cat, raw output
        command = 'journalctl --no-pager -o cat -u {}'.format(service_name)
        cmd_status = self.run_command(command)
        return cmd_status.stdout

    def is_active(self, instance_id, timeout=None, expected_rcs=frozenset({0})):
        """Get process info for specific tool instance.

        Args:
            instance_id(int):  tool instance ID
            timeout(int): command runner execution timeout
            expected_rcs(set): command runner expected return codes

        Raises:
            UICmdException

        Returns:
            bool:  tool process info

        """
        service_manager = self.instances[instance_id]['service_manager']
        # rc = 3, stdout = 'failed\n
        try:
            out, _, _ = service_manager.is_active(timeout=timeout, expected_rcs=expected_rcs)
            return out.strip() == 'active'
        except UICmdException:
            pass
        # use exact compare, not in
        # possible values are 'active' or 'unknown' or failed with rc 3.
        # only return true if we get 'active'
        return False

    def stop(self, instance_id, timeout=None, ignore_failed=False, ignore_inactive=False):
        """ Human readable params wrapper for _stop - the actual worker method.

        """
        expected_rcs = {RC_SUCCESS}
        if ignore_failed:
            expected_rcs.add(RC_SERVICE_FAILED)
        if ignore_inactive:
            expected_rcs.add(RC_SERVICE_INACTIVE)

        self._stop(instance_id, timeout=timeout, expected_rcs=expected_rcs)

    def _stop(self, instance_id, timeout=None, expected_rcs=frozenset({0})):
        """Stop the tool instance.

        Args:
            instance_id(int): tool instance ID
            timeout(int): command runner execution timeout
            expected_rcs(set): command runner expected return codes

        Raises:
            UICmdException

        """
        service_manager = self.instances[instance_id]['service_manager']
        service_manager.stop(timeout=timeout, expected_rcs=expected_rcs)
