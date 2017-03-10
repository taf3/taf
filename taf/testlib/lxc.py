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

"""``lxc.py``

`LXC-specific functionality`

"""

import os
import errno
import shutil
import stat

from subprocess import Popen, PIPE

# WORKAROUND BEGIN
import platform
# WORKAROUND END

from . import loggers

mod_logger = loggers.module_logger(name=__name__)


def mkdir_p(path):
    """Create dir and pass exception if one already exists.

    """
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            pass
        else:
            raise


class Lxc(object):
    """Base class to work with Linux containers.

    """

    class_logger = loggers.ClassLogger()

    def __init__(self, lxc_ip=None, lxc_iface=None, vlab_ip=None, switch_bin_path=None, switch_id=None, switch_port=8081):
        """Init method for container.

        Args:
            lxc_ip(str):  IP of the container
            lxc_iface(str):  Network interface for container
            vlab_ip(str):  real ip of the local vlab
            switch_bin_path(str):  path to switchpp binary
            switch_id(str):  simswitch id
            switch_port(int):  switchpp xmlrpc port

        Returns:
            None

        """
        self.topbuilddir = os.path.realpath(os.curdir)
        self.lxc_id = int(switch_port) - 8080
        self.lxc_env = os.path.join(os.path.realpath(os.curdir), "cfg%s" % (self.lxc_id, ))
        self.lxc_ip = lxc_ip
        self.lxc_iface = lxc_iface
        self.build_name = "%s%s" % (os.path.basename(self.topbuilddir), self.lxc_id)
        self.vlab_ip = vlab_ip
        self.switch_bin_path = switch_bin_path
        self.switch_id = switch_id or (int(switch_port) - 8080)

    def start(self, stdout=None, stderr=None):
        """Starts container.

        Args:
            stdout(str):  Output file
            stderr(str):  Error file

        Returns:
            None

        """
        mkdir_p(os.path.join(os.sep, "var", "run", "quagga"))
        mkdir_p(os.path.join(os.sep, "var", "run", "ovs"))
        mkdir_p(os.path.join(self.lxc_env, "rootfs", "root"))
        mkdir_p(os.path.join(self.lxc_env, "rootfs", "etc", "quagga"))
        mkdir_p(os.path.join(self.lxc_env, "rootfs", "etc", "network"))
        mkdir_p(os.path.join(self.lxc_env, "rootfs", "var", "run", "quagga"))
        mkdir_p(os.path.join(self.lxc_env, "rootfs", "var", "log", "quagga"))
        mkdir_p(os.path.join(self.lxc_env, "rootfs", "var", "run", "ovs"))
        shutil.copy(os.path.join(os.sep, "usr", "local", "etc", "zebra.conf.sample"), os.path.join(self.lxc_env, "rootfs", "etc", "quagga", "zebra.conf"))
        shutil.copy(os.path.join(os.sep, "usr", "local", "etc", "ospfd.conf.sample"), os.path.join(self.lxc_env, "rootfs", "etc", "quagga", "ospfd.conf"))
        with open(os.path.join(self.lxc_env, "rootfs", "etc", "network", "interfaces"), 'w+') as fo:
            fo.write('auto eth0\n')
            fo.write('iface eth0 inet dhcp\n')
        ld_lib_path = os.path.normpath(os.path.join(os.path.dirname(self.switch_bin_path), "../lib"))
        if not (os.path.exists(ld_lib_path) and os.path.isdir(ld_lib_path)):
            self.class_logger.log(loggers.levels['WARNING'], "LD_LIBRARY_PATH=%s not found and will not be exported." % ld_lib_path)
            ld_lib_path = None
        else:
            self.class_logger.log(loggers.levels['INFO'], "Found LD_LIBRARY_PATH=%s" % ld_lib_path)
        with open(os.path.join(self.lxc_env, "rootfs", "root", "init"), 'w+') as fo:
            fo.write('#!/bin/bash\n')
            if ld_lib_path is not None:
                fo.write('export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:%s\n' % ld_lib_path)
            fo.write('export OVS_RUNDIR=/var/run/ovs\n')
            fo.write('PATH=%s:%s\n' % (self.topbuilddir, os.getenv('PATH')))
            fo.write('chmod a+rw /var/run/quagga\n')
            fo.write('zebra -u root -g root -f /etc/quagga/zebra.conf -i /var/run/quagga/zebra.pid -d\n')
            fo.write('ospfd -u root -g root -f /etc/quagga/ospfd.conf -i /var/run/quagga/ospfd.pid -d\n')
            fo.write('sysctl -w net.ipv4.ip_forward=1\n')
            fo.write('/usr/sbin/sshd\n')
            fo.write('cd %s\n' % (os.path.dirname(self.switch_bin_path), ))
            fo.write('%s -v %s -i %s -e %s -d\n' % (self.switch_bin_path, self.vlab_ip, self.switch_id, self.switch_id + 4700))
        os.chmod(os.path.join(self.lxc_env, "rootfs", "root", "init"), stat.S_IXGRP | stat.S_IXUSR | stat.S_IXOTH)
        # TODO: Write files in one command instead of multiple f.write's
        with open(os.path.join(self.lxc_env, "conf"), 'w+') as fo:
            fo.write('lxc.utsname = %s\n' % (self.build_name, ))
            # WORKAROUND BEGIN: Ubuntu 12.04 bug #993706
            # https://bugs.launchpad.net/ubuntu/+source/lxc/+bug/993706
            if platform.platform().find("precise") > 0:
                fo.write('lxc.aa_profile = unconfined\n')
            # WORKAROUND END
            fo.write('lxc.network.type = veth\n')
            fo.write('lxc.network.flags = up\n')
            fo.write('lxc.network.link = %s\n' % (self.lxc_iface, ))
            fo.write('lxc.network.name = eth0\n')
            fo.write('lxc.network.ipv4 = %s\n' % (self.lxc_ip, ))
            fo.write('lxc.mount.entry = %s /root none bind 0 0\n' % (os.path.join(self.lxc_env, "rootfs", "root"), ))
            fo.write('lxc.mount.entry = %s /etc/quagga none bind 0 0\n' % (os.path.join(self.lxc_env, "rootfs", "etc", "quagga"), ))
            fo.write('lxc.mount.entry = %s /etc/network/interfaces none bind 0 0\n' % (os.path.join(self.lxc_env, "rootfs", "etc", "network", "interfaces"), ))
            fo.write('lxc.mount.entry = %s /var/run/quagga none bind 0 0\n' % (os.path.join(self.lxc_env, "rootfs", "var", "run", "quagga"), ))
            fo.write('lxc.mount.entry = %s /var/log/quagga none bind 0 0\n' % (os.path.join(self.lxc_env, "rootfs", "var", "log", "quagga"), ))
            fo.write('lxc.mount.entry = %s /var/run/ovs none bind 0 0\n' % (os.path.join(self.lxc_env, "rootfs", "var", "run", "ovs"), ))
        process = Popen(['/usr/bin/lxc-execute', '-n', '%s' % (self.build_name, ), '-f', '%s' % (os.path.join(self.lxc_env, "conf"), ), '/root/init', '&'],
                        stdout=stdout, stderr=stderr, close_fds=True)
        process = Popen(['lxc-wait', '-n', '%s' % (self.build_name, ), '-s', 'RUNNING'], stdout=stdout, stderr=stderr, close_fds=True)
        process.wait()

    def stop(self):
        """Stops container.

        Returns:
            None

        """
        process = Popen(['lxc-stop', '-n', '%s' % (self.build_name, )], stdout=PIPE, close_fds=True)
        process.wait()
        process = Popen(['lxc-wait', '-n', '%s' % (self.build_name, ), '-s', 'STOPPED'], stdout=PIPE, close_fds=True)
        process.wait()
        # try to remove LXC containers files in case lxc-wait did not do this for some reason
        try:
            shutil.rmtree(self.lxc_env)
        except Exception:
            pass
        # try to restore tty settings
        try:
            Popen(["stty", "sane"])
        except Exception:
            pass
