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


"""``ixia_helpers.py``

`Helpers functions for Ixia environment`
"""

import os
import time

from ..clissh import CLISSH


def ixtclhal_import(tcl_object):
    """Import IxTclHal package

    Args:
        tcl_object(Tkinter.Tcl):  Tcl interpreter

    Returns:
        None

    """
    command = ("catch {package require nonexistentName};" +
               "set available_packets_list [package names];" +
               "if {[lsearch $available_packets_list IxTclHal] > -1} {" +
               "        if {! [info exists env(IXIA_VERSION)]} {" +
               "                    puts \"Setting IXIA_VERSION ...\";" +
               "                    set env(IXIA_VERSION) [lindex [package versions IxTclHal] 0];" +
               "                    };" +
               "        package req IxTclHal;" +
               "} {" +
               "        return -code error \"Cannot import IxTclHal package.\";" +
               "}"
               )
    tcl_object.eval(command)


def ixload_import(tcl_object):
    """Import IxLoad package.

    Args:
        tcl_object(Tkinter.Tcl):  Tcl interpreter

    Returns:
        None

    Notes:
        IxTclHal package should be already imported

    """
    tcl_object.eval("catch {package require nonexistentName};" +
                    "set available_packets_list [package names];" +
                    "if {[lsearch $available_packets_list IxLoad] > -1} {" +
                    "    set ixload_package_version [lindex [package versions IxLoad] 0];" +
                    "    if {! [info exists env(IXLOAD_[string map {. _} $ixload_package_version]_INSTALLDIR)]} {" +
                    "      puts \"Setting IXLOAD_VERSION_INSTALLDIR for $ixload_package_version\";" +
                    "      set env(IXLOAD_[string map {. _} $ixload_package_version]_INSTALLDIR) [lindex [package ifneeded IxLoad $ixload_package_version] 1]" +
                    "      };" +
                    "      package req IxLoad;" +
                    "} {" +
                    "    return -code error \"Cannot import IxLoad package.\";" +
                    "}",
                    )


def tcl_puts_replace(tcl_interpret):
    """Replace original tcl puts function with new tcl_puts function for logging tcl output

    Args:
        tcl_interpret(Tkinter.Tcl):  Tcl interpreter

    Returns:
        None

    """
    tcl_interpret.eval("rename puts original_puts;" +
                       "proc puts {args} {" +
                       "    if {[llength $args]==2} {" +
                       "        if {\"[lindex $args 0]\" == \"stdout\"" +
                       "           || \"[lindex $args 0]\" == \"stderr\"} {" +
                       "            eval tcl_puts $args" +
                       "        } else {" +
                       "                eval original_puts $args" +
                       "        }" +
                       "    } elseif {[llength $args] == 1} {" +
                       "        eval tcl_puts $args" +
                       "    } else {" +
                       "        eval original_puts $args" +
                       "    }" +
                       "}",
                       )


def get_tcl_client_info(dst_file=None, tcl_srv_ip=None, tcl_srv_usr=None, tcl_srv_pass=None):
    """Get local or remote Tcl client version info.

    Args:
        dst_file(str):  Path to file to be written
        tcl_srv_ip(str):  Tcl server IP address
        tcl_srv_usr(str):  Tcl server user
        tcl_srv_pass(str):  Tcl user password

    Returns:
        str: Tcl client info

    """
    # Capture Tcl client info
    cmd1 = ("python -c \"import Tkinter; print Tkinter.Tcl().eval(" +
            "'package req Ixia')\"")
    cmd2 = ("python -c \"import Tkinter; print Tkinter.Tcl().eval(" +
            "'package req IxTclHal; puts IxLoad; package req IxLoad')\"")
    cmd = cmd1 + "; " + cmd2
    rc = ""
    if tcl_srv_ip is not None:
        ssh = CLISSH(tcl_srv_ip, 22, tcl_srv_usr, tcl_srv_pass)
        ssh.login()
        ssh.open_shell()
        # Clear receive buffer.
        ssh.shell.sendall("\n")
        time.sleep(1)
        if ssh.shell.recv_ready():
            ssh.shell.recv(4096)
        # Send command to obtain tcl client info
        ssh.shell.sendall(cmd + "\n")
        time.sleep(1)
        end_time = time.time() + 60
        while ssh.shell.recv_ready():
            if time.time() > end_time:
                rc += "Timeout exceeded. Closing shell..."
                break
            rc += ssh.shell.recv(1024)
            time.sleep(3)
        ssh.close()
    else:
        rcd = os.popen(cmd)
        rc = rcd.read()
        rcd.close()

    # Write to file.
    if dst_file is not None:
        fw = open(dst_file, "w+")
        fw.write(rc + "\n")
        fw.close()

    return rc
