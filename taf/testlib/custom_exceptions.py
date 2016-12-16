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

@file  custom_exceptions.py

@summary  Class to handle custom exceptions with basic introspection.
"""

import sys
import traceback

from . import loggers


class CustomException(Exception):
    """
    @description  Base class to handle custom exceptions with basic introspection.
    """

    class_logger = loggers.ClassLogger(for_exception=True)

    def __init__(self, value, trace=False):
        """
        @brief  Initialize CustomException class
        """
        self.class_logger.error(value)
        if trace:
            exc_type, exc_value, exc_tb = sys.exc_info()
            traceback_message = traceback.format_exception(exc_type, exc_value, exc_tb)
            self.class_logger.error("Traceback:\n{0}".format("".join(traceback_message)))
        self.parameter = value

    def __str__(self):
        """
        @brief  String representation
        """
        return repr(self.parameter)


class TAFCoreException(CustomException):
    """
    @description  Base class to handle Switch operation exceptions with basic introspection.
    """
    pass


class SwitchException(CustomException):
    """
    @description  Base class to handle Switch operation exceptions with basic introspection.
    """
    pass


class TGException(CustomException):
    """
    @description  General TG exception.
    """
    pass


class IxiaException(TGException):
    """
    @description  Base class to handle IXIA exceptions with basic introspection.
    """
    pass


class PypackerException(TGException):
    """
    @description  Base class to handle Pypacker exceptions with basic introspection.
    """
    pass


class HubException(CustomException):
    """
    @description  Base class to handle Hub exceptions with basic introspection.
    """
    pass


class CrossException(CustomException):
    """
    @description  Base class to handle Xconnect exceptions with basic introspection.
    """
    pass


class TAFLegacyException(CustomException):
    """
    @description  Base class to handle Pypacker exceptions with basic introspection.
    """
    pass


class OvsControllerException(CustomException):
    """
    @description  Base class to handle Ovs Controller exceptions with basic introspection.
    """
    pass


class AFSException(CustomException):
    """
    @description  Base class to handle AFS exceptions with basic introspection.
    """
    pass


class CLIException(CustomException):
    """
    @description  Base class to handle CLI exceptions with basic introspection.
    """
    pass


class ConnPoolException(CustomException):
    """
    @description  Base class to handle ConnPoll exceptions with basic introspection.
    """
    pass


class SysLogException(CustomException):
    """
    @description  Base class to handle SysLog exceptions with basic introspection.
    """
    pass


class CLISSHException(CLIException):
    """
    @description  Base class to handle clissh exceptions with basic introspection.
    """
    pass


class CLITelnetException(CLIException):
    """
    @description  Base class to handle clitelnet exceptions with basic introspection.
    """
    pass


class CLINNSException(CLIException):
    """
    @description  Base class to handle clinns exceptions with basic introspection.
    """
    pass


class CLICMDException(CustomException):
    """
    @description  Base class to handle clicmd exceptions with basic introspection.
    """
    pass


class UIException(CustomException):
    """
    @description  Base class to handle test_ui exceptions with basic introspection.
    """
    pass


class UICmdException(UIException):
    """
    @description  Base class to handle test_ui command exceptions with basic introspection.
    """

    def __init__(self, value, command, stdout, stderr, rc, trace=False):
        super(UICmdException, self).__init__(value, trace)
        self.command = command
        self.stdout = stdout
        self.stderr = stderr
        self.rc = rc

# Abstracted Error Types


class AccessError(UIException):
    """
    @description  Abstracted error class for any access errors.
    """
    pass


class ArgumentError(UIException):
    """
    @description  Abstracted error class for any argument errors.
    """
    pass


class BoundaryError(UIException):
    """
    @description  Abstracted error class for any boundary errors.
    """
    pass


class ExistsError(UIException):
    """
    @description  Abstracted error class for any duplication errors.
    """
    pass


class InvalidCommandError(UIException):
    """
    @description  Abstracted error class for any naming errors.
    """
    pass


class InvalidNameError(UIException):
    """
    @description  Abstracted error class for any naming errors.
    """
    pass


class NotExistsError(UIException):
    """
    @description  Abstracted error class for accessing non-existent parameters.
    """
    pass


class OpenStackNoSuchImage(Exception):
    pass


class SshExecCommandFailed(Exception):
    def __init__(self, command, ret):
        self.cmd = command
        self.ret = ret

    def __str__(self):
        return """\
Command '{0.cmd}' failed
Stdout: '{0.ret.stdout}'
Stderr: '{0.ret.stderr}'
rc: '{0.ret.rc}'
""".format(self)


class ToolException(CustomException):
    """
    @description  Base class to handle Linux Tool operation exceptions with basic introspection.
    """
    pass


class TrexException(TGException):
    """
    @description  Base class to handle TRex exceptions with basic introspection.
    """
    pass


class CmdArgsException(CustomException):
    """
    @description  Base class to handle command arguments exceptions with basic introspection.
    """
    pass


class UnknownArguments(CmdArgsException):
    def __init__(self, **kwargs):
        if kwargs:
            _unk_args = ['"{}"'.format(k) for k in kwargs]
            _unk_args_str = ', '.join(_unk_args)
            self.parameter = 'Unknown arguments({0}): {1}'.format(len(_unk_args), _unk_args_str)


class ArgumentsCollision(CmdArgsException):
    def __init__(self, **kwargs):
        if kwargs:
            _coll_args = ['{0[0]!r}:{0[1]!r}'.format(item) for item in kwargs.items()]
            _coll_args_str = ', '.join(_coll_args)
            self.parameter = "Colliding arguments({0}): {1}".format(len(_coll_args),
                                                                    _coll_args_str)
