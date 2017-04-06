# Copyright (c) 2014 - 2017, Intel Corporation.
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

"""``multcall.py``

`Implement simple python command line based RPC`

"""

import base64
from functools import partial
import inspect
import json
import pprint
import sys
import bz2
import errno
import itertools

from subprocess import call, Popen, PIPE

from . import remote_multicall_template

# This is run directly on a remote shell, it inlines the decode function.
HEADER = [
    "python -u -c 'import json, base64, bz2; payload = ",
    'json.loads(bz2.decompress(base64.urlsafe_b64decode(r"""',
]

# This our main entry point, we exec the decoded string with payload
# as globals().  WARNING: when using exec this way
# __name__ == '__builtin__' not '__main__'.  This is confusing
FOOTER = [
    '""".encode("utf-8"))).decode("utf-8")); globals().update(payload); exec(payload["module"], globals())',
    "'",
]


def decode(payload_str):
    """Decode base64 encoded bz2 compress network payload

    Args:
        payload_str(str): base64 encoded bz2 compressed byte stream

    Returns:
        str: original byte-stream

    """
    return bz2.decompress(base64.urlsafe_b64decode(payload_str.encode('utf-8')).decode('utf-8'))


def encode(payload):
    """Encode a string for tranmission over the network using base64 encoding of the bz2 compressed string.

    We bz2 compress because we can and also to counteract the inefficiency of the base64 encoding.

    Args:
        payload(str): string we want to transmit over the wire

    Returns:
        str: base64 encoded, bz2 compressed string

    """
    return base64.urlsafe_b64encode(bz2.compress(payload.encode('utf-8'))).decode('utf-8')


# max is 1024**127
PAYLOAD_CUTOFF = 1024 * 96


def bisect_if_too_large(cmd_list, payload_generator, max_size=PAYLOAD_CUTOFF):
    """Check the compressed payload lenght, if it is larger than the max CLI length (usually 127K)
    we bisect until we get under the limit.

    If an individual cmd is greater than the max_size then we will return the original list
    since we can't split a single command.

    Args:
        cmd_list(list): list of commands to split based on encoded payload size
        payload_generator(function): function that generates the payload
        max_size(int): maximun network payload size

    Returns:
        iter(str): iterator over all generator payloads for all the split cmd_list chunks

    """
    # Originally we attempted to check the size as we go and send a batch once we reached the
    # limit, but this was grossly inaccurate because the bz2 compression works better the larger
    # and more repetitve the payload.  Incremental compression estimates were grossly
    # overestimating the payload size.
    #
    # Instead we use the bisect in order to have an accurate size estimate and to speed up
    # the common case.
    first_try = payload_generator(cmd_list)
    payload_len = len(first_try)
    if payload_len < max_size or len(cmd_list) == 1:
        return [first_try]
    else:
        split = len(cmd_list) // 2
        return itertools.chain(bisect_if_too_large(cmd_list[:split], payload_generator, max_size),
                               bisect_if_too_large(cmd_list[split:], payload_generator, max_size))


def generate_calls(cmd_list, parallel_limit=None, remote_module_template=remote_multicall_template):
    """Generate a sequence of simple command line python RPC

    Take the supplied python module, get the source and then
    insert the command list as a base64 encoded bz2 compressed json

    We use the double encoding because there doesn't seem to be a safe
    way to inject JSON into a python module source.
    We know the base64, bz2 encoding is safe and compact, so just re-use that.

    The template uses a line like this, the raw triple-quoted string will be replaced
    with the encoded template::

        cmd_list = json.loads(bz2.decompress(base64.urlsafe_b64decode(r\"\"\"{}\"\"\")))

    Args:
        cmd_list(iter(str)): list of command
        parallel_limit(int): maximum number of parallel commands, None for automatic setting based on number of remote cpus
        remote_module_template(module): python module used as template for remote python module

    """
    # this is only true if cmd_list is consumed
    if iter(cmd_list) is iter(cmd_list):
        # convert to list because we need to bisect if the payload is too large
        cmd_list = list(cmd_list)
    runner = inspect.getsource(remote_module_template)
    # strip out comments
    stripped = "\n".join(l for l in runner.splitlines() if not l.strip().startswith('#'))
    payload_gen = partial(gen_payload, stripped, parallel_limit)
    for batch_payload_str in bisect_if_too_large(cmd_list, payload_gen):
        yield ''.join(itertools.chain(HEADER, [batch_payload_str], FOOTER))


def gen_payload(runner, parallel_limit, cmd_list):
    return encode(
        json.dumps({"module": runner, "cmd_list": cmd_list, "parallel_limit": parallel_limit}))


def _ssh_cli_test():
    """Private function to test RPC on the command line with ssh.

    """
    # this gets the source from a loaded module
    runner = inspect.getsource(remote_multicall_template)
    # strip out comments
    runner_str = "\n".join(l for l in runner.splitlines() if not l.strip().startswith('#'))
    print(runner_str)

    cmd_list = [["echo", "bridge", "fdb", "create", "vlan", str(vlan)] for vlan in range(4095)]
    payload_gen = partial(gen_payload, runner_str, None)

    for batch_payload_str in bisect_if_too_large(cmd_list, payload_gen, 1024 * 3):
        cmd_line = ''.join(itertools.chain(HEADER, [batch_payload_str], FOOTER))
        cmd_line = cmd_line.encode('utf-8')
        print("cmd_line len = %s" % len(cmd_line))
        # convert to back to bytes before sending
        proc = Popen(["ssh"] + sys.argv[1:] + [cmd_line], stdout=PIPE,
                     stderr=PIPE)
        output, err = proc.communicate()
        if err:
            print(err)
        else:
            try:
                results = json.loads(output.decode('utf-8'))
            except ValueError:
                sys.stderr.write(output)
            else:
                pprint.pprint(results)


def _test_env_var_size():
    # max seems to be 1024 * 127
    """Private function to verify the maximum command line payload size.

    This should be smatter and bisect, but it doesn't

    """
    for f in range(256, 100, -1):
        payload = 'a' * 1024 * f
        try:
            cmd = ["ssh", "-t"] + sys.argv[1:] +\
                  ["wc -c  <<<'{}' ; sleep 0.2 ; exit".format(payload)]
            if call(cmd) == 0:
                print("%s is good" % f)
                print(len(payload))
                break
        except OSError as e:
            if e.errno == errno.E2BIG:
                pass


if __name__ == "__main__":
    try:
        _arg = sys.argv.pop(1)
    except IndexError:
        pass
    else:
        if _arg == "test":
            _ssh_cli_test()
        elif _arg == "env":
            _test_env_var_size()
