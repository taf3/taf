"""
@copyright Copyright (c) 2016 - 2017, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file: invoke_test.py

"""
import time
import json
import os
import subprocess
import etcd
import socket
import fcntl
import struct
import re
from contextlib import closing, suppress
from functools import wraps
from io import StringIO


_LOCAL_DEFAULT = object()


class InvokeError(Exception):

    def __init__(self, message=None):
        super(InvokeError, self).__init__(message if message is not None else 'Unknown error')


def print_and_return_value(value, attr_name=_LOCAL_DEFAULT, key_name=_LOCAL_DEFAULT,
                           call_name=_LOCAL_DEFAULT, *args, **kwargs):
    if attr_name is not _LOCAL_DEFAULT:
        print(getattr(value, str(attr_name)))
    elif key_name is not _LOCAL_DEFAULT:
        print(value[key_name])
    elif call_name is not _LOCAL_DEFAULT:
        print(getattr(value, str(call_name))(*args, **kwargs))
    else:
        print(value)
    return value


class PrintAndReturnValueWrapper(object):

    def __init__(self, attr_name=_LOCAL_DEFAULT, key_name=_LOCAL_DEFAULT, call_name=_LOCAL_DEFAULT,
                 *args, **kwargs):
        super(PrintAndReturnValueWrapper, self).__init__()
        self.attr_name = attr_name
        self.key_name = key_name
        self.call_name = call_name
        self.args = args
        self.kwargs = kwargs

    def __call__(self, func):
        @wraps(func)
        def inner(*args, **kwargs):
            return print_and_return_value(func(*args, **kwargs), self.attr_name, self.key_name,
                                          self.call_name, *self.args, **self.kwargs)
        return inner


value_print_wrapper = PrintAndReturnValueWrapper()
value_attr_print_wrapper = PrintAndReturnValueWrapper('value')


class CommandExecution(object):

    CONNECTION_ATTEMPTS = 3
    BAD_OUTPUT_STRING_LIST = []

    def __init__(self, json_dict, caller):
        super().__init__()
        self.name = ''
        self.toggle_flags = []
        self.special_keys = []
        self.json_dict = json_dict
        self.caller = caller
        self.command = None
        self.process = None
        self.output = None
        self.error_output = None

    def prepare(self):
        self.command = self._parse_json()

    def _is_special_key(self, key):
        return key in self.special_keys

    def _is_toggle_key(self, key, value):
        return key in self.toggle_flags

    def _inject_after_binary(self, str_buffer):
        pass

    def _append_to_command(self, str_buffer):
        pass

    @value_print_wrapper
    def _parse_json(self):
        str_buffer = StringIO()
        str_buffer.write(self.name)
        str_buffer.write(' ')

        self._inject_after_binary(str_buffer)
        for key, value in self.json_dict.items():
            if self._is_special_key(key):
                continue
            str_buffer.write(' -')
            str_buffer.write(key)
            if not self._is_toggle_key(key, value):
                str_buffer.write(' ')
                str_buffer.write(str(value))

        self._append_to_command(str_buffer)
        return str_buffer.getvalue()

    def got_good_output(self):
        if not self.caller.server_ip:
            # server processes never fail
            return True

        if self.process.returncode != 0:
            return False

        return not any(bad_string in self.output for bad_string in self.BAD_OUTPUT_STRING_LIST)

    def run(self):
        for try_count in range(self.CONNECTION_ATTEMPTS):
            self.process = subprocess.Popen(self.command, shell=True, stdout=subprocess.PIPE)
            self.output, self.error_output = self.process.communicate()

            if self.got_good_output():
                self.caller.write_final_result(self.output, self.error_output)
                return self.output, self.error_output

            self.caller.write_bad_result(try_count, self.output)


class IperfExecution(CommandExecution):

    BAD_OUTPUT_STRING_LIST = [
        'error',
    ]

    def __init__(self):
        super().__init__()
        self.name = "iperf3 "
        self.toggle_flags = [
            'J',
            's',
            '4',
            '6',
            'u',
        ]

    def _append_to_command(self, str_buffer):
        if self.caller.server_ip:
            str_buffer.write('-c ')
            str_buffer.write(self.caller.server_ip)


class NetperfExecution(CommandExecution):

    BAD_OUTPUT_STRING_LIST = [
        "could not establish the control connection",
        "errno",
    ]

    def __init__(self):
        super().__init__()
        if self.caller.server_ip:
            self.name = "netperf"
        else:
            self.name = "netserver"

        self.toggle_list = [
            'D',
            'f',
            '4',
            '6',
        ]

    def _inject_after_binary(self, str_buffer):
        if self.caller.server_ip:
            str_buffer.write('-H ')
            str_buffer.write(self.caller.server_ip)


class NginxExecution(CommandExecution):

    NGINX_CONF_FILE_PATH = "/etc/nginx/nginx.conf"

    def __init__(self):
        super().__init__()
        self.name = "nginx"

    def _is_special_key(self, key):
        return True

    def _inject_after_binary(self, str_buffer):
        self._rewrite_nginx_conf_file()

    def _make_conf_line(self, key, value):
        if self._is_toggle_key(key, value):
            return '\t{0};\n'.format(key)
        return '\t{0} {1};\n'.format(key, value)

    def _rewrite_nginx_conf_file(self):
        if not self.json_dict:
            return

        new_events = [self._make_conf_line(key, value) for key, value in self.json_dict.items()]
        with open(self.NGINX_CONF_FILE_PATH) as handle:
            lines_list = handle.readlines()

        lines_iter = iter(enumerate(lines_list))
        # Find where events tag starts
        events_start_index = next((index for index, line in lines_iter
                                   if line.startswith('events {')), 0)
        # Find where events tag end
        events_end_index = next((index for index, line in lines_iter if line.startswith('}')), 0)

        with open(self.NGINX_CONF_FILE_PATH, 'w') as handle:
            handle.writelines(lines_list[0:events_start_index + 1])
            # Insert and replace parameter into events{} of the .conf file
            handle.writelines(new_events)
            handle.writelines(lines_list[events_end_index:])


class ApacheBenchExecution(CommandExecution):

    def __init__(self):
        super().__init__()
        self.name = 'ab'
        self.special_keys = ['custom_path']

    def _is_toggle_key(self, key, value):
        return isinstance(value, bool)

    def _append_to_command(self, str_buffer):
        if not self.caller.server_ip:
            return
        str_buffer.write(' ')
        str_buffer.write('http://')
        str_buffer.write(self.caller.server_ip)
        str_buffer.write('/')
        str_buffer.write(self.json_dict.get('custom_path', ''))


def get_ip_address(ifname):
    """
    Adapted from
    http://code.activestate.com/recipes/439094-get-the-ip-address-associated-with-a-network-inter/
    :author: Paul Cannon http://code.activestate.com/recipes/users/2551140/
    :license: PSF
    :param ifname: interface name
    :type ifname: str
    :return: IP address
    :rtype: str
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
        )[20:24])


def try_int(s):
    """"Convert to integer if possible."""
    with suppress(ValueError, TypeError):
        return int(s)
    return s


def natural_sort_key(s):
    """Used internally to get a tuple by which s is sorted."""
    return tuple(map(try_int, re.findall(r'(\d+|\D+)', s)))


def natural_case_key(s):
    return natural_sort_key(s.key.lower())


class ExecutionPlace(object):

    HELP_OUTPUT = ("server usage: docker run -ti -e INPUT_DATA=host:port:key_path "
                   "fedora/test python /home/parse_data_03.py\n"
                   "client usage: docker run -ti -e INPUT_DATA=host:port:key_path "
                   "-e CLIENT_ID=123 fedora/test python /home/parse_data_03.py")

    WRITE_ATTEMPTS = 3
    READ_ATTEMPTS = WRITE_ATTEMPTS

    LATEST_BOILERPLATE = "{0.base_path}/latest"
    TEST_PATH_BOILERPLATE = "{0.base_path}/test-{1}/"
    CONFIG_DATA_SUB_KEY_BOILERPLATE = ''

    READY_SUB_KEY_BOILERPLATE = '{0.name}'
    CONNECTION_ERROR_SUB_KEY_BOILERPLATE = ('result-establish-connection-error{1}/'
                                            'client-{0.client_id}')
    RESULT_ERROR_SUB_KEY_BOILERPLATE = 'result-getting-results-error/client-{0.client_id}'
    RESULT_SUB_KEY_BOILERPLATE = 'result/client-{0.client_id}'

    @classmethod
    def parse_input_data(cls, input_data):
        with suppress(TypeError, IndexError):
            input_words = input_data.split(":")
            return input_words[0], input_words[1], input_words[2]
        print(cls.HELP_OUTPUT)
        raise InvokeError("Invalid INPUT_DATA")

    def __init__(self, client_id=None, input_data=None, *args, **kwargs):
        super().__init__()

        self.executor = None
        self.ip = None
        self.name = 'UNKNOWN'
        self.client_id = client_id
        self.server_id = None
        self.server_ip = None

        host, port, self.base_path = self.parse_input_data(input_data)
        self.etcd_client = etcd.Client(host=host, port=int(port), allow_reconnect=True)

        base_data = print_and_return_value(
            self.etcd_read_data(self.LATEST_BOILERPLATE.format(self)),
            attr_name='value')
        self.test_path = print_and_return_value(
            self.TEST_PATH_BOILERPLATE.format(
                self,
                base_data.value   # pylint: disable=no-member
            )
        )

    @value_attr_print_wrapper
    def _get_config_data(self):
        data_path = self.make_input_key(self.CONFIG_DATA_SUB_KEY_BOILERPLATE)

        for try_count in range(self.READ_ATTEMPTS):
            with suppress(etcd.EtcdKeyNotFound):
                return self.etcd_read_data(data_path, True)
            time.sleep(1)

        raise InvokeError('Unable to read data path')

    def parse_json(self):
        data = self._get_config_data()

        try:
            json_data = json.loads(data.value)  # pylint: disable=no-member
        except ValueError:
            raise InvokeError('Failed to parse JSON data')

        # simple ordered dict
        command_execution_pairs = [
            ('ab', ApacheBenchExecution),
            ('nginx', NginxExecution),
            ('netperf', NetperfExecution),
            ('iperf', IperfExecution),
        ]

        for command_type, exec_class in command_execution_pairs:
            with suppress(KeyError):
                return exec_class(json_data[command_type], self)

        raise InvokeError('No command found to parse')

    def etcd_read_data(self, path, read_list=False):
        for try_count in range(self.READ_ATTEMPTS):
            with suppress(etcd.EtcdKeyNotFound):
                return self.etcd_client.read(path, recursive=read_list, sorted=read_list)
            time.sleep(1)

        raise InvokeError("etcd_client.read failed {}".format(path))

    def etcd_wait_for_data(self, path, timeout):
        while True:
            with suppress(Exception):
                data = self.etcd_client.read(path)
                return data
            time.sleep(timeout)

    def etcd_write_data(self, path, value):
        for try_count in range(self.WRITE_ATTEMPTS):
            with suppress(Exception):
                self.etcd_client.write(path, value)
                return
            time.sleep(1)

        raise InvokeError("unable to write {}".format(path))

    def prepare(self):
        raise NotImplementedError()

    def run(self):
        print('Running test command')
        self._run()

    def _run(self):
        raise NotImplementedError()

    @value_print_wrapper
    def make_test_path_key(self, sub_key, *args, **kwargs):
        return ''.join(['{0.test_path}', sub_key]).format(self, *args, **kwargs)

    def make_input_key(self, sub_key, *args, **kwargs):
        return self.make_test_path_key(''.join(['inputdata/', sub_key]), *args, **kwargs)

    def make_output_key(self, sub_key, *args, **kwargs):
        return self.make_test_path_key(''.join(['outputdata/', sub_key]), *args, **kwargs)

    def write_bad_result(self, count, output):
        self.etcd_write_data(self.make_output_key(
            self.CONNECTION_ERROR_SUB_KEY_BOILERPLATE.format(self, count)), output)

    def write_final_result(self, output, error_output):
        self.etcd_write_data(
            self.make_output_key(self.RESULT_SUB_KEY_BOILERPLATE.format(self)),
            output)
        self.etcd_write_data(
            self.make_output_key(self.RESULT_ERROR_SUB_KEY_BOILERPLATE.format(self)),
            error_output)


class ExecutionServer(ExecutionPlace):

    CONFIG_DATA_SUB_KEY_BOILERPLATE = "server"

    SERVER_IP_OUTPUT_PATH_BOILERPLATE = 'server/{0.name}'

    @staticmethod
    @value_print_wrapper
    def _get_name():
        with open('/etc/hostname', 'r') as file_handle:
            return next(file_handle, None)

    @staticmethod
    @value_print_wrapper
    def _get_ip():
        return get_ip_address(b'eth0')

    def prepare(self):
        self.executor = self.parse_json()
        self.ip = self._get_ip()
        self.name = self._get_name().strip()
        self.etcd_write_data(self.make_output_key(self.SERVER_IP_OUTPUT_PATH_BOILERPLATE), self.ip)
        self.executor.prepare()

    def _run(self):
        self.executor.run()
        print('This is a server so no need to save any statistics')


class ExecutionClient(ExecutionPlace):

    CONFIG_DATA_SUB_KEY_BOILERPLATE = "client"

    SERVER_DATA_SUB_KEY_BOILERPLATE = 'server/'
    SERVER_START_SUB_KEY_BOILERPLATE = 'start'
    SERVER_START_TIME_SUB_KEY_BOILERPLATE = 'starttime'

    READY_SUB_KEY_BOILERPLATE = 'state/client-{0.client_id}-is-ready-{0.server_ip}'
    CONNECTION_ERROR_SUB_KEY_BOILERPLATE = ('result-establish-connection-error{1}/'
                                            'client-{0.client_id}')
    RESULT_ERROR_SUB_KEY_BOILERPLATE = 'result-getting-results-error/client-{0.client_id}'
    RESULT_SUB_KEY_BOILERPLATE = 'result/client-{0.client_id}'

    def __init__(self, client_id=None, input_data=None, *args, **kwargs):
        super(ExecutionClient, self).__init__(int(client_id), input_data, *args, **kwargs)

    def prepare(self):
        master = self.etcd_read_data(
            self.make_output_key(self.SERVER_DATA_SUB_KEY_BOILERPLATE),
            True)
        server_list = list(master.children)
        server_count = len(server_list)
        print(server_count)

        if server_count < self.client_id:
            raise InvokeError("len(servers) < client_id")
        elif self.client_id < 1:
            raise InvokeError("client_id should positive value")

        server_list.sort(key=natural_case_key)
        server = server_list[self.client_id - 1]
        self.server_id = server.key
        self.server_ip = server.value
        print("Client {0.client_id} connects to {0.server_id} (IP: {0.server_ip})".format(self))

        self.executor = self.parse_json()

        self.executor.prepare()

        server_path = self.make_output_key(self.READY_SUB_KEY_BOILERPLATE).format(self.client_id,
                                                                                  self.server_ip)
        self.etcd_write_data(server_path, self.server_id)

        self.etcd_wait_for_data(self.make_input_key(self.SERVER_START_SUB_KEY_BOILERPLATE), 0.5)
        start_time = int(self.etcd_wait_for_data(
            self.make_input_key(self.SERVER_START_TIME_SUB_KEY_BOILERPLATE), 1).value.strip())
        now = int(time.time())

        if start_time > now:
            sleep_time = start_time - now
            print("Sleeping for {} seconds".format(sleep_time))
            time.sleep(sleep_time)
        elif not os.environ.get('DEBUG_SLEEP', 0):
            # for debugging purposes it is good to start even if it is late
            # (happens in debugger)
            raise InvokeError("Too late to start the executor.")

    def _run(self):
        if self.server_id is None:
            raise InvokeError('Client run before prepared or there was an undetected error '
                              'during prepare')
        self.executor.run()


def make_executor():
    input_data = os.environ.get('INPUT_DATA')
    with suppress(KeyError, TypeError, ValueError):
        return ExecutionClient(os.environ['CLIENT_ID'], input_data)
    return ExecutionServer(input_data=input_data)


def main():
    executor = make_executor()
    executor.prepare()
    executor.run()
    print('The test is finished')


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(e)
        debug_sleep_time = os.environ.get('DEBUG_SLEEP', 0)
        time.sleep(int(debug_sleep_time))
