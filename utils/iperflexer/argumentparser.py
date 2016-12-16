"""
Copyright (c) 2014 Russell Nakamura

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software,
and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
# python standard library
import argparse
import subprocess


if __name__ == '__builtin__':
    # we're in pweave
    print(subprocess.check_output('parseiperf -h'.split()))


class Arguments(object):
    """
    An adapter for the argparse.ArgumentParser
    """
    def __init__(self):
        self._parser = None
        return

    @property
    def parser(self):
        """
        :return: ArgumentParser 
        """
        if self._parser is None:
            self._parser = argparse.ArgumentParser()
        return self._parser

    def parse_args(self):
        """
        :return: namespace with command-line arguments
        """
        self.parser.add_argument("-g", "--glob",
                                 help="A file-glob to match input file names. (default=%(default)s)",
                                 default=None)

        self.parser.add_argument("-u", "--units",
                                 help="Output units per second [bits,Bytes,KBits,KBytes,Mbits,MBytes,Gbits,GBytes] (default=%(default)s)",
                                 default="Mbits")

        self.parser.add_argument('-i', '--interval',
                                 help="Reporting intervals (default=%(default)s)",
                                 default=1, type=float)

        self.parser.add_argument('--tolerance',
                                 help='Interval tolerance (if parsed interval differs from expected by more than tolerance, assume summation lines) (default=%(default)s)',
                                 default=0.1, type=float)

        self.parser.add_argument('-s', '--save',
                                 help="If  glob is provided, save to a file instead of sending to stdout. (default=%(default)s)",
                                 default=False,
                                 action="store_true")

        self.parser.add_argument("-v", "--voodoo",
                                 help="Add threads yourself instead of using 'sum' lines. (default=%(default)s)",
                                 action="store_true", default=False)

        self.parser.add_argument('--pudb',
                                 help="Enable pudb (if installed). (default=%(default)s)",
                                 default=False,                        
                                 action="store_true")

        self.parser.add_argument('--pdb',
                                 help="Enable pdb (default=%(default)s)",
                                 default=False, action="store_true")

        self.parser.add_argument("-t", '--tee',
                                 help="Send lines standard error as they come in. (default=%(default)s)",
                                 default=False,
                                 action="store_true")

        self.parser.add_argument('-p', '--threads',
                                 help="Specify thread count (default=%(default)s)",
                                 default=4, type=int)

        self.parser.add_argument("-m", "--maximum",
                                 help="Maximum allowed bandwidth (default=%(default)s)",
                                 default=1000000, type=int)
        self.parser.add_argument('-l', '--lastlinebandwidth',
                                 help="Get Iperf's final bandwidth value (default=%(default)s)",
                                 default=False, action="store_true")
        self.parser.add_argument('-d', '--lastlinetransfer',
                                 help="Get Iperf's final reported data transfer (default=%(default)s)",
                                 default=False, action="store_true")
        return self.parser.parse_args()
# end class Arguments
