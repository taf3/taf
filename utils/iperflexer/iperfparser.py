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
# python Standard Library
from collections import defaultdict
import os

# this code
from .baseclass import BaseClass

from .iperfexpressions import HumanExpression, ParserKeys
from .iperfexpressions import CsvExpression
from .unitconverter import UnitConverter, IperfbinaryConverter, BinaryUnitNames
from .coroutine import coroutine

MAXIMUM_BANDWITH = 10**9

class IperfParser(BaseClass):
    """
    The Iperf Parser extracts bandwidth and other information from the output
    """
    def __init__(self, expected_interval=1, interval_tolerance=0.1, units="Mbits",
                 threads=1, 
                 maximum=MAXIMUM_BANDWITH):
        """
        IperfParser Constructor
        
        :param:

         - `expected_interval`: the seconds between sample reports
         - `interval_tolerance`: upper bound of difference between actual and expected
         - `units`: desired output units (must match iperf output case - e.g. MBytes)
         - `threads`: (number of threads) needed for coroutine and pipe
         - `maximum`: the max value (after conversion) allowed (if exceeded converts to 0)
        """
        super(IperfParser, self).__init__()
        self._logger = None
        self.expected_interval = expected_interval
        self.interval_tolerance = interval_tolerance
        self.units = units
        self.threads = threads
        self.maximum = maximum
        self._regex = None
        self._human_regex = None
        self._csv_regex = None
        self._combined_regex = None

        self.intervals = defaultdict(lambda: 0)
        self.transfer_intervals = defaultdict(lambda: 0)
        self._threads = None
        self.format = None
        self._bandwidths = None
        self._transfers = None        
        self.thread_count = 0
        self.current_thread = None
        self.conversion = UnitConverter()
        self.binary_converter = IperfbinaryConverter()
        self._transfer_units = None
        return

    @property
    def transfer_units(self):
        """
        a hack to handle the fact that only the bandwidth units are being specified
        """
        if self._transfer_units is None:
            prefix = self.units[0]
            suffix = BinaryUnitNames.iperf_bytes
            if prefix == 'b':
                self._transfer_units = suffix
            else:
                self._transfer_units = "{0}{1}".format(prefix,
                                                       suffix)
        return self._transfer_units

    def traverse(self, intervals):
        """
        traverses the intervals, infilling missing intervals

        :param:
          - `intervals`: default dict of interval:value
        :yield: next value for the interval
        """
        # this was created because I was going to infill zeros
        # but studying the iperf reporting made me decide it
        # is a bad idea
        for actual in sorted(intervals):
            yield intervals[actual]
        return
    
    @property
    def bandwidths(self):
        """
        Traverses self.interval's keys in sorted order and generates their bandwidths.
        
        :yield: self.interval's values in the sorted order of the intervals
        """
        return self.traverse(self.intervals)

    @property
    def transfers(self):
        """
        generator of transfer values

        :yield: converted transfer interval values
        """
        return self.traverse(self.transfer_intervals)

    @property
    def regex(self):
        """
        A dictionary holding the regular expressions for the 2 formats
        
        :return: format:regex dictionary
        """
        if self._regex is None:
            self._regex = {ParserKeys.human:HumanExpression().regex,
                           ParserKeys.csv:CsvExpression().regex}
        return self._regex

    def valid(self, match):
        """
        :param:

         - `match`: a groupdict containing parsed iperf fields

        :return: True if the end-start interval is valid (within tolerance)
        """
        start, end = float(match[ParserKeys.start]), float(match[ParserKeys.end])
        return (end - start) - self.expected_interval < self.interval_tolerance

    def bandwidth(self, match):
        """
        :param:

         - `match`: A parsed match group dictionary

        :rtype: float
        :return: the bandwidth in the self.units
        """
        try:
            units = match[ParserKeys.units]
        except KeyError:
            # assume a csv-format
            units = 'bits'
        try:
            # if the value is big enough vs the units it will be an int
            # e.g. 113 MBytes is an int but 11.1 MBytes reports a float
            # so favor an int
            bandwidth = int(match[ParserKeys.bandwidth])
        except ValueError:
            # ints will raise an error if passed something with a decimal point
            bandwidth = float(match[ParserKeys.bandwidth])
        b = self.conversion[units][self.units] * bandwidth
        if b > self.maximum:
            return 0.0
        return b

    def transfer(self, match):
        """
        :param:

         - `match`: A parsed match group dictionary

        :rtype: float
        :return: the transfer in the self.units
        """
        try:
            units = match[ParserKeys.transfer_units]
        except KeyError:
            # assume a csv-format
            units = BinaryUnitNames.iperf_bytes

        try:
            transfer = int(match[ParserKeys.transfer])
        except ValueError:
            transfer = float(match[ParserKeys.transfer])
        transfer = self.binary_converter[units][self.transfer_units] * transfer
        if transfer > self.maximum:
            return 0
        return transfer

    def __call__(self, line):
        """
        :param:

         - `line`: a line of iperf output

        :return: bandwidth or None
        """
        match = self.search(line)
        bandwidth = None
        if match is not None and self.valid(match):
            interval_start = float(match[ParserKeys.start])
            self.thread_count = (self.thread_count + 1) % self.threads
            self.intervals[interval_start] += self.bandwidth(match)
            self.transfer_intervals[interval_start] += self.transfer(match)
            if self.thread_count == 0:
                self.current_thread = float(match[ParserKeys.start])
                bandwidth = self.intervals[self.current_thread]
        return bandwidth
    
    def search(self, line):
        """
        :param:

         - `line`: a string of iperf output
        :return: match dict or None
        """
        try:
            return self.regex[self.format].search(line).groupdict()
        except KeyError:
            self.logger.debug("{0} skipped, format not set".format(line))
        except AttributeError:
            pass

        try:
            match = self.regex[ParserKeys.human].search(line).groupdict()
            self.logger.debug("Matched: {0}".format(line))            
            self.format = ParserKeys.human
            self.logger.debug("Setting format to {0}".format(self.format))
            return match
        except AttributeError:
            pass

        try:
            match = self.regex[ParserKeys.csv].search(line).groupdict()
            self.logger.debug("Matched: {0}".format(line))
            self.format = ParserKeys.csv
            self.logger.debug("Setting format to {0}".format(self.format))
            return match
        except AttributeError:
            pass
        return

    @coroutine
    def pipe(self, target):
        """
        A coroutine to use in a pipeline
        
        :warnings:

         - For bad connections with threads this might break (as the threads die)
         - Use for good connections or live data only (use `bandwidths` and completed data for greater fidelity)
         
        :parameters:

         - `target`: a target to send matched output to

        :send:

         - bandwidth converted to self.units as a float
        """
        threads = defaultdict(lambda: [0, 0])
        thread_count = 0
        bandwidth = 1
        while True:
            line = (yield)
            match = self.search(line)
            if match is not None and self.valid(match):
                # threads is a dict of interval:(thread_count, bandwidths)
                interval = match[ParserKeys.start]
                threads[interval][thread_count] += 1
                threads[interval][bandwidth] += self.bandwidth(match)
                for key in threads:
                    if key == min(threads) and threads[interval][thread_count] == self.threads:
                        target.send(threads[interval][bandwidth])
        return
    
    def reset(self):
        """
        Resets the attributes set during parsing
        """
        self.format = None
        self._interval_threads = None
        self._intervals = None
        self._thread_count = None
        self._threads = None
        return

    def filename(self, basename):
        """
        Changes the extension of the basename to .csv
        
        :param:

         - `basename`: a the raw-iperf filename (without path)

        :return: the filename with the extension changed to .csv
        """
        base, ext = os.path.splitext(basename)
        return "{0}.csv".format(base)
# end class IperfParser
