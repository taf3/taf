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
import os

# this package
from .iperfparser import IperfParser 
from .iperfexpressions import HumanExpression, ParserKeys, CsvExpression
from . import oatbran as bran
from .coroutine import coroutine


class HumanExpressionSum(HumanExpression):
    """
    Changes the thread-column regular expression to match SUMS if needed
    """
    def __init__(self, threads=4):
        """
        :param:

         - `threads`: number of parallel threads
        """
        super(HumanExpressionSum, self).__init__()
        self.threads = threads
        return

    @property
    def thread_column(self):
        """
        :return: expression to match the thread (sum) column
        """
        if self._thread_column is None:
            if self.threads > 1:
                thread = "SUM"
            else:
                thread = bran.OPTIONAL_SPACES + bran.INTEGER
            self._thread_column = bran.L_BRACKET + thread + bran.R_BRACKET
        return self._thread_column
# end class HumanExpressionSum


class CsvExpressionSum(CsvExpression):
    """
    Changes the thread column to look for -1 if needed
    """
    def __init__(self, threads=4):
        """
        :param:

         - `threads`: the number of parallel threads
        """
        super(CsvExpressionSum, self).__init__()
        self.threads = threads
        return

    @property
    def thread_column(self):
        """
        :return: the expression to match the thread (sum) column
        """
        if self._thread_column is None:
            if self.threads > 1:
                thread = "-1"
            else:
                thread = bran.INTEGER
            self._thread_column = bran.NAMED(ParserKeys.thread, thread)
        return self._thread_column
# end class CsvExpressionSum    


class SumParser(IperfParser):
    """
    The SumParser emits bandwidth sum lines
    """
    def __init__(self, *args, **kwargs):
        super(SumParser, self).__init__(*args, **kwargs)
        self.log_format = "({0}) {1} {2}/sec"
        self.last_line_bandwidth = None
        self.last_line_transfer = None
        return

    @property
    def regex(self):
        """
        :return: a dictionary of compiled regular expressions
        """
        if self._regex is None:
            self._regex = {ParserKeys.human:HumanExpressionSum(threads=self.threads).regex,
                           ParserKeys.csv:CsvExpressionSum(threads=self.threads).regex}
        return self._regex

    def __call__(self, line):
        """
        The Main interface to add raw iperf lines to the parser
        
        :param:

         - `line`: a line of iperf output

        :return: bandwidth or None
        """
        match = self.search(line)
        assert isinstance(match, dict) or match is None, "match: {0}".format(type(match))
        bandwidth = None
        if match is not None:
            bandwidth = self.bandwidth(match)
            if self.valid(match):
                start = float(match[ParserKeys.start])
                self.intervals[start] = bandwidth
                self.transfer_intervals[start] = self.transfer(match)
            else:
                # Assume it's the last line summary
                self.last_line_bandwidth = bandwidth
                self.last_line_transfer = self.transfer(match)
                return
        return bandwidth

    @coroutine
    def pipe(self, target):
        """
        A coroutine pipeline segment
                
        :warnings:

         - For bad connections with threads this might break (as the threads die)
         - Use for good connections or live data only (use `bandwidths` and completed data for greater fidelity)
         
        :parameters:

         - `target`: a target to send matched output to

        :send:

         - bandwidth converted to self.units as a float
        """
        while True:
            line = (yield)
            match = self.search(line)
            if match is not None and self.valid(match):
                # threads is a dict of interval:(thread_count, bandwidths)
                target.send(self.bandwidth(match))
        return
# end class SumParser


in_documentation = __name__ == '__builtin__'


if in_documentation:
    data_folder = 'tests/steps/samples/'
    data_path = os.path.join(data_folder, 'client_data.iperf')
    parser = SumParser(threads=2)

    for line in open(data_path):
        bandwidth = parser(line)
        if bandwidth is not None:
            print(bandwidth)


if in_documentation:
    parser.reset()

    for line in open(data_path):
        parser(line)
    
    for bandwidth in parser.bandwidths:
        print(bandwidth)



if in_documentation:
    parser.reset()
    parser.threads = 4

    for line in open(data_path):
        parser(line)
    
    calculated_average = sum(parser.bandwidths)/len(parser.intervals)


if in_documentation:
    print('   Sum Lines, {0}'.format(calculated_average))
    print("   Iperf, {0}".format(parser.last_line_bandwidth))


if in_documentation:
    # set up the unitconverter
    from .unitconverter import UnitConverter 
    from .unitconverter import UnitNames
    from .unitconverter import BinaryUnitNames as b_names
    from .unitconverter import  BinaryUnitconverter 
    converter = UnitConverter()
    b_converter = BinaryUnitconverter()
    data_path = os.path.join(data_folder, 'client_p4_bits.iperf')

    # rename the sum-parser used earlier to make it clearer
    sum_parser = parser
    
    # setup the parsers to use bits
    voodoo = IperfParser(units=UnitNames.bits, threads=4)
    sum_parser.reset()
    sum_parser.units = UnitNames.bits
    sum_parser.threads = 4

    # load them up with the raw lines
    for line in open(data_path):
        sum_parser(line)
        voodoo(line)


if in_documentation:
    # convert the sums to Mbits and take the average
    total_bandwidth = sum(sum_parser.bandwidths) * converter[UnitNames.bits][UnitNames.mbits]
    calculated_average = total_bandwidth/len(sum_parser.intervals)

    # same for the re-added threads
    v_total = sum(voodoo.bandwidths) * converter['bits']['Mbits']
    v_average = v_total/len(voodoo.intervals)

    # now iperf's
    iperf_mean = sum_parser.last_line_bandwidth * converter['bits']['Mbits']


if in_documentation:
    print("   Iperf, {0}".format(iperf_mean))
    print('   Sum-Lines, {0}'.format(calculated_average))
    print("   Threads, {0}".format(v_average))


if in_documentation:
    voodoo = IperfParser(units=UnitNames.bits, threads=2)
    sum_parser = SumParser(threads=2, units=UnitNames.bits)

    filename = os.path.join(data_folder, 'tartarus_p2_bits_halfM.iperf')
    with open(filename) as reader:
        for line in reader:
            voodoo(line)
            sum_parser(line)
    print(line)


if in_documentation:
    mbytes = b_converter[b_names.bytes][b_names.mebibytes]
    
    recalculated_transfer = sum(voodoo.transfers)
    recalculated_transfer_mbytes = recalculated_transfer * mbytes
    
    iperfs_transfer = sum_parser.last_line_transfer
    iperfs_transfer_mbytes = iperfs_transfer * mbytes


if in_documentation:
    print("   Re-Calculated,{0}".format(recalculated_transfer_mbytes))
    print("   Iperf's Transfer,{0}").format(iperfs_transfer_mbytes)


if in_documentation:
    missing = b_converter[b_names.mebibytes][b_names.bytes]
    recalculated_transfer += missing
    recalculated_transfer_mbytes = recalculated_transfer * mbytes
    


if in_documentation:
    print("   Re-Calculated,{0}".format(recalculated_transfer_mbytes))
    print("   Iperf's Transfer,{0}").format(iperfs_transfer_mbytes)


if in_documentation:
    m_bits = converter[UnitNames.bits][UnitNames.mbits]
    recalculated_bandwidth = recalculated_transfer * b_converter[b_names.bytes][b_names.bits]
    recalculated_bandwidth = recalculated_bandwidth
    recalculated_bandwidth_mbits = (recalculated_bandwidth/10.2) * m_bits
    iperfs_bandwidth = sum_parser.last_line_bandwidth * m_bits


if in_documentation:
    print('   Re-Calculated,{0:.2f}'.format(recalculated_bandwidth_mbits))
    print('   Iperf,{0:.2f}'.format(iperfs_bandwidth))


if in_documentation:
    transfer = sum_parser.last_line_transfer * b_converter[b_names.bytes][b_names.bits]
    seconds = transfer/float(sum_parser.last_line_bandwidth)
    print(seconds)


if in_documentation:
    recalculated_bandwidth_mbits = (recalculated_bandwidth/seconds) * m_bits


if in_documentation:
    print('   Re-Calculated,{0:.2f}'.format(recalculated_bandwidth_mbits))
    print('   Iperf,{0:.2f}'.format(iperfs_bandwidth))
