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
class UnitNames(object):
    """
    Unit Names is a namespace to hold units
    """
    __slots__ = ()
    # bits
    bits = "bits"
    kbits = "K" + bits
    kilobits = kbits   
    mbits = "M" + bits
    megabits = mbits
    gbits = "G" + bits
    gigabits = gbits
    tbits = "T" + bits
    terabits = tbits
    pbits = "P" + bits
    petabits = pbits
    ebits = "E" + bits
    exabits = ebits
    zbits = "Z" + bits
    zettabits = zbits
    ybits = "Y" + bits
    yottabits = ybits

    # bytes
    bytes = "Bytes"
    kbytes = "K" + bytes
    kilobytes = kbytes
    mbytes = "M" + bytes
    megabytes = mbytes
    gbytes = "G" + bytes
    gigabytes = gbytes
    tbytes = "T" + bytes
    terabytes = tbytes
    pbytes = "P" + bytes
    petabytes = pbytes    
    ebytes = "E" + bytes
    exabytes = ebytes    
    zbytes = 'Z' + bytes
    zettabytes = zbytes
    ybytes = 'Y' + bytes
    yottabytes = ybytes


class BinaryUnitNames(object):
    """
    namespace for binary-unit names
    """
    bits = UnitNames.bits
    bibits = 'bi' + bits
    kibibits = "ki" + bibits
    mebibits = 'me' + bibits
    gibibits = "gi" + bibits
    tebibits = "te" + bibits
    pebibits = "pe" + bibits
    exbibits = "ex" + bibits
    zebibits = "ze" + bibits
    yobibits = "yo" + bibits

    bytes = 'bytes'
    bibytes = 'bi' + bytes
    kibibytes = "ki" + bibytes
    mebibytes = "me" + bibytes
    gibibytes = 'gi' + bibytes
    tebibytes = 'te' + bibytes
    pebibytes = 'pe' + bibytes
    exbibytes = "ex" + bibytes
    zebibytes = "ze" + bibytes
    yobibytes = "yo" + bibytes

    # iperf base 2
    iperf_bytes = UnitNames.bytes
    iperf_kibibytes = UnitNames.kbytes
    iperf_mebibytes = UnitNames.mbytes
    iperf_gibibytes = UnitNames.gbytes
    iperf_tebibytes = UnitNames.tbytes
    iperf_pebibytes = UnitNames.pbytes
    iperf_exbibytes = UnitNames.ebytes
    iperf_zebibytes = UnitNames.zbytes
    iperf_yobibytes = UnitNames.ybytes
# end BinaryUnitNames


IDENTITY = 1
ONE = 1.0
BYTE = 8
TO_BYTE = ONE/BYTE


class BaseConverter(dict):
    """
    A creator of unit-conversion dictionaries
    """
    def __init__(self, to_units, kilo_prefix):
        """
        base_converter constructor

        :param:

         - `to_units`: a list of the units to covert  to  (has to be half to-bits, half to-bytes)
         - `kilo_prefix`: kilo multiplier matching type of units
        """
        self.to_units = to_units
        self.kilo_prefix = kilo_prefix

        self._prefix_conversions = None
        self._bits_to_bytes = None
        self._bytes_to_bits = None

        # split the to_units list for later
        self.bit_conversions = self.byte_conversions = len(to_units)//2
        self.bit_units = to_units[:self.bit_conversions]
        self.byte_units = to_units[self.byte_conversions:]
        return

    @property
    def prefix_conversions(self):
        """
        List of lists of prefix conversions
        """
        if self._prefix_conversions is None:
            # start with list that assumes value has no prefix
            # this list is for 'bits' or 'bytes'
            # the values will be 1, 1/kilo, 1/mega, etc.
            start_list = [self.kilo_prefix**(-power)
                                         for power in range(self.bit_conversions)]
            self._prefix_conversions = self.conversions(conversion_factor=1,
                                                        start_list=start_list)
        return self._prefix_conversions

    @property
    def bits_to_bytes(self):
        """
        List of conversions for bits to bytes
        """
        if self._bits_to_bytes is None:
            self._bits_to_bytes = self.conversions(conversion_factor=TO_BYTE)
        return self._bits_to_bytes

    @property
    def bytes_to_bits(self):
        """
        list of conversions for bytes to bits
        """
        if self._bytes_to_bits is None:
            self._bytes_to_bits = self.conversions(conversion_factor=BYTE)
        return self._bytes_to_bits

    def conversions(self, conversion_factor, start_list=None):
        """
        Creates the converter-lists

        :param:

         - `conversion_factor`: multiplier for values (8 or 1/8, or 1)
         - `start_list`: if given, use to start the conversion-list

        :return: list of conversion_lists
        """
        if start_list is None:
            # assume that prefix_conversions exists (not safe, but...)
            start_list = self.prefix_conversions[0]
        # start with byte_factor times the base conversions (1, 1/kilo, etc.)
        converter_list = [[conversion_factor * conversion
                           for conversion in start_list]]
        for previous in range(self.bit_conversions - 1):
            # 'pop' last item from previous list
            # and prepend one higher-power conversion
            next_conversions = ([self.kilo_prefix**(previous+1) * conversion_factor] +
                                converter_list[previous][:-1])
            converter_list.append(next_conversions)
        return converter_list

    def build_conversions(self):
        """
        builds the dictionary
        """
        # from bits to bits or bytes
        for index, units in enumerate(self.bit_units):
            self[units] = dict(list(zip(self.to_units, self.prefix_conversions[index] +
                                   self.bits_to_bytes[index])))

        # from bytes to bits or bytes        
        for index, units in enumerate(self.byte_units):
            self[units] = dict(list(zip(self.to_units, self.bytes_to_bits[index] +
                                   self.prefix_conversions[index])))
        return
# end class BaseConverter


bit_units = [UnitNames.bits,
             UnitNames.kbits,
             UnitNames.mbits,
             UnitNames.gbits,
             UnitNames.terabits,
             UnitNames.petabits,
             UnitNames.exabits,
             UnitNames.zettabits,
             UnitNames.yottabits]

byte_units = [UnitNames.bytes,
              UnitNames.kbytes,
              UnitNames.mbytes,
              UnitNames.gbytes,
              UnitNames.terabytes,
              UnitNames.petabytes,
              UnitNames.exabytes,
              UnitNames.zettabytes,
              UnitNames.yottabytes]

decimal_to_units = bit_units + byte_units

    


KILO = 10**3


class UnitConverter(BaseConverter):
    """
    The UnitConverter makes conversions based on a base-10 system
    """
    def __init__(self):
        super(UnitConverter, self).__init__(to_units=decimal_to_units,
                                            kilo_prefix=KILO)
        self.build_conversions()
        return
# end class UnitConverter    


DecimalUnitConverter = UnitConverter


to_bits = [BinaryUnitNames.bits,
           BinaryUnitNames.kibibits,
           BinaryUnitNames.mebibits,
           BinaryUnitNames.gibibits,
           BinaryUnitNames.tebibits,
           BinaryUnitNames.pebibits,
           BinaryUnitNames.exbibits,
           BinaryUnitNames.zebibits,
           BinaryUnitNames.yobibits]

to_bytes = [BinaryUnitNames.bytes,
            BinaryUnitNames.kibibytes,
            BinaryUnitNames.mebibytes,
            BinaryUnitNames.gibibytes,
            BinaryUnitNames.tebibytes,
            BinaryUnitNames.pebibytes,
            BinaryUnitNames.exbibytes,
            BinaryUnitNames.zebibytes,
            BinaryUnitNames.yobibytes]

binary_to_units = to_bits + to_bytes


KIBI = 2**10


class BinaryUnitconverter(BaseConverter):
    """
    The BinaryUnitconverter is a conversion lookup table for binary data

    Usage::

       converted = old * UnitConverter[old units][new units]

    Use class UnitNames to get valid unit names
    """
    def __init__(self):
        super(BinaryUnitconverter, self).__init__(to_units=binary_to_units,
                                                  kilo_prefix=KIBI)
        self.build_conversions()
        return
# end class BinaryUnitConverter    


to_bits = [BinaryUnitNames.bits,
           BinaryUnitNames.kibibits,
           BinaryUnitNames.mebibits,
           BinaryUnitNames.gibibits,
           BinaryUnitNames.tebibits,
           BinaryUnitNames.pebibits,
           BinaryUnitNames.exbibits,
           BinaryUnitNames.zebibits,
           BinaryUnitNames.yobibits]

to_bytes = [BinaryUnitNames.iperf_bytes,
            BinaryUnitNames.iperf_kibibytes,
            BinaryUnitNames.iperf_mebibytes,
            BinaryUnitNames.iperf_gibibytes,
            BinaryUnitNames.iperf_tebibytes,
            BinaryUnitNames.iperf_pebibytes,
            BinaryUnitNames.iperf_exbibytes,
            BinaryUnitNames.iperf_zebibytes,
            BinaryUnitNames.iperf_yobibytes]

iperf_binary_to_units = to_bits + to_bytes


class IperfbinaryConverter(BaseConverter):
    """
    The IperfbinaryConverter is a conversion lookup table for binary data

    Usage::
       converter = IperfbinaryConverter()
       converted = old * converter[old units][new units]

    Use class UnitNames to get valid unit names
    """
    def __init__(self):
        super(IperfbinaryConverter, self).__init__(to_units=iperf_binary_to_units,
                                                  kilo_prefix=KIBI)
        self.build_conversions()
        return
# end class BinaryUnitConverter    


if __name__ == "__builtin__":
    unit_converter = UnitConverter()
    bits = 10**6
    converted = bits * unit_converter['bits']['Mbits']
    print("{0} Mbits".format(converted))


if __name__ == "__builtin__":
    binary_converter = BinaryUnitconverter()
    MBytes = 1
    bits = MBytes * binary_converter[BinaryUnitNames.mebibytes][UnitNames.bits]
    print("{0:,} bits".format(bits))


if __name__ == '__builtin__':
    mbits = bits * unit_converter[UnitNames.bits][UnitNames.mbits]
    print('{0} Mbits'.format(mbits))
