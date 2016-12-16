"""
Copyright (c) 2004-2008, AdytumSolutions, Inc.  All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
    copyright notice, this list of conditions and the following
    disclaimer in the documentation and/or other materials provided
    with the distribution.
    * Neither the name of AdytumSolutions, Inc. nor the names of
    its contributors may be used to endorse or promote products
    derived from this software without specific prior written
    permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
"""
import re

from ..util import NaN


def coerce(value):
    """
    >>> coerce("NaN")
    nan
    >>> coerce("nan")
    nan
    >>> coerce("Unkn")
    >>> coerce("u")
    >>> coerce("1")
    1.0
    >>> 0.039 < coerce("4.0000000000e-02") < 0.041
    True
    >>> 0.039 < coerce(4.0000000000e-02) < 0.041
    True
    """
    try:
        return float(value)
    except ValueError:
        value = str(value).lower()
        if value in ["unkn", "u"]:
            return None
        elif value == "nan":
            return NaN()
    raise ValueError("Unexpected type for data (%s)" % value)


def iterParse(lines):
    """
    >>> lines = [' 920804700: nan',
    ...  ' 920805000: 4.0000000000e-02',
    ...  ' 920805300: 2.0000000000e-02',
    ...  ' 920805600: 0.0000000000e+00',
    ...  ' 920805900: 0.0000000000e+00',
    ...  ' 920806200: 3.3333333333e-02',
    ...  ' 920806500: 3.3333333333e-02',
    ...  ' 920806800: 3.3333333333e-02',
    ...  ' 920807100: 2.0000000000e-02',
    ...  ' 920807400: 2.0000000000e-02',
    ...  ' 920807700: 2.0000000000e-02',
    ...  ' 920808000: 1.3333333333e-02',
    ...  ' 920808300: 1.6666666667e-02',
    ...  ' 920808600: 6.6666666667e-03',
    ...  ' 920808900: 3.3333333333e-03',
    ...  ' 920809200: nan']
    >>> g = iterParse(lines)
    >>> g.next()
    (920804700, nan)
    >>> g.next()
    (920805000, 0.04)
    >>> len(list(g)) == len(lines) - 2
    True
    """
    for line in lines:
        line = line.strip()
        time, value = [x.strip() for x in re.split(r':\s+', line)]
        yield (int(time), coerce(value))


def buildParameters(obj, validList):
    """
    >>> class TestClass(object):
    ...   pass
    >>> testClass = TestClass()
    >>> testClass.a = 1
    >>> testClass.b = "2"
    >>> testClass.c = 3
    >>> testClass.d = True
    >>> buildParameters(testClass, ["a", "b"])
    ['--a', u'1', '--b', u'2']

    >>> testClass.b = None
    >>> buildParameters(testClass, ["a", "b"])
    ['--a', u'1']

    The following shows support for boolean flags that don't have a value
    associated with them:

    >>> buildParameters(testClass, ["a", "d"])
    ['--a', u'1', '--d']
    """
    params = []
    for param in validList:
        attr = getattr(obj, param)
        if attr:
            param = param.replace("_", "-")
            if isinstance(attr, bool):
                attr = ""
            params.extend(["--%s" % param, str(attr)])
    return [x for x in params if x]


if __name__ == "__main__":
    import doctest
    doctest.testmod()
