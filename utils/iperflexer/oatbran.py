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

Oat Bran helps with regular expressions

names are uppercased to avoid keyword clashes
"""
import string

# groups

def GROUP(e):
    return "({e})".format(e=e)

def NAMED(n, e):
    return "(?P<{n}>{e})".format(n=n, e=e)

def CLASS(e):
    return "[{e}]".format(e=e)

def NOT(e):
    return "[^{e}]+".format(e=e)

def NOT_FOLLOWED_BY(e):
    return "(?!{e})".format(e=e)

def NOT_PRECEDED_BY(e):
    return "(?<!{e})".format(e=e)

# cardinality
ONE_OR_MORE = "+"
ZERO_OR_MORE = '*'
ZERO_OR_ONE = "?"

def M_TO_N(m, n, e):
    """
    :param:

     - `m`: the minimum required number of matches
     - `n`: the maximum number of  matches
     - `e`: the expression t match
    """
    return "{e}{{{m},{n}}}".format(m=m, n=n, e=e)

def M_TO_N_ONLY(m, n, e):
    """
    :param:

     - `m`: the minimum required number of matches
     - `n`: the maximum number of  matches
     - `e`: the expression t match
    """
    return r"\b{e}{{{m},{n}}}\b".format(m=m, n=n, e=e)
    
# exceptions
DECIMAL_POINT = r'\.'
L_BRACKET = r"\["
R_BRACKET = r"\]"

# operators
OR = "|"

def WORD_BOUNDARY(e):
    return r"\b{e}\b".format(e=e)

def STRING_BOUNDARY(e):
    """
    :return: expr that matches an entire line
    """
    return r"^{e}$".format(e=e)

# string help
STRING_START = "^"
STRING_END = "$"
ALPHA_NUMS = r"\w"

# anything and everything
ANYTHING = r"."
EVERYTHING = ANYTHING + ZERO_OR_MORE

# numbers
DIGIT = r"\d"
NOT_DIGIT = r"\D"
NON_ZERO = CLASS("1-9")
SINGLE_DIGIT = WORD_BOUNDARY(DIGIT)
TWO_DIGITS = WORD_BOUNDARY(NON_ZERO + DIGIT)
ONE_HUNDREDS = WORD_BOUNDARY("1" + DIGIT + DIGIT)
NATURAL = DIGIT + ONE_OR_MORE

INTEGER = NOT_PRECEDED_BY(DECIMAL_POINT) +  "-" + ZERO_OR_ONE + NATURAL + NOT_FOLLOWED_BY(DECIMAL_POINT)

FLOAT = "-" + ZERO_OR_ONE + NATURAL + DECIMAL_POINT + NATURAL
REAL = GROUP(FLOAT + OR + INTEGER)

SPACE = r"\s"
SPACES = SPACE + ONE_OR_MORE
OPTIONAL_SPACES = SPACE + ZERO_OR_MORE

# common constants
DASH = "-"
LETTER = CLASS(e=string.ascii_letters)
LETTERS = LETTER + ONE_OR_MORE
OPTIONAL_LETTERS = LETTER + ZERO_OR_MORE

# SPECIAL CASES
# NETWORKING
DOT = DECIMAL_POINT
OCTET = GROUP(e=OR.join([SINGLE_DIGIT, TWO_DIGITS, ONE_HUNDREDS,
                         WORD_BOUNDARY("2[0-4][0-9]"), WORD_BOUNDARY("25[0-5]")]))

IP_ADDRESS = DOT.join([OCTET] * 4)
