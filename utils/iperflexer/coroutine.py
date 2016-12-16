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


COMMA = ','
NEWLINE = '\n'
COMMA_JOIN = "{0},{1}"
WRITEABLE = 'w'


def coroutine(func):
    """
    A decorator to start coroutines

    :param:
    
     - `func`: A coroutine function.
    """
    def wrap(*args, **kwargs):
        coroutine_func = func(*args, **kwargs)
        next(coroutine_func)
        return coroutine_func
    return wrap


@coroutine
def broadcast(targets):
    """
    A coroutine to broadcast input.
    
    :param:

     - `targets`: A list of coroutines to send output to.
    """
    while True:
        line = (yield)
        for target in targets:
            target.send(line)
    return


@coroutine
def comma_join(target, input_count):
    """
    This outputs the data in the opposite order that it's received.
    This way the source of the data pipeline is output first.
    
    :param:

     - `target`: A coroutine to send output to.
     - `input_count`: number of inputs before creating line to send.
    """
    inputs = list(range(input_count))
    while True:
        line = COMMA.join(reversed([(yield) for source in inputs]))
        target.send(line)
    return


@coroutine
def output(target_file):    
    """
    Writes input to the target file
    
    :param:

     - `target_file`: A file-like object to write output to.
    """
    while True:
        line = (yield)
        if not line.endswith(NEWLINE):
            line += NEWLINE
        target_file.write(line)
    return


@coroutine
def comma_append(source, target):
    """
    Joins a source stream output and incoming strings with commas

    :param:

     - `source`: iterable of strings
     - `target`: target to send joined strings
    """
    for line in source:
        line_2 = (yield)
        target.send(COMMA_JOIN.format(line.rstrip(NEWLINE), line_2))
    return


@coroutine
def file_output(file_object):
    """
    Writes strings to a file, making sure there's a newline at the end

    :param:

     - `file_object`: opened, writable file or name of file to open
    """
    from io import IOBase
    if not isinstance(file_object, IOBase):
        file_object = open(file_object, WRITEABLE)
    while True:
        line = (yield)
        line = line.rstrip(NEWLINE) + NEWLINE
        file_object.write(line)
