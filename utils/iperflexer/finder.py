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
# python libraries
import fnmatch
import os
import re


WRITEABLE = 'w'
EOSection = ''


def find(glob, start=None):
    """
    Generates files matching the glob
    
    :param:

     - `glob`: A file-glob to match interesting files.
     - `start`: The top path (finds files below the top)

    :yield: Matching file name
    """
    if start is None:
        start = os.getcwd()
    for path, dir_list, file_list in os.walk(start):
        for name in fnmatch.filter(file_list, glob):
            yield os.path.join(path, name)
    return


def concatenate(glob, start=None):
    """
    Generates lines from all files that match the glob.
    
    :param:

     - `glob`: A file-glob to match interesting files.
     - `start`: The top path (finds files below the top)

    :yield: lines in matching files.
    """
    for name in find(glob, start):
        for line in open(name):
            yield line
    return


def sections(glob, start, end, top=None):
    """
    Generates section generators
    
    :param:

     - `glob`: A file glob that matches source files
     - `start`: A regular expression to match the start of a section.
     - `end`: A regular expression to match the end of a section.
     - `top`: The starting path to search for files

    :yield: section generator of lines
    """
    start, end = re.compile(start), re.compile(end)
    concatenator = concatenate(glob, top)
    for line in concatenator:
        if start.search(line):
            yield section(concatenator, end, line)
    return


def section(iterator, end, firstline=None):
    """
    Generates lines from the iterator until `end` is matched or iterator stops
    
    :param:

     - `iterator`: An iterator of lines
     - `end`: A regular expression to match the last line in the section

    :yield: lines up to and including the end match
    """
    ended = False
    if firstline is not None:
        yield firstline
    # uses next instead of iterator so it doesn't consume the last line
    while not ended:
        try:
            line = next(iterator)
            if end.search(line):
                ended = True
            yield line
        except StopIteration:
            return


def line_counter(glob, start, end, interesting):
    """
    Counts interesting lines within sections

    :param:

     - `glob`: the glob for the source files.
     - `start`: regular expression that defines the start of a section
     - `end`: end of section regular expression
     - `interesting`: interesting line regular expression

    :yield: count of interesting lines in each section
    """
    start, end, interesting = re.compile(start), re.compile(end), re.compile(interesting)
    for section in sections(glob, start, end):
        counter = 0
        for line in section:
            if interesting.search(line):
                counter += 1
        yield counter
