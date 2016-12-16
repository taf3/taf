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
import string


RST_EXTENSION = '.rst'
INDEX = 'index.rst'
NEWLINE = '\n'
TOCTREE = NEWLINE + '.. toctree::'
MAXDEPTH = '   :maxdepth: {0}' + NEWLINE
HEADER = TOCTREE + NEWLINE + MAXDEPTH
CONTENTS = '   {0} <{1}>'


def grab_headline(filename):
    """
    A convenience function to grab the first non-empty line

    :param:

     - `filename`: path to a file reachable from this directory

    :return: First non-empty line stripped (or None if all are empty)
    """
    with open(filename) as f:
        for line in f:
            if len(line.strip()):
                return line.strip()


def create_toctree(maxdepth=1, subfolders=None, add_headers=False):
    """
    Sends a toctree to standard out

    :param:

     - `maxdepth`: the depth for the tree (1=module, 2=headings, etc.)
     - `subfolders`: subfolders to add (adds all if None)
     - `add_folders`: use folder names to separate sub-folders
    """
    exists = os.path.exists
    join = os.path.join
    
    contents = sorted(os.listdir(os.getcwd()))
    filenames = (name for name in contents if name.endswith(RST_EXTENSION)
                 and name != INDEX)

    print(HEADER.format(maxdepth))

    for filename in filenames:
        pretty_name = grab_headline(filename)
        print(CONTENTS.format(pretty_name, filename))

    subfolder_toctree(maxdepth, subfolders, add_headers)
    print()
    return


def subfolder_toctree(maxdepth=1, subfolders=None, add_headers=False):
    """
    Creates the toctree for sub-folder indices

    :param:

     - `maxdepth`: Level of sub-headings to include
     - `subfolders`: iterable of sub-folders with index.rst
     - `add_headers`: True- use folder names as separators
    """
    exists = os.path.exists
    join = os.path.join
    
    contents = sorted(os.listdir(os.getcwd()))

    if subfolders is None and add_headers:
        name_indices = ((name, join(name, INDEX)) for name in contents if exists(join(name, INDEX)))
        for name, index in name_indices:
            print(name + ":")
            print(HEADER.format(maxdepth))
            pretty_name = grab_headline(index)
            print(CONTENTS.format(pretty_name, index))
        return
    
    print(HEADER.format(maxdepth))
    if subfolders is not None:
        sub_indices = (join(subfolder, INDEX) for subfolder in subfolders)
    else:
        sub_indices = (join(name, INDEX) for name in contents if exists(join(name, INDEX)))
        for sub_index in sub_indices:
            pretty_name = grab_headline(sub_index)
            print(CONTENTS.format(pretty_name, sub_index))
    
    return
