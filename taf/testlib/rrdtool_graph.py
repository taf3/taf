# Copyright (c) 2016 - 2017, Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""``rrdtool_graph.py``

`Generate commands for rrdtool graph creation`

"""

import os
from collections import namedtuple

from utils.pyrrd.graph import CalculationDefinition, ColorAttributes  # pylint: disable=no-name-in-module
from utils.pyrrd.graph import VariableDefinition, DataDefinition  # pylint: disable=no-name-in-module
from utils.pyrrd.graph import Area, Graph, GraphPrint, Line  # pylint: disable=no-name-in-module


# RRD file info: file name(str), var name used in calculations(str), ds name from file(str)
FileInfo = namedtuple('FileInfo', ('file', 'vname', 'dsname'))
# Cdef info:
# CdefInfo = namedtuple('CdefInfo', ('name', 'label'))
# Graph's Line info: data definition for display (FileInfo|Calculation),
#                    cdef info(str), show line(bool), show area(bool), label(str)
LineDef = namedtuple('LineDef', ('data_def', 'cdef', 'line', 'area', 'label'))
# Calculation info: var name(str), list of data definitions(list[FileInfo]), calculation(str)
Calculation = namedtuple('Calculation', ('vname', 'data_defs', 'calc'))
# Print info: data definition for display (FileInfo|Calculation), format(str)
Print = namedtuple('Print', ('data_defs', 'fstring'))
# Variable used in data defs: name(str), cdef(str), label(str)
Variable = namedtuple('Variable', ('name', 'label'))
# xgrid info for graph: time min value in seconds(int), time max value(int), xgrid value
XGrid = namedtuple('XGrid', ('min', 'max', 'value'))

# Colors for graph
canvas = '#ffffff'
black = '#000000'

full_red = '#ff0000'
full_green = '#00e000'
full_blue = '#0000ff'
full_yellow = '#f0a000'
full_cyan = '#00a0ff'
full_magenta = '#a000ff'
full_gray = '#333333'

half_red = '#f7b7b7'
half_green = '#b7efb7'
half_blue = '#b7b7f7'
half_yellow = '#f3dfb7'
half_cyan = '#b7dff7'
half_magenta = '#dfb7f7'
half_gray = '#888'
half_bluegreen = '#89b3c9'


COLORS = (full_red, half_red, full_green, half_green, full_blue, half_blue, full_yellow,
          half_yellow, full_cyan, half_cyan, full_magenta, half_magenta, full_gray, half_gray)


# Graph properties for different RRD files
TYPES = {'CPU': {'vertical_label': '"CPU usage [jiffies]"',
                 'rigid': True,
                 'y_grid': '10:5',
                 'upper_limit': 110},
         'MEMORY': {'units_exponent': 9, 'vertical_label': '"Memory usage [Gigabytes]"'},
         'INTERFACE': {'vertical_label': '"Network traffic [bits/sec]"',
                       'logarithmic': False, 'hrule': True},
         'INTERFACE_BYTES': {'vertical_label': '"Network traffic [bytes/sec]"',
                             'logarithmic': False, 'hrule': True},
         'LOAD': {'vertical_label': '"System load"'},
         'DISK': {'logarithmic': False,
                  'vertical_label': '"Disk traffic [bytes/sec]"'}}

# RRD cdef
CDEF = ('MIN', 'AVERAGE', 'MAX')

# RRD files for graphs
FILES = {
    'CPU': [
        FileInfo('cpu-user.rrd', 'user', 'value'),
        FileInfo('cpu-system.rrd', 'system', 'value'),
        FileInfo('cpu-wait.rrd', 'wait', 'value'),
        # FileInfo('cpu-idle.rrd', 'idle', 'value'),
        # FileInfo('cpu-interrupt.rrd', 'interrupt', 'value'),
        # FileInfo('cpu-nice.rrd', 'nice', 'value'),
    ],
    'MEMORY': [
        FileInfo('memory-used.rrd', 'used', 'value'),
        FileInfo('memory-buffered.rrd', 'buffered', 'value'),
        FileInfo('memory-cached.rrd', 'cached', 'value'),
        FileInfo('memory-free.rrd', 'free', 'value'),
    ],
    'INTERFACE': [
        FileInfo('if_octets.rrd', 'incoming', 'rx'),
        FileInfo('if_octets.rrd', 'outgoing', 'tx'),
    ],
    'INTERFACE_BYTES': [
        FileInfo('if_octets.rrd', 'incoming', 'rx'),
        FileInfo('if_octets.rrd', 'outgoing', 'tx'),
    ],
    'LOAD': [
        FileInfo('load.rrd', 'short', 'shortterm'),
        FileInfo('load.rrd', 'mid', 'midterm'),
        FileInfo('load.rrd', 'long', 'longterm'),
    ],
    'DISK': [
        FileInfo('disk_octets.rrd', 'read', 'read'),
        FileInfo('disk_octets.rrd', 'write', 'write'),
    ],
}

# Graphs calculations
CALCULATIONS = {
    'CPU': [
        Calculation('user_sys',
                    [(FILES['CPU'][0].vname, CDEF[1]),
                     (FILES['CPU'][1].vname, CDEF[1])],
                    '{0},{1},+'),
    ],
    'MEMORY': [
        Calculation('user_buffered',
                    [(FILES['MEMORY'][0].vname, CDEF[2]),
                     (FILES['MEMORY'][1].vname, CDEF[2])],
                    '{0},{1},+'),
        Calculation('user_buffered_cached',
                    [(FILES['MEMORY'][0].vname, CDEF[2]),
                     (FILES['MEMORY'][1].vname, CDEF[2]),
                     (FILES['MEMORY'][2].vname, CDEF[2])],
                    '{0},{1},+,{2},+'),
        Calculation('user_buffered_cached_free',
                    [(FILES['MEMORY'][0].vname, CDEF[2]),
                     (FILES['MEMORY'][1].vname, CDEF[2]),
                     (FILES['MEMORY'][2].vname, CDEF[2]),
                     (FILES['MEMORY'][3].vname, CDEF[2])],
                    '{0},{1},+,{2},+,{3},+'),
    ],
    # For bits/sec representation
    'INTERFACE': [
        Calculation('rx_min_bits',
                    [(FILES['INTERFACE'][0].vname, CDEF[0])],
                    '8,{0},*'),
        Calculation('rx_avg_bits',
                    [(FILES['INTERFACE'][0].vname, CDEF[1])],
                    '8,{0},*'),
        Calculation('rx_max_bits',
                    [(FILES['INTERFACE'][0].vname, CDEF[1])],
                    '8,{0},*'),
        Calculation('tx_min_bits',
                    [(FILES['INTERFACE'][1].vname, CDEF[0])],
                    '8,{0},*'),
        Calculation('tx_avg_bits',
                    [(FILES['INTERFACE'][1].vname, CDEF[1])],
                    '8,{0},*'),
        Calculation('tx_max_bits',
                    [(FILES['INTERFACE'][1].vname, CDEF[1])],
                    '8,{0},*'),
        Calculation('tx_max_bits_neg',
                    [(FILES['INTERFACE'][1].vname, CDEF[1])],
                    '-8,{0},*'),
    ],
    # For bytes/sec representation
    'INTERFACE_BYTES': [
        Calculation('tx_max_bytes_neg',
                    [(FILES['INTERFACE_BYTES'][1].vname, CDEF[1])],
                    '-1,{0},*'),
    ],
    'LOAD': [],
    'DISK': [],
}

# Graph's lines and areas
DISPLAY = {
    'CPU': [
        LineDef(CALCULATIONS['CPU'][0].vname, None, True, True, 'User\:'),
        LineDef(FILES['CPU'][1].vname, CDEF[1], True, True, 'System\:'),
        LineDef(FILES['CPU'][2].vname, CDEF[1], True, True, 'Wait-IO\:'),
    ],
    'MEMORY': [
        LineDef(CALCULATIONS['MEMORY'][2].vname, None, True, True, 'Free\:',),
        LineDef(CALCULATIONS['MEMORY'][1].vname, None, True, True, 'Page cache\:'),
        LineDef(CALCULATIONS['MEMORY'][0].vname, None, True, True, 'Buffer cache\:'),
        LineDef(FILES['MEMORY'][0].vname, CDEF[2], True, True, 'Used\:'),
    ],
    # For bits/sec representation
    'INTERFACE': [
        LineDef(CALCULATIONS['INTERFACE'][2].vname, None, True, True, 'Incoming\:',),
        LineDef(CALCULATIONS['INTERFACE'][6].vname, None, True, True, 'Outgoing\:'),
    ],
    # For bytes/sec representation
    'INTERFACE_BYTES': [
        LineDef(FILES['INTERFACE_BYTES'][0].vname, CDEF[2], True, True, 'Incoming\:',),
        LineDef(CALCULATIONS['INTERFACE_BYTES'][0].vname, None, True, True, 'Outgoing\:'),
    ],
    'LOAD': [
        LineDef(FILES['LOAD'][0].vname, CDEF[1], True, False, '1 minute average\:'),
        LineDef(FILES['LOAD'][1].vname, CDEF[1], True, False, '5 minute average\:'),
        LineDef(FILES['LOAD'][2].vname, CDEF[1], True, False, '15 minute average\:'),
    ],
    'DISK': [
        LineDef(FILES['DISK'][0].vname, CDEF[2], True, False, 'Read\:'),
        LineDef(FILES['DISK'][1].vname, CDEF[2], True, False, 'Written\:'),
    ],
}


VARS = [
    Variable('MINIMUM', 'Min',),
    Variable('AVERAGE', 'Avg,'),
    Variable('MAXIMUM', 'Max,'),
    Variable('LAST', 'Last\l'),
]


# Graph's prints
PRINTS = {
    'CPU': [
        Print([(FILES['CPU'][0].vname, CDEF[0], VARS[0]),
               (FILES['CPU'][0].vname, CDEF[1], VARS[1]),
               (FILES['CPU'][0].vname, CDEF[2], VARS[2]),
               (FILES['CPU'][0].vname, CDEF[1], VARS[3])], '%8.1lf {}'),
        Print([(FILES['CPU'][1].vname, CDEF[0], VARS[0]),
               (FILES['CPU'][1].vname, CDEF[1], VARS[1]),
               (FILES['CPU'][1].vname, CDEF[2], VARS[2]),
               (FILES['CPU'][1].vname, CDEF[1], VARS[3])], '%8.1lf {}'),
        Print([(FILES['CPU'][2].vname, CDEF[0], VARS[0]),
               (FILES['CPU'][2].vname, CDEF[1], VARS[1]),
               (FILES['CPU'][2].vname, CDEF[2], VARS[2]),
               (FILES['CPU'][2].vname, CDEF[1], VARS[3])], '%8.1lf {}'),
    ],
    'MEMORY': [
        Print([(FILES['MEMORY'][3].vname, CDEF[0], VARS[0]),
               (FILES['MEMORY'][3].vname, CDEF[1], VARS[1]),
               (FILES['MEMORY'][3].vname, CDEF[2], VARS[2]),
               (FILES['MEMORY'][3].vname, CDEF[1], VARS[3])], '%8.1lf%S {}'),
        Print([(FILES['MEMORY'][2].vname, CDEF[0], VARS[0]),
               (FILES['MEMORY'][2].vname, CDEF[1], VARS[1]),
               (FILES['MEMORY'][2].vname, CDEF[2], VARS[2]),
               (FILES['MEMORY'][2].vname, CDEF[1], VARS[3])], '%8.1lf%S {}'),
        Print([(FILES['MEMORY'][1].vname, CDEF[0], VARS[0]),
               (FILES['MEMORY'][1].vname, CDEF[1], VARS[1]),
               (FILES['MEMORY'][1].vname, CDEF[2], VARS[2]),
               (FILES['MEMORY'][1].vname, CDEF[1], VARS[3])], '%8.1lf%S {}'),
        Print([(FILES['MEMORY'][0].vname, CDEF[0], VARS[0]),
               (FILES['MEMORY'][0].vname, CDEF[1], VARS[1]),
               (FILES['MEMORY'][0].vname, CDEF[2], VARS[2]),
               (FILES['MEMORY'][0].vname, CDEF[1], VARS[3])], '%8.1lf%S {}'),
    ],
    # For bits/sec representation
    'INTERFACE': [
        Print([(CALCULATIONS['INTERFACE'][0].vname, None, VARS[0]),
               (CALCULATIONS['INTERFACE'][1].vname, None, VARS[1]),
               (CALCULATIONS['INTERFACE'][2].vname, None, VARS[2]),
               (CALCULATIONS['INTERFACE'][1].vname, None, VARS[3])], '%8.1lf%S {}'),
        Print([(CALCULATIONS['INTERFACE'][3].vname, None, VARS[0]),
               (CALCULATIONS['INTERFACE'][4].vname, None, VARS[1]),
               (CALCULATIONS['INTERFACE'][5].vname, None, VARS[2]),
               (CALCULATIONS['INTERFACE'][4].vname, None, VARS[3])], '%8.1lf%S {}'),
    ],
    # For bytes/sec representation
    'INTERFACE_BYTES': [
        Print([(FILES['INTERFACE_BYTES'][0].vname, CDEF[0], VARS[0]),
               (FILES['INTERFACE_BYTES'][0].vname, CDEF[1], VARS[1]),
               (FILES['INTERFACE_BYTES'][0].vname, CDEF[2], VARS[2]),
               (FILES['INTERFACE_BYTES'][0].vname, CDEF[1], VARS[3])], '%8.1lf%S {}'),
        Print([(FILES['INTERFACE_BYTES'][1].vname, CDEF[0], VARS[0]),
               (FILES['INTERFACE_BYTES'][1].vname, CDEF[1], VARS[1]),
               (FILES['INTERFACE_BYTES'][1].vname, CDEF[2], VARS[2]),
               (FILES['INTERFACE_BYTES'][1].vname, CDEF[1], VARS[3])], '%8.1lf%S {}'),
    ],
    'LOAD': [
        Print([(FILES['LOAD'][0].vname, CDEF[0], VARS[0]),
               (FILES['LOAD'][0].vname, CDEF[1], VARS[1]),
               (FILES['LOAD'][0].vname, CDEF[2], VARS[2]),
               (FILES['LOAD'][0].vname, CDEF[1], VARS[3])], '%8.1lf {}'),
        Print([(FILES['LOAD'][1].vname, CDEF[0], VARS[0]),
               (FILES['LOAD'][1].vname, CDEF[1], VARS[1]),
               (FILES['LOAD'][1].vname, CDEF[2], VARS[2]),
               (FILES['LOAD'][1].vname, CDEF[1], VARS[3])], '%8.1lf {}'),
        Print([(FILES['LOAD'][2].vname, CDEF[0], VARS[0]),
               (FILES['LOAD'][2].vname, CDEF[1], VARS[1]),
               (FILES['LOAD'][2].vname, CDEF[2], VARS[2]),
               (FILES['LOAD'][2].vname, CDEF[1], VARS[3])], '%8.1lf {}'),
    ],
    'DISK': [
        Print([(FILES['DISK'][0].vname, CDEF[0], VARS[0]),
               (FILES['DISK'][0].vname, CDEF[1], VARS[1]),
               (FILES['DISK'][0].vname, CDEF[2], VARS[2]),
               (FILES['DISK'][0].vname, CDEF[1], VARS[3])], '%8.1lf%S {}'),
        Print([(FILES['DISK'][1].vname, CDEF[0], VARS[0]),
               (FILES['DISK'][1].vname, CDEF[1], VARS[1]),
               (FILES['DISK'][1].vname, CDEF[2], VARS[2]),
               (FILES['DISK'][1].vname, CDEF[1], VARS[3])], '%8.1lf%S {}'),
    ],
}


# Graph's xgrid info depending on time period
XGRID = [
    XGrid(0, 120, 'SECOND:10:SECOND:60:SECOND:10:0:%H:%M:%S'),
    XGrid(121, 300, 'SECOND:30:SECOND:120:SECOND:30:0:%H:%M:%S'),
    XGrid(301, 900, 'SECOND:60:MINUTE:5:MINUTE:2:0:%H:%M'),
    XGrid(901, 3600, 'MINUTE:5:MINUTE:20:MINUTE:10:0:%R'),
    XGrid(3601, 18000, 'MINUTE:10:HOUR:1:MINUTE:30:0:%R'),
    XGrid(18001, 172800, 'MINUTE:30:HOUR:2:MINUTE:120:0:%R'),
    XGrid(172801, None, 'HOUR:2:HOUR:8:HOUR:8:0:%R'),
]


class GraphHrule(object):
    """Graph Hrule representation HRULE:value#color.

    """

    def __init__(self, value, color):
        self.value = value
        self.color = color

    def __repr__(self):
        return 'HRULE:{0}{1}'.format(self.value, self.color)


def _graph(graph_vars, start, end, units_length=8, destination='/tmp/rrd.png', **kwargs):
    """Generate rrdtool command for graph creation.

    Args:
        graph_vars(list):  graph calculations and data definitions
        start(int):  graph's start time in seconds
        end(int):  graph's end time in seconds
        units_length(int):  length of y-axis labels
        destination(str):  destination PNG file
        kwargs(dict):  additional graph configuration

    Returns:
        str:  rrdtool graph command

    """
    # Set graph's background colors
    color = ColorAttributes(lefttop_border='#0000', rightbottom_border='#0000',
                            background='#0000')
    # Set graph's width
    kwargs.setdefault('width', 820)
    # Set graph's x-axis grid
    graph_time = end - start
    xgrid = XGRID[-1].value
    for _xgrid in XGRID[: -1]:
        if graph_time >= _xgrid.min and graph_time <= _xgrid.max:
            xgrid = _xgrid.value
    kwargs.setdefault('x_grid', xgrid)
    hrule = kwargs.get('hrule', False)
    if hrule:
        graph_vars.append(GraphHrule(0, black))
        del kwargs['hrule']
    # Create Graph instance
    graph = Graph(destination, imgformat='PNG', height=210, start=start,
                  end=end, color=color, units_length=units_length, **kwargs)
    graph.data.extend(graph_vars)
    # Generate rrdtool command
    data = graph.backend.prepareObject('graph', graph)
    command = 'rrdtool graph {} '.format(data[0]) + " ".join(data[1])
    return command


def get_graph_command(plugin_dir, start, end, gtype='CPU', destination='/tmp/rrd.png'):
    """Generate rrdtool command for graph creation.

    Args:
        plugin_dir(str):  folder with rrd files
        start(int):  graph's start time in seconds
        end(int):  graph's end time in seconds
        gtype(str):  rrd info type
        destination(str):  destination PNG file

    Returns:
        str:  rrdtool graph command

    """
    # Generate title for graph
    title = '"{0} {1}"'.format(*plugin_dir.split(os.path.sep)[-2:])

    # Lists to store graph variables
    graph_datadefs = {}
    graph_calculations = {}
    graph_vars = []

    max_ll = max(len(x.label) for x in DISPLAY[gtype])

    # Create DATADEFs for rrd files
    for _rrdfile in FILES[gtype]:
        graph_datadefs[_rrdfile.vname] = {}

        rrdfile = os.path.join(plugin_dir, _rrdfile.file)

        # Generate graph data definitions for files
        for cdef in CDEF:
            vname = "{0}_{1}_{2}".format(_rrdfile.vname, _rrdfile.dsname, cdef.lower())
            data_def = DataDefinition(rrdfile=rrdfile,
                                      vname=vname,
                                      dsName=_rrdfile.dsname,
                                      cdef=cdef)
            graph_datadefs[_rrdfile.vname][cdef] = data_def
            graph_vars.append(data_def)

    # Perform additional claculations
    for calc in CALCULATIONS[gtype]:
        calculation = calc.calc.format(*[graph_datadefs[x[0]][x[1]].vname for x in calc.data_defs])
        calc_def = CalculationDefinition(vname=calc.vname, rpn=calculation)
        graph_calculations[calc.vname] = calc_def
        graph_vars.append(calc_def)

    # Create lines, areas and prints
    graph_prints = []
    color = 1
    for display, prints in zip(DISPLAY[gtype], PRINTS[gtype]):
        if display.data_def in graph_calculations:
            def_obj = graph_calculations[display.data_def]
        else:
            def_obj = graph_datadefs[display.data_def][display.cdef]
        if display.area:
            _area = Area(defObj=def_obj, color=COLORS[color])
            graph_prints.append(_area)
        _legend = "{0:<{1}}".format(display.label, max_ll)
        _line = Line(1, defObj=def_obj, color=COLORS[color - 1], legend=_legend)
        color += 2
        graph_prints.append(_line)

        for _data_def, _cdef, _var in prints.data_defs:
            var_name = "{0}_{1}_var".format(_data_def, _var.name.lower())
            if _cdef:
                var_def_obj = graph_datadefs[_data_def][_cdef].vname
            else:
                var_def_obj = graph_calculations[_data_def].vname
            var_def = VariableDefinition(var_name, rpn="{0},{1}".format(var_def_obj, _var.name))
            graph_vars.append(var_def)
            graph_prints.append(GraphPrint(var_def, prints.fstring.format(_var.label)))

    graph_vars.extend(graph_prints)

    # Generate rrdtool command
    return _graph(graph_vars, start, end, destination=destination, title=title, **TYPES[gtype])


RRDTOOL_FETCH = "rrdtool fetch {0} {1} --start {2} --end {3}"


def get_fetch_commands(plugin_dir, start, end, gtype='CPU'):
    """Generate rrdtool fetch commands for RRD files from folder.

    Args:
        plugin_dir(str):  folder with rrd files
        start(int):  graph's start time in seconds
        end(int):  graph's end time in seconds
        gtype(str):  rrd info type

    Returns:
        str:  rrdtool fetch command

    """
    commands = []
    for _rrdfile in FILES[gtype]:
        rrdfile = os.path.join(plugin_dir, _rrdfile.file)
        for cdef in CDEF:
            commands.append(RRDTOOL_FETCH.format(rrdfile, cdef, start, end))
    return commands
