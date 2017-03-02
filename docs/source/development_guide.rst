Development guide
=================
TAF code naming convention
^^^^^^^^^^^^^^^^^^^^^^^^^^

The heart of the design of python project is its high level of readability. One reason for code to be easily readable and understood is following set of code style guidelines. It is always advisable to maintain consistency in naming standards. This document describes the nomenclature suggested for use in TAF. TAF developers requires reading at `PEP 8 -- Style Guide for Python Code <https://www.python.org/dev/peps/pep-0008/>`_  , and TAF library is conservative and requires limiting lines to 99 characters (and docstrings/comments to 92) although it exceeds `PEP 8 <https://www.python.org/dev/peps/pep-0008/>`_  standard. 99 characters will give enough to review side-by-side with multiple files, and visualize the difference between changes well in code review tools. Only exception is in writing function name in testcases which can exceed this limit as long as it's helpful to understand the testcase.

Directory
+++++++++

* Referred to as packages in python project
* Short and all lowercase names
* Use of underscores is discouraged but can be used for better readability:

    `e.g.: testlib, sanity_tests`

File Names
++++++++++
* Referred to as modules in python project

**Python Files**

* Short and all lowercase names
* Use underscores for better readability
* Since module names are mapped to file names, and some file systems truncate long names, it is important that module names should be chosen to be fairly short

    `e.g.: test_fdb.py`

**Data Files**

Currently followed patterns for different data files are as follows:

* Json
    * lower_case_with_underscore

        `e.g.: synapsert_client.json`

    * CapsWords

        `e.g.: StormControl.json`

    * CapsWords_with_underscore

        `e.g.: RouteTable_Prem`

    * Startwithcapsletter

        `e.g.: Fdb.json`

    * lowerPlusCaps

        `e.g.: ifType.json`

* TCL
    * Lower_case_with_underscore
* XML
    * CapsWords
* Dox
    * lower_case_with_underscore
* Java
    * CapsWords
* Vm
    * lower_case_with_underscore
* Txt
    * lower_case_with_underscore

.. note::

   DO NOT follow mixed standard mentioned above. It is always recommended to use lower_case_with_underscores for all file formats

Class Names
+++++++++++

* Cap Words convention:

    `e.g.: TestAclCopyToCpuAction`

Some of the bad examples that are existing in TAF are as follows:

* Lowercase all

    `e.g.: cv`

* lowerThenUpper

    `e.g.: helpersUI`

* lower_with_underscores

    `e.g.: compare_color`

* Beginning with underscore

    `e.g.: _EncryptAndVerify`

* Caps_With_Underscore

    `e.g.: DHCP6_Decline`

Functions
+++++++++

**Test cases**

* Test case function names should be lowercase, with words separated by underscores as necessary to improve readability, and it must starts with word 'test'

    `e.g.: test_name_lowercase_with_underscores`

**Sub module functions**

* Starts with _

    `e.g.: _single_leading_underscore`

**Class functions**

* Class function names should be lowercase, with words separated by underscores as necessary to improve readability

    `e.g.: lowercase_with_underscores`

**Pytest configuration functions**

* Pytest configuration function names should be lowercase, with words separated by underscores as necessary to improve readability.
* Present in taf/plugins.
* Must start with word 'pytest'

    `e.g.: pytest_name_lowercase_with_underscores`

Constants and Variables
+++++++++++++++++++++++

**Constants**

* Capital letters with underscores separating words.

    `e.g.: MAX_OVERFLOW, TOTAL`

**Variables**

* Should be lowercase, with words separated by underscores.
* Global variables, attributes of the class and instance variables come under this category.

Arguments
+++++++++

**Class**

* Lowercase and can use underscores for better readability.
* Always use 'object' for the first argument if required.

**User-defined Methods**

* Lowercase and can use underscores for better readability.
* Always use 'self' for the first argument to instance methods.
* Always use 'cls' for the first argument to class methods.

**User-defined Functions**

* Lowercase and can use underscores for better readability.

Docstring
+++++++++

All files, classes, class methods and first level functions must have properly created docstrings. Note that 'type' syntax in Python docstrings is `Google style <https://google.github.io/styleguide/pyguide.html>`_ .

**Google style** tends to be easier to read for short and simple docstrings.

**File**

Each python file in TAF should contain a header where the main information about the file is stored:

* copyright
* licence information
* file name
* summary
* note with example of module usage in tests (optionally)

In accordance to `Google style <https://google.github.io/styleguide/pyguide.html>`_ of docstrings should look as following example:

*Example:*

.. code-block:: python
   :linenos:

   # Copyright (c) 2011 - 2016, Intel Corporation.
   #
   # Licensed under the Apache License, Version 2.0 (the "License");
   # you may not use this file except in compliance with the License.
   # You may obtain a copy of the License at
   #
   #     http://www.apache.org/licenses/LICENSE-2.0
   #
   # Unless required by applicable law or agreed to in writing, software
   # distributed under the License is distributed on an "AS IS" BASIS,
   # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   # See the License for the specific language governing permissions and
   # limitations under the License.

   """``dpdk.py``

   Class for dpdk operations

   Note:
       Examples of dpdk usage in tests::

           inst.ui.dpdk.modify_iface_status(bind_action='bind', ifaces=["0000:01:00.0", "01:00.0"],
                                            drv='igb_uio', force=False, show_status=True)

   """

**Class**

Create a class with appropriate docstring. Following keywords can be used:

+----------------------+----------------------------------------------------------------------------------------------------------------------------------------------------+
|**Note**              |An optional section that provides additional information about the code, possibly including a discussion of the algorithm                           |
+----------------------+----------------------------------------------------------------------------------------------------------------------------------------------------+
|**Example**           |Sections support any reStructuredText formatting, including literal blocks:: or `doctest <https://docs.python.org/3/library/doctest.html>`_ format  |
|                      |to mention any coding samples                                                                                                                       |
+----------------------+----------------------------------------------------------------------------------------------------------------------------------------------------+

*Example:*

.. code-block:: python
   :linenos:

   class NoErrArgumentParser(argparse.ArgumentParser):
       """ArgumentParser class that handle only predefined for an instance options.

       Note:
           The original ArgumentParser class raises an error if handle unknown option.
           But py.test have it's own options and it's own custom parser and if ArgumentParser find them it raises an error.
           Using this class allows not to define all possible options in each module that uses ArgumentParser.

       Examples::

               def parse_args(self, *args, **kwargs):
                   if len(args) > 0:
                       args_to_parse = args[0]
                   else:
                       args_to_parse = sys.argv[1:]
                   new_args_to_parse = []

       """

**Function**

Create a test case function with appropriate docstring.
Sub-functions inside first level functions don`t need to contain docstrings as far as they aren't designed for any external calls. Ignore `pylint <https://www.pylint.org/>`_ messages.

In case you wish to create a docstring, following keywords can be used:

+-------------+---------------------------------------------------------------------------------+
|**Args**     |description of the function arguments, keywords and their respective types       |
+-------------+---------------------------------------------------------------------------------+
|**Returns**  |explanation of the returned values and their types                               |
+-------------+---------------------------------------------------------------------------------+
|**Raises**   |an optional section detailing which errors get raised and under what conditions  |
+-------------+---------------------------------------------------------------------------------+
|**Yields**   |explanation of the yielded values and their types                                |
+-------------+---------------------------------------------------------------------------------+

*Example function docstrings with Returns key:*

.. code-block:: python
   :linenos:

   def __get__(self, instance, owner):
       """This method is called from class.

       Args:
           owner (owner):  class instance.

       Returns:
           logging.LoggerAdapter:  logger adaptor.

       Raises:
           KeyError: Cannot connect to logger adaptor.

       """
       if self.for_exception:
           caller_frame = inspect.stack()[2]
           module_name = inspect.getmodulename(caller_frame[1])
           func_name = caller_frame[3]
           try:
               class_name = caller_frame[0].f_locals["self"].__class__.__name__
           except KeyError:
               class_name = ""
           _logger_adaptor = self._get_logger(module_name, class_name, func_name)
       else:
           _logger_adaptor = self._get_logger(owner.__module__, owner.__name__)
       return _logger_adaptor

*Example function docstrings with Yields key:*

.. code-block:: python
   :linenos:

   def parse_table_vlan(self, vlan_table):
       """Parses the vlan table.

       This needs to be a loop because previous the table
       is built based on previous entries.

       Args:
           vlan_table (list[str] | iter()):  List of vlan raw output

       Yields:
           iter(): A dictionary containing the portId, vlanId, and tagged state for each vlan

       """
       for row in vlan_table:
           match = re.search(
               r"(?P<portId>\S*\d+)?\s*(?P<vlanId>\d+)\s*(?P<pvid>PVID)?\s*(?:Egress)?\s*(?P<tagged>\D+)?", row)
           if match:
               row = match.groupdict()
               row['vlanId'] = int(row['vlanId'])
               if row['tagged'] is None:
                   row['tagged'] = 'Tagged'
               row['pvid'] = (row['pvid'] == 'PVID')
               if row['portId'] is not None:
                   # Set portId on the first line and use that value for following lines
                   row['portId'] = self.name_to_portid_map[row['portId']]
                   port_id = row['portId']
               else:
                   # This row doesn't have a portId because it implicitly uses the previous
                   row['portId'] = port_id
               yield row

Test Case Structure
^^^^^^^^^^^^^^^^^^^
A group of test cases will be written in a python file which we call test suite. The name of the file should:

* be unique;
* start with `"test_"`;
* contain clear information about test suite (e.g. feature, setup, table name, etc.).

Test suite is divided into the following separate parts:

* header;
* imports block;
* additional functions (optional);
* test class;
* internal test class methods;
* test cases.

Header
++++++
Each test case python file in TAF3 ("testcases" directory) should contain a header with contains following information:

* copyright
* licence information
* file name
* summary
* note (contain information what following test case are tested)


.. code-block:: python
   :linenos:

   # Copyright (c) 2011 - 2016, Intel Corporation.
   #
   # Licensed under the Apache License, Version 2.0 (the "License");
   # you may not use this file except in compliance with the License.
   # You may obtain a copy of the License at
   #
   #     http://www.apache.org/licenses/LICENSE-2.0
   #
   # Unless required by applicable law or agreed to in writing, software
   # distributed under the License is distributed on an "AS IS" BASIS,
   # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   # See the License for the specific language governing permissions and
   # limitations under the License.

   """``test_vlan.py``

   `Test Vlan implementation`

   Note:
       Following test cases are tested:
        1. Verify that static VLAN can be created.
        2. Verify that static VLAN can be deleted and default VLAN cannot be deleted.

   """

.. note::

   File header should NOT contain below:

   `1 #!/usr/bin/env python`


Import
++++++
Import section has the following rules and sequence in TAF python code:

* import standard module (e.g., os, time);
* import 3rd-party libraries (e.g., pytest);
* import framework-specific libraries (e.g., from testlib import helpers);
* each section of above import group has to be separated by a blank line.

*Example:*

.. code-block:: python
   :linenos:

    import time
    import os

    import pytest

    from testlib import helpers
    from testlib import loggers


Developing Suite Class
++++++++++++++++++++++
Create class with unique name per suite (with appropriate docstring).

.. note::

   Do not use any of Unittest style methods for py.test test cases. All necessary fixtures/setup/teardowns have to be defined using py.test features

Class name should start with "Test". Class decorators should contain the following information:

* full cross connection setup name;
* information about premium functionality (optional);
* information about features that are tested;
* list of platform in case test suite/case is platform dependent (optional);
* mark to skip pidchecker plugin (optional).

*Example of test suite docstrings:*

.. code-block:: python
   :linenos:

    @pytest.mark.simplified
    @helpers.run_on_platforms(["lxc", ])
    @pytest.mark.skip_pidcheck("snmpd")
    @pytest.mark.acl
    @pytest.mark.lag
    class TestRSTPSimplified(object):
    """Suite for testing custom feature.

    """

*Example of test case functions docstrings:*

Write a summary of the particular test case which should explain actual device\'s behavior.

Describe test steps of the particular test case.

.. code-block:: python
   :linenos:

   def test_bpdu_packet_format(self, env):
       """Verify that BPDU packets sent by switch are correctly formatted.

       Steps:
           - # Capture BPDU frames from the DUT
           - # Verify BPDU frames are correctly formatted

       """

It's recommended to register all your markers in pytest.ini file.

.. code-block:: ini
   :linenos:

    # content of pytest.ini
    [pytest]
    markers =
        simplified: mark a tests which have to be execudted on "simplified" setup.


The following setups are allowed: simplified, golden, and diamond.

Class Methods and Variables
+++++++++++++++++++++++++++

This section contains internal variables and help methods used in the particular test suite.

Section should start with following comment separated with a blank line:

.. code-block:: python
   :linenos:

   # Attributes and Properties


Then, class attributes should contain short inline description:

.. code-block:: python
   :linenos:

   tp_id = 0x9100
   tagged = "Tagged"
   untagged = "Untagged"


Class method should have a docstring with following parts:

* summary with method description;
* parameters with name and description (optional);
* return value description (optional);
* usage examples (optional).
