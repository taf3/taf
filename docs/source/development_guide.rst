Development guide
=================
TAF code naming convention
^^^^^^^^^^^^^^^^^^^^^^^^^^
**General**

The heart of the design of python project is its high level of readability. One reason for code to be easily readable and understood is following set of code style guidelines. It is always advisable to maintain consistency in naming standards. This document describes the nomenclature suggested for use in TAF. TAF developers requires reading at `PEP 8 -- Style Guide for Python Code <https://www.python.org/dev/peps/pep-0008/>`_  , and TAF library is conservative and requires limiting lines to 79 characters (and docstrings/comments to 72) although it exceeds `PEP 8 <https://www.python.org/dev/peps/pep-0008/>`_  standard. 79 characters will give enough to review side-by-side with multiple files, and visualize the difference between changes well in code review tools. Only exception is in writing function name in testcases which can exceed this limit as long as it's helpful to understand the testcase.

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

All files, classes, class methods and first level functions must have properly created docstrings. Note that 'type' syntax in Python docstrings is not defined by any standard. Thus, suggest following notations at `PyCharm <https://www.jetbrains.com/pycharm/webhelp/type-hinting-in-pycharm.html>`_ , `Epydoc <http://epydoc.sourceforge.net/fields.html>`_. This type hinting is only for TAF core library, not for testcases.

**File**

Each python file in TAF should contain a header where the main information about the file is stored. Following keywords can be used:

+-----------------+------------------------------------------------------------------------------------+
|**@copyright**   |put Intel copyright statement                                                       |
+-----------------+------------------------------------------------------------------------------------+
|**@file**        |the name of the test suite (python file name, e.g.: `@file <test_suite_name>.py`)   |
+-----------------+------------------------------------------------------------------------------------+
|**@summary**     |the summary of the test suite                                                       |
+-----------------+------------------------------------------------------------------------------------+
|**@details**     |list available test cases in the test suite                                         |
+-----------------+------------------------------------------------------------------------------------+

*Example:*

.. code-block:: python
   :linenos:

    """
    @copyright Copyright (c) 2011 - 2017, Intel Corporation.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

    @file test_vlan.py

    @summary   Test Vlan implementation.

    @details
    Following test cases are tested:
      1. Verify that static VLAN can be created.
      2. Verify that static VLAN can be deleted and default VLAN cannot be deleted

    """

**Class**

Create a class with appropriate docstring. Following keywords can be used:

+----------------------+----------------------------------------------------------------+
|**@description**      |describing the functionality of testing suite                   |
+----------------------+----------------------------------------------------------------+
|**@par**              |paragraph for further detailed explanation or to give examples  |
+----------------------+----------------------------------------------------------------+
|**@code, @endcode**   |to mention any coding samples for the usage                     |
+----------------------+----------------------------------------------------------------+

*Example:*

.. code-block:: python
   :linenos:

    """
    @description  General Switch object functionality.

    @par Configuration examples:

    @code{.json}
    {
    "name": "simswitch2_lxc",
    "entry_type": "switch",
    "instance_type": "lxc",
    }
    @ endcode
    """


**Function**

*Test Case*

Create a test case function with appropriate docstring. Following keywords can be used:

+--------------+------------------------------------------------------------------------------+
|**@brief**    |summary of the particular test case should explain actual device's behavior   |
+--------------+------------------------------------------------------------------------------+
|**@steps**    |describe the steps for particular test case                                   |
+--------------+------------------------------------------------------------------------------+

*Example #1* *(TAF Core library)*

.. code-block:: python
   :linenos:

    def cli_set(self, commands, split_lines=True, expected_rc=0)
        """
        @brief: Sends a list of commands, will raise an exception on any error
        @param commands: command string to execute
        @type commands: list[list[str]]
        @param split_lines: determine to split or not
        @type split_lines: bool
        @param expected_rc: expected return code
        @type expected_rc: int
        @raise UIException
        @rtype: list[list[str]]
        @return: Output in sequence per list of commands
        """


*Example #2*  *(Test Case)*

.. code-block:: python
   :linenos:

    """
    @brief Verify that the Static entry can be removed
    @steps
        -# Disable STP.
        -# Add new static entry to FDB.
    @endsteps
    """


*Sub module Functions*

Sub-functions inside first level functions need not contain doc strings as far as they aren't designed for any external calls. Ignore `pylint <https://www.pylint.org/>`_ messages. In case you wish to create a docstring, following keywords can be used:

+---------------------+----------------------------------------------------+
|**@brief**           |summary of the particular function                  |
+---------------------+----------------------------------------------------+
|**@param**           |explanation of arguments given to a function        |
+---------------------+----------------------------------------------------+
|**@type**            |explanation of argument type given to a function    |
+---------------------+----------------------------------------------------+
|**@note**            |any notes for better understanding                  |
+---------------------+----------------------------------------------------+
|**@code, @endcode**  |to mention any coding samples for the usage         |
+---------------------+----------------------------------------------------+
|**@rtype**           |to specify return type of the function              |
+---------------------+----------------------------------------------------+
|**@return**          |to specify return value of the function             |
+---------------------+----------------------------------------------------+

*Example:*

.. code-block:: python
   :linenos:

    """
    @brief  Check that FDB table is filled correctly
    @param  switch_instance  Switch instance to work with
    @param  macaddress  MAC address for check
    @note  This function check if master port should be devided into slave ports.
    @return  Count of entries
    @code
    assert self._is_entry_added_to_fdb_table(portid=ports[('sw1', 'tg1')][1], macaddress=source_mac, vlanid=vlan_id, fdb_type="Dynamic", switch_instance=env.switch[1]) == 1
    @ endcode
    """


* Use `@copydoc <link-object>` command to avoid cases where a documentation block would otherwise have to be duplicated or to extend the documentation of an inherited member.
* In order to copy the documentation for a member of a class:

.. code-block:: python
   :linenos:

    def myfunction():
        """
        @copydoc MyClass::myfunction()
        More documentation if required
        """

In case if source docstring is in other file, you can use the following syntax:

.. code-block:: python
   :linenos:

    def customized_get_file():
        """
        @copydoc testlib::cli_template::CLIGeneric::get_file()
        More documentation if required
        """

Where testlib is file's folder, cli_template is file name, CLIGeneric is class, get_file() is function.

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
Each test case python file in TAF3 ("testcases" directory) should contain a header where the main information about the file is stored.

+--------------------+----------------------------------------------+
|**@copyright**      |copyright section                             |
+--------------------+----------------------------------------------+
|**@file**           |the name of the test suite (python file name) |
+--------------------+----------------------------------------------+

.. code-block:: python
   :linenos:

    @file  <test_suite_name>.py

+-----------------+-----------------------------------------------+
|**@summary**     |the summary of the test suite                  |
+-----------------+-----------------------------------------------+
|**@details**     |list available test cases in the test suite    |
+-----------------+-----------------------------------------------+

.. code-block:: python
   :linenos:

    @details
    Following test cases are tested:
    1.      <test 1 summary>
    2.      <test 2 summary>
    ..      ..
    n.      <test N summary>

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

*Example:*

.. code-block:: python
   :linenos:

    @pytest.mark.simplified
    @helpers.run_on_platforms(["lxc", ])
    @pytest.mark.skip_pidcheck("snmpd")
    @pytest.mark.acl
    @pytest.mark.lag
    class TestRSTPSimplified(object):
    """
    @description Suite for testing custom feature.
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

* brief summary with method description;
* parameters with name and description (optional);
* return value description (optional);
* usage examples (optional).
