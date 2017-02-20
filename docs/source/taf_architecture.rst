TAF architecture
================

Directory structure of TAF
^^^^^^^^^^^^^^^^^^^^^^^^^^
The current implementation of the testing framework has the following directory structure (only high-level directories are shown)::

    + taf-repo
       + docs
       + reporting
       + taf
         - plugins
         - testlib
       + tests
       + unittests
       + utils


Directory **"docs"** contains documentation generated using doxygen and docutils tools, which are described later.

Directory **"plugins"** contains TAF related plugins wich extends py.test and TAF testlib functionality and could be enabled/disabled for particular tests ot group of tests.

Directory **"testlib"** contains common functionality for the majority of tests, platform-specific libraries and various helper functions, described in System Architecture.

Directory **"unittests"** contains TAF unittests and TAF functional tests.

TAF plugins
^^^^^^^^^^^
Available **TAF plugins** located in **plugins** sub-directory. The most useful of plugins are:

plugins.pytest_reportingserver
++++++++++++++++++++++++++++++
* Starts Reporting Server as a separate process.
* Collects information about test case duration split by stages (setup/call/teardown).
* Options:
    ``--xml_html`` - create html report file at given path.

plugins.pytest_returns
++++++++++++++++++++++
Sometimes user wants to get specific information from the test instead of PASS/FAIL status. TAF allows to include returned information from the test into `pytest <http://doc.pytest.org/en/latest/>`_ . User must modify test case:

* Add return statement as test step in order to return necessary information.
* Add `@pytest.mark.returns` decorator to the test case or test class.

plugins.pytest_syslog
+++++++++++++++++++++
* Send notifications about test case start/end to the remote syslog server.
* Separate device must be specified in the environment Json file with ‘syslog_settings’ instance_type value, e.g.:

.. code-block:: json
   :linenos:

   [
     {"name": "std_syslog_settings", "entry_type": "settings", "instance_type": "syslog_settings", "id": "4",
           "ip": "X.X.X.X", "proto": "Udp", "port": 514, "localport": 514, "transport": "Tcp", "facility": -1,
           "severity": "Debug",
           "syslog_usr": "user", "syslog_passw": "password", "path_to_log": "/var/log/switches/"},
   ]

* This device must be included in the **related** devices of the DUT (**"related_id": ["6"]**), e.g.:

.. code-block:: json
   :linenos:

   [
     {"name": "simswitch1_lxc", "entry_type": "switch", "instance_type": "lxc", "id": "16",
           "ip_host": "X.X.X.X", "ip_port": "8081", "ports_count": 32,
           "cli_user": "lxc_user", "cli_user_passw": "password", "cli_user_prompt": "Switch ",
           "cli_img_path": "usr/lib/ons/cli_img/",
           "ports": [1, 2, 3],
           "related_id": ["6"]},
   ]

* Options:
    ``--syslog`` – enable syslog plugin. False by default.

plugins.pytest_pidchecker
+++++++++++++++++++++++++
* TAF gets info about ONS process IDs on test setup and teardown.
* TAF verifies PIDs are not changed during test case execution. In other case test’s teardown fails, TAF provides information about restarted processes.
* Options:
    ``--pidcheck_disable`` – disable process IDs verification.

.. note::

   During specific tests some processes could be restarted by design or device could be restarted. TAF has a special marker for these test cases that allows to skip process ID validation:
   `@pytest.mark.skip_pidchecker,   @pytest.mark.skip_pidchecker(“process1”, “process2”)`

plugins.pytest_caselogger
+++++++++++++++++++++++++
* Stores device’s logs on the remote host after test execution.
* Options:
    ``--log_enable`` – enable/disable log tool for test (False | True).

plugins.pytest_multiple_run
+++++++++++++++++++++++++++
* Execute test cases N times in a loop. N=1 by default.
* Options:
    ``--multiple_run=N``

plugins.pytest_start_from_case
++++++++++++++++++++++++++++++
* Run test suite starting from specific test case.
* Options:
    ``--start_from_case``

User may use strict test names or patterns, e.g.:

.. code-block:: bash

    --start_from_case  test_my_func
    --start_from_case  test*func
    --start_from_case  *func
    --start_from_case  test*

plugins.pytest_smartrerun
+++++++++++++++++++++++++
* Reruns Test Cases with 'Failed' and 'Cant Test' status from custom Test Plan.
* Options:
    ``--sm_rerun`` –custom Test Plan name.

plugins.pytest_heat_checker
+++++++++++++++++++++++++++
* TAF gets info about CPU temperature from ONS Sensors table and adds it into the test run logs.
* Options:
    ``--heat_check`` – enable/disable tool for temperature logging (False | True).

plugins.pytest_onsenv
+++++++++++++++++++++
* Initializes environment from common3.py module:

  * Reads environment json file
  * Reads setup json file.
  * Loads dev_* modules.
  * Creates instances of used devices according to setup json file.

* Options:
    ``--env`` – path to environment json file. None by default.

    ``--setup`` – path to setup json file. None by default.

plugins.pytest_skip_filter
++++++++++++++++++++++++++
* Remove skipped test cases from list of collected items.

.. note::

   Skip reason must be specified for all skipif markers

plugins.pytest_loganalyzer
++++++++++++++++++++++++++
* Performs analysis for ONPSS device’s logs, checks for duplicates and errors.
* Options:
    ``--log_analyzer`` – enable/disable log tool for test (False | True).

TAF features overview
^^^^^^^^^^^^^^^^^^^^^

**Support for:**
  1. Cross-connection solutions (Vlab, static links)
  2. Traffic generators (Ixia, TRex)
  3. Switches (ONS, ONPSS, Simulated)
  4. OVS controllers (OFTest, Floodlight)
  5. Power boards (APC)
  6. Terminal servers

**Integration with:**
  1. Test Case Management Systems (Jira, SynapseRT)
  2. Defect Trackers (Jira)

Available **TAF features** located in **testlib** sub-directory. The most useful of them are:

TAF ‘devices’
+++++++++++++
+---------------------------+---------------------------------+
|**common3.py**             |main environment file            |
+---------------------------+---------------------------------+
|**dev_switch_*.py**        |switch functionality             |
+---------------------------+---------------------------------+
|**dev_ixia.py**            |TG functionality                 |
+---------------------------+---------------------------------+
|**dev_chef.py**            |chef functionality               |
+---------------------------+---------------------------------+
|**dev_*cross.py**          |cross connector functionality    |
+---------------------------+---------------------------------+
|**dev_ovscontroller.py**   |OVS functionality                |
+---------------------------+---------------------------------+
|**dev_linux_host.py**      |Linux host functionality         |
+---------------------------+---------------------------------+

TAF ‘commons’
+++++++++++++
+--------------------------------------+--------------------------------+
|**entry_template.py**                 |generic code for all devices    |
+--------------------------------------+--------------------------------+
|**switch_general.py, switch_ons.py**  |generic code for switches       |
+--------------------------------------+--------------------------------+
|**testlib/Ixia/***                    |Ixia related files              |
+--------------------------------------+--------------------------------+
|**packet_processor.py**               |generic packet operations       |
+--------------------------------------+--------------------------------+
|**clissh.py, clitelnet.py**           |ssh, Telnet connection          |
+--------------------------------------+--------------------------------+
|**powerboard.py**                     |APC functionality               |
+--------------------------------------+--------------------------------+

TAF ‘UIs’
+++++++++
+--------------------------+----------------------------------+
|**ui_wrapper.py**         |generic code for all UIs          |
+--------------------------+----------------------------------+
|**ui_ons_xmlrpc.py**      |wrappers for ONS XmlRpc calls     |
+--------------------------+----------------------------------+
|**ui_ons_cli.py**         |wrappers for ONS ClI calls        |
+--------------------------+----------------------------------+
|**ui_onpss_shell.py**     |wrappers for ONPSS Shell calls    |
+--------------------------+----------------------------------+
|**ui_onpss_jsonrpc.py**   |wrappers for ONPSS JsonRpc        |
+--------------------------+----------------------------------+

TAF ‘helpers’
+++++++++++++
+-----------------------+-----------------------------+
|**ui_helpers.py**      |general switch operations    |
+-----------------------+-----------------------------+
|**helpers.py**         |general tests operations     |
+-----------------------+-----------------------------+
