## TAF overview

**TAF** is an integrated cross-platform system that sets the guidelines and provides tools for automation testing. The function libraries, test data sources, test object details, and various reusable modules are all integrated in one system. The platform provides an outline of the test automation process and reduces automation efforts. With this framework, an automation or validation engineer may run testing suites in different environments and obtain test results with detailed reports.

The [Python](https://www.python.org/) programming language was chosen for the Framework, due to its high development speed and great maintainability. In addition, it has an XML-RPC library. [Py.test](http://pytest.org/latest/) was chosen as it has several advantages over other available test libraries. We follow the principle of maximum usage of existing components and systems. The framework has some components which use threading which should be considered when looking for components to extend the system. The system is built in way that allows users to see all errors that occur during test execution and to trace the full path to the initial point where the defect appeared to simplify root cause analysis. There is no external storage required except integration with Test Case Management System(s) using a database via API to update test case execution results and any related information (automation status, automation owner, automated script location, etc).

### Design considerations

**System Requirements and Dependencies**

The framework is designed for use in Linux systems which have Python programming tools and the necessary libraries installed. The framework has been tested on following systems:

* Ubuntu 14.04.1 LTS running Python 3.4.0, py.test 2.9.2 and higher versions.
* Ubuntu 16.04.1 LTS running Python 3.4.0, py.test 2.9.2 and higher versions.

Test cases running with TAF might require additional software packages such as Ixia or Jira, depending upon test scenarios, which can be downloaded from internet or company website.

**Constraints**

The framework is originally intended to work with remote systems, so quality of network may affect testing results. In its original testing environment, **TAF** uses an Ixia traffic generator via Tcl API which may cause to slow down overall system performance, since **TAF** must use the Tkinter Python library to bind Tcl and Python. Furthermore, Ixia is a Windows-based system, however it does include a Tcl server component which allows access from Linux hosts. Ixia Tcl library (IxTclHAL) is not thread-safe which may add difficulties in future.

**Goals and Guidelines**

The **TAF** framework follows the "principle of atomicity" by splitting complex test cases into parts if possible and the DRY (Don't Repeat Yourself) principle by moving shared parts of code into helper functions and modules. **TAF** will define testing along the development phase, which will enable testers to configure the test environment, execute tests, and measure success/failure and coverage. The modular approach of **TAF** enables development of new tests without impacting existing ones, increasing reusability of developed tests.

### System architecture

![TAF architecture](https://github.com/IrynaBarna/taf/blob/master/docs/images/taf_architecture.png "Test Automation Framework Architecture")

The **TAF** is based on [py.test](http://pytest.org/latest/). The basic concept is to create libraries with all necessary functionality, to define how the environment configuration will be supplied to test suites, and to create a reporting processing functionality.

**TAF** package consists of two folders: **./taf** and **./testcases**. **taf** folder holds library modules (or plugins) for [py.test](http://pytest.org/latest/), and **testcases** contains test cases including test configuration and test scenarios. **./taf/testlib** contains of the following modules.

**Common functionality and helper functions:**

* `loggers` - integration of standard python logging library into framework;
* `helpers*` - contains different helper functions which can be used from test suites;
* `common3` - contains base class to handle test environment.

**Groups of modules to handle environment-specific functionality:**

* `environment` - functions for manipulation the operating system environment variables etc.

**Hardware-related libraries:**

* `dev_*` - modules which contain classes to handle particular environment type;
* `powerboard`  - startup/shutdown of the devices using SNMP via APC power boards.

**Typical sequence of actions and operations:**

1. Execution starts from calling py.test with necessary command line arguments.
2. Py.test collects test cases according to its discovery rules.
3. Py.test analyses conftest.py file(s) according to its discovery rules.
4. Py.test performs setup procedure defined in conftest.py file.
5. Py.test starts test suites execution one by one.
6. Py.test performs tear down procedure defined in conftest.py file.
7. Logs are stored and ready for further processing.


## Installation

### Docker container

**TAF** is very easy to install and deploy as a Docker container.

**Docker** can build images automatically by reading instructions from a Dockerfile, a text document that contains all the commands a user can call on the command line to assemble an image. Using Docker build, users can create an automated build that executes several command-line instructions in succession. **TAF** has a configuration file, called Dockerfile, located in the root of the **TAF**  directory. It is based on Ubuntu 16.04 and Python 3.4.0.

**Install and configure Docker**

In order to install Docker, refer [Docker](https://docs.docker.com/engine/installation/linux/ubuntulinux/) .

**Build image**

To build **TAF** image you need to execute command:
```
    docker build -t <image_name>:<tag> -f Dockerfile .
    E.g. :root@14-04:~/taf# docker build -t ubuntu:taf3 -f Dockerfile .
```

Building the **TAF** image from Dockerfile can take over 15 minutes.

**Run container**

To run the **TAF** image and login to the container, execute command:
```
    docker run -i -t  <image_name>:<tag>
    E.g.: root@14-04:~# docker run -i -t ubuntu:taf3
```

After execution of previous command, the prompt should changed to:
```
    root@<container_id>:~#
    E.g.: root@fa3ced1fdcbf:~#
```

The **TAF** repository can be found in the root directory. Once in the **TAF** container, sample testcases can be run:
```
    $ cd unittests
    $ /root/taf/unittests/ py.test test_common3.py
```

### Simple test execution

* **Git clone testcases repository**

Link to repository [testcases](https://github.com/taf3/testcases)

* **Run test**

    Command line used to execute specified test case:
```
 /<host>/:~ /testcases$ env PYTHONPATH=/root/taf/taf py.test --env=config/env/environment_examples.json
  --setup_file=config/setup/linuxhost_standalone.json general/ -m lhost_sample --logdir=demo_logs --xml_html=demo.html
```
> Note:

> Test example requires to install and configure OpenSSH server. Appropriate ssh credentials need to be specified in environment_examples.json file with "entry_type" linux_host.

     env PYTHONPATH – set up PYTHONPATH variable with path to TAF repository;

     env – provide path to the environment*.json file;

     setup – provide path to the setup*.json file.

 * More **detailed information** can be found by the following link: [Test execution preconfiguration](http://taf.readthedocs.io/en/sphinx_docs/test_execution_preconfiguration.html)


## Support and contact

Link to wiki [Сontribution guidelines](http://taf.readthedocs.io/en/sphinx_docs/contribution_guidelines.html).

## License

Apache 2.0. See [LICENSE](https://github.com/taf3/taf/blob/master/LICENSE) for more details.


