# TAF3

The TAF is based on py.test (http://pytest.org/latest/). The basic concept is to create library with all necessary functionality, to define how the environment configuration will be supplied to test suites, and to create reporting processing functionality.

TAF package consists of two folders: ./taf-repo and ./testcases-repo. taf-repo folder holds library modules (or plugins) for py.test, and testcases-repo contains test cases including test configuration and test scenarios. ./taf-repo/testlib contains of the following modules.

## Common functionality and helper functions:
* loggers - integration of standard python logging library into Framework;
* helpers - contains different helper functions which might be used from test suites;
* common3 - contains base class to handle test environment.

## Groups of modules to handle environment-specific functionality:
* environment - functions for manipulation with operating system environment variables etc.

## Hardware-related libraries:
* dev_* - modules which contain classes to handle particular environment type;
* powerboard - startup/shutdown of the devices using SNMP via APC power boards;

## Typical sequence of actions and operations:
1. Execution starts from calling py.test with necessary command line arguments.
2. Py.test collects test cases according to its discovery rules.
3. Py.test analyses conftest.py file(s) according to its discovery rules.
4. Py.test performs setup procedure defined in conftest.py file.
5. Py.test starts test suites execution one by one.
6. Py.test performs tear down procedure defined in conftest.py file.
7. Logs are stored and ready for further processing.

## License:
Apache 2.0. See LICENSE for more details.

