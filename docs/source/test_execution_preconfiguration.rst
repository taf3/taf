Test execution preconfiguration
===============================

All TAF test cases are parameterized in a way that they have access to **env** object which is built from environment description. For example typical **env** object contains already initialized switch(es), traffic generator and cross connection tool. You just need to describe in your `conftest.py <http://doc.pytest.org/en/latest/writing_plugins.html?highlight=conftest#conftest-py-plugins>`_ file and test which methods and in which order should be called on different stages of test execution.

SETUP config - `testcases/config/setup/*.json`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
**Setup config** contains **env** and **cross** parts.

* The **env** part is a list of devices in the current setup. Its format is the same as the environment config, except that you need define only entry IDs that corresponds to the ones in the env conf file.
* The **cross** part is a dictionary with cross ids as the keys and the appropriate list of connections as values.

Env Part
++++++++
In general, you should define only ids of necessary devices, but you can also override parts of the device configuration from **env** config.

*Examples*:

.. code-block:: json
   :linenos:

   {
   "env": [
           {"id": 22, "related_id": ["33"]},
           {"id": "33", "related_id": [16]},
           {"id": 16}
          ],
   }

.. code-block:: json
   :linenos:

   {
   "env": [
           {"id": 0, "ifaces": [[1, 1, 6], [1, 1, 7], [1, 1, 8], [1, 1, 9], [1, 1, 10], [1, 1, 11], [1, 1, 12], [1, 1, 13], [1, 1, 14]]},
           {"id": 1, "ports": [24, 25, 26, 33, 48, 39, 34, 35]},
           {"id": 4, "ports": [28, 29, 24, 25, 26, 27]},
           {"id": 3, "ports": [24, 25, 28, 29, 34, 35]},
           {"id": 2, "ports": [24, 25, 33, 48, 39, 34, 35]},
           {"id": "33"}
          ],
   }

Cross Part
++++++++++
This list of connections is a list of lists. Each connection is a list of four elements: `[<device1 id>="">, <port id>="">, <device2 id>="">, <port id>="">]` :

* Port ID is the ID for a port in the list of real ports in the device configuration (ids starts from 1).
* Device id is the value of the "id" field in the environment config.

*Examples*:

.. code-block:: json
   :linenos:

   {
   "cross": {"2": [[0,1,1,1], [0,2,1,2], [0,3,1,3], [0,4,1,4], [0,5,1,5]]}
   }

.. code-block:: json
   :linenos:

   {
   "cross": {"4": [[0,1,1,1], [0,2,1,2], [0,3,1,3], [0,4,1,4], [0,5,1,5], [0,10,3,1],
                   [0,11,3,2], [0,12,3,3], [0,6,2,1], [0,7,2,2],
                   [0,8,2,3], [0,9,2,4]],
             "5": [[1,16,2,16], [1,17,2,17], [1,18,2,18], [1,19,2,19],
                   [1,20,2,20], [1,21,2,21],
                   [1,22,2,22], [1,23,2,23], [1,24,2,24], [1,11,3,11],
                   [1,12,3,12], [1,13,3,13], [1,14,3,14],
                   [2,11,3,5], [2,12,3,6], [2,13,3,7], [2,14,3,8]]}
   }


**Complete Configuration**

*Examples*:

.. code-block:: json
   :linenos:

   {
   "env": [
           {"id": 0, "ifaces": [[1, 1, 6], [1, 1, 7], [1, 1, 8], [1, 1, 9], [1, 1, 10]]},
           {"id": 1},
           {"id": "30"}
          ],
   "cross": {"30": [[0,1,1,1], [0,2,1,2], [0,3,1,3], [0,4,1,4], [0,5,1,5]]}
   }

.. code-block:: json
   :linenos:

   {
   "env": [
           {"id": 22, "related_id": ["33"]},
           {"id": "33", "related_id": [16, 17, 18]},
           {"id": 16},
           {"id": 17},
           {"id": 18}
          ],
   "cross": {"33": [[22,1,16,1], [22,2,16,2], [22,3,16,3], [22,4,16,4],[22,5,16,5],
                    [16,16,17,16], [16,17,17,17], [16,18,17,18], [16,19,17,19], [16,20,17,20],
                    [16,21,17,21], [16,22,17,22], [16,23,17,23],[16,24,17,24],
                    [16,11,18,11], [16,12,18,12], [16,13,18,13],[16,14,18,14],
                    [22,10,18,1], [22,11,18,2], [22,12,18,3], [17,11,18,5], [17,12,18,6], [17,13,18,7],
                    [17,14,18,8],[22,6,17,1], [22,7,17,2], [22,8,17,3], [22,9,17,4]]
            }
   }

ENVIRONMENT config - `testcases/config/env/*.json`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
**Environment config** describes all allowed devices for setups. Which devices will be used in current run is defined in the setup configuration.

Environment configuration is a list of dictionaries. Each dictionary is a record for one device in SUT.

Each device type has it's own fields, but "entry_type", "instance_type" and "id" are obligatory for all devices.

For each DUT type, the following **"entry_type"** - **"instance_type"** variants are possible:

* **tg** - traffic generators:
    - ixiahl;
    - ixload;
    - trex
* **switch** - switches:
    - lxc - simswitch in lxc container for L3 testing;
    - `<chipname>` - real devices based on particular hardware
* **cross** - cross connection devices:
    - vlab - virtual cross connection tool;
    - static_ons - just stub for static connections
* **linux_host** - Linux bases hosts:
    - generic - real Linux host;
    - netns - Linux network namespase which emulates real Lunux Host behaviour
* **hub** - Hubs:
    - real;
    - simulated

.. note::

   The "id" field values must be unique for all devices in config


In some cases, one device type needs a part of the config of another device. In this case you can use the "related_id" key (list type).

This key contains IDs of other devices, for which the config is necessary for the current one. For example  `{"entry_type": "tg", "instance_type": "trex"}`  uses vlab interfaces for sending and sniffing packets, and therefore  `"related_id": [<vlab_id>]`  should be added.

Real port names must be described only in appropriate device config. Then in other config and cross parts only port IDs from that device config will be used.

*Examples:*

TG:
++++

* Ixia traffic generator:

.. code-block:: json
   :linenos:

   [
     {"entry_type": "tg", "instance_type": "ixia", "id": 0,
      "ip_host": "X.X.X.X", "ports": [[1, 1, 1], [1, 1, 2], [1, 1, 3], [1, 1, 4], [1, 1, 5]]},
   ]

Linux Hosts:
++++++++++++

* Network namespace:

.. code-block:: json
   :linenos:

   [
     {"name": "Namespace_Simulated_2", "entry_type": "linux_host", "instance_type": "netns", "id": 1520,
      "ipaddr": "X.X.X.X", "ssh_user": "User", "ssh_pass": "pAsSwD",
      "ports": ["veth0", "veth1", "veth2"]
     },
   ]

* Real Linux Host:

.. code-block:: json
   :linenos:

   [
     {"name": "Localhost1", "entry_type": "linux_host", "instance_type": "generic", "id": 999,
      "ipaddr": "localhost", "ssh_user": "User", "ssh_pass": "pAsSwD",
      "ports": ["lo"]
     },
   ]

Switch:
+++++++

* Simulated switch in LXC container:

.. code-block:: json
   :linenos:

   [
     {"entry_type": "switch", "instance_type": "lxc", "id": 1,
      "ip_host": "X.X.X.X", "ip_port": "8081",
      "ports_count": "32",
      "ports": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24],
      "related_id": [5]},
   ]

* Real switch:

.. code-block:: json
   :linenos:

   [
     {"name": "some_real_device", "entry_type": "switch", "instance_type": "real", "id": 415,
      "ip_host": "192.168.1.20", "ip_port": "8081",
      "use_sshtun": 1, "sshtun_user": "xmluser", "sshtun_pass": "password", "sshtun_port": 22,
      "default_gw": "192.168.1.1", "net_mask": "255.255.255.0",
      "pwboard_host": "192.168.1.100", "pwboard_port": "15", "halt": 0,
      "portserv_host": "192.168.1.101", "portserv_user": "root", "portserv_pass": "pass", "portserv_tty": 15, "portserv_port": 2015,
      "telnet_loginprompt": "switch login:", "telnet_passprompt": "Password:", "telnet_user": "admin",
      "telnet_pass": "password", "telnet_prompt": "[admin@switch ~]$",
      "cli_user": "admin", "cli_user_passw": "admin" "cli_user_prompt": "Switch",
      "ports_count": "52",
      "ports": [40, 41, 43, 44, 45, 46, 47, 11, 12, 36, 37, 10, 23, 20, 39, 38],
      "related_id": [210]},
   ]

Cross:
++++++

* Vlab:

.. code-block:: json
   :linenos:

   [
     {"entry_type": "cross", "instance_type": "vlab", "id": "2",
      "ip_host": "localhost", "ip_port": "8050",
      "ifaces": ["vlab0", "vlab1", "vlab2", "vlab3", "vlab4"],
      "tgmap": [0],
      "related_id": [1]},
   ]

