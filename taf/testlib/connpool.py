# Copyright (c) 2011 - 2017, Intel Corporation.
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


"""``connpool.py``

`Connection Pool class`

"""

import time
from itertools import chain

from . import loggers
from .custom_exceptions import ConnPoolException


# TODO: add ability to block waiting on a connection to be released
# TODO: check if new connection object isn't link to previous one
class ConnectionPool(object):
    """Generic connection pool`

    """

    class_logger = loggers.ClassLogger()

    def __init__(self, connection_class=None, max_connections=None, time_to_live=30, **connection_kwargs):
        """Initialize ConnectionPool class.

        Args:
            connection_class(TelnetCMD):  Telnet connection class
            max_connections(int):  Maximum available connections
            time_to_live(int):  Time to live for each connection
            connection_kwargs(dict):  Connection arguments

        """
        self.connection_class = connection_class
        self.connection_kwargs = connection_kwargs
        self.max_connections = max_connections or 1
        self.time_to_live = time_to_live
        self.retry_count = 3
        self._available_connections = []
        self._in_use_connections = set()

    def get_connection(self):
        """Get a connection from the pool.

        Raises:
            ConnPoolException:  connection is dead, error on connection creation

        Returns:
            TelnetCMD:  Telnet connection

        """
        # self.class_logger.info("Try to get connection...")
        for i in range(1, self.retry_count + 1):

            if len(self._available_connections) > 0:
                connection, last_time = self._available_connections.pop()
                if (last_time + self.time_to_live) < time.time():
                    try:
                        self.class_logger.debug("Time to leave is exceeded. Destroy connection and try to make new one.")
                        connection.disconnect()
                    except Exception as err:
                        self.class_logger.warning("Error occurred while disconnecting connection: %s" % (err, ))
                    finally:
                        del connection

            # If connection is not created/got on previous step
            if "connection" not in locals():
                self.class_logger.debug("Connection is not available. Making one...")
                try:
                    connection = self.make_connection()
                    self.class_logger.debug("...completed.")
                except Exception as err:
                    self.class_logger.debug("...failed: %s." % (err, ))

            try:
                if "connection" in locals():
                    if not connection.check_connection():
                        raise ConnPoolException("Connection is dead.")
                    self._in_use_connections.add(connection)
                    self.class_logger.debug("Connection check passed.")
                    return connection

            except Exception as err:
                self.class_logger.warning("Error occurred: %s" % (err, ))
                try:
                    self.class_logger.debug("Deleting connection since it's not OK...")
                    # self.del_connection_in_use(connection)
                    connection.disconnect()
                    self.class_logger.debug("...Deletion succeeded.")
                except Exception as err:
                    self.class_logger.warning("Broken connection deletion failed: %s." % (err, ))

            sleep_time = i ** 2
            self.class_logger.debug("Connection check failed. Sleeping for %s secs before retry." % (sleep_time, ))
            time.sleep(sleep_time)

        message = "ERROR: Cannot create connection after %s attempts." % (self.retry_count, )
        self.class_logger.error(message)
        raise ConnPoolException(message)

    def make_connection(self):
        """Create a new connection.

        Raises:
            ConnPoolException:  too many connections

        Returns:
            TelnetCMD:  Telnet connection

        """
        if self._created_connections() >= self.max_connections:
            raise ConnPoolException("Too many connections.")
        connection = self.connection_class(**self.connection_kwargs)
        connection.connect()
        return connection

    def release(self, connection):
        """Releases the connection back to the pool.

        Args:
            connection(TelnetCMD):  Telnet connection

        """
        self._in_use_connections.remove(connection)
        self._available_connections.append((connection, time.time()))

    def del_connection_in_use(self, connection):
        """Delete connection in use (in case any error).

        Args:
            connection(TelnetCMD):  Telnet connection

        """
        try:
            self._in_use_connections.remove(connection)
            connection.disconnect()
        except Exception as err:
            self.class_logger.warning("Error occurred while removing connection: %s" % (err, ))

    def disconnect_all(self):
        """Disconnects all connections in the pool.

        """
        all_conns = chain([_x[0] for _x in self._available_connections], self._in_use_connections)
        for connection in all_conns:
            try:
                connection.disconnect()
            except Exception as err:
                self.class_logger.warning("Error occurred while disconnecting connection: %s" % (err, ))
        self._available_connections = []
        self._in_use_connections = set()

    def _created_connections(self):
        """Return number of created connections

        Returns:
            int:  Number of created connections

        """
        return len(self._available_connections) + len(self._in_use_connections)
