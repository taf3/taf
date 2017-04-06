Continuous integration
======================
**Continuous integration** can help catch bugs by running your tests automatically.
The main goal is to eliminate the long and tedious integration process, the work that you normally have to do between version's final development stage and its deployment in production.
A **continuous integration (CI)** process is highly recommended and is extremely useful in ensuring that your application stays functional.
TAF project uses open source `Travis <https://docs.travis-ci.com/>`_ continuous integration service.

TAF Travis CI job
^^^^^^^^^^^^^^^^^
* TAF project notifies Travis whenever pull request is submitted or updated.
* TAF Travis job is configured via .travis.yml and run script project_checker.py.

.. note::

   .travis.yml file is located in the TAF root directory

   project_checker.py file is located in TAF 'ci' branch


**TAF Travis** job performs the following verification steps:

1. Run `flake8 <https://pypi.python.org/pypi/flake8>`_ tool
2. Run `pylint <https://pypi.python.org/pypi/pylint/1.6.4>`_ tool
3. Run taf/unittests

TAF Travis build status and logging messages you can find by the following link - https://travis-ci.org/taf3/taf .

Code Errors that trigger -1 verified
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python
   :linenos:

   FLAKE8_FATAL_ERRORS = {
    "E101", # indentation contains mixed spaces and tabs
    "E111", # indentation is not a multiple of four
    "E112", # expected an indented block
    "E113", # unexpected indentation
    "E114", # indentation is not a multiple of four (comment)
    "E115", # expected an indented block (comment)
    "E116", # unexpected indentation (comment)
    "E711", # (^) comparison to None should be 'if cond is None:'
    "E712", # (^) comparison to True should be 'if cond is True:' or 'if cond:'
    "E713", # test for membership should be 'not in'
    "E714", # test for object identity should be 'is not'
    "E721", # do not compare types, use 'isinstance()'
    "E731", # do not assign a lambda expression, use a def
    "W191", # indentation contains tabs
    "W601", # .has_key() is deprecated, use 'in'
    "W602", # deprecated form of raising exception
    "W603", # '<>' is deprecated, use '!='
    "W604", # backticks are deprecated, use 'repr()'
    "F403", # 'from module import *' used; unable to detect undefined names
    "F821", # undefined name name
    "F822", # undefined name name in __all__
    "F831", # duplicate argument name in function definition
    "N804", # first argument of a classmethod should be named 'cls'
    "N805", # first argument of a method should be named 'self'
    "N811", # constant imported as non constant
    "N812", # lowercase imported as non lowercase
    "N813", # camelcase imported as lowercase
    "N814", # camelcase imported as constant
   }

.. code-block:: python
   :linenos:

   PYLINT_FATAL_ERRORS = {
    "C0121",  # Missing required attribute "%s"
    "C0202",  # Class method %s should have cls as first argument
    "C0203",  # Metaclass method %s should have mcs as first argument
    "C0204",  # Metaclass class method %s should have %s as first argument
    "C1001",  # Old-style class defined.

    "E0001",  # (syntax error raised for a module; message varies)
    "E0011",  # Unrecognized file option %r
    "E0012",  # Bad option value %r
    "E0100",  # __init__ method is a generator
    "E0101",  # Explicit return in __init__
    "E0102",  # %s already defined line %s
    "E0103",  # %r not properly in loop
    "E0104",  # Return outside function
    "E0105",  # Yield outside function
    "E0106",  # Return with argument inside generator
    "E0107",  # Use of the non-existent %s operator
    "E0108",  # Duplicate argument name %s in function definition
    "E0202",  # An attribute affected in %s line %s hide this method
    "E0203",  # Access to member %r before its definition line %s
    "E0211",  # Method has no argument
    "E0213",  # Method should have "self" as first argument
    "E0221",  # Interface resolved to %s is not a class
    "E0222",  # Missing method %r from %s interface
    "E0235",  # __exit__ must accept 3 arguments: type, value, traceback
    "E0501",  # Old: Non ascii characters found but no encoding specified (PEP 263)
    "E0502",  # Old: Wrong encoding specified (%s)
    "E0503",  # Old: Unknown encoding specified (%s)
    "E0601",  # Using variable %r before assignment
    "E0602",  # Undefined variable %r
    "E0603",  # Undefined variable name %r in __all__
    "E0604",  # Invalid object %r in __all__, must contain only strings
    "E0611",  # No name %r in module %r
    "E0701",  # Bad except clauses order (%s)
    "E0702",  # Raising %s while only classes, instances or string are allowed
    "E0710",  # Raising a new style class which doesn't inherit from BaseException
    "E0711",  # NotImplemented raised - should raise NotImplementedError
    "E0712",  # Catching an exception which doesn\'t inherit from BaseException: %s
    "E1001",  # Use of __slots__ on an old style class
    "E1002",  # Use of super on an old style class
    "E1003",  # Bad first argument %r given to super()
    "E1004",  # Missing argument to super()
    "E1101",  # %s %r has no %r member
    "E1102",  # %s is not callable
    "E1103",  # %s %r has no %r member (but some types could not be inferred)
    "E1111",  # Assigning to function call which doesn't return
    "E1120",  # No value passed for parameter %s in function call
    "E1121",  # Too many positional arguments for function call
    "E1122",  # Old: Duplicate keyword argument %r in function call
    "E1123",  # Passing unexpected keyword argument %r in function call
    "E1124",  # Parameter %r passed as both positional and keyword argument
    "E1125",  # Old: Missing mandatory keyword argument %r
    "E1200",  # Unsupported logging format character %r (%#02x) at index %d
    "E1201",  # Logging format string ends in middle of conversion specifier
    "E1205",  # Too many arguments for logging format string
    "E1206",  # Not enough arguments for logging format string
    "E1300",  # Unsupported format character %r (%#02x) at index %d
    "E1301",  # Format string ends in middle of conversion specifier
    "E1302",  # Mixing named and unnamed conversion specifiers in format string
    "E1303",  # Expected mapping for format string, not %s
    "E1304",  # Missing key %r in format string dictionary
    "E1305",  # Too many arguments for format string
    "E1306",  # Not enough arguments for format string
    "E1310",  # Suspicious argument in %s.%s call

    "F0001",  # (error prevented analysis; message varies)
    "F0002",  # %s: %s (message varies)
    "F0010",  # error while code parsing: %s

    "R0401",  # Cyclic import (%s)
    "W0102",  # Dangerous default value %s as argument
    "W0109",  # Duplicate key %r in dictionary
    "W0121",  # Use raise ErrorClass(args) instead of raise ErrorClass, args.
    "W0122",  # Use of exec
    "W0150",  # %s statement in finally block may swallow exception
    "W0199",  # Assert called on a 2-uple. Did you mean \'assert x,y\'?
    "W0211",  # Static method with %r as first argument
    "W0221",  # Arguments number differs from %s method
    "W0233",  # __init__ method from a non direct base class %r is called
    "W0234",  # iter returns non-iterator
    "W0311",  # Bad indentation. Found %s %s, expected %s
    "W0331",  # Use of the <> operator
    "W0332",  # Use of "l" as long integer identifier
    "W0333",  # Use of the `` operator
    "W0401",  # Wildcard import %s
    "W0402",  # Uses of a deprecated module %r
    "W0404",  # Reimport %r (imported line %s)
    "W0410",  # __future__ import is not the first non docstring statement
    "W0406",  # Module import itself
    "W0512",  # Cannot decode using encoding "%s", unexpected byte at position %d
    "W0601",  # Global variable %r undefined at the module level
    "W0602",  # Using global for %r but no assigment is done
    "W0604",  # Using the global statement at the module level
    "W0614",  # Unused import %s from wildcard import
    "W0622",  # Redefining built-in %r
    "W0623",  # Redefining name %r from %s in exception handler
    "W0631",  # Using possibly undefined loop variable %r
    "W0632",  # Possible unbalanced tuple unpacking with sequence%s:
    "W0633",  # Attempting to unpack a non-sequence%s
    "W0701",  # Raising a string exception
    "W0702",  # No exception type(s) specified
    "W0711",  # Exception to catch is the result of a binary "%s" operation
    "W0712",  # Implicit unpacking of exceptions is not supported in Python 3
    "W1001",  # Use of "property" on an old style class
    "W1111",  # Assigning to function call which only returns None
    "W1201",  # Specify string format arguments as logging function parameters
    "W1300",  # Format string dictionary key should be a string, not %s
    "W1301",  # Unused key %r in format string dictionary
    "W1501",  # "%s" is not a valid mode for open.
}
