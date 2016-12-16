import os
import sys
try:
    trex_lib_path = os.environ["TREX_CLIENT_LIB"]
    sys.path.append(trex_lib_path)
except KeyError:
    pass
