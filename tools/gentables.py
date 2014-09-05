# Copyright 2004-present Facebook. All Rights Reserved.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import logging
import os
import subprocess
import sys

# set DEVELOPING to True for debug statements
DEVELOPING = False

# the log format for the logging module
LOG_FORMAT = "%(levelname)s [Line %(lineno)d]: %(message)s"

# the project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

# the directory where the table specs are stored
SPEC_DIR = os.path.join(BASE_DIR, "osquery/tables/specs")

# the directory where the cross-platform specs are stored
X_SPEC_DIR = os.path.join(SPEC_DIR, "x")

# the directory where the OS specific specs are stored
platform = sys.platform
if platform.startswith("linux"):
    # remove kernel major version http://bugs.python.org/issue12326
    platform = "linux"
OS_SPEC_DIR = os.path.join(SPEC_DIR, platform)

# the directory where generated tables are stored
GENERATED_TABLE_DIR = os.path.join(BASE_DIR, "osquery/tables/generated")

# the path of the gentable.py tool
GENTABLE_PATH = os.path.join(BASE_DIR, "tools/gentable.py")

def main(argc, argv):
    if DEVELOPING:
        logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG)
    else:
        logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)

    if not os.path.isdir(GENERATED_TABLE_DIR):
        os.mkdir(GENERATED_TABLE_DIR)
    tables_specs = []
    tables_specs += [os.path.join(X_SPEC_DIR, i) for i in os.listdir(X_SPEC_DIR)]
    tables_specs += [os.path.join(OS_SPEC_DIR, i) for i in os.listdir(OS_SPEC_DIR)]
    for filename in tables_specs:
        args = ["python", GENTABLE_PATH, filename]
        logging.info(" ".join(args))
        p = subprocess.Popen(args, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        out = p.stdout.readlines()
        if out:
            print("\n".join(filter(None, out))),
        err = p.stderr.readlines()
        if err:
            print("\n".join(filter(None, err))),

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
