# Copyright 2004-present Facebook. All Rights Reserved.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import ast
import logging
import os
import plistlib
import sys

# set DEVELOPING to True for debug statements
DEVELOPING = False

# the log format for the logging module
LOG_FORMAT = "%(levelname)s [Line %(lineno)d]: %(message)s"

# the path to the pkgproj file
PKG_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__))),
    "package/osx/osquery.pkgproj",
)

def usage():
    """ print program usage """
    print("Usage: %s <filename>" % sys.argv[0])

def main(argc, argv):
    if DEVELOPING:
        logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG)
    else:
        logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)

    logging.debug("Config path is: %s" % PKG_CONFIG_PATH)

    plist = plistlib.readPlist(PKG_CONFIG_PATH)

    logging.debug("Project version: %s" % (
        plist["PROJECT"]["PACKAGE_SETTINGS"]["VERSION"]
    ))

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
