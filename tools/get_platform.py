#!/usr/bin/env python

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import re
import sys
import argparse
import platform
import subprocess

ORACLE_RELEASE = "/etc/oracle-release"
SYSTEM_RELEASE = "/etc/system-release"
LSB_RELEASE    = "/etc/lsb-release"
OS_RELEASE     = "/etc/os-release"
DEBIAN_VERSION = "/etc/debian_version"
GENTOO_RELEASE = "/etc/gentoo-release"
SUSE_RELEASE   = "/etc/SuSE-release"

def _platform():
    osType, _, _, _, _, _ = platform.uname()

    if osType == "Windows":
        return ("windows", "windows")
    elif osType == "Linux":
        if os.path.exists(ORACLE_RELEASE):
            return ("redhat", "oracle")

        if os.path.exists(SYSTEM_RELEASE):
            with open(SYSTEM_RELEASE, "r") as fd:
                fileContents = fd.read()

                if fileContents.find("CentOS") != -1:
                    return ("redhat", "centos")

                if fileContents.find("Scientific Linux") != -1:
                    return ("redhat", "scientific")

                if fileContents.find("Red Hat Enterprise") != -1:
                    return ("redhat", "rhel")

                if fileContents.find("Amazon Linux") != -1:
                    return ("redhat", "amazon")

                if fileContents.find("Fedora") != -1:
                    return ("redhat", "fedora")

        if os.path.exists(LSB_RELEASE):
            with open(LSB_RELEASE, "r") as fd:
                fileContents = fd.read()

                if fileContents.find("DISTRIB_ID=Ubuntu") != -1:
                    return ("debian", "ubuntu")

                if fileContents.find("DISTRIB_ID=Arch") != -1:
                    return ("arch", "arch")

                if fileContents.find("DISTRIB_ID=ManjaroLinux") != -1:
                    return ("arch", "manjaro")

        if os.path.exists(OS_RELEASE):
            with open(OS_RELEASE, "r") as fd:
                fileContents = fd.read()

                if fileContents.find("ID=nixos") != -1:
                    return ("nixos", "nixos")

        if os.path.exists(DEBIAN_VERSION):
            return ("debian", "debian")

        if os.path.exists(GENTOO_RELEASE):
            return ("gentoo", "gentoo")

        if os.path.exists(SUSE_RELEASE):
            return ("suse", "suse")
    else:
        return (None, osType.lower())

def _distro(osType):
    def getRedhatDistroVersion(pattern):
        with open(SYSTEM_RELEASE, "r") as fd:
            contents = fd.read()

            result = re.findall(pattern, contents)
            if result and len(result) == 1:
                return result[0].replace("release ", osType)
        return None

    def commandOutput(cmd):
        try:
            output = subprocess.check_output(cmd)
            return output
        except subprocess.CalledProcessError:
            return None
        except OSError:
            return None
        except WindowsError:
            return None

    _, _, osVersion, _, _, _ = platform.uname()

    if osType == "oracle":
        result = getRedhatDistroVersion(r'release [5-7]')
        if result is not None:
            return result
    elif osType in ["centos", "scientific", "rhel"]:
        result = getRedhatDistroVersion(r'release [6-7]')
        if result is not None:
            return result
    elif osType == "amazon":
        result = getRedhatDistroVersion(r'release 20[12][0-9]\.[0-9][0-9]')
        if result is not None:
            return result
    elif osType == "ubuntu":
        with open(LSB_RELEASE, "r") as fd:
            contents = fd.read()
            results = re.findall(r'DISTRIB_CODENAME=(.*)', contents)
            if len(results) == 1:
                return results[0]
    elif osType == "darwin":
        rawResult = commandOutput(["sw_vers", "-productVersion"])
        if rawResult is not None:
            results = re.findall(r'[0-9]+\.[0-9]+', rawResult)
            if len(results) == 1:
                return results[0]
    elif osType == "fedora":
        with open(SYSTEM_RELEASE, "r") as fd:
          contents = fd.read()
          results = contents.split()
          if len(results) > 2:
            return results[2]
    elif osType == "arch":
        with open("/etc/arch-release", "r") as fd:
          contents = fd.read()
          results = contents.split()
          if len(results) > 2:
            return results[2]
    elif osType == "manjaro":
        with open(LSB_RELEASE, "r") as fd:
            contents = fd.read()
            results = re.findall(r'DISTRIB_CODENAME=(.*)', contents)
            if len(results) == 1:
                return results[0]
    elif osType == "debian":
        result = commandOutput(["lsb_release", "-cs"])
        if result is not None:
            return result
    elif osType == "freebsd":
        rawResult = commandOutput(["uname", "-r"])
        results = rawResult.split("-")
        if len(results) > 0:
          return results[0]
    elif osType == "gentoo":
        with open(GENTOO_RELEASE, "r") as fd:
          contents = fd.read()
          results = contents.split()
        if len(results) > 0:
          return results[len(results) -1]
    elif osType == "suse":
        with open(SUSE_RELEASE, "r") as fd:
            contents = fd.read()
            results = re.findall(r'VERSION = (.*)', contents)
            if len(results) == 1:
                return results[0]
    elif osType == "nixos":
        with open(OS_RELEASE, "r") as fd:
            contents = fd.read()
            results = re.findall(r'VERSION_ID=\"(.*)\"', contents)
            if len(results) == 1:
                return results[0]
    elif osType == "windows":
        return "windows%s" % osVersion

    return "unknown_version"

def platformAction():
    family, osType = _platform()
    print(osType)

def distroAction():
    family, osType = _platform()
    print(_distro(osType))

def familyAction():
    family, osType = _platform()
    if family:
        print(family)

def defaultAction():
    family, osType = _platform()
    distro = _distro(osType)
    print("%s;%s" % (osType, distro))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Platform detection script for osquery")
    parser.add_argument("--platform", action="store_true", help="Outputs the detected platform")
    parser.add_argument("--distro", action="store_true", help="Outputs the detected distribution")
    parser.add_argument("--family", action="store_true", help="Outputs the detected family")

    args = parser.parse_args()

    if args.platform and \
        not args.distro and \
        not args.family:
      platformAction()
    elif not args.platform and \
        args.distro and \
        not args.family:
      distroAction()
    elif not args.platform and \
        not args.distro and \
        args.family:
      familyAction()
    else:
      defaultAction()

    sys.exit(0)
