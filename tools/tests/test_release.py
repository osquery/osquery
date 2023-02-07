#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import argparse
import subprocess
import unittest
import sys
import platform
import utils


linux_expected_libraries = [
    "linux-vdso.so",
    "libdl.so",
    "libresolv.so",
    "librt.so",
    "libm.so",
    "libpthread.so",
    "libc.so",
]

windows_expected_libraries = [
    "SHLWAPI.dll",
    "RPCRT4.dll",
    "CRYPT32.dll",
    "Secur32.dll",
    "bcrypt.dll",
    "KERNEL32.dll",
    "WS2_32.dll",
    "ncrypt.dll",
    "USERENV.dll",
    "VERSION.dll",
    "USER32.dll",
    "SHELL32.dll",
    "ole32.dll",
    "OLEAUT32.dll",
    "ADVAPI32.dll",
    "ntdll.dll",
    "IPHLPAPI.DLL",
    "NETAPI32.dll",
    "WTSAPI32.dll",
    "dbghelp.dll",
    "dbgeng.dll",
    "WINTRUST.dll",
    "SETUPAPI.dll",
    "wevtapi.dll",
    "tdh.dll",
]


class ReleaseTests(unittest.TestCase):
    @unittest.skipUnless(
        utils.platform() == "linux" or utils.platform() == "darwin",
        "Test for Darwin and Linux only",
    )
    def test_no_nonsystem_link(self):

        if utils.platform() == "linux":
            proc = subprocess.call(
                "ldd %s | awk '{ print $1\" \"$3 }' | grep -Ev '^/lib64|^/lib| /lib|linux-vdso.so.1'"
                % (BUILD_DIR + "/osquery/osqueryd"),
                shell=True,
            )
        else:
            proc = subprocess.call(
                "otool -L %s | awk '{ if (NR > 1) print $1}' | grep -Ev '^/usr/lib|^/System/Library'"
                % (BUILD_DIR + "/osquery/osqueryd"),
                shell=True,
            )

        # Require all libraries to be system libraries.
        self.assertEqual(proc, 1)

    @unittest.skipUnless(
        utils.platform() == "linux" or utils.platform() == "win32",
        "Test for Windows and Linux only",
    )
    def test_linked_system_libraries(self):

        if utils.platform() == "linux":
            output_bytes = subprocess.check_output(
                "ldd %s | awk '{ print $1 }'"
                % (BUILD_DIR + "/osquery/osqueryd"),
                shell=True,
            )

            self.assertTrue(output_bytes)

            output = output_bytes.decode("utf-8")
            libraries = list(filter(None, output.split(sep="\n")))

            self.assertGreaterEqual(len(libraries), 0)

            if platform.processor() == "x86_64":
                linux_expected_libraries.append("ld-linux-x86-64.so")
            else:
                linux_expected_libraries.append("ld-linux-aarch64.so")

            for expected_library in linux_expected_libraries:
                found_index = -1

                for i, library in enumerate(libraries):
                    if expected_library in library:
                        found_index = i

                self.assertGreaterEqual(
                    found_index,
                    0,
                    msg="Missing expected library %s" % expected_library,
                )
                libraries.pop(found_index)

            if len(libraries) > 0:
                self.fail(
                    "Found these additional unwanted libraries linked:\n%s"
                    % ("\n".join(libraries))
                )
        elif utils.platform() == "win32":
            output_bytes = subprocess.check_output(
                "dumpbin /DEPENDENTS %s"
                % (BUILD_DIR + "/osquery/osqueryd.exe"),
            )

            self.assertTrue(output_bytes)

            output = output_bytes.decode("utf-8")
            libraries = [
                line
                for line in list(filter(None, output.split(sep="\r\n")))
                if ".dll" in line.lower()
            ]

            self.assertGreaterEqual(len(libraries), 0)

            for expected_library in windows_expected_libraries:
                found_index = -1

                for i, library in enumerate(libraries):
                    if expected_library.lower() in library.lower().strip():
                        found_index = i

                self.assertGreaterEqual(
                    found_index,
                    0,
                    msg="Missing expected library %s" % expected_library,
                )
                libraries.pop(found_index)

            if len(libraries) > 0:
                self.fail(
                    "Found these additional unwanted libraries linked:\n%s"
                    % ("\n".join(libraries))
                )


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument(
        "--build_dir",
        required=True,
        help="Path of the build directory",
    )

    args, remaining = arg_parser.parse_known_args()
    global BUILD_DIR
    BUILD_DIR = args.build_dir

    additional_argv = [sys.argv[0]]
    additional_argv.extend(remaining)

    unittest.main(argv=additional_argv)
