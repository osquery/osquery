#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import argparse
import os
import subprocess
import sys


def check(base_commit, exclude_folders, clang_binary):
    try:
        cmd = [
          sys.executable,
          os.path.join(os.path.dirname(os.path.abspath(__file__)), "git-clang-format.py"),
          "--style=file",
          "--diff",
          "--commit",
          base_commit,
        ]

        if exclude_folders:
            cmd += ["--exclude-folders", exclude_folders]

        if clang_binary:
            cmd += ["--binary", clang_binary]

        p = subprocess.Popen(cmd,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             encoding='utf8')
        out, err = p.communicate()
    except OSError as e:
        print("{}\n\n{!r}".format("Failed to call git-clang-format.py", e))
        return False

    if p.returncode:
        print("{}\n\n{}\n{}".format(
            "Failed to run formatting script", out, err
            ))
        return False
    elif out.startswith("no modified files to format"):
        print("No code changes found!")
        return True
    elif out.startswith("clang-format did not modify any files"):
        print("Code passes formatting tests!")
        return True
    else:
        print("{}\n\n{}".format(
            "Modifications failed code formatting requirements", out
            ))
        return False

def get_base_commit(base_branch):
    try:
        return subprocess.check_output(
                ["git", "merge-base", "HEAD", base_branch]
                ).decode().strip()
    except OSError as e:
        print("{}\n\n{}".format("Failed to execute git", str(e)))
    except subprocess.CalledProcessError as e:
        print("{}\n\n{}".format("Failed to determine merge-base", str(e)))

    return None


def main():
    parser = argparse.ArgumentParser(description="Check code changes formatting.")
    parser.add_argument(
        "--exclude-folders",
        metavar="excluded_folders",
        type=str,
        default="",
        help="comma-separated list of relative paths to folders to exclude from formatting"
    )
    parser.add_argument(
        "--binary",
        metavar="clang_binary",
        dest="clang_binary",
        type=str,
        default="",
        help="Path to the clang-format binary"
    )
    parser.add_argument(
        "base_branch",
        metavar="base_branch",
        type=str,
        nargs="?",
        default="master",
        help="The base branch to compare to.",
    )

    args = parser.parse_args()

    base_commit = get_base_commit(args.base_branch)

    return check(base_commit, args.exclude_folders, args.clang_binary) if base_commit is not None else False

if __name__ == "__main__":
    sys.exit(not main())
