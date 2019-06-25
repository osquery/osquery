#!/usr/bin/env python

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed in accordance with the terms specified in
#  the LICENSE file found in the root directory of this source tree.

import argparse
import os
import subprocess
import sys


def check(base_commit):
    try:
        p = subprocess.Popen(
                [
                    "python",
                    os.path.join(os.path.dirname(os.path.abspath(__file__)), "git-clang-format.py"),
                    "--style=file",
                    "--diff",
                    "--commit",
                    base_commit,
                    ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
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
                ).strip()
    except OSError as e:
        print("{}\n\n{}".format("Failed to execut git", str(e)))
    except subprocess.CalledProcessError as e:
        print("{}\n\n{}".format("Failed to determine merge-base", str(e)))

    return None


def main():
    parser = argparse.ArgumentParser(description="Check code changes formatting.")
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

    return check(base_commit) if base_commit is not None else False

if __name__ == "__main__":
    sys.exit(not main())
