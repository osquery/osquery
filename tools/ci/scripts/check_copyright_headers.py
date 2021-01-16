#!/usr/bin/env python3

#
# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
#

import sys
import os
import pathlib

valid_extension_list = [".c", ".h", ".cpp", ".m", ".mm"]

ignored_folder_list = ["libraries", "osquery/extensions/thrift/gen"]

ignored_file_list = [
  "osquery/tables/system/efi_misc.h",
  "osquery/tables/system/windows/kva_speculative_info.cpp",
  "osquery/devtools/shell.cpp",
  "plugins/logger/generated_wel.h"
]

copyright_header="/**\n * Copyright (c) 2014-present, The osquery authors\n *\n * This source code is licensed as defined by the LICENSE file found in the\n * root directory of this source tree.\n *\n * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)\n */\n"

def main():
  if not os.path.isfile(".clang-format") or not os.path.isfile("LICENSE"):
    print("This script needs to be run from the osquery repository root")
    return 1

  invalid_file_list = []

  for current_path, folder_name_list, file_name_list in os.walk(os.getcwd()):
    current_rel_path = str(pathlib.Path(current_path).relative_to(os.getcwd()))

    skip_folder = False
    for ignored_folder in ignored_folder_list:
      if current_rel_path.find(ignored_folder) == 0:
          skip_folder = True
          break

    if skip_folder:
      continue

    for file_name in file_name_list:
      file_path = current_path + "/" + file_name

      file_extension = pathlib.Path(file_path).suffix
      if not file_extension in valid_extension_list:
        continue

      with open(file_path, "r") as source_file:
        source_file_contents = source_file.read()

      if source_file_contents.find(copyright_header) != -1:
        continue

      rel_file_path = str(pathlib.Path(file_path).relative_to(os.getcwd()))
      if rel_file_path not in ignored_file_list:
        invalid_file_list.append(file_path)

  if len(invalid_file_list) != 0:
    print("The following source files do not contain the required copyright header:")

    for invalid_file in invalid_file_list:
      print("\t{0}".format(invalid_file))

    return 1

  return 0

if __name__ == "__main__":
  sys.exit(main())
