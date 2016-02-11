/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/string/split.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/hash.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

const std::string kKernelArgumentsPath = "/proc/cmdline";
const std::string kKernelSignaturePath = "/proc/version";

QueryData genKernelInfo(QueryContext& context) {
  QueryData results;
  Row r;

  if (pathExists(kKernelArgumentsPath).ok()) {
    std::string arguments_line;
    // Grab the whole arguments string from proc.
    if (readFile(kKernelArgumentsPath, arguments_line).ok()) {
      auto arguments = split(arguments_line, " ");
      std::string additional_arguments;

      // Iterate over each space-tokenized argument.
      for (const auto& argument : arguments) {
        if (argument.substr(0, 11) == "BOOT_IMAGE=") {
          r["path"] = argument.substr(11);
        } else if (argument.substr(0, 5) == "root=") {
          r["device"] = argument.substr(5);
        } else {
          if (additional_arguments.size() > 0) {
            additional_arguments += " ";
          }
          additional_arguments += argument;
        }
      }
      r["arguments"] = additional_arguments;
    }
  } else {
    VLOG(1) << "Cannot find kernel arguments file: " << kKernelArgumentsPath;
  }

  if (pathExists(kKernelSignaturePath).ok()) {
    std::string signature;

    // The signature includes the kernel version, build data, buildhost,
    // GCC version used, and possibly build date.
    if (readFile(kKernelSignaturePath, signature).ok()) {
      auto details = split(signature, " ");
      if (details.size() > 2 && details[1] == "version") {
        r["version"] = details[2];
      }
    }
  } else {
    VLOG(1) << "Cannot find kernel signature file: " << kKernelSignaturePath;
  }

  results.push_back(r);
  return results;
}
}
}
