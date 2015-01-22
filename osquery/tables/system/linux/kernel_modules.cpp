/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <fstream>

#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

const std::string kKernelModulePath = "/proc/modules";

QueryData genKernelModules(QueryContext& context) {
  QueryData results;

  if (!pathExists(kKernelModulePath).ok()) {
    VLOG(1) << "Cannot find kernel modules proc file: " << kKernelModulePath;
    return {};
  }

  // Cannot seek to the end of procfs.
  std::ifstream fd(kKernelModulePath, std::ios::in);
  if (!fd) {
    VLOG(1) << "Cannot read kernel modules from: " << kKernelModulePath;
    return {};
  }

  auto module_info = std::string(std::istreambuf_iterator<char>(fd),
                                 std::istreambuf_iterator<char>());

  for (const auto& module : split(module_info, "\n")) {
    Row r;
    auto module_info = split(module, " ");
    if (module_info.size() < 6) {
      // Interesting error case, this module line is not well formed.
      continue;
    }

    for (auto& detail : module_info) {
      // Clean up the delimiters
      boost::trim(detail);
      if (detail.back() == ',') {
        detail.pop_back();
      }
    }

    r["name"] = module_info[0];
    r["size"] = module_info[1];
    r["used_by"] = module_info[3];
    r["status"] = module_info[4];
    r["address"] = module_info[5];
    results.push_back(r);
  }

  return results;
}
}
}
