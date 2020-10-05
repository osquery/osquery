/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fstream>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>

namespace osquery {
namespace tables {

static const std::string kKernelModulePath = "/proc/modules";

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

  for (const auto& module : osquery::split(module_info, "\n")) {
    Row r;
    auto details = osquery::split(module, " ");
    if (details.size() < 6) {
      // Interesting error case, this module line is not well formed.
      continue;
    }

    for (auto& detail : details) {
      // Clean up the delimiters
      boost::trim(detail);
      if (detail.back() == ',') {
        detail.pop_back();
      }
    }

    r["name"] = details[0];
    r["size"] = details[1];
    r["used_by"] = details[3];
    r["status"] = details[4];
    r["address"] = details[5];
    results.push_back(r);
  }

  return results;
}
}
}
