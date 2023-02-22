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

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>

namespace osquery {
namespace tables {

static const std::string kProcKeysPath = "/proc/keys";

QueryData genKernelKeys(QueryContext& context) {
  if (!pathExists(kProcKeysPath).ok()) {
    VLOG(1) << "Cannot find keyrings file: " << kProcKeysPath;
    return {};
  }

  std::string content;
  auto res = osquery::readFile(kProcKeysPath, content);
  if (!res.ok()) {
    VLOG(1) << "Error reading keyrings file: " << kProcKeysPath;
    return {};
  }

  QueryData results;
  for (const auto& key : osquery::split(content, "\n")) {
    Row r = {};
    auto details = osquery::split(key, " ");
    if (details.size() != 10) {
      VLOG(1) << "Malformed key format: " << key;
      continue;
    }

    r["serial_number"] = details[0];
    r["flags"] = details[1];
    r["usage"] = details[2];
    r["timeout"] = details[3];
    r["permissions"] = details[4];
    r["uid"] = details[5];
    r["gid"] = details[6];
    r["type"] = details[7];
    r["description"] = details[8] + details[9];

    results.push_back(std::move(r));
  }

  return results;
}
} // namespace tables
} // namespace osquery
