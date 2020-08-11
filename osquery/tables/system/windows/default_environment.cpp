/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/windows/registry.h>

namespace osquery {
namespace tables {
static std::string kEnvironmentKey =
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session "
    "Manager\\Environment";

QueryData genDefaultEnvironment(QueryContext& context) {
  QueryData results, environment;
  auto status = queryKey(kEnvironmentKey, environment);

  if (!status.ok()) {
    TLOG << "Error querying the default environment";
    return results;
  }

  for (const auto& env : environment) {
    Row r;
    r["variable"] = env.at("name");
    r["value"] = env.at("data");
    r["expand"] = INTEGER(env.at("type") == "REG_EXPAND_SZ");
    results.push_back(std::move(r));
  }

  return results;
}
} // namespace tables
} // namespace osquery
