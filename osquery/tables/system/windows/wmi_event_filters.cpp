/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genWmiFilters(QueryContext& context) {
  QueryData results_data;
  std::stringstream ss;
  ss << "SELECT * FROM __EventFilter";

  BSTR bstr = ::SysAllocString(L"ROOT\\Subscription");
  WmiRequest request(ss.str(), bstr);
  ::SysFreeString(bstr);

  if (request.getStatus().ok()) {
    auto& results = request.results();
    for (const auto& result : results) {
      Row r;

      result.GetString("Name", r["name"]);
      result.GetString("Query", r["query"]);
      result.GetString("QueryLanguage", r["query_language"]);
      result.GetString("__CLASS", r["class"]);
      result.GetString("__RELPATH", r["relative_path"]);
      results_data.push_back(r);
    }
  }

  return results_data;
}
} // namespace tables
} // namespace osquery
