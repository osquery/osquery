/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <sstream>

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genFilterConsumer(QueryContext& context) {
  QueryData results_data;
  std::stringstream ss;
  ss << "SELECT * FROM __FilterToConsumerBinding";

  BSTR bstr = ::SysAllocString(L"ROOT\\Subscription");
  WmiRequest request(ss.str(), bstr);
  ::SysFreeString(bstr);

  if (request.getStatus().ok()) {
    auto& results = request.results();
    for (const auto& result : results) {
      Row r;

      result.GetString("Consumer", r["consumer"]);
      result.GetString("Filter", r["filter"]);
      result.GetString("__CLASS", r["class"]);
      result.GetString("__RELPATH", r["relative_path"]);
      results_data.push_back(r);
    }
  }

  return results_data;
}
} // namespace tables
} // namespace osquery
