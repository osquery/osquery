/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sstream>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

namespace {
const std::vector<std::pair<std::wstring, std::string>> kWmiNamespaces = {
    {L"ROOT\\Subscription", "ROOT\\Subscription"},
    {L"ROOT\\default", "ROOT\\default"},
};
} // namespace

QueryData genFilterConsumer(QueryContext& context) {
  QueryData results_data;
  std::stringstream ss;
  ss << "SELECT * FROM __FilterToConsumerBinding";

  for (const auto& ns : kWmiNamespaces) {
    BSTR bstr = ::SysAllocString(ns.first.c_str());
    const auto request = WmiRequest::CreateWmiRequest(ss.str(), bstr);
    ::SysFreeString(bstr);

    if (request && request->getStatus().ok()) {
      const auto& results = request->results();
      for (const auto& result : results) {
        Row r;

        r["namespace"] = ns.second;
        result.GetString("Consumer", r["consumer"]);
        result.GetString("Filter", r["filter"]);
        result.GetString("__CLASS", r["class"]);
        result.GetString("__RELPATH", r["relative_path"]);
        results_data.push_back(r);
      }
    }
  }

  return results_data;
}
} // namespace tables
} // namespace osquery
