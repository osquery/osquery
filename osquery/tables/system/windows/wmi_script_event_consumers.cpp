/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sstream>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genScriptConsumers(QueryContext& context) {
  QueryData results_data;
  std::stringstream ss;
  ss << "SELECT * FROM ActiveScriptEventConsumer";

  BSTR bstr = ::SysAllocString(L"ROOT\\Subscription");
  const auto request = WmiRequest::CreateWmiRequest(ss.str(), bstr);
  ::SysFreeString(bstr);

  if (request && request->getStatus().ok()) {
    const auto& results = request->results();
    for (const auto& result : results) {
      Row r;

      result.GetString("ScriptText", r["script_text"]);
      result.GetString("ScriptFileName", r["script_file_name"]);
      result.GetString("ScriptingEngine", r["scripting_engine"]);
      result.GetString("Name", r["name"]);
      result.GetString("__CLASS", r["class"]);
      result.GetString("__RELPATH", r["relative_path"]);
      results_data.push_back(r);
    }
  }

  return results_data;
}
} // namespace tables
} // namespace osquery
