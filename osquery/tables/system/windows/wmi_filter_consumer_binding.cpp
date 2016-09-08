/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <map>
#include <sstream>
#include <string>

#include <stdlib.h>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genFilterConsumer(QueryContext& context) {
  QueryData results_data;
  std::stringstream ss;
  ss << "SELECT * FROM __FilterToConsumerBinding";

  WmiRequest request(ss.str(), L"ROOT\\Subscription");
  if (request.getStatus().ok()) {
    std::vector<WmiResultItem>& results = request.results();
    for (const auto& result : results) {
      Row r;
      Status s;
      std::string sPlaceHolder;

      s = result.GetString("Consumer", sPlaceHolder);
      r["consumer"] = SQL_TEXT(sPlaceHolder);
      s = result.GetString("Filter", sPlaceHolder);
      r["filter"] = SQL_TEXT(sPlaceHolder);
      s = result.GetString("__CLASS", sPlaceHolder);
      r["__class"] = SQL_TEXT(sPlaceHolder);
      s = result.GetString("__RELPATH", sPlaceHolder);
      r["__relpath"] = SQL_TEXT(sPlaceHolder);
      results_data.push_back(r);
    }
  }

  return results_data;
}
}
}