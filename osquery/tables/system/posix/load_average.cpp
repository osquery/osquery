/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <stdlib.h>

#include "osquery/core/conversions.h"
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genLoadAverage(QueryContext& context) {
  QueryData results;

  double loads[3];
  std::vector<std::string> periods = {"1m", "5m", "15m"};
  if (getloadavg(loads, 3) != -1) {
    for (int i = 0; i < 3; i++) {
      Row r;
      r["period"] = periods[i];
      r["average"] = std::to_string(loads[i]);
      results.push_back(r);
    }
  };

  return results;
}
} // namespace tables
} // namespace osquery
