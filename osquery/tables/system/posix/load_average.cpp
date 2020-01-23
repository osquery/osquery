/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <stdlib.h>

#include <array>

#include <boost/utility/string_view.hpp>

#include <osquery/tables.h>

namespace osquery {
namespace tables {

static constexpr std::array<boost::string_view, 3> kPeriods = {
    {boost::string_view("1m", 2),
     boost::string_view("5m", 2),
     boost::string_view("15m", 3)}};

QueryData genLoadAverage(QueryContext& context) {
  QueryData results(3);

  double loads[3];

  if (getloadavg(loads, 3) != -1) {
    for (int i = 0; i < 3; i++) {
      Row r = {{"period", kPeriods[i].data()},
               {"average", std::to_string(loads[i])}};

      results[i] = r;
    }
  };

  return results;
}
} // namespace tables
} // namespace osquery
