/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <stdlib.h>

#include <array>

#include <boost/utility/string_view.hpp>

#include <osquery/core/tables.h>

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
