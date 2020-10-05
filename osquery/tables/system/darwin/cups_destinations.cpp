/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cups/cups.h>

#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

class CupsDestinations {
 public:
  cups_dest_t* destination_list;
  int num_destinations;

  CupsDestinations() : destination_list(nullptr), num_destinations(0) {
    num_destinations = cupsGetDests(&destination_list);
  }

  ~CupsDestinations() {
    cupsFreeDests(num_destinations, destination_list);
  }

  cups_dest_t* begin() {
    return destination_list;
  }

  cups_dest_t* end() {
    return &destination_list[num_destinations];
  }
};

QueryData genCupsDestinations(QueryContext& request) {
  QueryData results;
  CupsDestinations dests;

  for (const auto& dest : dests) {
    auto num_options = dest.num_options;
    if (num_options == 0) {
      Row r;
      r["name"] = SQL_TEXT(dest.name);
      results.push_back(r);
    } else {
      for (int j = 0; j < num_options; ++j) {
        Row r;
        r["name"] = SQL_TEXT(dest.name);
        r["option_name"] = SQL_TEXT(dest.options[j].name);
        r["option_value"] = SQL_TEXT(dest.options[j].value);
        results.push_back(r);
      }
    }
  }
  return results;
}

} // namespace tables
} // namespace osquery
