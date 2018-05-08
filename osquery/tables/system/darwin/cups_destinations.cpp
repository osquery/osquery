/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <cups/cups.h>

#include <osquery/tables.h>

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
