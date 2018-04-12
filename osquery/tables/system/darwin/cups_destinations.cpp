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

#include <osquery/system.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

class SafeCupsDestinations {
 public:
  cups_dest_t* destination_list;
  int num_destinations;

  SafeCupsDestinations() {
    num_destinations = cupsGetDests(&destination_list);
  }

  ~SafeCupsDestinations() {
    cupsFreeDests(num_destinations, destination_list);
  }
};

QueryData genCupsDestinations(QueryContext& request) {
  QueryData results;
  SafeCupsDestinations destinations;

  for (auto i{0}; i < destinations.num_destinations; ++i) {
    auto num_options = destinations.destination_list[i].num_options;
    if (num_options == 0) {
      Row r;
      r["name"] = std::string(destinations.destination_list[i].name);
      results.push_back(r);
    } else {
      for (auto j{0}; j < num_options; ++j) {
        Row r;
        r["name"] = std::string(destinations.destination_list[i].name);
        r["option_name"] =
            std::string(destinations.destination_list[i].options[j].name);
        r["option_value"] =
            std::string(destinations.destination_list[i].options[j].value);
        results.push_back(r);
      }
    }
  }
  return results;
}

} // namespace tables
} // namespace osquery
