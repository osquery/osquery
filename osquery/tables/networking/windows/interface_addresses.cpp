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

void genInterfaceAddresses(QueryData& results_data) {
  std::stringstream ss;
  ss << "SELECT * FROM win32_networkadapterconfiguration where IPEnabled=TRUE";

  WmiRequest request(ss.str());
  if (request.getStatus().ok()) {
    std::vector<WmiResultItem>& results = request.results();
    for (const auto& result : results) {
      Row r;
      Status s;
      long lPlaceHolder;
      std::string sPlaceHolder;
      std::vector<std::string> vPlaceHolder;
      std::vector<std::string> vPlaceHolderTwo;

      s = result.GetLong("InterfaceIndex", lPlaceHolder);
      r["interface_index"] = INTEGER(lPlaceHolder);
      s = result.GetVectorOfStrings("IPAddress", vPlaceHolder);
      s = result.GetVectorOfStrings("IPSubnet", vPlaceHolderTwo);
      for (std::vector<int>::size_type i = 0; i < vPlaceHolder.size(); i++) {
        r["address"] = SQL_TEXT(vPlaceHolder.at(i));
        r["mask"] = SQL_TEXT(vPlaceHolderTwo.at(i));
        results_data.push_back(r);
      }
    }
  }
}

QueryData genWinInterfaceAddresses(QueryContext& context) {
  QueryData results;
  genInterfaceAddresses(results);

  return results;
}
}
}