/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/carver.h>
#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

void enumerateCarves(QueryData& results) {
  Row r;
  r["timestamp"] = INTEGER(time(nullptr));
  r["md5"] = "";
  r["carve"] = INTEGER(0);
  r["path"] = "/";
  results.push_back(r);
}

QueryData genCarves(QueryContext& context) {
  QueryData results;

  if (context.constraints["carve"].exists(EQUALS) &&
      context.constraints["path"].getAll(EQUALS).size() > 0) {
    /// Kick off the file carver with the path requested by the user
    Dispatcher::addService(
        std::make_shared<Carver>(context.constraints["path"].getAll(EQUALS)));
  } else {
    enumerateCarves(results);
  }

  return results;
}
}
}
