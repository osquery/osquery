/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <mutex>
#include <set>

#include <grp.h>

#include <osquery/core.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genServices(QueryContext& context) {
  Row r;
  r["name"] = "hello!";
  r["status"] = "hello!";
  r["path"] = "hello!";
  r["start_type"] = "hello!";
  r["service_type"] = "hello!";

  return {r};
}
} // namespace tables
} // namespace osquery
