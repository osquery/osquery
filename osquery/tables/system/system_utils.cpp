/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/sql.h>

#include "osquery/core/process.h"

namespace osquery {
namespace tables {

QueryData usersFromContext(const QueryContext& context, bool all) {
  QueryData users;
  if (context.hasConstraint("uid", EQUALS)) {
    context.iteritems("uid", EQUALS, ([&users](const std::string& expr) {
                        auto user =
                            SQL::selectAllFrom("users", "uid", EQUALS, expr);
                        users.insert(users.end(), user.begin(), user.end());
                      }));
  } else if (!all) {
    users = SQL::selectAllFrom(
        "users", "uid", EQUALS, std::to_string(platformGetUid()));
  } else {
    users = SQL::selectAllFrom("users");
  }
  return users;
}

QueryData pidsFromContext(const QueryContext& context, bool all) {
  QueryData procs;
  if (context.hasConstraint("pid", EQUALS)) {
    context.iteritems("pid", EQUALS, ([&procs](const std::string& expr) {
                        auto proc = SQL::selectAllFrom(
                            "processes", "pid", EQUALS, expr);
                        procs.insert(procs.end(), procs.begin(), procs.end());
                      }));
  } else if (!all) {
    procs = SQL::selectAllFrom(
        "processes", "pid", EQUALS, std::to_string(platformGetPid()));
  } else {
    procs = SQL::selectAllFrom("processes");
  }
  return procs;
}
}
}
