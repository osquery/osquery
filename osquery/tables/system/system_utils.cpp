/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/sql.h>

#include <osquery/process/process.h>

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
