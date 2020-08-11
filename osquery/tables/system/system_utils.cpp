/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/sql/sql.h>

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
