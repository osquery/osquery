/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <osquery/sql/sql.h>

namespace osquery {
namespace tables {

QueryData usersFromContext(const QueryContext& context, bool all) {
  QueryData users;

  // If there is a constraint on uid, use that to limit users.
  //
  // If this is linux, there is a special case where we may need to
  // add the include_remote constraint to get remote users.  Because
  // we don't have direct knowledge that include_remote is needed, we
  // first try without it, and if no users are returned, we try again
  // with the include_remote constraint.  We only do this when a uid
  // constraint is provided to avoid possible performance issues with
  // querying all users with include_remote.
  //
  if (context.hasConstraint("uid", EQUALS)) {
    context.iteritems(
        "uid", EQUALS, ([&users](const std::string& expr) {
          ConstraintMap constraints;
          constraints["uid"].add(Constraint(EQUALS, expr));
          auto user = SQL::selectAllFrom("users", "uid", EQUALS, expr);
#if defined(__linux__)
          if (user.empty()) {
            constraints["include_remote"].add(Constraint(EQUALS, "1"));
            user = SQL::selectFrom({}, "users", std::move(constraints));
          }
#endif
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
