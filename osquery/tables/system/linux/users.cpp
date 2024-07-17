/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <errno.h>
#include <pwd.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace osquery {
namespace tables {

void genUser(const struct passwd* pwd,
             QueryData& results,
             const std::string& include_remote) {
  Row r;
  r["uid"] = BIGINT(pwd->pw_uid);
  r["gid"] = BIGINT(pwd->pw_gid);
  r["uid_signed"] = BIGINT((int32_t)pwd->pw_uid);
  r["gid_signed"] = BIGINT((int32_t)pwd->pw_gid);

  if (pwd->pw_name != nullptr) {
    r["username"] = SQL_TEXT(pwd->pw_name);
  }

  if (pwd->pw_gecos != nullptr) {
    r["description"] = SQL_TEXT(pwd->pw_gecos);
  }

  if (pwd->pw_dir != nullptr) {
    r["directory"] = SQL_TEXT(pwd->pw_dir);
  }

  if (pwd->pw_shell != nullptr) {
    r["shell"] = SQL_TEXT(pwd->pw_shell);
  }
  r["pid_with_namespace"] = "0";
  r["include_remote"] = include_remote;
  results.push_back(r);
}

QueryData genUsersImplIncludeRemote(QueryContext& context, Logger& logger) {
  QueryData results;
  struct passwd pwd;
  struct passwd* pwd_results{nullptr};

  size_t bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (bufsize > 16384) { /* Value was indeterminate */
    bufsize = 16384; /* Should be more than enough */
  }
  auto buf = std::make_unique<char[]>(bufsize);

  if (context.constraints["uid"].exists(EQUALS)) {
    auto uids = context.constraints["uid"].getAll(EQUALS);
    for (const auto& uid : uids) {
      auto const auid_exp = tryTo<long>(uid, 10);
      if (auid_exp.isValue()) {
        getpwuid_r(auid_exp.get(), &pwd, buf.get(), bufsize, &pwd_results);
        if (pwd_results != nullptr) {
          genUser(pwd_results, results, "1");
        }
      }
    }
  } else if (context.constraints["username"].exists(EQUALS)) {
    auto usernames = context.constraints["username"].getAll(EQUALS);
    for (const auto& username : usernames) {
      getpwnam_r(username.c_str(), &pwd, buf.get(), bufsize, &pwd_results);
      if (pwd_results != nullptr) {
        genUser(pwd_results, results, "1");
      }
    }
  } else {
    setpwent();
    while (1) {
      getpwent_r(&pwd, buf.get(), bufsize, &pwd_results);
      if (pwd_results == nullptr) {
        break;
      }
      genUser(pwd_results, results, "1");
    }
    endpwent();
  }

  return results;
}

QueryData genUsersImplLocal(QueryContext& context, Logger& logger) {
  //
  // Either "username" or "uid" is set on the constraints, not both.
  //
  const auto usernames = context.constraints["username"].getAll(EQUALS);
  const auto uids = [&context]() -> std::set<uid_t> {
    std::set<uid_t> uids;
    const auto uid_constraints = context.constraints["uid"].getAll(EQUALS);
    for (const auto& uid_constraint : uid_constraints) {
      auto const auid_exp = tryTo<long>(uid_constraint, 10);
      if (auid_exp.isValue()) {
        uids.insert(auid_exp.get());
      }
    }
    return uids;
  }();

  //
  // We are avoiding the use of setpwent, getpwent_r, endpwent, getpwnam_r and
  // getpwuid_r to prevent osquery sending requests to LDAP directories on
  // hosts that have LDAP configured for authentication.
  // (See https://github.com/osquery/osquery/issues/8337.)
  //
  QueryData results;
  FILE* passwd_file = fopen("/etc/passwd", "r");
  if (passwd_file == nullptr) {
    LOG(ERROR) << "could not open /etc/passwd file: " << std::strerror(errno);
    return results;
  }

  size_t bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (bufsize > 16384) { // value was indeterminate
    bufsize = 16384; // should be more than enough
  }
  auto buf = std::make_unique<char[]>(bufsize);

  struct passwd pwd;
  struct passwd* result{nullptr};
  int ret;
  while (1) {
    ret = fgetpwent_r(passwd_file, &pwd, buf.get(), bufsize, &result);
    if (ret != 0 || result == nullptr) {
      break;
    }
    if (!usernames.empty()) {
      if (usernames.find(result->pw_name) == usernames.end()) {
        continue;
      }
    } else if (!uids.empty()) {
      if (uids.find(result->pw_uid) == uids.end()) {
        continue;
      }
    }
    genUser(result, results, "0");
  }

  if (ret != 0 && ret != ENOENT) {
    LOG(ERROR) << "failed to iterate /etc/passwd file: "
               << std::strerror(errno);
  }
  fclose(passwd_file);

  return results;
}

QueryData genUsersImpl(QueryContext& context, Logger& logger) {
  auto include_remote = 0;
  if (context.hasConstraint("include_remote", EQUALS)) {
    include_remote = context.constraints["include_remote"].matches<int>(1);
  }
  if (include_remote) {
    return genUsersImplIncludeRemote(context, logger);
  }
  return genUsersImplLocal(context, logger);
}

QueryData genUsers(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "users", genUsersImpl);
  } else {
    GLOGLogger logger;
    return genUsersImpl(context, logger);
  }
}

} // namespace tables
} // namespace osquery
