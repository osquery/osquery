/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <grp.h>
#include <pwd.h>

#include <osquery/core/tables.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {
namespace tables {

QueryData genUsers(QueryContext& context) {
  QueryData results;
  setpwent();
  struct passwd* pw;
  while ((pw = getpwent()) != nullptr) {
    Row r;
    r["uid"] = std::to_string(pw->pw_uid);
    r["gid"] = std::to_string(pw->pw_gid);
    r["uid_signed"] = std::to_string(static_cast<int32_t>(pw->pw_uid));
    r["gid_signed"] = std::to_string(static_cast<int32_t>(pw->pw_gid));
    r["username"] = pw->pw_name != nullptr ? pw->pw_name : "";
    r["description"] = pw->pw_gecos != nullptr ? pw->pw_gecos : "";
    r["directory"] = pw->pw_dir != nullptr ? pw->pw_dir : "";
    r["shell"] = pw->pw_shell != nullptr ? pw->pw_shell : "";
    r["uuid"] = "";
    r["type"] = "";
    results.push_back(r);
  }
  endpwent();
  return results;
}

QueryData genGroups(QueryContext& context) {
  QueryData results;
  setgrent();
  struct group* gr;
  while ((gr = getgrent()) != nullptr) {
    Row r;
    r["gid"] = std::to_string(gr->gr_gid);
    r["gid_signed"] = std::to_string(static_cast<int32_t>(gr->gr_gid));
    r["groupname"] = gr->gr_name != nullptr ? gr->gr_name : "";
    results.push_back(r);
  }
  endgrent();
  return results;
}

} // namespace tables
} // namespace osquery
