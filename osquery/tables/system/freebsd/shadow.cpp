/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 *
 * FreeBSD shadow table.  Source is master.passwd via getpwent(3); only
 * readable by root, which matches the upstream contract on Linux.
 */

#include <pwd.h>
#include <string.h>

#include <string>

#include <osquery/core/tables.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {
namespace tables {

static std::string hashAlg(const char* h) {
  if (h == nullptr || h[0] == '\0') {
    return "";
  }
  // Locked / empty markers come first.
  if (strcmp(h, "*") == 0 || strcmp(h, "*LOCKED*") == 0 ||
      strncmp(h, "*LOCKED*", 8) == 0) {
    return "locked";
  }
  if (h[0] != '$') {
    return "des"; // legacy crypt(3) DES
  }
  // Modular crypt format: $id$...
  const char* end = strchr(h + 1, '$');
  if (end == nullptr) {
    return "";
  }
  std::string id(h + 1, end - (h + 1));
  if (id == "1")
    return "md5";
  if (id == "2" || id == "2a" || id == "2b" || id == "2y")
    return "blowfish";
  if (id == "5")
    return "sha256";
  if (id == "6")
    return "sha512";
  if (id == "7")
    return "scrypt";
  if (id == "y")
    return "yescrypt";
  return id;
}

static std::string passwordStatus(const struct passwd* pw) {
  const char* h = pw->pw_passwd;
  if (h == nullptr || h[0] == '\0') {
    return "empty";
  }
  if (h[0] == '*' || h[0] == '!') {
    return "locked";
  }
  return "active";
}

QueryData genShadow(QueryContext& context) {
  QueryData results;
  setpwent();
  while (auto* pw = getpwent()) {
    Row r;
    r["username"] = pw->pw_name;
    r["password_status"] = passwordStatus(pw);
    r["hash_alg"] = hashAlg(pw->pw_passwd);
    // FreeBSD master.passwd stores absolute change/expire times (seconds
    // since epoch), not "days since last change" like Linux /etc/shadow.
    // Expose the raw epoch value in last_change/expire and leave the
    // Linux-only aging policy fields zero.
    r["last_change"] = BIGINT((int64_t)pw->pw_change);
    r["min"] = "0";
    r["max"] = "0";
    r["warning"] = "0";
    r["inactive"] = "0";
    r["expire"] = BIGINT((int64_t)pw->pw_expire);
    r["flag"] = "0";
    results.push_back(r);
  }
  endpwent();
  return results;
}

} // namespace tables
} // namespace osquery
