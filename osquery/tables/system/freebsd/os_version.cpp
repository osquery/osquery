/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>

#include <cstdlib>
#include <sstream>
#include <string>

#include <osquery/core/tables.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {
namespace tables {

QueryData genOSVersion(QueryContext& context) {
  Row r;
  struct utsname un;
  if (uname(&un) != 0) {
    return {};
  }

  r["name"] = "FreeBSD";
  r["platform"] = "freebsd";
  r["platform_like"] = "freebsd";
  r["version"] = un.release;

  // Parse "X.Y-RELEASE" or "X.Y-CURRENT"
  std::string release(un.release);
  auto dash = release.find('-');
  std::string ver =
      (dash != std::string::npos) ? release.substr(0, dash) : release;
  auto dot = ver.find('.');
  if (dot != std::string::npos) {
    r["major"] = ver.substr(0, dot);
    r["minor"] = ver.substr(dot + 1);
  } else {
    r["major"] = ver;
    r["minor"] = "0";
  }
  r["patch"] = "0";
  r["build"] = un.version;
  r["codename"] = "";
  r["arch"] = un.machine;
  return {r};
}

} // namespace tables
} // namespace osquery
