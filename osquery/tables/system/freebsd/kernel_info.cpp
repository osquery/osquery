/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <string>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {
namespace tables {

static std::string sysctlStr(const char* name) {
  size_t len = 0;
  if (sysctlbyname(name, nullptr, &len, nullptr, 0) != 0 || len == 0) {
    return "";
  }
  std::vector<char> buf(len);
  if (sysctlbyname(name, buf.data(), &len, nullptr, 0) != 0) {
    return "";
  }
  if (!buf.empty() && buf[len - 1] == '\0') {
    return std::string(buf.data());
  }
  return std::string(buf.data(), len);
}

QueryData genKernelInfo(QueryContext& context) {
  Row r;
  struct utsname un;
  if (uname(&un) == 0) {
    r["version"] = un.release;
  } else {
    r["version"] = sysctlStr("kern.osrelease");
  }
  r["arguments"] = sysctlStr("kern.bootargs");
  r["path"] = sysctlStr("kern.bootfile");
  r["device"] = "";
  return {r};
}

} // namespace tables
} // namespace osquery
