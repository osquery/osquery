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
#include <unistd.h>

#include <string>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {
namespace tables {

static std::string sysctlString(const char* name) {
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

static std::string sysctlInt(const char* name) {
  long val = 0;
  size_t len = sizeof(val);
  if (sysctlbyname(name, &val, &len, nullptr, 0) != 0) {
    return "";
  }
  return std::to_string(val);
}

QueryData genSystemInfo(QueryContext& context) {
  Row r;
  char hostname[256] = {0};
  if (gethostname(hostname, sizeof(hostname) - 1) == 0) {
    r["hostname"] = hostname;
    r["computer_name"] = hostname;
    r["local_hostname"] = hostname;
  }
  r["uuid"] = sysctlString("kern.hostuuid");
  r["cpu_type"] = sysctlString("hw.machine");
  r["cpu_subtype"] = sysctlString("hw.model");
  r["cpu_brand"] = sysctlString("hw.model");
  r["cpu_physical_cores"] = sysctlInt("hw.ncpu");
  r["cpu_logical_cores"] = sysctlInt("hw.ncpu");
  r["cpu_microcode"] = "";
  r["physical_memory"] = sysctlInt("hw.physmem");
  r["hardware_vendor"] = sysctlString("smbios.system.maker");
  r["hardware_model"] = sysctlString("smbios.system.product");
  r["hardware_version"] = sysctlString("smbios.system.version");
  r["hardware_serial"] = sysctlString("smbios.system.serial");
  r["board_vendor"] = sysctlString("smbios.planar.maker");
  r["board_model"] = sysctlString("smbios.planar.product");
  r["board_version"] = sysctlString("smbios.planar.version");
  r["board_serial"] = sysctlString("smbios.planar.serial");
  r["cpu_sockets"] = "";
  return {r};
}

} // namespace tables
} // namespace osquery
