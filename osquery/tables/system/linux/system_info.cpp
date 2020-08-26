/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <thread>

#include <sys/utsname.h>

#include <boost/algorithm/string.hpp>
#include <boost/thread/thread.hpp>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/system/linux/smbios_utils.h>
#include <osquery/utils/conversions/split.h>

namespace osquery {
namespace tables {

QueryData genSystemInfo(QueryContext& context) {
  Row r;
  r["hostname"] = osquery::getFqdn();
  r["computer_name"] = osquery::getHostname();
  r["local_hostname"] = r["hostname"];

  std::string uuid;
  r["uuid"] = (osquery::getHostUUID(uuid)) ? uuid : "";

#ifdef __x86_64__
  auto qd = SQL::selectAllFrom("cpuid");
  for (const auto& row : qd) {
    if (row.at("feature") == "product_name") {
      r["cpu_brand"] = row.at("value");
      boost::trim(r["cpu_brand"]);
    }
  }
#endif /* __x86_64__ */

  auto logical_cores = std::thread::hardware_concurrency();
  r["cpu_logical_cores"] = (logical_cores > 0) ? INTEGER(logical_cores) : "-1";

  r["cpu_physical_cores"] = INTEGER(boost::thread::physical_concurrency());

  static long pages = sysconf(_SC_PHYS_PAGES);
  static long pagesize = sysconf(_SC_PAGESIZE);

  if (pages > 0 && pagesize > 0) {
    r["physical_memory"] = BIGINT((long long)pages * (long long)pagesize);
  } else {
    r["physical_memory"] = "-1";
  }

  r["cpu_subtype"] = "0";

  struct utsname utsbuf;
  if (uname(&utsbuf) == -1) {
    LOG(WARNING) << "Failed to get cpu_type, uname failed with error code: "
                 << std::to_string(errno);
  } else {
    r["cpu_type"] = std::string(utsbuf.machine);
  }

  // Read the types from CPU info within proc.
  std::string content;
  if (readFile("/proc/cpuinfo", content)) {
    for (const auto& line : osquery::split(content, "\n")) {
      // Iterate each line and look for labels (there is also a model type).
      if (line.find("model\t") == 0) {
        auto details = osquery::split(line, ":");
        if (details.size() == 2) {
          r["cpu_subtype"] = details[1];
        }
      } else if (line.find("microcode") == 0) {
        auto details = osquery::split(line, ":");
        if (details.size() == 2) {
          r["cpu_microcode"] = details[1];
        }
      }

      // Minor optimization to not parse every line.
      if (line.size() == 0) {
        break;
      }
    }
  }

  {
    LinuxSMBIOSParser parser;
    if (!parser.discover()) {
      r["hardware_model"] = "";
    } else {
      parser.tables(([&r](size_t index,
                          const SMBStructHeader* hdr,
                          uint8_t* address,
                          uint8_t* textAddrs,
                          size_t size) {
        if (size < 0x12) {
          return;
        }

        if (hdr->type == kSMBIOSTypeSystem) {
          auto maxlen = size - hdr->length;
          r["hardware_vendor"] = dmiString(textAddrs, address[0x04], maxlen);
          r["hardware_model"] = dmiString(textAddrs, address[0x05], maxlen);
          r["hardware_version"] = dmiString(textAddrs, address[0x06], maxlen);
          r["hardware_serial"] = dmiString(textAddrs, address[0x07], maxlen);
          return;
        }

        if (hdr->type == kSMBIOSTypeBoard) {
          auto maxlen = size - hdr->length;
          r["board_vendor"] = dmiString(textAddrs, address[0x04], maxlen);
          r["board_model"] = dmiString(textAddrs, address[0x05], maxlen);
          r["board_version"] = dmiString(textAddrs, address[0x06], maxlen);
          r["board_serial"] = dmiString(textAddrs, address[0x07], maxlen);
          return;
        }
      }));
    }
  }

  return {r};
}
} // namespace tables
} // namespace osquery
