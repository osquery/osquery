// Copyright 2004-present Facebook. All Rights Reserved.

#include <fstream>

#include <boost/algorithm/string/split.hpp>

#include "osquery/database.h"
#include "osquery/filesystem.h"

namespace osquery {
namespace tables {

const std::string kLinuxArpTable = "/proc/net/arp";

QueryData genArpTable() {
  QueryData results;

  // We are already calling 'popen', let's give it some more work with sed to clean.
  if (!osquery::isReadable(kLinuxArpTable)) {
    VLOG(1) << "Cannot read arp table.";
    return results;
  }

  std::ifstream fd(kLinuxArpTable, std::ios::in | std::ios::binary);
  std::string line;

  if (fd.fail() || fd.eof()) {
    VLOG(1) << "Empty or failed arp table.";
    return results;
  }

  // Read the header line.
  std::getline(fd, line, '\0');
  while (!(fd.fail() || fd.eof())) {
    std::getline(fd, line, '\0');

    // IP address, HW type, Flags, HW address, Mask Device
    std::std::vector<std::string> fields;
    boost::split(fields, line, boost::is_any_of(" "), boost::token_compress_on);
    for (auto& f : fields) {
      // Inline trim each split.
      boost::trim(f);
    }

    if (fields.size() == 6) {
      Row r;
      r["address"] = fields[0];
      r["mac"] = fields[3];
      r["interface"] = fields[5];

      results.push_back(r);
    }
  }

  return results;
}
}
}
