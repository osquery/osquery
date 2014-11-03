// Copyright 2004-present Facebook. All Rights Reserved.

#include <stdio.h>
#include <string.h>

#include "osquery/database.h"

namespace osquery {
namespace tables {

QueryData genArp() {
  Row r;
  QueryData results;
  FILE *proc_arp_fd;
  char *line = nullptr;
  size_t length;
  int ret;

  // We are already calling 'popen', let's give it some more work with sed to clean.
  proc_arp_fd = fopen("/proc/net/arp" , "r");
  if (proc_arp_fd == nullptr) {
    return results;
  }

  ret = getline(&line, &length, proc_arp_fd); // Discard first one. Just a header
  ret = getline(&line, &length, proc_arp_fd);
  while (ret > 0) {
    std::vector<std::string> fields;
    // IP address       HW type     Flags       HW address            Mask     Device
    boost::split(fields, line, boost::is_any_of(" "));

    r["ip"] = fields[0];
    r["mac"] = fields[3];
    r["iface"] = fields[5];

    results.push_back(r);

    line = nullptr;
    ret = getline(&line, &length, proc_arp_fd);
  }

  return results;
}
}
}
