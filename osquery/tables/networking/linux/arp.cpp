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
  char *line = NULL;
  size_t length;
  int ret;

  char ip[32];
  char arp[64];
  char iface[32];
  char foo[128];

  // We are already calling 'popen', let's give it some more work with sed to clean.
  proc_arp_fd = fopen("/proc/net/arp" , "r");
  if (proc_arp_fd == NULL) {
    return results;
  }

  ret = getline(&line, &length, proc_arp_fd); // Discard first one. Just a header
  ret = getline(&line, &length, proc_arp_fd);
  while (ret > 0) {
    // IP address       HW type     Flags       HW address            Mask     Device
    sscanf(line, "%s %s %s %s %s %s", ip, foo, foo, arp, foo, iface);

    r["ip"] = ip;
    r["arp"] = arp;
    r["iface"] = iface;

    results.push_back(r);

    line = NULL;
    ret = getline(&line, &length, proc_arp_fd);
  }

  return results;
}
}
}
