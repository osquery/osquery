// Copyright 2004-present Facebook. All Rights Reserved.

#include <stdio.h>
#include <string.h>

#include "osquery/database.h"

namespace osquery {
namespace tables {

QueryData genArp() {
  Row r;
  QueryData results;
  FILE *arp_cmd_output;
  char *line = NULL;
  size_t length;
  int ret;

  char ip[32];
  char arp[64];
  char iface[32];

  // We are already calling 'popen', let's give it some more work with sed to clean.
  arp_cmd_output = popen("arp -an | sed 's,^[^(]*(\\([^)]*\\)) at \\([^ ]*\\).*on \\([^ ]*\\).*$,\\1 \\2 \\3,'", "r");
  if (arp_cmd_output == NULL) {
    return results;
  }

  ret = getline(&line, &length, arp_cmd_output);
  while (ret > 0) {
    sscanf(line, "%s %s %s", ip, arp, iface);

    r["ip"] = ip;
    r["arp"] = arp;
    r["iface"] = iface;

    results.push_back(r);

    line = NULL;
    ret = getline(&line, &length, arp_cmd_output);
  }

  return results;
}
}
}
