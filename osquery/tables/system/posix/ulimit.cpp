/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <climits>
#include <map>
#include <string>

#include <sys/resource.h>

#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

void getLimit(QueryData& results) {
  std::map<std::string, int> resource_map; // system resources
  resource_map["cpu"] = RLIMIT_CPU;
  resource_map["fsize"] = RLIMIT_FSIZE;
  resource_map["data"] = RLIMIT_DATA;
  resource_map["stack"] = RLIMIT_STACK;
  resource_map["core"] = RLIMIT_CORE;
  resource_map["rss"] = RLIMIT_RSS;
  resource_map["memlock"] = RLIMIT_MEMLOCK;
  resource_map["nproc"] = RLIMIT_NPROC;
  resource_map["nofile"] = RLIMIT_NOFILE;
  resource_map["as"] = RLIMIT_AS;
  resource_map["locks"] = RLIMIT_LOCKS;
  resource_map["sigpending"] = RLIMIT_SIGPENDING;
  resource_map["msgqueue"] = RLIMIT_MSGQUEUE;
  resource_map["nice"] = RLIMIT_NICE;
  resource_map["rtprio"] = RLIMIT_RTPRIO;

  for (std::map<std::string, int>::iterator it = resource_map.begin();
       it != resource_map.end();
       ++it) {
    struct rlimit rlp;
    int result = getrlimit(it->second, &rlp);
    if (result == -1) {
      LOG(INFO) << "Failed to get limit for " << it->first;
      continue;
    }
    Row r;
    r["type"] = it->first;
    r["soft_limit"] = (rlp.rlim_cur == ULONG_MAX)
                          ? "unlimited"
                          : std::to_string(rlp.rlim_cur);
    r["hard_limit"] = (rlp.rlim_max == ULONG_MAX)
                          ? "unlimited"
                          : std::to_string(rlp.rlim_max);
    results.push_back(r);
  }
}

QueryData genUlimit(QueryContext& context) {
  QueryData results;

  getLimit(results);

  return results;
}
} // namespace tables
} // namespace osquery
