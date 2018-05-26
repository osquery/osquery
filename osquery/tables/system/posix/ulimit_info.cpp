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

#ifndef RLIMIT_LOCKS
#define RLIMIT_LOCKS -1
#endif
#ifndef RLIMIT_SIGPENDING
#define RLIMIT_SIGPENDING -1
#endif
#ifndef RLIMIT_MSGQUEUE
#define RLIMIT_MSGQUEUE -1
#endif
#ifndef RLIMIT_NICE
#define RLIMIT_NICE -1
#endif
#ifndef RLIMIT_RTPRIO
#define RLIMIT_RTPRIO -1
#endif
#ifndef RLIMIT_SBSIZE
#define RLIMIT_SBSIZE -1
#endif
#ifndef RLIMIT_NPTS
#define RLIMIT_NPTS -1
#endif
#ifndef RLIMIT_SWAP
#define RLIMIT_SWAP -1
#endif
#ifndef RLIMIT_KQUEUES
#define RLIMIT_KQUEUES -1
#endif
#ifndef RLIMIT_UMTXP
#define RLIMIT_UMTXP -1
#endif

namespace osquery {
namespace tables {

void getLimit(QueryData& results) {
  std::map<std::string, int> resource_map = {
      {"cpu", RLIMIT_CPU},
      {"fsize", RLIMIT_FSIZE},
      {"data", RLIMIT_DATA},
      {"stack", RLIMIT_STACK},
      {"core", RLIMIT_CORE},
      {"nofile", RLIMIT_NOFILE},
      {"as", RLIMIT_AS},
      {"rss", RLIMIT_RSS},
      {"memlock", RLIMIT_MEMLOCK},
      {"nproc", RLIMIT_NPROC},
      {"locks", RLIMIT_LOCKS},
      {"sigpending", RLIMIT_SIGPENDING},
      {"msgqueue", RLIMIT_MSGQUEUE},
      {"nice", RLIMIT_NICE},
      {"rtprio", RLIMIT_RTPRIO},
      {"sbsize", RLIMIT_SBSIZE},
      {"npts", RLIMIT_NPTS},
      {"swap", RLIMIT_SWAP},
      {"kqueues", RLIMIT_KQUEUES},
      {"umtxp", RLIMIT_UMTXP},
  };

  for (const auto& it : resource_map) {
    struct rlimit rlp;
    auto result = getrlimit(it.second, &rlp);
    if (result == -1) {
      LOG(INFO) << "Failed to get limit for " << it.first;
      continue;
    }
    Row r;
    r["type"] = it.first;
    r["soft_limit"] = (rlp.rlim_cur == ULONG_MAX)
                          ? "unlimited"
                          : std::to_string(rlp.rlim_cur);
    r["hard_limit"] = (rlp.rlim_max == ULONG_MAX)
                          ? "unlimited"
                          : std::to_string(rlp.rlim_max);
    results.push_back(r);
  }
}

QueryData genUlimitInfo(QueryContext& context) {
  QueryData results;

  getLimit(results);

  return results;
}
} // namespace tables
} // namespace osquery
