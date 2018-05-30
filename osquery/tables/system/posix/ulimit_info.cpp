/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <cerrno>
#include <climits>
#include <map>
#include <string>

#include <sys/resource.h>

#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

void getLimit(QueryData& results) {
  static const std::map<std::string, int> resource_map = {
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
#ifdef RLIMIT_LOCKS
      {"locks", RLIMIT_LOCKS},
#endif
#ifdef RLIMIT_SIGPENDING
      {"sigpending", RLIMIT_SIGPENDING},
#endif
#ifdef RLIMIT_MSGQUEUE
      {"msgqueue", RLIMIT_MSGQUEUE},
#endif
#ifdef RLIMIT_NICE
      {"nice", RLIMIT_NICE},
#endif
#ifdef RLIMIT_RTPRIO
      {"rtprio", RLIMIT_RTPRIO},
#endif
#ifdef RLIMIT_SBSIZE
      {"sbsize", RLIMIT_SBSIZE},
#endif
#ifdef RLIMIT_NPTS
      {"npts", RLIMIT_NPTS},
#endif
#ifdef RLIMIT_SWAP
      {"swap", RLIMIT_SWAP},
#endif
#ifdef RLIMIT_KQUEUES
      {"kqueues", RLIMIT_KQUEUES},
#endif
#ifdef RLIMIT_UMTXP
      {"umtxp", RLIMIT_UMTXP},
#endif
  };

  for (const auto& it : resource_map) {
    struct rlimit rlp;
    auto result = getrlimit(it.second, &rlp);
    if (result == -1) {
      LOG(INFO) << "Failed to get limit for " << it.first << ": "
                << std::strerror(errno);
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
