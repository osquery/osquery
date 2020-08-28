/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cerrno>
#include <climits>
#include <map>
#include <string>

#include <sys/resource.h>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

namespace osquery {
namespace tables {
const std::map<std::string, int> kLimitsResourceMap = {
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

void getLimit(QueryData& results) {
  for (const auto& it : kLimitsResourceMap) {
    struct rlimit rlp;
    auto result = getrlimit(it.second, &rlp);
    if (result == -1) {
      LOG(INFO) << "Failed to get limit for " << it.first << ": "
                << std::strerror(errno);
      continue;
    }
    Row r;
    r["type"] = it.first;
    r["soft_limit"] = (rlp.rlim_cur == RLIM_INFINITY)
                          ? "unlimited"
                          : std::to_string(rlp.rlim_cur);
    r["hard_limit"] = (rlp.rlim_max == RLIM_INFINITY)
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
