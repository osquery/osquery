/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <libprocstat.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/freebsd/procstat.h>

namespace osquery {
namespace tables {

// Heavily inspired by procstat(1) on FreeBSD.
std::pair<std::string, int>& sockaddr_to_pair(struct sockaddr_storage* sstor) {
  char buffer[INET6_ADDRSTRLEN] = {0};
  struct sockaddr_in6* sin6 = nullptr;
  struct sockaddr_in* sin = nullptr;
  struct sockaddr_un* sun = nullptr;

  static std::pair<std::string, int> addr;
  switch (sstor->ss_family) {
    case AF_LOCAL:
      sun = (struct sockaddr_un*) sstor;
      addr = std::make_pair(std::string(sun->sun_path), 0);
      break;
    case AF_INET:
      sin = (struct sockaddr_in*) sstor;
      addr = std::make_pair(std::string(inet_ntoa(sin->sin_addr)),
                            ntohs(sin->sin_port));
      break;
    case AF_INET6:
      sin6 = (struct sockaddr_in6*) sstor;
      inet_ntop(AF_INET6, &sin6->sin6_addr, buffer, sizeof(buffer));
      addr = std::make_pair(std::string(buffer), ntohs(sin6->sin6_port));
      break;
    default:
      addr = std::make_pair(std::string(""), 0);
      break;
  }

  return addr;
}

void genSockets(struct procstat* pstat,
                struct kinfo_proc* proc,
                QueryData &results) {
  Row r;
  struct filestat_list* files = nullptr;
  struct filestat* file = nullptr;
  struct sockstat sock;
  int error;
  std::pair<std::string, int> addr;

  files = procstat_getfiles(pstat, proc, 0);
  if (files == nullptr) {
    return;
  }

  STAILQ_FOREACH(file, files, next) {
    // Skip files that aren't sockets.
    if (file->fs_type != PS_FST_TYPE_SOCKET) {
      continue;
    }

    error = procstat_get_socket_info(pstat, file, &sock, nullptr);
    if (error != 0) {
      continue;
    }

    r["pid"] = INTEGER(proc->ki_pid);
    r["socket"] = INTEGER(file->fs_fd);
    r["family"] = INTEGER(sock.dom_family);
    r["protocol"] = INTEGER(sock.proto);

    addr = sockaddr_to_pair(&(sock.sa_local));
    r["local_address"] = TEXT(addr.first);
    r["local_port"] = INTEGER(addr.second);

    addr = sockaddr_to_pair(&(sock.sa_peer));
    r["remote_address"] = TEXT(addr.first);
    r["remote_port"] = INTEGER(addr.second);

    results.push_back(r);
  }

  procstat_freefiles(pstat, files);
}

QueryData genOpenSockets(QueryContext &context) {
  QueryData results;
  struct kinfo_proc* procs = nullptr;
  struct procstat* pstat = nullptr;

  auto cnt = getProcesses(context, &pstat, &procs);

  for (size_t i = 0; i < cnt; i++) {
    genSockets(pstat, &procs[i], results);
  }

  procstatCleanup(pstat, procs);

  return results;
}
}
}
