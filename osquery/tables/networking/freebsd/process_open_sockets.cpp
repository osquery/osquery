/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 *
 * FreeBSD process_open_sockets: enumerate per-process socket descriptors via
 * libprocstat (the same library sockstat(1) uses).  For each fd whose
 * underlying object is a socket, procstat_get_socket_info() exposes the
 * domain family, protocol, local + peer sockaddrs, TCP state, and the unix
 * domain path -- everything the table schema demands.
 *
 * Notes
 *   * family is reported using FreeBSD-native AF_* values (AF_INET=2,
 *     AF_INET6=28, AF_UNIX=1).  The platform-agnostic listening_ports.cpp
 *     hardcodes Linux values for AF_INET6 (=10), so it needs a corresponding
 *     FreeBSD patch to recognise 28; AF_INET and AF_UNIX match across both.
 *   * net_namespace is Linux-only and intentionally left unset.
 */

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <sys/user.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp_fsm.h>

#include <libprocstat.h>

#include <set>
#include <string>

#include <osquery/core/tables.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {
namespace tables {

namespace {

// Mirror the TCP state strings the Linux table emits so cross-platform
// queries (WHERE state = 'LISTEN') keep working.
std::string tcpStateString(int state) {
  switch (state) {
  case TCPS_CLOSED:
    return "CLOSED";
  case TCPS_LISTEN:
    return "LISTEN";
  case TCPS_SYN_SENT:
    return "SYN_SENT";
  case TCPS_SYN_RECEIVED:
    return "SYN_RECV";
  case TCPS_ESTABLISHED:
    return "ESTABLISHED";
  case TCPS_CLOSE_WAIT:
    return "CLOSE_WAIT";
  case TCPS_FIN_WAIT_1:
    return "FIN_WAIT1";
  case TCPS_CLOSING:
    return "CLOSING";
  case TCPS_LAST_ACK:
    return "LAST_ACK";
  case TCPS_FIN_WAIT_2:
    return "FIN_WAIT2";
  case TCPS_TIME_WAIT:
    return "TIME_WAIT";
  default:
    return "";
  }
}

// Extract numeric address + port from a sockaddr_storage.  Empty address on
// AF_UNIX -- callers pull the path from sockstat::dname instead.
void formatEndpoint(const struct sockaddr_storage& ss,
                    std::string& addr_out,
                    int& port_out) {
  char buf[INET6_ADDRSTRLEN] = {0};
  port_out = 0;
  if (ss.ss_family == AF_INET) {
    auto* sin = reinterpret_cast<const struct sockaddr_in*>(&ss);
    if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) != nullptr) {
      addr_out = buf;
    }
    port_out = ntohs(sin->sin_port);
  } else if (ss.ss_family == AF_INET6) {
    auto* sin6 = reinterpret_cast<const struct sockaddr_in6*>(&ss);
    if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)) != nullptr) {
      addr_out = buf;
    }
    port_out = ntohs(sin6->sin6_port);
  }
}

} // namespace

QueryData genOpenSockets(QueryContext& context) {
  QueryData results;

  struct procstat* ps = procstat_open_sysctl();
  if (ps == nullptr) {
    return results;
  }

  unsigned int cnt = 0;
  struct kinfo_proc* procs = procstat_getprocs(ps, KERN_PROC_PROC, 0, &cnt);
  if (procs == nullptr) {
    procstat_close(ps);
    return results;
  }

  // Honour WHERE pid = X to avoid the O(processes * fds) walk for targeted
  // queries.  The Linux table treats pid=-1 as a wildcard meaning "include
  // orphan sockets"; we have no orphan sockets on FreeBSD (every socket has
  // a holder process visible via procstat), so -1 is just a no-op filter.
  // Use the string-overload of getAll(): the templated getAll<T>(op)
  // silently ignores its `op` argument and would also accept SQLite's
  // LIMIT pushdown (synthetic op SQLITE_INDEX_CONSTRAINT_LIMIT=73) as a
  // pid equality on modern SQLite, turning a bare "LIMIT N" into
  // "WHERE pid = N".
  std::set<pid_t> wanted;
  bool filter = false;
  if (context.constraints.count("pid") > 0) {
    auto pids = context.constraints.at("pid").getAll(EQUALS);
    for (const auto& p : pids) {
      long long pl;
      try {
        pl = std::stoll(p);
      } catch (...) {
        continue;
      }
      if (pl == -1) {
        filter = false;
        wanted.clear();
        break;
      }
      filter = true;
      wanted.insert(static_cast<pid_t>(pl));
    }
  }

  for (unsigned int i = 0; i < cnt; i++) {
    pid_t pid = procs[i].ki_pid;
    if (filter && wanted.count(pid) == 0) {
      continue;
    }
    struct filestat_list* head = procstat_getfiles(ps, &procs[i], 0);
    if (head == nullptr) {
      continue;
    }
    struct filestat* fst;
    STAILQ_FOREACH(fst, head, next) {
      if (fst->fs_type != PS_FST_TYPE_SOCKET) {
        continue;
      }
      // Skip non-fd entries (text/cwd/root/jail/trace/mmap/ctty) -- those are
      // never reachable through socket(2) and would only confuse joins.
      if (fst->fs_uflags &
          (PS_FST_UFLAG_TEXT | PS_FST_UFLAG_CDIR | PS_FST_UFLAG_RDIR |
           PS_FST_UFLAG_JAIL | PS_FST_UFLAG_TRACE | PS_FST_UFLAG_MMAP |
           PS_FST_UFLAG_CTTY)) {
        continue;
      }

      struct sockstat sock;
      char errbuf[_POSIX2_LINE_MAX];
      if (procstat_get_socket_info(ps, fst, &sock, errbuf) != 0) {
        continue;
      }

      Row r;
      r["pid"] = BIGINT(pid);
      r["fd"] = BIGINT(fst->fs_fd);
      // The Linux table uses the inode number for "socket"; FreeBSD doesn't
      // expose one, so use the kernel socket address as a stable identifier.
      r["socket"] = BIGINT(sock.so_addr);
      r["family"] = INTEGER(sock.dom_family);
      r["protocol"] = INTEGER(sock.proto);
      // Default-init every schema column so listening_ports's blind .at()
      // calls (which iterate sockets and read remote_port etc. on every row)
      // don't throw map::at on, say, a UNIX socket.
      r["local_address"] = "";
      r["local_port"] = INTEGER(0);
      r["remote_address"] = "";
      r["remote_port"] = INTEGER(0);
      r["path"] = "";
      r["state"] = "";

      if (sock.dom_family == AF_INET || sock.dom_family == AF_INET6) {
        std::string addr;
        int port = 0;
        formatEndpoint(sock.sa_local, addr, port);
        r["local_address"] = addr;
        r["local_port"] = INTEGER(port);
        formatEndpoint(sock.sa_peer, addr, port);
        r["remote_address"] = addr;
        r["remote_port"] = INTEGER(port);
        if (sock.proto == IPPROTO_TCP) {
          r["state"] = tcpStateString(sock.so_rcv_sb_state);
        }
      } else if (sock.dom_family == AF_UNIX || sock.dom_family == AF_LOCAL) {
        // dname is the bound path (empty for unbound/anonymous sockets,
        // which matches Linux behaviour for /proc/net/unix entries without
        // a path).
        r["path"] = sock.dname;
      }

      results.push_back(r);
    }
    procstat_freefiles(ps, head);
  }

  procstat_freeprocs(ps, procs);
  procstat_close(ps);
  return results;
}

} // namespace tables
} // namespace osquery
