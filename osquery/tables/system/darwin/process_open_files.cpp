/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <set>

// Keep sys/socket first.
#include <sys/socket.h>
#include <arpa/inet.h>
#include <libproc.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

enum {
  SOCKET_TYPE_LOCAL,
  SOCKET_TYPE_FOREIGN,
};

// From processes.cpp
std::set<int> getProcList();

std::string socketIpAsString(const struct in_sockinfo *in,
                             int type,
                             int family) {
  char dst[INET6_ADDRSTRLEN];
  memset(dst, 0, sizeof(dst));

  // The caller determines whether to parse the local or remote address.
  if (type == SOCKET_TYPE_LOCAL) {
    // The input struct insi_vflag determines protocol type.
    if ((in->insi_vflag & INI_IPV4) != 0 || family == AF_INET) {
      inet_ntop(AF_INET, &(in->insi_laddr.ina_46.i46a_addr4), dst, sizeof(dst));
    } else {
      inet_ntop(AF_INET6, &(in->insi_laddr.ina_6), dst, sizeof(dst));
    }
  } else {
    if ((in->insi_vflag & INI_IPV4) != 0 || family == AF_INET) {
      inet_ntop(AF_INET, &(in->insi_faddr.ina_46.i46a_addr4), dst, sizeof(dst));
    } else {
      inet_ntop(AF_INET6, &(in->insi_faddr.ina_6), dst, sizeof(dst));
    }
  }

  std::string address(dst);
  return address;
}

void parseNetworkSocket(const struct socket_fdinfo socket_info, Row &r) {
  // Set socket protocol.
  const struct in_sockinfo *in;
  if (socket_info.psi.soi_kind == SOCKINFO_TCP) {
    r["file_type"] = "TCP";
    in = &socket_info.psi.soi_proto.pri_tcp.tcpsi_ini;
  } else {
    r["file_type"] = "UDP";
    in = &socket_info.psi.soi_proto.pri_in;
  }

  auto family = socket_info.psi.soi_family;
  r["local_path"] = INTEGER(socket_info.psi.soi_kind);
  r["local_host"] = socketIpAsString(in, SOCKET_TYPE_LOCAL, family);
  r["local_port"] = INTEGER(ntohs(in->insi_lport));
  r["remote_host"] = socketIpAsString(in, SOCKET_TYPE_FOREIGN, family);
  r["remote_port"] = INTEGER(ntohs(in->insi_fport));
}

void genOpenFiles(int pid, QueryData &results) {
  // std::vector<OpenFile> open_files;
  int bufsize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, 0, 0);
  if (bufsize == -1) {
    VLOG(1) << "An error occurred retrieving the open files " << pid;
    return;
  }

  // Allocate structs for each descriptor.
  proc_fdinfo fds[bufsize / PROC_PIDLISTFD_SIZE];
  int num_fds = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, sizeof(fds));

  for (auto fd_info : fds) {
    Row r;

    r["pid"] = INTEGER(pid);
    if (fd_info.proc_fdtype == PROX_FDTYPE_VNODE) {
      struct vnode_fdinfowithpath vi;
      if (proc_pidfdinfo(pid,
                         fd_info.proc_fd,
                         PROC_PIDFDVNODEPATHINFO,
                         &vi,
                         PROC_PIDFDVNODEPATHINFO_SIZE) <= 0) {
        continue;
      }

      r["file_type"] = "file";
      r["local_path"] = std::string(vi.pvip.vip_path);
    } else if (fd_info.proc_fdtype == PROX_FDTYPE_SOCKET) {
      struct socket_fdinfo si;
      if (proc_pidfdinfo(pid,
                         fd_info.proc_fd,
                         PROC_PIDFDSOCKETINFO,
                         &si,
                         PROC_PIDFDSOCKETINFO_SIZE) <= 0) {
        continue;
      }

      auto socket_kind = si.psi.soi_kind;
      auto socket_family = si.psi.soi_family;
      if (socket_kind == SOCKINFO_IN || socket_kind == SOCKINFO_TCP) {
        parseNetworkSocket(si, r);
      } else {
        // Not supporting non-network socket parsing.
        continue;
      }
    } else {
      // Only supporting vnode and socket types.
      continue;
    }

    results.push_back(r);
  }
}

QueryData genProcessOpenFiles(QueryContext &context) {
  QueryData results;
  auto pidlist = getProcList();

  for (auto &pid : pidlist) {
    if (!context.constraints["pid"].matches<int>(pid)) {
      // Optimize by not searching when a pid is a constraint.
      continue;
    }

    genOpenFiles(pid, results);
  }

  return results;
}
}
}
