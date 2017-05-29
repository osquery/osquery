/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <set>

// Keep sys/socket first.
#include <arpa/inet.h>
#include <libproc.h>
#include <sys/socket.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

enum {
  SOCKET_TYPE_LOCAL,
  SOCKET_TYPE_FOREIGN,
};

enum descriptor_type {
  DESCRIPTORS_TYPE_SOCKET,
  DESCRIPTORS_TYPE_VNODE,
};

// From processes.cpp
std::set<int> getProcList(const QueryContext& context);

inline std::string socketIpAsString(const struct in_sockinfo* in,
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

void parseNetworkSocket(const struct socket_fdinfo socket_info, Row& r) {
  // Set socket protocol.
  const struct in_sockinfo* in = nullptr;
  if (socket_info.psi.soi_kind == SOCKINFO_TCP) {
    in = &socket_info.psi.soi_proto.pri_tcp.tcpsi_ini;
  } else {
    in = &socket_info.psi.soi_proto.pri_in;
  }

  auto family = socket_info.psi.soi_family;
  r["local_address"] = socketIpAsString(in, SOCKET_TYPE_LOCAL, family);
  r["local_port"] = INTEGER(ntohs(in->insi_lport));
  r["remote_address"] = socketIpAsString(in, SOCKET_TYPE_FOREIGN, family);
  r["remote_port"] = INTEGER(ntohs(in->insi_fport));
}

void genFileDescriptor(int pid, int descriptor, QueryData& results) {
  struct vnode_fdinfowithpath vi;
  if (proc_pidfdinfo(pid,
                     descriptor,
                     PROC_PIDFDVNODEPATHINFO,
                     &vi,
                     PROC_PIDFDVNODEPATHINFO_SIZE) <= 0) {
    return;
  }

  Row r;
  r["pid"] = INTEGER(pid);
  r["fd"] = INTEGER(descriptor);
  r["path"] = std::string(vi.pvip.vip_path);
  results.push_back(r);
}

void genSocketDescriptor(int pid, int descriptor, QueryData& results) {
  struct socket_fdinfo si;
  if (proc_pidfdinfo(pid,
                     descriptor,
                     PROC_PIDFDSOCKETINFO,
                     &si,
                     PROC_PIDFDSOCKETINFO_SIZE) <= 0) {
    return;
  }

  if (si.psi.soi_family == AF_INET || si.psi.soi_family == AF_INET6) {
    Row r;

    r["pid"] = INTEGER(pid);
    r["fd"] = BIGINT(descriptor);
    r["socket"] = BIGINT(si.psi.soi_so);
    r["path"] = "";

    // Darwin/OSX SOCKINFO_TCP is not IPPROTO_TCP
    if (si.psi.soi_kind == SOCKINFO_TCP) {
      r["protocol"] = INTEGER(6);
    } else {
      r["protocol"] = INTEGER(17);
    }

    // Darwin/OSX AF_INET6 == 30
    if (si.psi.soi_family == AF_INET) {
      r["family"] = INTEGER(2);
    } else {
      r["family"] = INTEGER(10);
    }

    parseNetworkSocket(si, r);
    results.push_back(r);
  } else if (si.psi.soi_family == AF_UNIX) {
    Row r;

    r["pid"] = INTEGER(pid);
    r["socket"] = INTEGER(descriptor);
    r["family"] = "0";
    r["protocol"] = "0";
    r["local_address"] = "";
    r["local_port"] = "0";
    r["remote_address"] = "";
    r["remote_port"] = "0";
    if ((char*)si.psi.soi_proto.pri_un.unsi_addr.ua_sun.sun_path != nullptr) {
      r["path"] = si.psi.soi_proto.pri_un.unsi_addr.ua_sun.sun_path;
    } else {
      r["path"] = "";
    }
    results.push_back(r);
  } else if (si.psi.soi_family == AF_APPLETALK) {
    // AF_APPLETALK = 17
  } else if (si.psi.soi_family == AF_NATM) {
    // AF_NATM = 32
  } else {
    // Unsupported socket type.
  }
}

void genOpenDescriptors(int pid, descriptor_type type, QueryData& results) {
  int bufsize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, 0, 0);
  if (bufsize == -1) {
    VLOG(1) << "Could not list descriptors for pid: " << pid;
    return;
  }

  // Allocate structs for each descriptor.
  proc_fdinfo* fds = static_cast<proc_fdinfo*>(
      malloc(sizeof(proc_fdinfo) * (bufsize / PROC_PIDLISTFD_SIZE)));
  if (fds == nullptr) {
    return;
  }
  // proc_fdinfo fds[bufsize / PROC_PIDLISTFD_SIZE];
  proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, bufsize);

  for (size_t i = 0; i < bufsize / PROC_PIDLISTFD_SIZE; ++i) {
    if (type == DESCRIPTORS_TYPE_VNODE &&
        fds[i].proc_fdtype == PROX_FDTYPE_VNODE) {
      genFileDescriptor(pid, fds[i].proc_fd, results);
    } else if (type == DESCRIPTORS_TYPE_SOCKET &&
               fds[i].proc_fdtype == PROX_FDTYPE_SOCKET) {
      genSocketDescriptor(pid, fds[i].proc_fd, results);
    }
  }
  free(fds);
}

QueryData genOpenSockets(QueryContext& context) {
  QueryData results;

  auto pidlist = getProcList(context);
  for (auto& pid : pidlist) {
    if (!context.constraints["pid"].matches(pid)) {
      // Optimize by not searching when a pid is a constraint.
      continue;
    }
    genOpenDescriptors(pid, DESCRIPTORS_TYPE_SOCKET, results);
  }

  return results;
}

QueryData genOpenFiles(QueryContext& context) {
  QueryData results;

  auto pidlist = getProcList(context);
  for (auto& pid : pidlist) {
    if (!context.constraints["pid"].matches(pid)) {
      // Optimize by not searching when a pid is a constraint.
      continue;
    }

    genOpenDescriptors(pid, DESCRIPTORS_TYPE_VNODE, results);
  }

  return results;
}
}
}
