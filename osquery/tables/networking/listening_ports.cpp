// Copyright 2004-present Facebook. All Rights Reserved.

#include <string>
#include <iomanip>

#include <stdio.h>
#include <stdlib.h>
#include <libproc.h>

#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"

using namespace osquery::core;
using namespace osquery::db;

namespace osquery {
namespace tables {

void genSocket(pid_t pid, struct socket_fdinfo socket, QueryData &results) {
  int family = socket.psi.soi_family;
  int protocol = socket.psi.soi_protocol;
  int local, remote;

  // E.g., limit to TCP socket.psi.soi_kind == SOCKINFO_TCP
  if (family != AF_INET && family != AF_INET6) {
    return;
  }

  local = (int)ntohs(socket.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
  remote = (int)ntohs(socket.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport);
  if (remote != 0 || local == 0) {
    return;
  }

  struct in6_addr ipv6 = socket.psi.soi_proto.pri_in.insi_laddr.ina_6;
  uint32_t ipv4 = ipv6.__u6_addr.__u6_addr32[3];

  Row r;
  r["pid"] = boost::lexical_cast<std::string>(pid);
  r["port"] = boost::lexical_cast<std::string>(local);
  r["protocol"] = boost::lexical_cast<std::string>(protocol);
  r["family"] = boost::lexical_cast<std::string>(family);

  int octet;
  std::stringstream addr;
  if (family == AF_INET) {
    // Parse IPv4
    for (int i = 0; i < 4; i++) {
      octet = (int)ipv6.__u6_addr.__u6_addr8[i + 12];
      addr << boost::lexical_cast<std::string>(octet);
      if (i < 3) {
        addr << ".";
      }
    }
  } else {
    // Parse IPv6.
    for (int i = 0; i < 16; i++) {
      octet = (int)ipv6.__u6_addr.__u6_addr8[i];
      addr << std::setfill('0') << std::setw(2);
      addr << std::hex << octet;
      if ((i + 1) % 2 == 0 && i > 0) {
        addr << ":";
      }
    }
  }

  r["address"] = addr.str();
  results.push_back(r);
}

QueryData genListeningPorts() {
  QueryData results;

  int num_pids;
  pid_t *pids;

  int fd_size, socket_size;
  struct proc_fdinfo *fd_list;
  struct socket_fdinfo socket;

  num_pids = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
  if (num_pids <= 0) {
    return {};
  }

  // Allocate *2 for processes created between calls to listpids.
  pids = (pid_t *)malloc(sizeof(pid_t) * (num_pids * 2));
  num_pids =
      proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pid_t) * (num_pids * 2));
  if (num_pids <= 0) {
    free(pids);
    return {};
  }

  // Iterate over each pid.
  for (int i = 0; i < num_pids; ++i) {
    if (pids[i] <= 0) {
      continue;
    }

    // Get FD set for a given pid.
    fd_size = proc_pidinfo(pids[i], PROC_PIDLISTFDS, 0, 0, 0);
    if (fd_size == 0) {
      continue;
    }

    fd_list = (struct proc_fdinfo *)malloc(fd_size);
    fd_size = proc_pidinfo(pids[i], PROC_PIDLISTFDS, 0, fd_list, fd_size);

    for (int j = 0; j < fd_size / PROC_PIDLISTFD_SIZE; j++) {
      // Iterate over each FD, looking for SOCKETs only.
      if (fd_list[j].proc_fdtype != PROX_FDTYPE_SOCKET) {
        continue;
      }

      socket_size = proc_pidfdinfo(pids[i],
                                   fd_list[j].proc_fd,
                                   PROC_PIDFDSOCKETINFO,
                                   &socket,
                                   PROC_PIDFDSOCKETINFO_SIZE);

      // Generate the socket row if it's a listening socket.
      genSocket(pids[i], socket, results);
    }

    free(fd_list);
  }

  return results;
}
}
}
