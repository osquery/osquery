// Copyright 2004-present Facebook. All Rights Reserved.

#include <set>

// Keep sys/socket first.
#include <sys/socket.h>
#include <arpa/inet.h>
#include <libproc.h>
#include <netinet/in.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

#include "osquery/core.h"
#include "osquery/filesystem.h"
#include "osquery/logger.h"
#include "osquery/tables.h"

#define IPv6_2_IPv4(v6) (((uint8_t *)((struct in6_addr *)v6)->s6_addr) + 12)

namespace osquery {
namespace tables {

// From processes.cpp
std::set<int> getProcList();

struct OpenFile {
  std::string local_path;
  std::string file_type;
  std::string remote_host;
  std::string remote_port;
  std::string local_host;
  std::string local_port;
};

std::vector<OpenFile> getOpenFiles(int pid) {
  std::vector<OpenFile> open_files;
  int sz;
  int bufsize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, 0, 0);
  if (bufsize == -1) {
    LOG(ERROR) << "An error occurred retrieving the open files " << pid;
    return open_files;
  }

  proc_fdinfo fd_infos[bufsize / PROC_PIDLISTFD_SIZE];

  int num_fds =
      proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fd_infos, sizeof(fd_infos));
  struct vnode_fdinfowithpath vnode_info;
  struct socket_fdinfo socket_info;
  void *la = NULL, *fa = NULL;
  int lp, fp, v4mapped;
  char buf[1024];

  for (int i = 0; i < num_fds; ++i) {
    OpenFile row;
    auto fd_info = fd_infos[i];
    switch (fd_info.proc_fdtype) {
    case PROX_FDTYPE_VNODE:
      row.file_type = "file";
      sz = proc_pidfdinfo(pid,
                          fd_info.proc_fd,
                          PROC_PIDFDVNODEPATHINFO,
                          &vnode_info,
                          PROC_PIDFDVNODEPATHINFO_SIZE);
      if (sz > 0) {
        row.local_path = std::string(vnode_info.pvip.vip_path);
      }
      break;
    case PROX_FDTYPE_SOCKET:
      // Its a socket
      sz = proc_pidfdinfo(pid,
                          fd_info.proc_fd,
                          PROC_PIDFDSOCKETINFO,
                          &socket_info,
                          PROC_PIDFDSOCKETINFO_SIZE);

      if (sz > 0) {
        switch (socket_info.psi.soi_family) {
        case AF_INET:
          if (socket_info.psi.soi_kind == SOCKINFO_TCP) {
            row.file_type = "TCP";

            la = &socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_46
                      .i46a_addr4;
            lp = ntohs(socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
            fa = &socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_46
                      .i46a_addr4;
            fp = ntohs(socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport);

          } else {
            row.file_type = "UDP";
            la = &socket_info.psi.soi_proto.pri_in.insi_laddr.ina_46.i46a_addr4;
            lp = ntohs(socket_info.psi.soi_proto.pri_in.insi_lport);
            fa = &socket_info.psi.soi_proto.pri_in.insi_faddr.ina_46.i46a_addr4;
            fp = ntohs(socket_info.psi.soi_proto.pri_in.insi_fport);
          }

          row.local_host =
              std::string(inet_ntop(AF_INET,
                                    &(((struct sockaddr_in *)la)->sin_addr),
                                    buf,
                                    sizeof(buf)));
          row.local_port = boost::lexical_cast<std::string>(lp);
          row.remote_host =
              std::string(inet_ntop(AF_INET,
                                    &(((struct sockaddr_in *)fa)->sin_addr),
                                    buf,
                                    sizeof(buf)));
          row.remote_port = boost::lexical_cast<std::string>(fp);

          break;
        case AF_INET6:
          if (socket_info.psi.soi_kind == SOCKINFO_TCP) {
            row.file_type = "TCP6";

            la = &socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_6;
            lp = ntohs(socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
            fa = &socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_6;
            fp = ntohs(socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport);

            if ((socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_vflag &
                 INI_IPV4) != 0) {
              v4mapped = 1;
            }
          } else {
            row.file_type = "UDP6";

            la = &socket_info.psi.soi_proto.pri_in.insi_laddr.ina_6;
            lp = ntohs(socket_info.psi.soi_proto.pri_in.insi_lport);
            fa = &socket_info.psi.soi_proto.pri_in.insi_faddr.ina_6;
            fp = ntohs(socket_info.psi.soi_proto.pri_in.insi_fport);

            if ((socket_info.psi.soi_proto.pri_in.insi_vflag & INI_IPV4) != 0) {
              v4mapped = 1;
            }
          }

          if (v4mapped) {
            // Adjust IPv4 addresses mapped in IPv6 addresses.
            if (la) {
              la = (struct sockaddr *)IPv6_2_IPv4(la);
            }
            if (fa) {
              fa = (struct sockaddr *)IPv6_2_IPv4(fa);
            }
          }

          row.local_host =
              std::string(inet_ntop(AF_INET6,
                                    &(((struct sockaddr_in6 *)la)->sin6_addr),
                                    buf,
                                    sizeof(buf)));
          row.local_port = boost::lexical_cast<std::string>(lp);
          row.remote_host =
              std::string(inet_ntop(AF_INET6,
                                    &(((struct sockaddr_in6 *)fa)->sin6_addr),
                                    buf,
                                    sizeof(buf)));
          row.remote_port = boost::lexical_cast<std::string>(fp);
          break;
        default:
          break;
        }
      }

      break;
    default:
      break;
    }

    open_files.push_back(row);
  }
  return open_files;
}

QueryData genProcessOpenFiles(QueryContext &context) {
  QueryData results;
  auto pidlist = getProcList();

  for (auto &pid : pidlist) {
    auto open_files = getOpenFiles(pid);
    for (auto &open_file : open_files) {
      Row r;

      r["pid"] = INTEGER(pid);
      r["file_type"] = open_file.file_type;
      r["local_path"] = open_file.local_path;
      r["local_host"] = open_file.local_host;
      r["local_port"] = open_file.local_port;
      r["remote_host"] = open_file.remote_host;
      r["remote_port"] = open_file.remote_port;

      results.push_back(r);
    }
  }

  return results;
}
}
}