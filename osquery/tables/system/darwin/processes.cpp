// Copyright 2004-present Facebook. All Rights Reserved.

#include <algorithm>
#include <map>
#include <string>
#include <unordered_set>
#include <map>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <stdlib.h>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"

#define IPv6_2_IPv4(v6) (((uint8_t *)((struct in6_addr *)v6)->s6_addr)+12)

namespace osquery {
namespace tables {

std::unordered_set<int> getProcList() {
  std::unordered_set<int> pidlist;
  int bufsize = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
  if (bufsize <= 0) {
    LOG(ERROR) << "An error occured retrieving the process list";
    return pidlist;
  }

  // arbitrarily create a list with 2x capacity in case more processes have
  // been loaded since the last proc_listpids was executed
  pid_t pids[2 * bufsize/sizeof(pid_t)];

  // now that we've allocated "pids", let's overwrite num_pids with the actual
  // amount of data that was returned for proc_listpids when we populate the
  // pids data structure
  bufsize = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
  if (bufsize <= 0) {
    LOG(ERROR) << "An error occured retrieving the process list";
    return pidlist;
  }

  int num_pids = bufsize / sizeof(pid_t);
  for (int i = 0; i < num_pids; ++i) {
    // if the pid is negative or 0, it doesn't represent a real process so
    // continue the iterations so that we don't add it to the results set
    if (pids[i] <= 0) {
      continue;
    }
    pidlist.insert(pids[i]);
  }

  return pidlist;
}

std::unordered_map<int, int> getParentMap(std::unordered_set<int> & pidlist) {
  std::unordered_map<int, int> pidmap;
  auto num_pids = pidlist.size();
  pid_t children[num_pids];

  // Find children for each pid, and mark that pid as their parent
  for (auto& pid : pidlist) {
    int num_children = proc_listchildpids(pid, children, sizeof(children));
    for (int i = 0; i < num_children; ++i) {
      pidmap[children[i]] = pid;
    }
  }

  return pidmap;
}

std::string getProcName(int pid) {
  char name[1024];
  proc_name(pid, name, sizeof(name));

  return std::string(name);
}

std::string getProcPath(int pid) {
  char path[PROC_PIDPATHINFO_MAXSIZE];
  proc_pidpath(pid, path, sizeof(path));

  return std::string(path);
}

// Get the max args space
int genMaxArgs() {
  int mib[2] = {CTL_KERN, KERN_ARGMAX};

  int argmax = 0;
  size_t size = sizeof(argmax);
  if (sysctl(mib, 2, &argmax, &size, NULL, 0) == -1) {
    LOG(ERROR) << "An error occured retrieving the max arg size";
    return 0;
  }

  return argmax;
}

std::unordered_map<std::string, std::string> getProcEnv(int pid, size_t argmax) {
  std::unordered_map<std::string, std::string> env;
  std::vector<std::string> args;

  char procargs[argmax];
  const char* cp = procargs;
  int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};

  if (sysctl(mib, 3, &procargs, &argmax, NULL, 0) == -1) {
    LOG(ERROR) << "An error occured retrieving the env for " << pid;
    return env;
  }

  // Here we make the assertion that we are interested in all non-empty strings
  // in the proc args+env
  do {
    std::string s = std::string(cp);
    if (s.length() > 0) {
      args.push_back(s);
    }
    cp += args.back().size() + 1;
  } while (cp < procargs + argmax);

  // Since we know that all envs will have an = sign and are at the end of the
  // list, we iterate from the end forward until we stop seeing = signs.
  // According to the // ps source, there is no programmatic way to know where
  // args stop and env begins, so args at the end of a command string which
  // contain "=" may erroneously appear as env vars.
  for (auto itr = args.rbegin(); itr < args.rend(); ++itr) {
    size_t idx = itr->find_first_of("=");
    if (idx == std::string::npos) {
      break;
    }
    std::string key = itr->substr(0, idx);
    std::string value = itr->substr(idx + 1);
    env[key] = value;
  }

  return env;
}

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
    LOG(ERROR) << "An error occured retrieving the open files " << pid;
    return open_files;
  }

  proc_fdinfo fd_infos[bufsize / PROC_PIDLISTFD_SIZE];

  int num_fds = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fd_infos, sizeof(fd_infos));
  struct vnode_fdinfowithpath vnode_info;
  struct socket_fdinfo socket_info;
  void * la = NULL, * fa = NULL;
  int lp, fp, v4mapped;
  char buf[1024];

  for (int i = 0; i < num_fds; ++i) {
    OpenFile row;
    auto fd_info = fd_infos[i];
    switch (fd_info.proc_fdtype) {
      case PROX_FDTYPE_VNODE:
        row.file_type = "file";
        sz = proc_pidfdinfo(pid, fd_info.proc_fd, PROC_PIDFDVNODEPATHINFO, &vnode_info, PROC_PIDFDVNODEPATHINFO_SIZE);
        if (sz > 0) {
          row.local_path = std::string(vnode_info.pvip.vip_path);
        }
        break;
      case PROX_FDTYPE_SOCKET:
        // Its a socket
        sz = proc_pidfdinfo(pid, fd_info.proc_fd, PROC_PIDFDSOCKETINFO, &socket_info, PROC_PIDFDSOCKETINFO_SIZE);

        if (sz > 0) {
          switch (socket_info.psi.soi_family) {
            case AF_INET:
              if (socket_info.psi.soi_kind == SOCKINFO_TCP) {
                row.file_type = "TCP";

                la = &socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4;
                lp = ntohs(socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
                fa = &socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_46.i46a_addr4;
                fp = ntohs(socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport);

              } else {
                row.file_type = "UDP";
                la = &socket_info.psi.soi_proto.pri_in.insi_laddr.ina_46.i46a_addr4;
                lp = ntohs(socket_info.psi.soi_proto.pri_in.insi_lport);
                fa = &socket_info.psi.soi_proto.pri_in.insi_faddr.ina_46.i46a_addr4;
                fp = ntohs(socket_info.psi.soi_proto.pri_in.insi_fport);
              }

              row.local_host = std::string(inet_ntop(AF_INET, &(((struct sockaddr_in *)la)->sin_addr), buf, sizeof(buf)));
              row.local_port  = boost::lexical_cast<std::string>(lp);
              row.remote_host = std::string(inet_ntop(AF_INET, &(((struct sockaddr_in *)fa)->sin_addr), buf, sizeof(buf)));
              row.remote_port = boost::lexical_cast<std::string>(fp);

              break;
            case AF_INET6:
              if (socket_info.psi.soi_kind == SOCKINFO_TCP) {
                row.file_type = "TCP6";

                la = &socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_6;
                lp = ntohs(socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
                fa = &socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_6;
                fp = ntohs(socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport);

                if ((socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_vflag & INI_IPV4) != 0) {
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

              row.local_host = std::string(inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)la)->sin6_addr), buf, sizeof(buf)));
              row.local_port  = boost::lexical_cast<std::string>(lp);
              row.remote_host = std::string(inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)fa)->sin6_addr), buf, sizeof(buf)));
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

QueryData genProcesses() {
  QueryData results;
  auto pidlist = getProcList();
  auto parent_pid = getParentMap(pidlist);

  for (auto& pid : pidlist) {
    Row r;
    r["pid"] = boost::lexical_cast<std::string>(pid);
    r["name"] = getProcName(pid);
    r["path"] = getProcPath(pid);

    const auto parent_it = parent_pid.find(pid);
    if (parent_it != parent_pid.end()) {
      r["parent"] = boost::lexical_cast<std::string>(parent_it->second);
    } else {
      r["parent"] = "-1";
    }

    // if the path of the executable that started the process is available and
    // the path exists on disk, set on_disk to 1.  if the path is not
    // available, set on_disk to -1.  if, and only if, the path of the
    // executable is available and the file does not exist on disk, set on_disk
    // to 0.
    r["on_disk"] = osquery::pathExists(r["path"]).toString();

    // systems usage and time information
    struct rusage_info_v2 rusage_info_data;
    int rusage_status = proc_pid_rusage(
        pid, RUSAGE_INFO_V2, (rusage_info_t*)&rusage_info_data);
    // proc_pid_rusage returns -1 if it was unable to gather information
    if (rusage_status == 0) {
      // size information
      r["wired_size"] =
          boost::lexical_cast<std::string>(rusage_info_data.ri_wired_size);
      r["resident_size"] =
          boost::lexical_cast<std::string>(rusage_info_data.ri_resident_size);
      r["phys_footprint"] =
          boost::lexical_cast<std::string>(rusage_info_data.ri_phys_footprint);

      // time information
      r["user_time"] =
          boost::lexical_cast<std::string>(rusage_info_data.ri_user_time);
      r["system_time"] =
          boost::lexical_cast<std::string>(rusage_info_data.ri_system_time);
      r["start_time"] = boost::lexical_cast<std::string>(
          rusage_info_data.ri_proc_start_abstime);
    }

    // save the results
    results.push_back(r);
  }

  return results;
}

QueryData genProcessEnvs() {
  QueryData results;
  auto pidlist = getProcList();
  int argmax = genMaxArgs();

  for (auto& pid : pidlist) {
    auto env = getProcEnv(pid, argmax);
    for (auto env_itr = env.begin(); env_itr != env.end(); ++env_itr) {
      Row r;

      r["pid"] = boost::lexical_cast<std::string>(pid);
      r["name"] = getProcName(pid);
      r["path"] = getProcPath(pid);
      r["key"] = env_itr->first;
      r["value"] = env_itr->second;

      results.push_back(r);
    }
  }

  return results;
}

QueryData genProcessOpenFiles() {
  QueryData results;
  auto pidlist = getProcList();

  for (auto& pid : pidlist) {
    auto open_files = getOpenFiles(pid);
    for (auto& open_file : open_files) {
      Row r;

      r["pid"] = boost::lexical_cast<std::string>(pid);
      r["name"] = getProcName(pid);
      r["path"] = getProcPath(pid);
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
