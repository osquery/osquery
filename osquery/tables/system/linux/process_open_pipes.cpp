/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iostream>
#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <regex>

namespace osquery {
namespace tables {

struct pipe_info {
  pid_t pid;
  int fd;
  std::string mode;
  ino_t inode;
  std::string type;
  pipe_info(pid_t pid, int fd, std::string mode, ino_t inode, std::string type)
      : pid(pid),
        fd(fd),
        mode(std::move(mode)),
        inode(std::move(inode)),
        type(type) {}
};

using PidToPipesMap =
    std::map<pid_t, std::vector<std::reference_wrapper<pipe_info>>>;
using InodeToPipesMap =
    std::map<ino_t, std::vector<std::reference_wrapper<pipe_info>>>;

bool isSamePipe(const pipe_info& p1, const pipe_info& p2) {
  return (p1.pid == p2.pid && p1.inode == p2.inode && p1.fd == p2.fd &&
          p1.mode == p2.mode);
}

bool isReaderWriterPair(const pipe_info& p1, const pipe_info& p2) {
  // Assumption: p1 and p2 have same inode
  return ((p1.mode != p2.mode) || (p1.mode == "rw"));
}

bool isUnconnectedPipe(ino_t inode, const InodeToPipesMap& pipe_partners) {
  return (pipe_partners.at(inode).size() == 1);
}

int parseInode(const std::string& pipe_str) {
  std::smatch match;
  if (std::regex_search(pipe_str, match, std::regex("\\d+"))) {
    return std::stoul(match[0]);
  } else {
    return 0;
  }
}

std::string getMode(const std::string& pid, const std::string& fd) {
  std::string mode = "";
  struct stat file_stat;
  std::string filename = std::string("/proc/") + pid + "/fd/" + fd;
  if (lstat(filename.c_str(), &file_stat)) {
    return "-";
  }
  if (file_stat.st_mode & S_IRUSR || file_stat.st_mode & S_IRGRP ||
      file_stat.st_mode & S_IROTH) {
    mode += 'r';
  }
  if (file_stat.st_mode & S_IWUSR || file_stat.st_mode & S_IWGRP ||
      file_stat.st_mode & S_IWOTH) {
    mode += 'w';
  }
  return mode;
}

std::unique_ptr<pipe_info> createPipeInfoStruct(pid_t pid,
                                                int fd,
                                                const std::string& mode,
                                                ino_t inode,
                                                const std::string& type) {
  auto ps = std::make_unique<pipe_info>(pid, fd, mode, inode, type);
  if (!ps) {
    LOG(ERROR) << "Error creating pipe_info for pid: " << pid;
  }
  return ps;
}

std::unique_ptr<pipe_info> getNamedPipeInfo(
    const std::string& process,
    const std::pair<std::string, std::string>& desc) {
  if (desc.second.find("socket:") != std::string::npos ||
      desc.second.find("anon_inode:") != std::string::npos) {
    return nullptr;
  }
  struct stat file_stat;
  if (stat(desc.second.c_str(), &file_stat) || // lstat on file path
      !S_ISFIFO(file_stat.st_mode)) { // not a pipe
    return nullptr;
  }
  return createPipeInfoStruct(std::stoi(process),
                              std::stoi(desc.first),
                              getMode(process, desc.first),
                              file_stat.st_ino,
                              "named");
}

std::unique_ptr<pipe_info> getPipeInfo(
    const std::string& process,
    const std::pair<std::string, std::string>& desc) {
  if (desc.second.find("pipe:") != std::string::npos) { // found unnamed pipe
    return createPipeInfoStruct(std::stoi(process),
                                std::stoi(desc.first),
                                getMode(process, desc.first),
                                parseInode(desc.second),
                                "anonymous");
  } else { // check for potential named pipe
    return getNamedPipeInfo(process, desc);
  }
}

void genPipePartners(const std::string& process,
                     const std::map<std::string, std::string>& descriptors,
                     PidToPipesMap& pipe_desc,
                     InodeToPipesMap& pipe_partners,
                     std::vector<std::unique_ptr<pipe_info>>& pipe_structs) {
  std::unique_ptr<pipe_info> ps;
  for (const auto& desc : descriptors) {
    ps = getPipeInfo(process, desc);
    if (!ps) {
      continue;
    }
    pipe_desc[ps->pid].push_back(*ps);
    pipe_partners[ps->inode].push_back(*ps);
    pipe_structs.push_back(std::move(ps));
  }
}

void populatePartialRow(const std::string& process,
                        const pipe_info& ps,
                        Row& r) {
  r["pid"] = process;
  r["fd"] = std::to_string(ps.fd);
  r["mode"] = ps.mode;
  r["inode"] = std::to_string(ps.inode);
  r["type"] = ps.type;
}

void createRow(const std::string& process,
               const pipe_info& ps,
               const pipe_info& partner_ps,
               QueryData& results) {
  Row r;
  populatePartialRow(process, ps, r);
  r["partner_pid"] = std::to_string(partner_ps.pid);
  r["partner_fd"] = std::to_string(partner_ps.fd);
  r["partner_mode"] = partner_ps.mode;
  results.push_back(r);
}

void createRow(const std::string& process,
               const pipe_info& ps,
               QueryData& results) {
  Row r;
  populatePartialRow(process, ps, r);
  results.push_back(r);
}

void genResults(const std::string& process,
                const PidToPipesMap& pipe_desc,
                const InodeToPipesMap& pipe_partners,
                QueryData& results) {
  auto pipe_desc_iter = pipe_desc.find((std::stoi(process)));
  if (pipe_desc_iter == pipe_desc.end()) {
    return;
  }

  for (const auto& ps :
       pipe_desc_iter->second) { // iterate over vector of pipe_info
    for (const auto& partner_ps : pipe_partners.at(ps.get().inode)) {
      if (isUnconnectedPipe(ps.get().inode, pipe_partners)) {
        createRow(process, ps, results);
      } else if (isSamePipe(ps, partner_ps) ||
                 !isReaderWriterPair(ps, partner_ps)) {
        continue;
      } else {
        createRow(process, ps, partner_ps, results);
      }
    }
  }
}

QueryData genPipes(QueryContext& context) {
  QueryData results;
  std::set<std::string> pids;
  PidToPipesMap pipe_desc;
  InodeToPipesMap pipe_partners;
  std::vector<std::unique_ptr<pipe_info>> pipe_structs;

  osquery::procProcesses(pids);

  for (const auto& process : pids) {
    std::map<std::string, std::string> descriptors;
    if (osquery::procDescriptors(process, descriptors).ok()) {
      genPipePartners(
          process, descriptors, pipe_desc, pipe_partners, pipe_structs);
    }
  }

  for (const auto& process : pids) {
    genResults(process, pipe_desc, pipe_partners, results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
