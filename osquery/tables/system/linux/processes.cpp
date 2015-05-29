/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>
#include <map>

#include <stdlib.h>
#include <unistd.h>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>

namespace osquery {
namespace tables {

inline std::string getProcAttr(const std::string& attr, const std::string& pid) {
  return "/proc/" + pid + "/" + attr;
}

inline std::string readProcCMDLine(const std::string& pid) {
  auto attr = getProcAttr("cmdline", pid);

  std::string content;
  readFile(attr, content);
  // Remove \0 delimiters.
  std::replace_if(content.begin(),
                  content.end(),
                  [](const char& c) { return c == 0; },
                  ' ');
  // Remove trailing delimiter.
  boost::algorithm::trim(content);
  return content;
}

inline std::string readProcLink(const std::string& attr, const std::string& pid) {
  // The exe is a symlink to the binary on-disk.
  auto attr_path = getProcAttr(attr, pid);

  std::string result;
  char link_path[PATH_MAX] = {0};
  auto bytes = readlink(attr_path.c_str(), link_path, sizeof(link_path) - 1);
  if (bytes >= 0) {
    result = std::string(link_path);
  }

  return result;
}

void genProcessEnvironment(const std::string& pid, QueryData& results) {
  auto attr = getProcAttr("environ", pid);

  std::string content;
  readFile(attr, content);
  for (const auto& buf : osquery::split(content, "\n")) {
    size_t idx = buf.find_first_of("=");

    Row r;
    r["pid"] = pid;
    r["key"] = buf.substr(0, idx);
    r["value"] = buf.substr(idx + 1);
    results.push_back(r);
  }
}

void genProcessMap(const std::string& pid, QueryData& results) {
  auto map = getProcAttr("maps", pid);

  std::string content;
  readFile(map, content);
  for (auto& line : osquery::split(content, "\n")) {
    auto fields = osquery::split(line, " ");

    Row r;
    r["pid"] = pid;

    // If can't read address, not sure.
    if (fields.size() < 5) {
      continue;
    }

    if (fields[0].size() > 0) {
      auto addresses = osquery::split(fields[0], "-");
      r["start"] = "0x" + addresses[0];
      r["end"] = "0x" + addresses[1];
    }

    r["permissions"] = fields[1];
    r["offset"] = BIGINT(std::stoll(fields[2], nullptr, 16));
    r["device"] = fields[3];
    r["inode"] = fields[4];

    // Path name must be trimmed.
    if (fields.size() > 5) {
      boost::trim(fields[5]);
      r["path"] = fields[5];
    }

    // BSS with name in pathname.
    r["pseudo"] = (fields[4] == "0" && r["path"].size() > 0) ? "1" : "0";
    results.push_back(r);
  }
}

struct SimpleProcStat {
  // Output from string parsing /proc/<pid>/status.
  std::string parent; // PPid:
  std::string name; // Name:
  std::string real_uid; // Uid: * - - -
  std::string real_gid; // Gid: * - - -
  std::string effective_uid; // Uid: - * - -
  std::string effective_gid; // Gid: - * - -

  std::string resident_size; // VmRSS:
  std::string phys_footprint;  // VmSize:

  // Output from sring parsing /proc/<pid>/stat.
  std::string user_time;
  std::string system_time;
  std::string start_time;
};

SimpleProcStat getProcStat(const std::string& pid) {
  SimpleProcStat stat;
  std::string content;
  if (readFile(getProcAttr("stat", pid), content).ok()) {
    auto detail_start = content.find_last_of(")");
    // Start parsing stats from ") <MODE>..."
    auto details = osquery::split(content.substr(detail_start + 2), " ");
    stat.parent = details.at(1);
    stat.user_time = details.at(11);
    stat.system_time = details.at(12);
    stat.start_time = details.at(19);
  }

  if (readFile(getProcAttr("status", pid), content).ok()) {
    for (const auto& line : osquery::split(content, "\n")) {
      // Status lines are formatted: Key: Value....\n.
      auto detail = osquery::split(line, ":", 1);
      if (detail.size() != 2) {
        continue;
      }

      // There are specific fields from each detail.
      if (detail.at(0) == "Name") {
        stat.name = detail.at(1);
      } else if (detail.at(0) == "VmRSS") {
        detail[1].erase(detail.at(1).end() - 3, detail.at(1).end());
        // Memory is reported in kB.
        stat.resident_size = detail.at(1) + "000";
      } else if (detail.at(0) == "VmSize") {
        detail[1].erase(detail.at(1).end() - 3, detail.at(1).end());
        // Memory is reported in kB.
        stat.phys_footprint = detail.at(1) + "000";
      } else if (detail.at(0) == "Gid") {
        // Format is: R E - -
        auto gid_detail = osquery::split(detail.at(1), "\t");
        if (gid_detail.size() == 4) {
          stat.real_gid = gid_detail.at(0);
          stat.effective_gid = gid_detail.at(1);
        }
      } else if (detail.at(0) == "Uid") {
        auto uid_detail = osquery::split(detail.at(1), "\t");
        if (uid_detail.size() == 4) {
          stat.real_uid = uid_detail.at(0);
          stat.effective_uid = uid_detail.at(1);
        }
      }
    }
  }

  return stat;
}

void genProcess(const std::string& pid, QueryData& results) {
  // Parse the process stat and status.
  auto proc_stat = getProcStat(pid);

  Row r;
  r["pid"] = pid;
  r["parent"] = proc_stat.parent;
  r["path"] = readProcLink("exe", pid);
  r["name"] = proc_stat.name;

  // Read/parse cmdline arguments.
  r["cmdline"] = readProcCMDLine(pid);
  r["cwd"] = readProcLink("cwd", pid);
  r["root"] = readProcLink("root", pid);

  r["uid"] = proc_stat.real_uid;
  r["euid"] = proc_stat.effective_uid;
  r["gid"] = proc_stat.real_gid;
  r["egid"] = proc_stat.effective_gid;

  // If the path of the executable that started the process is available and
  // the path exists on disk, set on_disk to 1. If the path is not
  // available, set on_disk to -1. If, and only if, the path of the
  // executable is available and the file does NOT exist on disk, set on_disk
  // to 0.
  r["on_disk"] = osquery::pathExists(r["path"]).toString();

  // size/memory information
  r["wired_size"] = "0"; // No support for unpagable counters in linux.
  r["resident_size"] = proc_stat.resident_size;
  r["phys_footprint"] = proc_stat.phys_footprint;

  // time information
  r["user_time"] = proc_stat.user_time;
  r["system_time"] = proc_stat.system_time;
  r["start_time"] = proc_stat.start_time;

  results.push_back(r);
}

QueryData genProcesses(QueryContext& context) {
  QueryData results;

  std::set<std::string> pids;
  if (context.constraints["pid"].exists(EQUALS)) {
    pids = context.constraints["pid"].getAll(EQUALS);
  } else {
    osquery::procProcesses(pids);
  }

  // Generate data for all pids in the vector.
  // If there are comparison constraints this could apply the operator
  // before generating the process structure.
  for (const auto& pid : pids) {
    genProcess(pid, results);
  }

  return results;
}

QueryData genProcessEnvs(QueryContext& context) {
  QueryData results;

  std::set<std::string> pids;
  if (context.constraints["pid"].exists(EQUALS)) {
    pids = context.constraints["pid"].getAll(EQUALS);
  } else {
    osquery::procProcesses(pids);
  }

  for (const auto& pid : pids) {
    genProcessEnvironment(pid, results);
  }

  return results;
}

QueryData genProcessMemoryMap(QueryContext& context) {
  QueryData results;

  std::set<std::string> pids;
  if (context.constraints["pid"].exists(EQUALS)) {
    pids = context.constraints["pid"].getAll(EQUALS);
  } else {
    osquery::procProcesses(pids);
  }

  for (const auto& pid : pids) {
    genProcessMap(pid, results);
  }

  return results;
}
}
}
