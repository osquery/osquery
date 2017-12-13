/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <mutex>
#include <set>

#include <mutex>
#include <set>
#include <unordered_map>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace {

namespace boostfs = boost::filesystem;

bool systemvEnabled() {
  static boost::optional<bool> enabled;
  if (enabled != boost::none) {
    return enabled.get();
  }

  static std::mutex m;
  std::lock_guard<std::mutex> lock(m);
  if (enabled != boost::none) {
    return enabled.get();
  }

  enabled = boostfs::exists("/etc/init.d");
  VLOG(1) << "SystemV was " << (enabled.get() ? "" : "NOT") << " found";

  return enabled.get();
}

bool upstartEnabled() {
  static boost::optional<bool> enabled;
  if (enabled != boost::none) {
    return enabled.get();
  }

  static std::mutex m;
  std::lock_guard<std::mutex> lock(m);
  if (enabled != boost::none) {
    return enabled.get();
  }

  enabled = std::system("which service") == 0;
  VLOG(1) << "Upstart was " << (enabled.get() ? "" : "NOT") << " found";

  return enabled.get();
}

bool systemdEnabled() {
  static boost::optional<bool> enabled;
  if (enabled != boost::none) {
    return enabled.get();
  }

  static std::mutex m;
  std::lock_guard<std::mutex> lock(m);
  if (enabled != boost::none) {
    return enabled.get();
  }

  enabled = std::system("which systemctl") == 0;
  VLOG(1) << "SystemD was " << (enabled.get() ? "" : "NOT") << " found";

  return enabled.get();
}

Status enumerateSystemVServices(QueryData& query_data) {
  if (!systemvEnabled()) {
    return Status(true, "OK");
  }

  static const std::vector<std::string> run_level_dir_list = {"/etc/rc0.d",
                                                              "/etc/rc1.d",
                                                              "/etc/rc2.d",
                                                              "/etc/rc3.d",
                                                              "/etc/rc4.d",
                                                              "/etc/rc5.d",
                                                              "/etc/rc6.d",
                                                              "/etc/rcS.d"};

  std::unordered_map<std::string, std::set<size_t>> service_list;

  for (size_t run_level = 0U; run_level < run_level_dir_list.size();
       ++run_level) {
    const auto& run_level_path = run_level_dir_list[run_level];

    boostfs::directory_iterator end_it;
    for (auto it = boostfs::directory_iterator(run_level_path); it != end_it;
         ++it) {
      const auto& symlink = it->path();
      if (!boostfs::is_symlink(symlink)) {
        VLOG(1) << "This is not a symlink: " << symlink;
        continue;
      }

      auto symlink_destination = boost::filesystem::canonical(symlink);
      if (!boostfs::is_regular_file(symlink_destination)) {
        VLOG(1) << "Skipping invalid symlink: " << symlink << " -> "
                << symlink_destination;
        continue;
      }

      auto service_name = symlink_destination.filename().string();
      service_list[service_name].insert(run_level);
    }
  }

  for (auto it = service_list.begin(); it != service_list.end(); it++) {
    const auto& service_name = it->first;
    const auto& run_level_list = it->second;

    Row r;
    r["name"] = service_name;
    r["status"] = "STOPPED/RUNNING";
    r["path"] = std::string("/etc/init.d/") + service_name;
    r["service_type"] = "SystemV";

    for (auto run_level : run_level_list) {
      if (!r["start_type"].empty()) {
        r["start_type"] += ", ";
      }

      if (run_level != 7) {
        r["start_type"] += std::to_string(run_level);
      } else {
        r["start_type"] += "S";
      }
    }

    query_data.push_back(r);
  }

  return Status(true, "OK");
}

Status enumerateUpstartServices(QueryData& query_data) {
  if (!upstartEnabled()) {
    return Status(true, "OK");
  }

  return Status(true, "OK");
}

Status enumerateSystemdServices(QueryData& query_data) {
  if (!systemdEnabled()) {
    return Status(true, "OK");
  }

  return Status(true, "OK");
}
} // namespace

namespace tables {
QueryData genServices(QueryContext& context) {
  QueryData query_data;

  if (!enumerateSystemVServices(query_data).ok()) {
    VLOG(1) << "Failed to enumerate the SystemV services";
  }

  if (!enumerateUpstartServices(query_data).ok()) {
    VLOG(1) << "Failed to enumerate the SystemV services";
  }

  if (!enumerateSystemdServices(query_data).ok()) {
    VLOG(1) << "Failed to enumerate the SystemV services";
  }

  return query_data;
}
} // namespace tables
} // namespace osquery
