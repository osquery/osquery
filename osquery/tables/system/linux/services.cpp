/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <mutex>
#include <set>

#include <algorithm>
#include <mutex>
#include <set>
#include <unordered_map>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/process.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace {

namespace boostfs = boost::filesystem;
namespace boostproc = boost::process;

bool sysVinitEnabled() {
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
  VLOG(1) << "SysVinit was" << (enabled.get() ? " " : " NOT ") << "found";

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

  enabled = boostfs::exists("/etc/init");
  VLOG(1) << "Upstart was" << (enabled.get() ? " " : " NOT ") << "found";

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

  enabled = std::system("which systemctl > /dev/null 2>&1") == 0;
  VLOG(1) << "systemd was" << (enabled.get() ? " " : " NOT ") << "found";

  return enabled.get();
}

Status enumerateSysVinitServices(QueryData& query_data) {
  if (!sysVinitEnabled()) {
    return Status(0, "OK");
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

    try {
      boostfs::directory_iterator end_it;
      for (auto it = boostfs::directory_iterator(run_level_path); it != end_it;
           ++it) {
        const auto& symlink = it->path();
        if (!boostfs::is_symlink(symlink)) {
          continue;
        }

        auto symlink_destination = boost::filesystem::canonical(symlink);
        if (!boostfs::is_regular_file(symlink_destination)) {
          VLOG(1) << "Skipping broken symlink: " << symlink << " -> "
                  << symlink_destination;

          continue;
        }

        auto service_name = symlink_destination.filename().string();
        service_list[service_name].insert(run_level);
      }
    } catch (const boost::filesystem::filesystem_error& e) {
      VLOG(1) << "An error has occurred: " << e.what() << ". Continuing anyway";
    }
  }

  for (auto it = service_list.begin(); it != service_list.end(); it++) {
    const auto& service_name = it->first;
    const auto& run_level_list = it->second;

    Row r;
    r["name"] = service_name;
    r["status"] = "";
    r["path"] = std::string("/etc/init.d/") + service_name;
    r["service_type"] = "SysVinit";

    // Use the same syntax as Upstart
    if (!run_level_list.empty()) {
      r["start_type"] = "runlevel [";

      for (auto run_level : run_level_list) {
        if (run_level != 7) {
          r["start_type"] += std::to_string(run_level);
        } else {
          r["start_type"] += "S";
        }
      }

      r["start_type"] += "]";
    }

    query_data.push_back(r);
  }

  return Status(0, "OK");
}

Status grabProgramOutput(std::vector<std::string>& output,
                         const std::string& executable,
                         const std::vector<std::string>& parameters) {
  output.clear();

  try {
    boostproc::ipstream process_output;
    boostproc::child process(boostproc::search_path(executable),
                             parameters,
                             boostproc::std_out > process_output,
                             boostproc::std_err > boostproc::null);

    process.wait();

    // clang-format off
    for (std::string line; std::getline(process_output, line);
         output.push_back(line));
    // clang-format on

    return Status(0, "OK");

  } catch (...) {
    return Status(1, "Failed to execute the process");
  }
}

Status getUpstartServiceStatus(bool& running, const std::string& service_name) {
  running = false;

  std::vector<std::string> output;
  auto status = grabProgramOutput(output, "initctl", {"status", service_name});
  if (!status.ok()) {
    return status;
  }

  // clang-format off
  auto it = std::find_if(
    output.begin(),
    output.end(),
    [service_name](const std::string &obj) -> bool {
      auto str = service_name + " start/";
      return (obj.find(str) != std::string::npos);
    }
  );
  // clang-format on

  running = (it != output.end());
  return Status(0, "OK");
}

Status getUpstartServiceStartCondition(std::string& condition,
                                       const std::string& service_name) {
  condition.clear();

  std::vector<std::string> output;
  auto status =
      grabProgramOutput(output, "initctl", {"show-config", service_name});
  if (!status.ok()) {
    return status;
  }

  // clang-format off
  auto it = std::find_if(
    output.begin(),
    output.end(),
    [](const std::string &obj) -> bool {
      return (obj.find("  start on") == 0);
    }
  );
  // clang-format on

  if (it == output.end()) {
    condition = "DISABLED";
    return Status(0, "OK");
  }

  condition = it->substr(11);
  return Status(0, "OK");
}

Status enumerateUpstartServices(QueryData& query_data) {
  if (!upstartEnabled()) {
    return Status(0, "OK");
  }

  boostfs::directory_iterator end_it;
  for (auto it = boostfs::directory_iterator("/etc/init"); it != end_it; ++it) {
    const auto& service_config_path = it->path();
    if (!boostfs::is_regular_file(service_config_path)) {
      VLOG(1) << "Skipping invalid service configuration file: "
              << service_config_path;

      continue;
    }

    Row r = {};
    auto service_name = service_config_path.filename().stem().string();
    r["name"] = service_name;
    r["path"] = service_config_path.string();
    r["service_type"] = "Upstart";

    bool running;
    auto status = getUpstartServiceStatus(running, service_name);
    if (!status.ok()) {
      running = false;
      VLOG(1) << "Failed to determine whether the following Upstart service is "
                 "running or not: "
              << service_name;
    }

    r["status"] = running ? "RUNNING" : "STOPPED";

    std::string start_condition;
    status = getUpstartServiceStartCondition(start_condition, service_name);
    if (!status.ok()) {
      start_condition.clear();

      VLOG(1) << "Failed to determine the following Upstart service "
                 "start condition: "
              << service_name;
    }

    r["start_type"] = start_condition;

    query_data.push_back(r);
  }

  return Status(0, "OK");
}

Status enumerateSystemdServices(QueryData& query_data) {
  if (!systemdEnabled()) {
    return Status(0, "OK");
  }

  return Status(0, "OK");
}
} // namespace

namespace tables {
QueryData genServices(QueryContext& context) {
  QueryData query_data;

  auto status = enumerateSysVinitServices(query_data);
  if (!status.ok()) {
    VLOG(1) << "Failed to enumerate the SysVinit services: "
            << status.getMessage();
  }

  status = enumerateUpstartServices(query_data);
  if (!status.ok()) {
    VLOG(1) << "Failed to enumerate the Upstart services: "
            << status.getMessage();
  }

  status = enumerateSystemdServices(query_data);
  if (!status.ok()) {
    VLOG(1) << "Failed to enumerate the systemd services: "
            << status.getMessage();
  }

  return query_data;
}
} // namespace tables
} // namespace osquery
