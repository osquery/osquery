/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <algorithm>
#include <mutex>
#include <set>
#include <unordered_map>

#define OSQUERY_ENABLE_SYSTEMD 1

#ifdef OSQUERY_ENABLE_SYSTEMD
#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-login.h>
#endif

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

#ifdef OSQUERY_ENABLE_SYSTEMD
/*
  https://github.com/systemd/systemd/blob/master/ENVIRONMENT.md

  $SYSTEMCTL_FORCE_BUS=1
    if set, do not connect to PID1's private D-Bus listener, and
    instead always connect through the dbus-daemon D-bus broker.
*/

sd_bus* getSystemdBusHandle() {
  auto force_dbus_env_var = std::getenv("SYSTEMCTL_FORCE_BUS");

  bool connection_mode = true;
  if (force_dbus_env_var != nullptr) {
    connection_mode = boost::lexical_cast<bool>(force_dbus_env_var);
  }

  if (connection_mode || geteuid() != 0) {
    VLOG(1) << "using sd_bus_default_system"; // XXX
    sd_bus* bus = nullptr;
    if (sd_bus_default_system(&bus) < 0) {
      return nullptr;
    }

    sd_bus_set_allow_interactive_authorization(bus, 0);
    return bus;
  }

  sd_bus* bus = nullptr;

  try {
    if (sd_bus_new(&bus) < 0 || bus == nullptr) {
      throw std::runtime_error("Failed to start the bus");
    }

    if (sd_bus_set_address(bus, "unix:path=/run/systemd/private") < 0) {
      throw std::runtime_error("Failed to set the bus address");
    }

    if (sd_bus_start(bus) < 0) {
      throw std::runtime_error("Failed to start the bus");
    }

    sd_bus_set_allow_interactive_authorization(bus, 0);

    auto fd = sd_bus_get_fd(bus);
    if (fd < 0) {
      throw std::runtime_error("Failed to acquire the bus file descriptor");
    }

    socklen_t l = sizeof(struct ucred);
    struct ucred ucred = {};

    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &l) < 0) {
      throw std::runtime_error("");
    }

    if (l != sizeof(struct ucred)) {
      throw std::runtime_error("");
    }

    if (ucred.uid != 0 && ucred.uid != geteuid()) {
      throw std::runtime_error("");
    }

    return bus;

  } catch (const std::exception& e) {
    VLOG(1) << e.what();

    if (bus != nullptr) {
      bus = sd_bus_flush_close_unref(bus);
    }

    return nullptr;
  }
}

struct SystemdUnitInfo final {
  std::string path;
  std::string state;
};

Status getSystemdUnitList(std::vector<SystemdUnitInfo>& unit_list,
                          sd_bus* bus) {
  unit_list.clear();

  sd_bus_message* reply = nullptr;
  sd_bus_error bus_error = SD_BUS_ERROR_NULL;

  try {
    /*if (sd_bus_message_new_method_call(bus,
                                       &message,
                                       "org.freedesktop.systemd1",
                                       "/org/freedesktop/systemd1",
                                       "org.freedesktop.systemd1.Manager",
                                       "ListUnitFiles")) {
      throw std::runtime_error("Failed to list the systemd units");
    }

    char** unit_filter = nullptr;
    int r = sd_bus_message_append_strv(message, unit_filter);
    if (r < 0) {
      throw std::runtime_error("");
    }*/

    if (sd_bus_call_method(bus,
                           "org.freedesktop.systemd1",
                           "/org/freedesktop/systemd1",
                           "org.freedesktop.systemd1.Manager",
                           "ListUnitFiles",
                           &bus_error,
                           &reply,
                           nullptr) < 0) {
      std::string error_message;
      if (bus_error.message != nullptr) {
        error_message = bus_error.message;
      } else {
        error_message = "Failed to call the remote method";
      }

      throw std::runtime_error(error_message);
    }

    if (sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ss)") < 0) {
      throw std::runtime_error("Failed to parse the reply");
    }

    while (true) {
      char* unit_path = nullptr;
      char* unit_state = nullptr;

      auto error = sd_bus_message_read(reply, "(ss)", &unit_path, &unit_state);
      if (error == 0) {
        break;
      } else if (error < 0) {
        throw std::runtime_error("Failed to parse the unit information");
      }

      unit_list.push_back({unit_path, unit_state});
    }

    reply = sd_bus_message_unref(reply);

    if (unit_list.empty()) {
      return Status(1, "No services returned by the manager!");
    }

    return Status(0, "OK");

  } catch (const std::exception& e) {
    if (reply != nullptr) {
      reply = sd_bus_message_unref(reply);
    }

    return Status(1, e.what());
  }
}

Status enumerateSystemdServices(QueryData& query_data) {
  auto bus = getSystemdBusHandle();
  if (bus == nullptr) {
    return Status(1, "Failed to acquire the bus handle");
  }

  std::vector<SystemdUnitInfo> unit_list;
  auto status = getSystemdUnitList(unit_list, bus);
  if (!status.ok()) {
    VLOG(1) << "Failed to enumerate the systemd units: " << status.getMessage();

  } else {
    for (const auto& unit_info : unit_list) {
      VLOG(1) << unit_info.path << " " << unit_info.state << std::endl;
    }
  }

  bus = sd_bus_flush_close_unref(bus);
  return Status(0, "OK");
}
#endif
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

#ifdef OSQUERY_ENABLE_SYSTEMD
  status = enumerateSystemdServices(query_data);
  if (!status.ok()) {
    VLOG(1) << "Failed to enumerate the systemd services: "
            << status.getMessage();
  }
#endif

  return query_data;
}
} // namespace tables
} // namespace osquery
