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
#include <cstdlib>
#include <unordered_map>
#include <vector>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/process.hpp>

#include <osquery/core.h>
#include <osquery/tables.h>

/*
  You can compile this with the system libraries by uncommenting these lines
  and removing "services.h"

  #include <systemd/sd-bus.h>
  #include <systemd/sd-daemon.h>
  #include <systemd/sd-login.h>
*/

#include "services.h"
using namespace systemd_deps;

namespace osquery {
namespace {

namespace boostfs = boost::filesystem;
namespace boostproc = boost::process;

bool isSysVinitEnabled() {
  auto enabled = boostfs::exists("/etc/init.d");
  VLOG(1) << "SysVinit support has been " << (enabled ? "enabled" : "disabled");

  return enabled;
}

bool isUpstartEnabled() {
  auto enabled = boostfs::exists("/etc/init");
  return enabled;
}

bool isSystemdEnabled() {
  static auto enabled = loadSystemdDependencies();
  VLOG(1) << "systemd support has been " << (enabled ? "enabled" : "disabled");

  return enabled;
}

Status enumerateSysVinitServices(QueryData& query_data) {
  static bool sysvinit_enabled = isSysVinitEnabled();
  if (!sysvinit_enabled) {
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

  std::unordered_map<std::string, std::vector<size_t>> service_list;

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

        auto symlink_destination = boostfs::canonical(symlink);
        if (!boostfs::is_regular_file(symlink_destination)) {
          VLOG(1) << "Skipping broken symlink: " << symlink << " -> "
                  << symlink_destination;

          continue;
        }

        auto service_name = symlink_destination.filename().string();
        service_list[service_name].push_back(run_level);
      }
    } catch (const boostfs::filesystem_error& e) {
      VLOG(1) << "An error has occurred: " << e.what() << ". Continuing anyway";
    }
  }

  for (const auto& p : service_list) {
    const auto& service_name = p.first;
    const auto& run_level_list = p.second;

    Row r;
    r["name"] = service_name;
    r["status"] = "";
    r["path"] = std::string("/etc/init.d/") + service_name;
    r["service_type"] = "SysVinit";

    // Use the same syntax as Upstart
    if (!run_level_list.empty()) {
      r["start_type"] = "runlevel [";

      for (const auto& run_level : run_level_list) {
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

sd_bus* getSystemdBusHandle() {
  /*
    https://github.com/systemd/systemd/blob/master/ENVIRONMENT.md

    $SYSTEMCTL_FORCE_BUS=1
      if set, do not connect to PID1's private D-Bus listener, and
      instead always connect through the dbus-daemon D-bus broker.
  */

  auto force_dbus_env_var = std::getenv("SYSTEMCTL_FORCE_BUS");

  bool connection_mode = true;
  if (force_dbus_env_var != nullptr) {
    connection_mode = boost::lexical_cast<bool>(force_dbus_env_var);
  }

  if (connection_mode || geteuid() != 0) {
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

Status getSystemdUnitPid(pid_t& process_id,
                         const std::string& unit_path,
                         sd_bus* bus) {
  sd_bus_message* reply = nullptr;
  sd_bus_error bus_error = SD_BUS_ERROR_NULL;

  try {
    sd_bus_call_method(bus,
                       "org.freedesktop.systemd1",
                       unit_path.data(),
                       "org.freedesktop.DBus.Properties",
                       "GetAll",
                       &bus_error,
                       &reply,
                       "s",
                       "");

    if (sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{sv}") < 0) {
      throw std::runtime_error("Failed to enter the data container");
    }

    while (true) {
      auto container_err =
          sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sv");
      if (container_err == 0) {
        break;
      } else if (container_err < 0) {
        throw std::runtime_error("Failed to enter the data container");
      }

      const char* property_name = nullptr;
      if (sd_bus_message_read(reply, "s", &property_name) < 0) {
        throw std::runtime_error("Failed to retrieve the property name");
      }

      if (std::strcmp(property_name, "MainPID") == 0) {
        const char* contents;
        if (sd_bus_message_peek_type(reply, NULL, &contents) < 0) {
          throw std::runtime_error("Failed to determine the property type");
        }

        if (sd_bus_message_enter_container(
                reply, SD_BUS_TYPE_VARIANT, contents) < 0) {
          throw std::runtime_error("Failed to enter the variant container");
        }

        char property_type;
        if (sd_bus_message_peek_type(reply, &property_type, NULL) < 0) {
          throw std::runtime_error("Failed to determine the property type");
        }

        if (sd_bus_message_read_basic(reply, property_type, &process_id) < 0) {
          throw std::runtime_error("Failed to read the property value");
        }

        if (sd_bus_message_exit_container(reply) < 0) {
          throw std::runtime_error("Failed to exit the data container");
        }

      } else if (sd_bus_message_skip(reply, "v") < 0) {
        throw std::runtime_error("Failed to skip the data entry");
      }

      if (sd_bus_message_exit_container(reply) < 0) {
        throw std::runtime_error("Failed to exit the data container");
      }
    }

    if (sd_bus_message_exit_container(reply) < 0) {
      throw std::runtime_error("Failed to exit the data container");
    }

    reply = sd_bus_message_unref(reply);
    return Status(0, "OK");

  } catch (const std::exception& e) {
    if (reply != nullptr) {
      reply = sd_bus_message_unref(reply);
    }

    return Status(1, e.what());
  }
}

struct SystemdUnitInfo final {
  std::string id;
  std::string description;
  std::string load_state;
  std::string active_state;
  std::string sub_state;
  std::string following;
  std::string unit_path;
  std::uint32_t job_id;
  std::string job_type;
  std::string job_path;
  pid_t process_id;
};

Status appendLoadedSystemdUnitList(std::vector<SystemdUnitInfo>& unit_list,
                                   sd_bus* bus) {
  sd_bus_message* message = nullptr;
  sd_bus_message* reply = nullptr;
  sd_bus_error bus_error = SD_BUS_ERROR_NULL;

  try {
    if (sd_bus_message_new_method_call(bus,
                                       &message,
                                       "org.freedesktop.systemd1",
                                       "/org/freedesktop/systemd1",
                                       "org.freedesktop.systemd1.Manager",
                                       "ListUnitsFiltered")) {
      throw std::runtime_error("Failed to list the systemd units");
    }

    char** unit_filter = nullptr;
    int r = sd_bus_message_append_strv(message, unit_filter);
    if (r < 0) {
      throw std::runtime_error("");
    }

    if (sd_bus_call(bus, message, 0, &bus_error, &reply) < 0) {
      std::string error_message;
      if (bus_error.message != nullptr) {
        error_message = bus_error.message;
      } else {
        error_message = "Failed to call the remote method";
      }

      throw std::runtime_error(error_message);
    }

    if (sd_bus_message_enter_container(
            reply, SD_BUS_TYPE_ARRAY, "(ssssssouso)") < 0) {
      throw std::runtime_error("Failed to enter the data container");
    }

    while (true) {
      const char* id = nullptr;
      const char* description = nullptr;
      const char* load_state = nullptr;
      const char* active_state = nullptr;
      const char* sub_state = nullptr;
      const char* following = nullptr;
      const char* unit_path = nullptr;
      std::uint32_t job_id = 0U;
      const char* job_type = nullptr;
      const char* job_path = nullptr;

      auto error = sd_bus_message_read(reply,
                                       "(ssssssouso)",
                                       &id,
                                       &description,
                                       &load_state,
                                       &active_state,
                                       &sub_state,
                                       &following,
                                       &unit_path,
                                       &job_id,
                                       &job_type,
                                       &job_path);
      if (error == 0) {
        break;
      } else if (error < 0) {
        throw std::runtime_error("Failed to parse the unit information");
      }

      SystemdUnitInfo unit_info = {id,
                                   description,
                                   load_state,
                                   active_state,
                                   sub_state,
                                   following,
                                   unit_path,
                                   job_id,
                                   job_type,
                                   job_path,
                                   0U};

      auto status = getSystemdUnitPid(unit_info.process_id, unit_path, bus);
      if (!status.ok()) {
        VLOG(1) << "Failed to determine the process id for the following "
                   "systemd unit: "
                << unit_path << ". Error: " << status.getMessage();
      }

      unit_list.push_back(unit_info);
    }

    if (sd_bus_message_exit_container(reply) < 0) {
      throw std::runtime_error("Failed to exit the data container");
    }

    reply = sd_bus_message_unref(reply);
    message = sd_bus_message_unref(message);

    return Status(0, "OK");

  } catch (const std::exception& e) {
    if (reply != nullptr) {
      reply = sd_bus_message_unref(reply);
    }

    if (message != nullptr) {
      message = sd_bus_message_unref(message);
    }

    return Status(1, e.what());
  }
}

Status appendInactiveSystemdUnitList(std::vector<SystemdUnitInfo>& unit_list,
                                     sd_bus* bus) {
  sd_bus_message* message = nullptr;
  sd_bus_message* reply = nullptr;
  sd_bus_error bus_error = SD_BUS_ERROR_NULL;

  try {
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
      throw std::runtime_error("Failed to enter the data container");
    }

    while (true) {
      const char* unit_path = nullptr;
      const char* unit_state = nullptr;

      auto error = sd_bus_message_read(reply, "(ss)", &unit_path, &unit_state);
      if (error == 0) {
        break;
      } else if (error < 0) {
        throw std::runtime_error("Failed to parse the unit information");
      }

      if (std::strcmp(unit_state, "disabled") != 0) {
        continue;
      }

      SystemdUnitInfo info = {};
      info.unit_path = unit_path;
      info.active_state = unit_state;

      unit_list.push_back(info);
    }

    if (sd_bus_message_exit_container(reply) < 0) {
      throw std::runtime_error("Failed to exit the data container");
    }

    reply = sd_bus_message_unref(reply);
    message = sd_bus_message_unref(message);

    if (unit_list.empty()) {
      return Status(1, "No services returned by the manager!");
    }

    return Status(0, "OK");

  } catch (const std::exception& e) {
    if (reply != nullptr) {
      reply = sd_bus_message_unref(reply);
    }

    if (message != nullptr) {
      message = sd_bus_message_unref(message);
    }

    return Status(1, e.what());
  }
}

Status getSystemdUnitList(std::vector<SystemdUnitInfo>& unit_list,
                          sd_bus* bus) {
  unit_list.clear();

  auto status = appendLoadedSystemdUnitList(unit_list, bus);
  if (!status.ok()) {
    return status;
  }

  status = appendInactiveSystemdUnitList(unit_list, bus);
  if (!status.ok()) {
    return status;
  }

  return Status(0, "OK");
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
      Row r = {};
      r["name"] = unit_info.id;
      r["status"] = unit_info.active_state;
      r["path"] = unit_info.unit_path;

      r["start_type"] =
          (unit_info.active_state != "disabled") ? "SYSTEM_START" : "DISABLED";

      r["service_type"] = "systemd";
      r["pid"] = std::to_string(unit_info.process_id);
      r["description"] = unit_info.description;

      query_data.push_back(r);
    }
  }

  bus = sd_bus_flush_close_unref(bus);
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

  // In older Ubuntu versions, you could revert back to Upstart by
  // disabling systemd. The "/etc/systemd/system" folder remains
  // intact when doing so, but the packages conflict with each
  // other so you can't have both binaries installed
  static bool systemd_enabled = isSystemdEnabled();
  static bool upstart_enabled = isUpstartEnabled();

  if (systemd_enabled) {
    status = enumerateSystemdServices(query_data);
    if (!status.ok()) {
      VLOG(1) << "Failed to enumerate the systemd services: "
              << status.getMessage();
    }

  } else if (upstart_enabled) {
    VLOG(1) << "Upstart service enumeration is not yet supported";
  } else {
    VLOG(1) << "Unknown init system";
  }

  return query_data;
}
} // namespace tables
} // namespace osquery
