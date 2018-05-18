/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */
#include <string>
#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <systemd/sd-bus.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

//https://github.com/systemd/systemd/blob/4d09e1c8bab1d684172b1f277f3213825b30d2d9/src/libsystemd/sd-bus/bus-error.c#L550-L565
static const char *bus_error_message(const sd_bus_error *e, int error) {

  if (e) {
    /* Sometimes, the D-Bus server is a little bit too verbose with
    * its error messages, so let's override them here */
    if (e && e->name && strcmp(e->name, "org.freedesktop.DBus.Error.AccessDenied") == 0)
      return "Access denied";

    if (e->message)
      return e->message;
  }

  if (error < 0)
    error = -error;

  return strerror(error);
}

//https://github.com/systemd/systemd/blob/81321f51cf7968060a3ad458c199d63a6999f2da/src/systemctl/systemctl.c#L1486-L1560
QueryData genStartupItems(QueryContext& context) {
  QueryData results;
  sd_bus_message *reply = NULL;
  const char *state;
  char *path;
  int r;

  sd_bus_message *m = NULL;
  sd_bus_error error = SD_BUS_ERROR_NULL;
  sd_bus *bus;

  r = sd_bus_open_system(&bus);
  if (r < 0)
    return results;

  r = sd_bus_message_new_method_call(bus,
                                     &m,
                                     "org.freedesktop.systemd1",
                                     "/org/freedesktop/systemd1",
                                     "org.freedesktop.systemd1.Manager",
                                     "ListUnitFiles");
  if (r < 0){
    VLOG(1) << "Bus error " << bus_error_message(&error, r);
    return results;
  }


  r = sd_bus_call(bus, m, 0, &error, &reply);
  if (r < 0){
    VLOG(1) << "Bus error " << bus_error_message(&error, r);
    return results;
  }


  r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ss)");
  if (r < 0){
    VLOG(1) << "Bus error " << bus_error_message(&error, r);
    return results;
  }

  while ((r = sd_bus_message_read(reply, "(ss)", &path, &state)) > 0) {
    Row row;
    auto blacklist_state = osquery::split(state, " ");
    row["status"] = std::string(state);
    row["source"] = std::string(path);
    results.push_back(row);
  }
  if (r < 0){
    VLOG(1) << "Bus error " << bus_error_message(&error, r);
    return results;
  }

  r = sd_bus_message_exit_container(reply);
  if (r < 0){
    VLOG(1) << "Bus error " << bus_error_message(&error, r);
    return results;
  }

  return results;
}
}
}
