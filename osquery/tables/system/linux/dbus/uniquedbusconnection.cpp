/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tables/system/linux/dbus/uniquedbusconnection.h>

namespace osquery {

Status UniqueDbusConnectionAllocator::allocate(ResourceType& connection,
                                               bool system) {
  auto connection_type = system ? DBUS_BUS_SYSTEM : DBUS_BUS_SESSION;

  DBusError error DBUS_ERROR_INIT;
  connection = dbus_bus_get(connection_type, &error);
  if (dbus_error_is_set(&error)) {
    std::stringstream message;
    message << "Failed to connect to the " << (system ? "system" : "session")
            << " dbus: " << error.message << " (" << error.name << ")";

    dbus_error_free(&error);
    return Status::failure(message.str());
  }

  return Status::success();
}

void UniqueDbusConnectionAllocator::deallocate(ResourceType& connection) {
  if (connection == nullptr) {
    return;
  }

  dbus_connection_unref(connection);
  connection = nullptr;
}

} // namespace osquery
