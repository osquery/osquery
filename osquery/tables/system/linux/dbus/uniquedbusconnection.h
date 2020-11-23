/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/tables/system/linux/dbus/uniqueresource.h>

#include <dbus/dbus.h>

namespace osquery {

class UniqueDbusConnectionAllocator {
 protected:
  using ResourceType = DBusConnection*;

  UniqueDbusConnectionAllocator() = default;
  virtual ~UniqueDbusConnectionAllocator() = default;

  static Status allocate(ResourceType& connection, bool system);
  static void deallocate(ResourceType& connection);
};

using UniqueDbusConnection =
    UniqueResource<UniqueDbusConnectionAllocator, bool>;

} // namespace osquery
